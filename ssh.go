package main

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

// WebSocketClient manages a bidirectional connection between WebSocket and SSH.
type WebSocketClient struct {
	conn    *websocket.Conn
	sshConn *ssh.Client
	session *ssh.Session

	stdin  io.WriteCloser
	stdout io.Reader
	stderr io.Reader

	mu      sync.Mutex
	writeMu sync.Mutex
	done    chan struct{}
	started bool // true once SSH session.Shell() has been called
}

// AuthData contains SSH credentials received from the WebSocket client.
type AuthData struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// connectSSH establishes an SSH connection and starts the shell.
func (c *WebSocketClient) connectSSH(auth AuthData) error {
	config := &ssh.ClientConfig{
		User:            auth.Username,
		Auth:            []ssh.AuthMethod{ssh.Password(auth.Password)},
		HostKeyCallback: knownHosts,
		Timeout:         10 * time.Second,
	}
	addr := fmt.Sprintf("%s:%d", auth.Host, auth.Port)
	sshConn, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return fmt.Errorf("ssh dial: %w", err)
	}
	c.sshConn = sshConn

	session, err := sshConn.NewSession()
	if err != nil {
		sshConn.Close()
		return fmt.Errorf("new session: %w", err)
	}
	c.session = session

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	ptyTerm := "xterm-256color"
	if err := session.RequestPty(ptyTerm, 160, 48, modes); err != nil {
		ptyTerm = "xterm"
		if err2 := session.RequestPty(ptyTerm, 160, 48, modes); err2 != nil {
			session.Close()
			sshConn.Close()
			return fmt.Errorf("request pty: %v (tried xterm: %v)", err, err2)
		}
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		session.Close()
		sshConn.Close()
		return fmt.Errorf("stdin pipe: %w", err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		stdin.Close()
		session.Close()
		sshConn.Close()
		return fmt.Errorf("stdout pipe: %w", err)
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		stdin.Close()
		session.Close()
		sshConn.Close()
		return fmt.Errorf("stderr pipe: %w", err)
	}
	c.stdin = stdin
	c.stdout = stdout
	c.stderr = stderr

	// Start shell synchronously BEFORE handling messages
	if err := session.Shell(); err != nil {
		stdin.Close()
		session.Close()
		sshConn.Close()
		return fmt.Errorf("shell start: %w", err)
	}
	c.started = true

	// Launch output readers
	go c.readOutput()
	go c.readError()

	debugPrintf("SSH shell started: %s@%s", auth.Username, auth.Host)
	return nil
}

func (c *WebSocketClient) readOutput() {
	buf := make([]byte, 8192)
	for {
		select {
		case <-c.done:
			return
		default:
		}
		n, err := c.stdout.Read(buf)
		if n > 0 {
			c.sendOutput(string(buf[:n]))
		}
		if err != nil {
			if err != io.EOF {
				debugPrintf("SSH stdout read error: %v", err)
			}
			return
		}
	}
}

func (c *WebSocketClient) readError() {
	buf := make([]byte, 8192)
	for {
		select {
		case <-c.done:
			return
		default:
		}
		n, err := c.stderr.Read(buf)
		if n > 0 {
			c.sendOutput(string(buf[:n]))
		}
		if err != nil {
			if err != io.EOF {
				debugPrintf("SSH stderr read error: %v", err)
			}
			return
		}
	}
}

// handleMessages processes incoming WebSocket messages (commands and resize events).
func (c *WebSocketClient) handleMessages() {
	defer close(c.done)
	for {
		_, msg, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				debugPrintf("WebSocket read error: %v", err)
			}
			return
		}
		var data map[string]interface{}
		if err := jsonUnmarshal(msg, &data); err != nil {
			debugPrintf("Invalid message from client: %v", err)
			continue
		}
		if cmd, ok := data["command"].(string); ok {
			c.writeToStdin(cmd)
		} else if resize, ok := data["resize"].(map[string]interface{}); ok {
			if rows, ok := getFloat(resize["rows"]); ok {
				if cols, ok := getFloat(resize["cols"]); ok {
					c.mu.Lock()
					if c.session != nil && c.started {
						_ = c.session.WindowChange(int(rows), int(cols))
					}
					c.mu.Unlock()
				}
			}
		}
	}
}

// writeToStdin sends a string to the SSH session stdin.
// For multi-character input (paste), normalize \n to \r.
// Single characters (keyboard input) are sent as-is — xterm
// already includes \r when Enter is pressed.
func (c *WebSocketClient) writeToStdin(data string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stdin == nil {
		return
	}
	// For multi-character input (paste), normalize \n to \r.
	// Single characters (keyboard input) are sent as-is — xterm
	// already includes \r when Enter is pressed.
	if len(data) > 1 {
		data = strings.ReplaceAll(data, "\n", "\r")
	}
	c.writeMu.Lock()
	_, _ = c.stdin.Write([]byte(data))
	c.writeMu.Unlock()
}

func (c *WebSocketClient) sendOutput(data string) {
	c.sendJSON(map[string]interface{}{"type": "output", "data": data})
}

func (c *WebSocketClient) sendError(errMsg string) {
	c.sendJSON(map[string]interface{}{"type": "error", "error": errMsg})
}

func (c *WebSocketClient) sendJSON(msg map[string]interface{}) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_ = c.conn.WriteJSON(msg)
}

// close safely terminates the SSH session and WebSocket connection.
func (c *WebSocketClient) close() {
	// Signal goroutines to stop
	select {
	case <-c.done:
		// already closed
	default:
		close(c.done)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.session != nil {
		// Send exit to remote shell, then close session
		if c.stdin != nil {
			_, _ = c.stdin.Write([]byte("exit\r"))
			c.stdin.Close()
		}
		c.session.Close()
	}
	if c.sshConn != nil {
		c.sshConn.Close()
	}
}

// getFloat is a helper to safely extract a float64 from interface{}.
func getFloat(v interface{}) (float64, bool) {
	f, ok := v.(float64)
	return f, ok
}