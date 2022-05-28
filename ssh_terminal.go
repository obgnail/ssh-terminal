package main

import (
	"fmt"
	"github.com/juju/errors"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
	"io"
	"io/ioutil"
	"os"
	"os/signal"
	"path"
	"strings"
	"syscall"
	"time"
)

type SSHTerminal struct {
	Session *ssh.Session
	stdin   io.Writer
	stdout  io.Reader
	stderr  io.Reader
	exitMsg string
}

func NewSSHTerminal(session *ssh.Session) *SSHTerminal {
	return &SSHTerminal{Session: session}
}

func (term *SSHTerminal) updateTerminalSize() {
	go func() {
		// SIGWINCH is sent to the process when the window size of the terminal has
		// changed.
		sigwinchCh := make(chan os.Signal, 1)
		signal.Notify(sigwinchCh, syscall.SIGWINCH)

		fd := int(os.Stdin.Fd())
		termWidth, termHeight, err := terminal.GetSize(fd)
		if err != nil {
			fmt.Println(errors.Trace(err))
		}

		for {
			select {
			// The client updated the size of the local PTY. This change needs to occur
			// on the server side PTY as well.
			case sigwinch := <-sigwinchCh:
				if sigwinch == nil {
					return
				}
				currTermWidth, currTermHeight, err := terminal.GetSize(fd)

				// Terminal size has not changed, don'term do anything.
				if currTermHeight == termHeight && currTermWidth == termWidth {
					continue
				}

				term.Session.WindowChange(currTermHeight, currTermWidth)
				if err != nil {
					fmt.Printf("Unable to send window-change reqest: %s.", err)
					continue
				}

				termWidth, termHeight = currTermWidth, currTermHeight
			}
		}
	}()
}

func (term *SSHTerminal) Interact(commands []string) error {
	defer func() {
		if term.exitMsg == "" {
			fmt.Fprintln(os.Stdout, "the connection was closed on the remote side on ", time.Now().Format(time.RFC822))
		} else {
			fmt.Fprintln(os.Stdout, term.exitMsg)
		}
	}()

	fd := int(os.Stdin.Fd())
	state, err := terminal.MakeRaw(fd)
	if err != nil {
		return errors.Trace(err)
	}
	defer terminal.Restore(fd, state)

	termWidth, termHeight, err := terminal.GetSize(fd)
	if err != nil {
		return errors.Trace(err)
	}

	termType := os.Getenv("TERM")
	if termType == "" {
		termType = "xterm-256color"
	}

	err = term.Session.RequestPty(termType, termHeight, termWidth, ssh.TerminalModes{})
	if err != nil {
		return errors.Trace(err)
	}

	term.updateTerminalSize()

	term.stdin, err = term.Session.StdinPipe()
	if err != nil {
		return errors.Trace(err)
	}
	term.stdout, err = term.Session.StdoutPipe()
	if err != nil {
		return errors.Trace(err)
	}
	term.stderr, err = term.Session.StderrPipe()
	if err != nil {
		return errors.Trace(err)
	}

	go io.Copy(os.Stderr, term.stderr)
	go io.Copy(os.Stdout, term.stdout)
	go func() {
		buf := make([]byte, 128)
		for {
			n, err := os.Stdin.Read(buf)
			if err != nil {
				fmt.Println(errors.Trace(err))
				return
			}
			if n > 0 {
				_, err = term.stdin.Write(buf[:n])
				if err != nil {
					fmt.Println(errors.Trace(err))
					term.exitMsg = err.Error()
					return
				}
			}
		}
	}()

	err = term.Session.Shell()
	if err != nil {
		return errors.Trace(err)
	}
	time.Sleep(time.Second)
	//term.Session.Run()
	if err := term.Exec(commands); err != nil {
		return errors.Trace(err)
	}
	err = term.Session.Wait()
	if err != nil {
		return errors.Trace(err)
	}
	return nil
}

func (term *SSHTerminal) Exec(commands []string) error {
	for _, cmd := range commands {
		_, err := fmt.Fprintln(term.stdin, cmd)
		if err != nil {
			return errors.Trace(err)
		}
		time.Sleep(time.Second)
	}
	return nil
}

func Dial(config *Conf) (*ssh.Client, error) {
	if len(config.Addr) == 0 || len(config.User) == 0 || len(config.CommandChainPath) == 0 {
		return nil, errors.New("config error")
	}

	// 优先级为：用户密码 > 密钥文本 > 密钥地址
	var auth ssh.AuthMethod
	if len(config.Password) != 0 {
		auth = ssh.Password(config.Password)
	}
	if auth == nil && len(config.PrivateKey) != 0 {
		signer, err := ssh.ParsePrivateKey([]byte(config.PrivateKey))
		if err != nil {
			return nil, errors.Trace(err)
		}
		auth = ssh.PublicKeys(signer)
	}
	if auth == nil {
		dir := config.SSHDirPath
		if len(dir) == 0 {
			homePath, err := os.UserHomeDir()
			if err != nil {
				return nil, errors.Trace(err)
			}
			dir = homePath
		}
		key, err := ioutil.ReadFile(path.Join(dir, ".ssh", "id_rsa"))
		if err != nil {
			return nil, errors.Trace(err)
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, errors.Trace(err)
		}
		auth = ssh.PublicKeys(signer)
	}

	if auth == nil {
		return nil, errors.New("empty auth")
	}

	sshConfig := &ssh.ClientConfig{
		User:            config.User,
		Auth:            []ssh.AuthMethod{auth},
		Timeout:         30 * time.Second,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	addr := config.Addr
	if !strings.Contains(addr, ":") {
		addr = fmt.Sprintf("%s:%d", addr, 22)
	}
	client, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		return nil, errors.Trace(err)
	}
	return client, nil
}
