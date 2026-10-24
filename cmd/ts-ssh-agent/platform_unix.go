//go:build !windows

package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const systemdUnit = "ts-ssh-agent.service"

func listenAgent(path string) (net.Listener, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	// The directory may live in a shared location like /tmp, so make sure
	// nobody else pre-created it.
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !info.IsDir() || !ok || int(st.Uid) != os.Getuid() || info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s must be a directory owned by you with mode 0700", dir)
	}

	if _, err := os.Stat(path); err == nil {
		if conn, err := dialAgent(path); err == nil {
			conn.Close()
			return nil, fmt.Errorf("an agent is already listening on %s", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("removing stale socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

func printAgentEnv(path string, csh, sh bool) {
	if csh || (!sh && strings.HasSuffix(os.Getenv("SHELL"), "csh")) {
		fmt.Printf("setenv SSH_AUTH_SOCK %s;\n", path)
	} else {
		fmt.Printf("SSH_AUTH_SOCK=%s; export SSH_AUTH_SOCK;\n", path)
	}
}

// startAgentService starts the systemd user unit if one is installed,
// reporting whether it did so.
func startAgentService() (bool, error) {
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return false, nil
	}
	if exec.Command(systemctl, "--user", "cat", systemdUnit).Run() != nil {
		return false, nil
	}
	if out, err := exec.Command(systemctl, "--user", "start", systemdUnit).CombinedOutput(); err != nil {
		return true, fmt.Errorf("systemctl --user start %s: %v: %s", systemdUnit, err, strings.TrimSpace(string(out)))
	}
	return true, nil
}

func defaultAgentPath() string {
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return filepath.Join(dir, "ts-ssh-agent", "agent.sock")
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("ts-ssh-agent-%d", os.Getuid()), "agent.sock")
}

func dialAgent(path string) (net.Conn, error) {
	return net.DialTimeout("unix", path, time.Second)
}

func detachedProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}

// openTerminal returns the controlling terminal for both prompting and
// reading, even when stdin/stdout are redirected.
func openTerminal() (in, out *os.File, err error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	return tty, tty, err
}
