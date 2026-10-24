package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const agentStartTimeout = 5 * time.Second

func runShell(args []string) error {
	fs := flag.NewFlagSet("shell", flag.ExitOnError)
	serverURL := serverURLFlag(fs)
	path := fs.String("a", defaultAgentPath(), "socket (Unix) or named pipe (Windows) of the agent")
	cshStyle := fs.Bool("c", false, "print csh-style environment commands")
	shStyle := fs.Bool("s", false, "print sh-style environment commands")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: ts-ssh-agent shell [flags]\n\n"+
			"Starts the agent if it isn't running, then prints the environment for your shell:\n"+
			`  eval "$(ts-ssh-agent shell)"                 # bash/zsh`+"\n"+
			`  ts-ssh-agent shell | Invoke-Expression       # PowerShell`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	// Still print the environment on failure, so the shell is configured for
	// whenever the agent does come up.
	if err := ensureAgent(*path, *serverURL); err != nil {
		fmt.Fprintf(os.Stderr, "ts-ssh-agent: %v\n", err)
	}
	printAgentEnv(*path, *cshStyle, *shStyle)
	return nil
}

// ensureAgent makes sure an agent is listening on path, preferring the
// systemd user unit when one is installed over spawning a background agent.
func ensureAgent(path, serverURL string) error {
	if agentAlive(path) {
		return nil
	}

	usedService := false
	if path == defaultAgentPath() {
		var err error
		if usedService, err = startAgentService(serverURL); err != nil {
			return err
		}
	}

	var logPath string
	if !usedService {
		var err error
		if logPath, err = spawnAgent(path, serverURL); err != nil {
			return fmt.Errorf("starting agent: %w", err)
		}
	}

	deadline := time.Now().Add(agentStartTimeout)
	for !agentAlive(path) {
		if time.Now().After(deadline) {
			if logPath != "" {
				return fmt.Errorf("agent didn't start listening on %s; see %s", path, logPath)
			}
			return fmt.Errorf("agent didn't start listening on %s; see journalctl --user -u ts-ssh-agent", path)
		}
		time.Sleep(50 * time.Millisecond)
	}
	return nil
}

// spawnAgent starts `ts-ssh-agent agent` detached from the current session,
// logging to a file, and returns the log path.
func spawnAgent(path, serverURL string) (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	logPath, err := agentLogPath()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
		return "", err
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return "", err
	}
	defer logFile.Close()

	cmd := exec.Command(exe, "agent", "-a", path, "-server", serverURL)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = detachedProcAttr()
	if err := cmd.Start(); err != nil {
		return "", err
	}
	return logPath, cmd.Process.Release()
}

func agentAlive(path string) bool {
	conn, err := dialAgent(path)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func agentLogPath() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("can't find a directory for the agent log: %w", err)
	}
	return filepath.Join(dir, "ts-ssh-agent", "agent.log"), nil
}
