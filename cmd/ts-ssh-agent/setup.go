package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	serverUnit = "ts-ssh-agent-server.service"
	// How long to wait for the server to come up when no browser login is
	// involved; once a login link is shown we wait for the user indefinitely.
	serverStartTimeout = 2 * time.Minute
)

var loginURLPattern = regexp.MustCompile(`https://login\.tailscale\.com/\S+`)

func runServerSetup(args []string) error {
	fs := flag.NewFlagSet("server-setup", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: ts-ssh-agent server-setup\n\n"+
			"Configures and starts the key server as a systemd user service, walking you\n"+
			"through adding it to your tailnet.")
	}
	fs.Parse(args)

	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return errors.New("server-setup needs systemd; elsewhere, run the server with Docker")
	}
	if exec.Command(systemctl, "--user", "cat", serverUnit).Run() != nil {
		return fmt.Errorf("the %s user unit isn't installed; install the .deb or Arch package first", serverUnit)
	}

	envPath, err := serverEnvPath()
	if err != nil {
		return err
	}
	if _, err := os.Stat(envPath); err == nil {
		fmt.Printf("Using existing settings in %s\n", envPath)
	} else if errors.Is(err, os.ErrNotExist) {
		if err := writeServerEnv(envPath); err != nil {
			return err
		}
	} else {
		return err
	}

	if err := runSystemctl(systemctl, "enable", serverUnit); err != nil {
		return err
	}
	if err := runSystemctl(systemctl, "restart", serverUnit); err != nil {
		return err
	}
	out, err := exec.Command(systemctl, "--user", "show", "--property=InvocationID", "--value", serverUnit).Output()
	if err != nil {
		return fmt.Errorf("looking up the server's invocation ID: %w", err)
	}
	fmt.Println("Started the key server; waiting for it to join your tailnet...")

	usedBrowserLogin, err := waitForServer(systemctl, strings.TrimSpace(string(out)))
	if err != nil {
		return err
	}

	if !lingerEnabled() {
		fmt.Println("\nUser services stop when you log out. To keep the server running, enable lingering:\n" +
			"  sudo loginctl enable-linger $USER")
	}
	if usedBrowserLogin {
		fmt.Println("\nThe server was added with your own login, so its Tailscale key expires (after 180 days\n" +
			"by default). Turn on \"Disable key expiry\" for it at https://login.tailscale.com/admin/machines")
	}
	return nil
}

func writeServerEnv(path string) error {
	authKey, err := readPassphrase("Tailscale auth key (leave empty to log in with a browser link instead): ")
	if err != nil {
		return err
	}
	passphrase, err := readPassphrase("Passphrase to encrypt stored keys (leave empty for none): ")
	if err != nil {
		return err
	}
	if len(passphrase) > 0 {
		again, err := readPassphrase("Repeat passphrase: ")
		if err != nil {
			return err
		}
		if !bytes.Equal(passphrase, again) {
			return errors.New("passphrases don't match")
		}
	}

	var b strings.Builder
	b.WriteString("# Written by `ts-ssh-agent server-setup`, read by " + serverUnit + ".\n")
	if len(authKey) > 0 {
		b.WriteString("TS_AUTHKEY=" + quoteEnvValue(string(authKey)) + "\n")
	}
	if len(passphrase) > 0 {
		b.WriteString("TS_SSH_AGENT_STORE_PASSPHRASE=" + quoteEnvValue(string(passphrase)) + "\n")
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		return err
	}
	fmt.Printf("Wrote %s\n", path)
	return nil
}

// waitForServer follows the journal of one run of the unit until the server
// is serving, showing the login link if Tailscale asks for one. It reports
// whether the user had to log in through the browser.
func waitForServer(systemctl, invocationID string) (bool, error) {
	cmd := exec.Command("journalctl", "--user", "--follow", "--lines=all", "--output", "cat",
		"_SYSTEMD_INVOCATION_ID="+invocationID)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return false, err
	}
	if err := cmd.Start(); err != nil {
		return false, err
	}
	defer cmd.Process.Kill()

	lines := make(chan string)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
		close(lines)
	}()

	timeout := time.NewTimer(serverStartTimeout)
	defer timeout.Stop()
	poll := time.NewTicker(2 * time.Second)
	defer poll.Stop()
	seeLogs := "see journalctl --user -u " + serverUnit

	usedBrowserLogin := false
	for {
		select {
		case line, ok := <-lines:
			if !ok {
				return false, errors.New("journalctl exited unexpectedly; " + seeLogs)
			}
			if url := loginURLPattern.FindString(line); url != "" && !usedBrowserLogin {
				usedBrowserLogin = true
				timeout.Stop()
				fmt.Printf("\nOpen this link to add the key server to your tailnet:\n\n  %s\n\nWaiting for you to approve it...\n", url)
			}
			if _, addr, ok := strings.Cut(line, "serving on "); ok {
				fmt.Printf("\nThe key server is up at %s\n", addr)
				return usedBrowserLogin, nil
			}
			if _, msg, ok := strings.Cut(line, "ts-ssh-agent server: "); ok {
				return false, fmt.Errorf("the key server failed: %s; %s", msg, seeLogs)
			}
		case <-poll.C:
			if exec.Command(systemctl, "--user", "is-failed", "--quiet", serverUnit).Run() == nil {
				return false, fmt.Errorf("%s failed to start; %s", serverUnit, seeLogs)
			}
		case <-timeout.C:
			return false, fmt.Errorf("the key server didn't come up within %v; %s", serverStartTimeout, seeLogs)
		}
	}
}

func lingerEnabled() bool {
	out, err := exec.Command("loginctl", "show-user", "--property=Linger", "--value").Output()
	return err == nil && strings.TrimSpace(string(out)) == "yes"
}

// serverEnvPath matches the unit's EnvironmentFile=%E/ts-ssh-agent/server.env.
func serverEnvPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "ts-ssh-agent", "server.env"), nil
}

// quoteEnvValue quotes a value for a systemd EnvironmentFile.
func quoteEnvValue(v string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v) + `"`
}

func runSystemctl(systemctl string, args ...string) error {
	out, err := exec.Command(systemctl, append([]string{"--user"}, args...)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl --user %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
