//go:build windows

package main

import (
	"fmt"
	"log"
	"net"
	"os"

	"github.com/tailscale/go-winio"
	"golang.org/x/sys/windows"
)

// openSSHAgentPipe is where Windows OpenSSH looks for an agent when
// SSH_AUTH_SOCK is unset. Windows OpenSSH can only talk to named pipes, not
// Unix sockets.
const openSSHAgentPipe = `\\.\pipe\openssh-ssh-agent`

func listenAgent(path string) (net.Listener, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("looking up current user: %w", err)
	}
	// The default named pipe ACL grants Everyone read access, so restrict the
	// pipe to the current user only.
	sddl := fmt.Sprintf("D:P(A;;GA;;;%s)", user.User.Sid.String())

	ln, err := winio.ListenPipe(path, &winio.PipeConfig{SecurityDescriptor: sddl})
	if err != nil && path == openSSHAgentPipe {
		return nil, fmt.Errorf("listening on %s: %w\n"+
			"If the Windows OpenSSH agent service is running, disable it (as admin):\n"+
			"  Stop-Service ssh-agent; Set-Service ssh-agent -StartupType Disabled\n"+
			`or pass -a \\.\pipe\ts-ssh-agent and set SSH_AUTH_SOCK to that`, path, err)
	}
	return ln, err
}

func printAgentEnv(path string, _, _ bool) {
	if path == openSSHAgentPipe {
		log.Printf("using the default Windows OpenSSH agent pipe; SSH_AUTH_SOCK does not need to be set")
		return
	}
	fmt.Printf("$env:SSH_AUTH_SOCK = '%s'\n", path)
}

func defaultAgentPath() string {
	return openSSHAgentPipe
}

// openTerminal returns the console for prompting and reading, even when
// stdin/stdout are redirected.
func openTerminal() (in, out *os.File, err error) {
	in, err = os.OpenFile("CONIN$", os.O_RDWR, 0)
	if err != nil {
		return nil, nil, err
	}
	out, err = os.OpenFile("CONOUT$", os.O_WRONLY, 0)
	if err != nil {
		in.Close()
		return nil, nil, err
	}
	return in, out, nil
}
