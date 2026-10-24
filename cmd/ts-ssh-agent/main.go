// Command ts-ssh-agent is an SSH agent whose keys live on a server in your
// tailnet instead of on the local machine.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/anaisbetts/ts-ssh-agent/internal/api"
	"github.com/anaisbetts/ts-ssh-agent/internal/client"
)

const usage = `usage: ts-ssh-agent <command> [flags]

Commands:
  server   Run the key server (joins the tailnet via tsnet)
  server-setup
           Set up and start the key server as a systemd user service
  agent    Run a local SSH agent backed by the key server
  shell    Start the agent if needed and print SSH_AUTH_SOCK for your shell rc
  add      Upload private keys to the key server (like ssh-add)
  list     List keys stored on the key server (like ssh-add -l / -L)
  remove   Remove keys from the key server (like ssh-add -d / -D)
  whoami   Show which Tailscale identity the key server sees

Run 'ts-ssh-agent <command> -h' for command flags.
`

var commands = map[string]func(args []string) error{
	"server":       runServer,
	"server-setup": runServerSetup,
	"agent":        runAgent,
	"shell":        runShell,
	"add":          runAdd,
	"list":         runList,
	"remove":       runRemove,
	"whoami":       runWhoAmI,
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if os.Args[1] == "-h" || os.Args[1] == "--help" || os.Args[1] == "help" {
		fmt.Print(usage)
		return
	}

	cmd, ok := commands[os.Args[1]]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err := cmd(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "ts-ssh-agent %s: %v\n", os.Args[1], err)
		os.Exit(1)
	}
}

// serverFlag registers the --server flag shared by all client commands and
// returns a constructor for a client pointed at it.
func serverFlag(fs *flag.FlagSet) func() *client.Client {
	url := serverURLFlag(fs)
	return func() *client.Client { return client.New(*url, nil) }
}

func serverURLFlag(fs *flag.FlagSet) *string {
	return fs.String("server", envOr("TS_SSH_AGENT_SERVER", api.DefaultServerURL), "key server URL (env TS_SSH_AGENT_SERVER)")
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
