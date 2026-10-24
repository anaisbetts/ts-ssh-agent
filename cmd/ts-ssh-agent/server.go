package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/anaisbetts/ts-ssh-agent/internal/server"
)

func runServer(args []string) error {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	hostname := fs.String("hostname", envOr("TS_SSH_AGENT_HOSTNAME", "ts-ssh-agent"), "tailnet hostname (env TS_SSH_AGENT_HOSTNAME)")
	stateDir := fs.String("state-dir", envOr("TS_SSH_AGENT_STATE_DIR", "/var/lib/ts-ssh-agent"), "directory for tailscale state and keys (env TS_SSH_AGENT_STATE_DIR)")
	listen := fs.String("listen", ":80", "tailnet address to listen on")
	allowed := fs.String("allowed-users", os.Getenv("TS_SSH_AGENT_ALLOWED_USERS"), "comma-separated Tailscale login names allowed to connect; empty allows any user (env TS_SSH_AGENT_ALLOWED_USERS)")
	verbose := fs.Bool("v", false, "verbose tailscale logging")
	fs.Parse(args)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	return server.Run(ctx, server.Config{
		Hostname:        *hostname,
		StateDir:        *stateDir,
		AuthKey:         os.Getenv("TS_AUTHKEY"),
		ListenAddr:      *listen,
		StorePassphrase: os.Getenv("TS_SSH_AGENT_STORE_PASSPHRASE"),
		AllowedUsers:    splitList(*allowed),
		Verbose:         *verbose,
	})
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
