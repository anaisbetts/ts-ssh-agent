package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/anaisbetts/ts-ssh-agent/internal/agent"
)

func runAgent(args []string) error {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	newClient := serverFlag(fs)
	path := fs.String("a", defaultAgentPath(), "socket (Unix) or named pipe (Windows) to listen on")
	cshStyle := fs.Bool("c", false, "print csh-style environment commands")
	shStyle := fs.Bool("s", false, "print sh-style environment commands")
	fs.Parse(args)

	ln, err := listenAgent(*path)
	if err != nil {
		return err
	}
	printAgentEnv(*path, *cshStyle, *shStyle)

	c := newClient()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	if who, err := c.WhoAmI(ctx); err != nil {
		log.Printf("warning: can't reach key server yet: %v", err)
	} else {
		log.Printf("connected to key server as %s from %s", who.LoginName, who.NodeName)
	}
	cancel()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Printf("listening on %s", *path)
	return agent.Serve(ctx, ln, agent.New(c))
}
