// Package agent exposes a ts-ssh-agent server as a standard SSH agent, so
// that ssh, ssh-add, git, etc. can use it via SSH_AUTH_SOCK.
package agent

import (
	"context"
	"crypto/subtle"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"

	"github.com/anaisbetts/ts-ssh-agent/internal/api"
	"github.com/anaisbetts/ts-ssh-agent/internal/client"
)

const requestTimeout = 30 * time.Second

var errLocked = errors.New("agent is locked")

// Agent implements sshagent.ExtendedAgent by forwarding every operation to
// the remote server. Private keys never touch this process except in transit
// during Add.
type Agent struct {
	client *client.Client

	mu             sync.Mutex
	lockPassphrase []byte
}

type remoteSigner struct {
	agent *Agent
	pub   ssh.PublicKey
}

var _ sshagent.ExtendedAgent = (*Agent)(nil)

func New(c *client.Client) *Agent {
	return &Agent{client: c}
}

// Serve accepts SSH agent connections on ln until ctx is cancelled.
func Serve(ctx context.Context, ln net.Listener, a *Agent) error {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go func() {
			defer conn.Close()
			if err := sshagent.ServeAgent(a, conn); err != nil && !errors.Is(err, io.EOF) {
				log.Printf("agent connection: %v", err)
			}
		}()
	}
}

func (a *Agent) List() ([]*sshagent.Key, error) {
	if a.isLocked() {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	keys, err := a.client.ListKeys(ctx)
	if err != nil {
		return nil, err
	}

	var out []*sshagent.Key
	for _, k := range keys {
		pub, err := ssh.ParsePublicKey(k.PublicKey)
		if err != nil {
			log.Printf("list: skipping unparseable key %s: %v", k.Fingerprint, err)
			continue
		}
		out = append(out, &sshagent.Key{Format: pub.Type(), Blob: k.PublicKey, Comment: k.Comment})
	}
	return out, nil
}

func (a *Agent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(key, data, 0)
}

func (a *Agent) SignWithFlags(key ssh.PublicKey, data []byte, flags sshagent.SignatureFlags) (*ssh.Signature, error) {
	if a.isLocked() {
		return nil, errLocked
	}
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	sig, err := a.client.Sign(ctx, &api.SignRequest{PublicKey: key.Marshal(), Data: data, Flags: uint32(flags)})
	if err != nil {
		return nil, err
	}
	return sig, nil
}

func (a *Agent) Add(key sshagent.AddedKey) error {
	if a.isLocked() {
		return errLocked
	}
	// Silently dropping these would leave keys usable longer or more freely
	// than the user asked for.
	if key.ConfirmBeforeUse || key.LifetimeSecs != 0 || len(key.ConstraintExtensions) > 0 {
		return errors.New("key constraints (-c, -t, ...) are not supported")
	}

	block, err := ssh.MarshalPrivateKey(key.PrivateKey, key.Comment)
	if err != nil {
		return err
	}
	req := &api.AddKeyRequest{PrivateKey: pem.EncodeToMemory(block), Comment: key.Comment}
	if key.Certificate != nil {
		req.Certificate = key.Certificate.Marshal()
	}

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	_, err = a.client.AddKey(ctx, req)
	return err
}

func (a *Agent) Remove(key ssh.PublicKey) error {
	if a.isLocked() {
		return errLocked
	}
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	removed, err := a.client.RemoveKey(ctx, ssh.FingerprintSHA256(key))
	if err == nil && removed == 0 {
		err = fmt.Errorf("key %s not found", ssh.FingerprintSHA256(key))
	}
	return err
}

func (a *Agent) RemoveAll() error {
	if a.isLocked() {
		return errLocked
	}
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	_, err := a.client.RemoveAllKeys(ctx)
	return err
}

// Lock only locks this local agent; the keys on the server remain usable by
// other agents belonging to the same user.
func (a *Agent) Lock(passphrase []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.lockPassphrase != nil {
		return errLocked
	}
	a.lockPassphrase = append([]byte{}, passphrase...)
	return nil
}

func (a *Agent) Unlock(passphrase []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.lockPassphrase == nil {
		return errors.New("agent is not locked")
	}
	if subtle.ConstantTimeCompare(a.lockPassphrase, passphrase) != 1 {
		return errors.New("incorrect passphrase")
	}
	a.lockPassphrase = nil
	return nil
}

func (a *Agent) Signers() ([]ssh.Signer, error) {
	keys, err := a.List()
	if err != nil {
		return nil, err
	}
	var signers []ssh.Signer
	for _, k := range keys {
		pub, err := ssh.ParsePublicKey(k.Blob)
		if err != nil {
			return nil, err
		}
		signers = append(signers, &remoteSigner{agent: a, pub: pub})
	}
	return signers, nil
}

func (a *Agent) Extension(string, []byte) ([]byte, error) {
	return nil, sshagent.ErrExtensionUnsupported
}

func (a *Agent) isLocked() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lockPassphrase != nil
}

func (s *remoteSigner) PublicKey() ssh.PublicKey {
	return s.pub
}

func (s *remoteSigner) Sign(_ io.Reader, data []byte) (*ssh.Signature, error) {
	return s.agent.Sign(s.pub, data)
}
