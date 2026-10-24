package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"

	"github.com/anaisbetts/ts-ssh-agent/internal/client"
	"github.com/anaisbetts/ts-ssh-agent/internal/keystore"
	"github.com/anaisbetts/ts-ssh-agent/internal/server"
)

const userHeader = "X-Test-User"

type userTransport string

func TestEndToEnd(t *testing.T) {
	srv := newTestServer(t)
	alice := newAgentClient(t, srv, "alice@example.com")
	bob := newAgentClient(t, srv, "bob@example.com")

	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []sshagent.AddedKey{
		{PrivateKey: edKey, Comment: "ed"},
		{PrivateKey: rsaKey, Comment: "rsa"},
	} {
		if err := alice.Add(k); err != nil {
			t.Fatalf("add %s: %v", k.Comment, err)
		}
	}

	keys, err := alice.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys[0].Comment != "ed" || keys[1].Comment != "rsa" {
		t.Fatalf("unexpected keys: %v", keys)
	}

	edPub, _ := ssh.NewPublicKey(edKey.Public())
	sig, err := alice.Sign(edPub, []byte("data"))
	if err != nil {
		t.Fatal(err)
	}
	if err := edPub.Verify([]byte("data"), sig); err != nil {
		t.Fatal(err)
	}

	rsaPub, _ := ssh.NewPublicKey(&rsaKey.PublicKey)
	sig, err = alice.SignWithFlags(rsaPub, []byte("data"), sshagent.SignatureFlagRsaSha512)
	if err != nil {
		t.Fatal(err)
	}
	if sig.Format != ssh.KeyAlgoRSASHA512 {
		t.Fatalf("expected %s signature, got %s", ssh.KeyAlgoRSASHA512, sig.Format)
	}
	if err := rsaPub.Verify([]byte("data"), sig); err != nil {
		t.Fatal(err)
	}

	if keys, _ := bob.List(); len(keys) != 0 {
		t.Fatalf("bob can see alice's keys: %v", keys)
	}
	if _, err := bob.Sign(edPub, []byte("data")); err == nil {
		t.Fatal("bob signed with alice's key")
	}

	if err := alice.Lock([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.Sign(edPub, []byte("data")); err == nil {
		t.Fatal("signed while locked")
	}
	if err := alice.Unlock([]byte("pw")); err != nil {
		t.Fatal(err)
	}

	if err := alice.Remove(edPub); err != nil {
		t.Fatal(err)
	}
	if keys, _ := alice.List(); len(keys) != 1 {
		t.Fatalf("expected 1 key after remove, got %v", keys)
	}
	if err := alice.RemoveAll(); err != nil {
		t.Fatal(err)
	}
	if keys, _ := alice.List(); len(keys) != 0 {
		t.Fatalf("expected no keys after remove all, got %v", keys)
	}
}

func TestRejectsConstrainedKeys(t *testing.T) {
	alice := newAgentClient(t, newTestServer(t), "alice@example.com")
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	if err := alice.Add(sshagent.AddedKey{PrivateKey: key, LifetimeSecs: 60}); err == nil {
		t.Fatal("expected lifetime-constrained add to fail")
	}
}

func TestUnidentifiedCallersAreRejected(t *testing.T) {
	srv := newTestServer(t)
	c := client.New(srv.URL, nil)
	_, err := c.ListKeys(t.Context())

	var statusErr *client.StatusError
	if !errors.As(err, &statusErr) || statusErr.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %v", err)
	}
}

func TestAllowedUsers(t *testing.T) {
	store, err := keystore.New(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(server.NewHandler(store, identifyFromHeader, []string{"alice@example.com"}))
	t.Cleanup(srv.Close)

	if _, err := newAgentClient(t, srv, "alice@example.com").List(); err != nil {
		t.Fatalf("alice should be allowed: %v", err)
	}
	if _, err := newAgentClient(t, srv, "mallory@example.com").List(); err == nil {
		t.Fatal("mallory should be rejected")
	}
}

func (u userTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set(userHeader, string(u))
	return http.DefaultTransport.RoundTrip(r)
}

func newTestServer(t *testing.T) *httptest.Server {
	store, err := keystore.New(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(server.NewHandler(store, identifyFromHeader, nil))
	t.Cleanup(srv.Close)
	return srv
}

// newAgentClient returns an SSH agent protocol client talking to a local
// Agent that authenticates to srv as user.
func newAgentClient(t *testing.T, srv *httptest.Server, user string) sshagent.ExtendedAgent {
	a := New(client.New(srv.URL, &http.Client{Transport: userTransport(user)}))
	clientConn, agentConn := net.Pipe()
	go sshagent.ServeAgent(a, agentConn)
	t.Cleanup(func() { clientConn.Close() })
	return sshagent.NewClient(clientConn)
}

func identifyFromHeader(r *http.Request) (*server.Identity, error) {
	user := r.Header.Get(userHeader)
	if user == "" {
		return nil, server.ErrUnauthorized
	}
	return &server.Identity{LoginName: user, NodeName: "test-node"}, nil
}
