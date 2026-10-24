package keystore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestPersistsEncryptedAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	passphrase := []byte("hunter2")

	s, err := New(dir, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pub, err := s.Add("alice@example.com", priv, "laptop", nil)
	if err != nil {
		t.Fatal(err)
	}

	files, _ := filepath.Glob(filepath.Join(dir, "alice@example.com", "*.json"))
	if len(files) != 1 {
		t.Fatalf("expected 1 key file, got %v", files)
	}
	raw, _ := os.ReadFile(files[0])
	var rec record
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	var missing *ssh.PassphraseMissingError
	if _, err := ssh.ParseRawPrivateKey([]byte(rec.PrivateKey)); !errors.As(err, &missing) {
		t.Fatalf("stored key is not passphrase-encrypted: %v", err)
	}

	noPass, err := New(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := noPass.List("alice@example.com"); err == nil {
		t.Fatal("expected loading encrypted keys without a passphrase to fail")
	}

	reopened, err := New(dir, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := reopened.List("alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0].Comment != "laptop" || !bytes.Equal(ids[0].PublicKey.Marshal(), pub.Marshal()) {
		t.Fatalf("unexpected identities after reopen: %+v", ids)
	}

	sig, err := reopened.Sign("alice@example.com", pub.Marshal(), []byte("hello"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := pub.Verify([]byte("hello"), sig); err != nil {
		t.Fatal(err)
	}

	n, err := reopened.Remove("alice@example.com", ssh.FingerprintSHA256(pub))
	if err != nil || n != 1 {
		t.Fatalf("remove: n=%d err=%v", n, err)
	}
	if files, _ := filepath.Glob(filepath.Join(dir, "alice@example.com", "*.json")); len(files) != 0 {
		t.Fatalf("key file not deleted: %v", files)
	}
}

func TestRejectsTraversalUserNames(t *testing.T) {
	s, err := New(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, user := range []string{"", ".", ".."} {
		if _, err := s.List(user); err == nil {
			t.Errorf("expected error for user %q", user)
		}
	}
	if _, err := s.List("../etc"); err != nil {
		t.Errorf("slashes should be escaped, not rejected: %v", err)
	}
}
