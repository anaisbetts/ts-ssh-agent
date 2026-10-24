// Package keystore persists SSH private keys on disk, partitioned by the
// Tailscale login name of the user who owns them.
package keystore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const recordExt = ".json"

var ErrNotFound = errors.New("key not found")

type Identity struct {
	PublicKey ssh.PublicKey
	Comment   string
}

type Store struct {
	dir        string
	passphrase []byte

	mu    sync.Mutex
	users map[string]map[string]*entry
}

type entry struct {
	signer      ssh.Signer
	comment     string
	certificate *ssh.Certificate
	addedAt     time.Time
}

type record struct {
	Comment string    `json:"comment"`
	AddedAt time.Time `json:"added_at"`
	// PrivateKey is an OpenSSH PEM private key, encrypted with the store
	// passphrase when one is configured.
	PrivateKey  string `json:"private_key"`
	Certificate []byte `json:"certificate,omitempty"`
}

// New opens (creating if needed) a key store rooted at dir. If passphrase is
// non-empty, private keys are encrypted at rest with it.
func New(dir string, passphrase []byte) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Store{dir: dir, passphrase: passphrase, users: map[string]map[string]*entry{}}, nil
}

func (s *Store) List(user string) ([]Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := s.loadUser(user)
	if err != nil {
		return nil, err
	}

	sorted := make([]*entry, 0, len(entries))
	for _, e := range entries {
		sorted = append(sorted, e)
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].addedAt.Before(sorted[j].addedAt) })

	var ids []Identity
	for _, e := range sorted {
		ids = append(ids, Identity{PublicKey: e.signer.PublicKey(), Comment: e.comment})
		if e.certificate != nil {
			ids = append(ids, Identity{PublicKey: e.certificate, Comment: e.comment})
		}
	}
	return ids, nil
}

// Add stores privateKey (any key type accepted by ssh.NewSignerFromKey) for
// user, replacing any existing copy of the same key.
func (s *Store) Add(user string, privateKey any, comment string, cert *ssh.Certificate) (ssh.PublicKey, error) {
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("unsupported private key: %w", err)
	}
	pub := signer.PublicKey()
	if cert != nil && !bytes.Equal(cert.Key.Marshal(), pub.Marshal()) {
		return nil, errors.New("certificate does not match private key")
	}

	var block *pem.Block
	if len(s.passphrase) > 0 {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(privateKey, comment, s.passphrase)
	} else {
		block, err = ssh.MarshalPrivateKey(privateKey, comment)
	}
	if err != nil {
		return nil, err
	}

	rec := record{Comment: comment, AddedAt: time.Now().UTC(), PrivateKey: string(pem.EncodeToMemory(block))}
	if cert != nil {
		rec.Certificate = cert.Marshal()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := s.loadUser(user)
	if err != nil {
		return nil, err
	}
	userDir, err := s.userDir(user)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(userDir, 0o700); err != nil {
		return nil, err
	}

	id := keyID(pub)
	if err := writeRecord(filepath.Join(userDir, id+recordExt), &rec); err != nil {
		return nil, err
	}
	entries[id] = &entry{signer: signer, comment: comment, certificate: cert, addedAt: rec.AddedAt}
	return pub, nil
}

// Remove deletes every key of user whose public key or certificate has the
// given SHA256 fingerprint, returning how many were removed.
func (s *Store) Remove(user, fingerprint string) (int, error) {
	return s.removeMatching(user, func(e *entry) bool {
		if ssh.FingerprintSHA256(e.signer.PublicKey()) == fingerprint {
			return true
		}
		return e.certificate != nil && ssh.FingerprintSHA256(e.certificate) == fingerprint
	})
}

func (s *Store) RemoveAll(user string) (int, error) {
	return s.removeMatching(user, func(*entry) bool { return true })
}

// Sign signs data with the key of user identified by publicKeyBlob (either the
// raw public key or its certificate). flags select the RSA hash algorithm.
func (s *Store) Sign(user string, publicKeyBlob, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	s.mu.Lock()
	entries, err := s.loadUser(user)
	var signer ssh.Signer
	if err == nil {
		for _, e := range entries {
			if bytes.Equal(e.signer.PublicKey().Marshal(), publicKeyBlob) ||
				(e.certificate != nil && bytes.Equal(e.certificate.Marshal(), publicKeyBlob)) {
				signer = e.signer
				break
			}
		}
	}
	s.mu.Unlock()

	if err != nil {
		return nil, err
	}
	if signer == nil {
		return nil, ErrNotFound
	}

	algorithm := rsaAlgorithm(flags)
	if signer.PublicKey().Type() != ssh.KeyAlgoRSA || algorithm == "" {
		return signer.Sign(nil, data)
	}
	algSigner, ok := signer.(ssh.AlgorithmSigner)
	if !ok {
		return nil, fmt.Errorf("signer does not support algorithm %q", algorithm)
	}
	return algSigner.SignWithAlgorithm(nil, data, algorithm)
}

func (s *Store) removeMatching(user string, match func(*entry) bool) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := s.loadUser(user)
	if err != nil {
		return 0, err
	}
	userDir, err := s.userDir(user)
	if err != nil {
		return 0, err
	}

	removed := 0
	for id, e := range entries {
		if !match(e) {
			continue
		}
		if err := os.Remove(filepath.Join(userDir, id+recordExt)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return removed, err
		}
		delete(entries, id)
		removed++
	}
	return removed, nil
}

// loadUser returns the cached entries for user, reading them from disk on
// first access. s.mu must be held.
func (s *Store) loadUser(user string) (map[string]*entry, error) {
	if entries, ok := s.users[user]; ok {
		return entries, nil
	}

	userDir, err := s.userDir(user)
	if err != nil {
		return nil, err
	}

	entries := map[string]*entry{}
	files, err := os.ReadDir(userDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), recordExt) {
			continue
		}
		path := filepath.Join(userDir, f.Name())
		e, err := s.readEntry(path)
		if err != nil {
			return nil, fmt.Errorf("loading %s: %w", path, err)
		}
		entries[strings.TrimSuffix(f.Name(), recordExt)] = e
	}

	s.users[user] = entries
	return entries, nil
}

func (s *Store) readEntry(path string) (*entry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rec record
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, err
	}

	pemBytes := []byte(rec.PrivateKey)
	key, err := ssh.ParseRawPrivateKey(pemBytes)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		if len(s.passphrase) == 0 {
			return nil, errors.New("key is encrypted but no store passphrase is configured")
		}
		key, err = ssh.ParseRawPrivateKeyWithPassphrase(pemBytes, s.passphrase)
	}
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, err
	}

	e := &entry{signer: signer, comment: rec.Comment, addedAt: rec.AddedAt}
	if len(rec.Certificate) > 0 {
		pub, err := ssh.ParsePublicKey(rec.Certificate)
		if err != nil {
			return nil, fmt.Errorf("parsing certificate: %w", err)
		}
		cert, ok := pub.(*ssh.Certificate)
		if !ok {
			return nil, errors.New("stored certificate is not an SSH certificate")
		}
		e.certificate = cert
	}
	return e, nil
}

func (s *Store) userDir(user string) (string, error) {
	name := url.PathEscape(user)
	if name == "" || name == "." || name == ".." {
		return "", fmt.Errorf("invalid user name %q", user)
	}
	return filepath.Join(s.dir, name), nil
}

func writeRecord(path string, rec *record) error {
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func keyID(pub ssh.PublicKey) string {
	sum := sha256.Sum256(pub.Marshal())
	return hex.EncodeToString(sum[:])
}

func rsaAlgorithm(flags agent.SignatureFlags) string {
	switch {
	case flags&agent.SignatureFlagRsaSha512 != 0:
		return ssh.KeyAlgoRSASHA512
	case flags&agent.SignatureFlagRsaSha256 != 0:
		return ssh.KeyAlgoRSASHA256
	default:
		return ""
	}
}
