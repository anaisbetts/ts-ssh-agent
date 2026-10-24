package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"github.com/anaisbetts/ts-ssh-agent/internal/api"
)

const commandTimeout = 30 * time.Second

var defaultKeyFiles = []string{"id_ed25519", "id_ecdsa", "id_rsa"}

func runAdd(args []string) error {
	fs := flag.NewFlagSet("add", flag.ExitOnError)
	newClient := serverFlag(fs)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: ts-ssh-agent add [flags] [keyfile ...]\n\nWith no files, adds ~/.ssh/id_ed25519, id_ecdsa and id_rsa if present.")
		fs.PrintDefaults()
	}
	fs.Parse(args)

	files := fs.Args()
	if len(files) == 0 {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		for _, name := range defaultKeyFiles {
			path := filepath.Join(home, ".ssh", name)
			if _, err := os.Stat(path); err == nil {
				files = append(files, path)
			}
		}
		if len(files) == 0 {
			return errors.New("no default keys found in ~/.ssh; pass key files explicitly")
		}
	}

	c := newClient()
	for _, path := range files {
		req, err := loadKeyFile(path)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
		fp, err := c.AddKey(ctx, req)
		cancel()
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		fmt.Printf("Identity added: %s (%s) %s\n", path, req.Comment, fp)
		if req.Certificate != nil {
			fmt.Printf("Certificate added: %s-cert.pub\n", path)
		}
	}
	return nil
}

func runList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	newClient := serverFlag(fs)
	public := fs.Bool("L", false, "print public keys in authorized_keys format instead of fingerprints")
	fs.Parse(args)

	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	keys, err := newClient().ListKeys(ctx)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		fmt.Println("The key server has no identities for you.")
		return nil
	}

	for _, k := range keys {
		pub, err := ssh.ParsePublicKey(k.PublicKey)
		if err != nil {
			return fmt.Errorf("server returned an invalid key: %w", err)
		}
		if *public {
			fmt.Printf("%s %s\n", strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))), k.Comment)
		} else {
			fmt.Printf("%d %s %s (%s)\n", keyBits(pub), k.Fingerprint, k.Comment, keyTypeLabel(pub))
		}
	}
	return nil
}

func runRemove(args []string) error {
	fs := flag.NewFlagSet("remove", flag.ExitOnError)
	newClient := serverFlag(fs)
	all := fs.Bool("a", false, "remove all of your keys")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: ts-ssh-agent remove [flags] (-a | <keyfile|SHA256:fingerprint> ...)")
		fs.PrintDefaults()
	}
	fs.Parse(args)

	c := newClient()
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	if *all {
		n, err := c.RemoveAllKeys(ctx)
		if err != nil {
			return err
		}
		fmt.Printf("Removed %d identities.\n", n)
		return nil
	}
	if fs.NArg() == 0 {
		fs.Usage()
		os.Exit(2)
	}

	for _, arg := range fs.Args() {
		fp, err := resolveFingerprint(arg)
		if err != nil {
			return fmt.Errorf("%s: %w", arg, err)
		}
		n, err := c.RemoveKey(ctx, fp)
		if err != nil {
			return fmt.Errorf("%s: %w", arg, err)
		}
		if n == 0 {
			return fmt.Errorf("%s: no key with fingerprint %s", arg, fp)
		}
		fmt.Printf("Identity removed: %s (%s)\n", arg, fp)
	}
	return nil
}

func runWhoAmI(args []string) error {
	fs := flag.NewFlagSet("whoami", flag.ExitOnError)
	newClient := serverFlag(fs)
	fs.Parse(args)

	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	who, err := newClient().WhoAmI(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("%s (%s) on %s\n", who.LoginName, who.DisplayName, who.NodeName)
	return nil
}

// loadKeyFile reads a private key (prompting for its passphrase if needed),
// plus its comment from the .pub file and certificate from -cert.pub if they
// exist, and re-encodes the key unencrypted for upload.
func loadKeyFile(path string) (*api.AddKeyRequest, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	key, err := ssh.ParseRawPrivateKey(pemBytes)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		var passphrase []byte
		passphrase, err = readPassphrase(fmt.Sprintf("Enter passphrase for %s: ", path))
		if err != nil {
			return nil, err
		}
		key, err = ssh.ParseRawPrivateKeyWithPassphrase(pemBytes, passphrase)
	}
	if err != nil {
		return nil, err
	}

	comment := path
	if pubBytes, err := os.ReadFile(path + ".pub"); err == nil {
		if _, c, _, _, err := ssh.ParseAuthorizedKey(pubBytes); err == nil && c != "" {
			comment = c
		}
	}

	block, err := ssh.MarshalPrivateKey(key, comment)
	if err != nil {
		return nil, err
	}
	req := &api.AddKeyRequest{PrivateKey: pem.EncodeToMemory(block), Comment: comment}

	if certBytes, err := os.ReadFile(path + "-cert.pub"); err == nil {
		pub, _, _, _, err := ssh.ParseAuthorizedKey(certBytes)
		if err != nil {
			return nil, fmt.Errorf("parsing certificate: %w", err)
		}
		if _, ok := pub.(*ssh.Certificate); !ok {
			return nil, fmt.Errorf("%s-cert.pub is not a certificate", path)
		}
		req.Certificate = pub.Marshal()
	}
	return req, nil
}

// resolveFingerprint accepts a SHA256 fingerprint, a public key file, or a
// private key file (using its .pub sibling when the key is encrypted).
func resolveFingerprint(arg string) (string, error) {
	if strings.HasPrefix(arg, "SHA256:") {
		return arg, nil
	}

	candidates := []string{arg}
	if !strings.HasSuffix(arg, ".pub") {
		candidates = append(candidates, arg+".pub")
	}
	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if pub, _, _, _, err := ssh.ParseAuthorizedKey(data); err == nil {
			return ssh.FingerprintSHA256(pub), nil
		}
		if signer, err := ssh.ParsePrivateKey(data); err == nil {
			return ssh.FingerprintSHA256(signer.PublicKey()), nil
		}
	}
	return "", errors.New("not a fingerprint or readable key file")
}

func readPassphrase(prompt string) ([]byte, error) {
	in, out, err := openTerminal()
	if err != nil {
		return nil, fmt.Errorf("key is encrypted and no terminal is available: %w", err)
	}
	defer in.Close()
	if out != in {
		defer out.Close()
	}

	fmt.Fprint(out, prompt)
	passphrase, err := term.ReadPassword(int(in.Fd()))
	fmt.Fprintln(out)
	return passphrase, err
}

func keyBits(pub ssh.PublicKey) int {
	if cert, ok := pub.(*ssh.Certificate); ok {
		pub = cert.Key
	}
	cpk, ok := pub.(ssh.CryptoPublicKey)
	if !ok {
		return 0
	}
	switch k := cpk.CryptoPublicKey().(type) {
	case *rsa.PublicKey:
		return k.N.BitLen()
	case *ecdsa.PublicKey:
		return k.Curve.Params().BitSize
	case ed25519.PublicKey:
		return 256
	default:
		return 0
	}
}

func keyTypeLabel(pub ssh.PublicKey) string {
	suffix := ""
	if cert, ok := pub.(*ssh.Certificate); ok {
		pub = cert.Key
		suffix = "-CERT"
	}
	label := strings.ToUpper(strings.TrimPrefix(pub.Type(), "ssh-"))
	if strings.HasPrefix(pub.Type(), "ecdsa-") {
		label = "ECDSA"
	}
	return label + suffix
}
