// Package server implements the tailnet-facing key server. Every request is
// attributed to a Tailscale user via WhoIs, and each user can only see and use
// their own keys.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"tailscale.com/client/local"
	"tailscale.com/tsnet"

	"github.com/anaisbetts/ts-ssh-agent/internal/api"
	"github.com/anaisbetts/ts-ssh-agent/internal/keystore"
)

const maxRequestBody = 1 << 20

var ErrUnauthorized = errors.New("unauthorized")

type Config struct {
	Hostname   string
	StateDir   string
	AuthKey    string
	ListenAddr string
	// StorePassphrase, if set, encrypts private keys at rest.
	StorePassphrase string
	// AllowedUsers restricts access to these Tailscale login names. Empty
	// means any (untagged) tailnet user.
	AllowedUsers []string
	Verbose      bool
}

type Identity struct {
	LoginName   string
	DisplayName string
	NodeName    string
}

// IdentifyFunc resolves the Tailscale user behind a request, returning
// ErrUnauthorized if there isn't one.
type IdentifyFunc func(r *http.Request) (*Identity, error)

type handler struct {
	store    *keystore.Store
	identify IdentifyFunc
	allowed  map[string]bool
}

// Run joins the tailnet and serves the key API until ctx is cancelled.
func Run(ctx context.Context, cfg Config) error {
	store, err := keystore.New(filepath.Join(cfg.StateDir, "keys"), []byte(cfg.StorePassphrase))
	if err != nil {
		return fmt.Errorf("opening key store: %w", err)
	}

	ts := &tsnet.Server{
		Hostname: cfg.Hostname,
		Dir:      filepath.Join(cfg.StateDir, "tailscale"),
		AuthKey:  cfg.AuthKey,
		UserLogf: log.Printf,
	}
	if !cfg.Verbose {
		ts.Logf = func(string, ...any) {}
	}
	defer ts.Close()

	status, err := ts.Up(ctx)
	if err != nil {
		return fmt.Errorf("joining tailnet: %w", err)
	}
	lc, err := ts.LocalClient()
	if err != nil {
		return err
	}

	ln, err := ts.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Handler:           NewHandler(store, TailscaleIdentifier(lc), cfg.AllowedUsers),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()

	log.Printf("serving on %s%s (%v)", status.Self.DNSName, cfg.ListenAddr, status.TailscaleIPs)
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func NewHandler(store *keystore.Store, identify IdentifyFunc, allowedUsers []string) http.Handler {
	h := &handler{store: store, identify: identify}
	if len(allowedUsers) > 0 {
		h.allowed = map[string]bool{}
		for _, u := range allowedUsers {
			h.allowed[u] = true
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET "+api.PathWhoAmI, h.authed(h.whoAmI))
	mux.HandleFunc("GET "+api.PathKeys, h.authed(h.listKeys))
	mux.HandleFunc("POST "+api.PathKeys, h.authed(h.addKey))
	mux.HandleFunc("DELETE "+api.PathKeys, h.authed(h.removeKeys))
	mux.HandleFunc("POST "+api.PathSign, h.authed(h.sign))
	return mux
}

// TailscaleIdentifier identifies callers with tailscaled's WhoIs. Tagged nodes
// are rejected since they don't act on behalf of a human user.
func TailscaleIdentifier(lc *local.Client) IdentifyFunc {
	return func(r *http.Request) (*Identity, error) {
		who, err := lc.WhoIs(r.Context(), r.RemoteAddr)
		if err != nil {
			return nil, fmt.Errorf("%w: whois %s: %v", ErrUnauthorized, r.RemoteAddr, err)
		}
		if who.Node == nil || who.UserProfile == nil || who.Node.IsTagged() || who.UserProfile.LoginName == "" {
			return nil, fmt.Errorf("%w: %s is not a user-owned node", ErrUnauthorized, r.RemoteAddr)
		}
		return &Identity{
			LoginName:   who.UserProfile.LoginName,
			DisplayName: who.UserProfile.DisplayName,
			NodeName:    who.Node.ComputedName,
		}, nil
	}
}

func (h *handler) authed(next func(http.ResponseWriter, *http.Request, *Identity)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := h.identify(r)
		if err == nil && h.allowed != nil && !h.allowed[id.LoginName] {
			err = fmt.Errorf("%w: %s is not in the allowed user list", ErrUnauthorized, id.LoginName)
		}
		if err != nil {
			log.Printf("rejected %s %s from %s: %v", r.Method, r.URL.Path, r.RemoteAddr, err)
			writeError(w, http.StatusForbidden, "who are you? pound sand")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
		next(w, r, id)
	}
}

func (h *handler) whoAmI(w http.ResponseWriter, r *http.Request, id *Identity) {
	writeJSON(w, api.WhoAmIResponse{LoginName: id.LoginName, DisplayName: id.DisplayName, NodeName: id.NodeName})
}

func (h *handler) listKeys(w http.ResponseWriter, r *http.Request, id *Identity) {
	ids, err := h.store.List(id.LoginName)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	resp := api.ListKeysResponse{Keys: []api.Key{}}
	for _, k := range ids {
		resp.Keys = append(resp.Keys, api.Key{
			PublicKey:   k.PublicKey.Marshal(),
			Comment:     k.Comment,
			Fingerprint: ssh.FingerprintSHA256(k.PublicKey),
		})
	}
	writeJSON(w, resp)
}

func (h *handler) addKey(w http.ResponseWriter, r *http.Request, id *Identity) {
	var req api.AddKeyRequest
	if !readJSON(w, r, &req) {
		return
	}
	key, err := ssh.ParseRawPrivateKey(req.PrivateKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid private key: "+err.Error())
		return
	}

	var cert *ssh.Certificate
	if len(req.Certificate) > 0 {
		pub, err := ssh.ParsePublicKey(req.Certificate)
		c, ok := pub.(*ssh.Certificate)
		if err != nil || !ok {
			writeError(w, http.StatusBadRequest, "invalid certificate")
			return
		}
		cert = c
	}

	pub, err := h.store.Add(id.LoginName, key, req.Comment, cert)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	fp := ssh.FingerprintSHA256(pub)
	log.Printf("%s (%s) added key %s %q", id.LoginName, id.NodeName, fp, req.Comment)
	writeJSON(w, api.AddKeyResponse{Fingerprint: fp})
}

func (h *handler) removeKeys(w http.ResponseWriter, r *http.Request, id *Identity) {
	q := r.URL.Query()
	fingerprint := q.Get("fingerprint")

	var removed int
	var err error
	switch {
	case q.Get("all") == "true":
		removed, err = h.store.RemoveAll(id.LoginName)
	case fingerprint != "":
		removed, err = h.store.Remove(id.LoginName, fingerprint)
	default:
		writeError(w, http.StatusBadRequest, "specify fingerprint=<fp> or all=true")
		return
	}
	if err != nil {
		writeInternalError(w, err)
		return
	}
	log.Printf("%s (%s) removed %d key(s) [fingerprint=%q all=%q]", id.LoginName, id.NodeName, removed, fingerprint, q.Get("all"))
	writeJSON(w, api.RemoveKeysResponse{Removed: removed})
}

func (h *handler) sign(w http.ResponseWriter, r *http.Request, id *Identity) {
	var req api.SignRequest
	if !readJSON(w, r, &req) {
		return
	}
	sig, err := h.store.Sign(id.LoginName, req.PublicKey, req.Data, agent.SignatureFlags(req.Flags))
	if errors.Is(err, keystore.ErrNotFound) {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	if err != nil {
		writeInternalError(w, err)
		return
	}

	fp := "?"
	if pub, err := ssh.ParsePublicKey(req.PublicKey); err == nil {
		fp = ssh.FingerprintSHA256(pub)
	}
	log.Printf("%s (%s) signed with %s", id.LoginName, id.NodeName, fp)
	writeJSON(w, api.SignResponse{Format: sig.Format, Blob: sig.Blob, Rest: sig.Rest})
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func writeInternalError(w http.ResponseWriter, err error) {
	log.Printf("internal error: %v", err)
	writeError(w, http.StatusInternalServerError, "internal error")
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(api.ErrorResponse{Error: msg})
}
