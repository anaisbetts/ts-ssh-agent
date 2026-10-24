// Package api defines the JSON wire protocol spoken between the ts-ssh-agent
// server and its clients (the local SSH agent and the CLI).
package api

const (
	PathWhoAmI = "/v1/whoami"
	PathKeys   = "/v1/keys"
	PathSign   = "/v1/sign"

	// DefaultServerURL assumes the server joined the tailnet with the default
	// hostname and that MagicDNS is enabled.
	DefaultServerURL = "http://ts-ssh-agent"
)

type WhoAmIResponse struct {
	LoginName   string `json:"login_name"`
	DisplayName string `json:"display_name"`
	NodeName    string `json:"node_name"`
}

type Key struct {
	// PublicKey is the SSH wire-format public key (or certificate) blob.
	PublicKey   []byte `json:"public_key"`
	Comment     string `json:"comment"`
	Fingerprint string `json:"fingerprint"`
}

type ListKeysResponse struct {
	Keys []Key `json:"keys"`
}

type AddKeyRequest struct {
	// PrivateKey is an unencrypted OpenSSH PEM-encoded private key.
	PrivateKey []byte `json:"private_key"`
	Comment    string `json:"comment"`
	// Certificate is an optional SSH wire-format certificate for the key.
	Certificate []byte `json:"certificate,omitempty"`
}

type AddKeyResponse struct {
	Fingerprint string `json:"fingerprint"`
}

type RemoveKeysResponse struct {
	Removed int `json:"removed"`
}

type SignRequest struct {
	PublicKey []byte `json:"public_key"`
	Data      []byte `json:"data"`
	// Flags are the raw SSH agent signature flags (see agent.SignatureFlags).
	Flags uint32 `json:"flags"`
}

type SignResponse struct {
	Format string `json:"format"`
	Blob   []byte `json:"blob"`
	Rest   []byte `json:"rest,omitempty"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}
