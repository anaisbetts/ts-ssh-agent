# ts-ssh-agent

An SSH agent whose private keys live on a server in your tailnet instead of on
each machine. The server uses Tailscale identity to decide who you are: every
Tailscale user gets their own isolated set of keys, and requests from tagged
nodes or unknown peers are rejected.

```
ssh / git / ssh-add ──unix socket──> ts-ssh-agent agent ──tailnet HTTP──> ts-ssh-agent server (Docker, tsnet)
                                                                            └─ WhoIs(caller) → per-user key store
```

Private keys never leave the server once uploaded; clients only ever get
public keys and signatures back.

## Server

```sh
TS_AUTHKEY=tskey-auth-... TS_SSH_AGENT_STORE_PASSPHRASE=... docker compose up -d
```

The server joins the tailnet as `ts-ssh-agent` (via `tsnet`, no tailscaled
needed in the container) and listens on port 80 of its tailnet address only.
Traffic is encrypted by WireGuard.

| Env var | Purpose |
| --- | --- |
| `TS_AUTHKEY` | Auth key for first login (state persists in the volume afterwards) |
| `TS_SSH_AGENT_STORE_PASSPHRASE` | Encrypts private keys at rest. Recommended |
| `TS_SSH_AGENT_ALLOWED_USERS` | Comma-separated login names allowed in; empty means any user |
| `TS_SSH_AGENT_HOSTNAME` | Tailnet hostname (default `ts-ssh-agent`) |

Restrict who can reach it with your tailnet policy as well, e.g. only allow
`autogroup:member` to `tag:ssh-agent:80`.

## Client

The client machine must be on the tailnet (regular Tailscale install).

Run the agent in the background (a systemd user unit is easiest):

```ini
# ~/.config/systemd/user/ts-ssh-agent.service
[Service]
ExecStart=%h/go/bin/ts-ssh-agent agent

[Install]
WantedBy=default.target
```

```sh
systemctl --user enable --now ts-ssh-agent
export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/ts-ssh-agent/agent.sock"   # in your shell rc

ts-ssh-agent whoami                # check the server recognizes you
ts-ssh-agent add ~/.ssh/id_ed25519 # upload a key (or plain `ssh-add`, it works too)
ts-ssh-agent list                  # like ssh-add -l; -L for public keys
ts-ssh-agent remove ~/.ssh/id_ed25519   # or a SHA256:... fingerprint; -a for all
```

### Windows

Windows OpenSSH only talks to agents over named pipes, and by default looks
for `\\.\pipe\openssh-ssh-agent`. `ts-ssh-agent agent` listens there by
default (restricted to your user), so `ssh` works with no `SSH_AUTH_SOCK`.
Windows' own agent service holds that pipe if it's running, so disable it first:

```powershell
Stop-Service ssh-agent; Set-Service ssh-agent -StartupType Disabled   # as admin
ts-ssh-agent agent
```

Alternatively, use `-a \\.\pipe\ts-ssh-agent` and set `$env:SSH_AUTH_SOCK` to
match. Git for Windows' bundled MSYS `ssh` doesn't use Windows named pipes;
point Git at the system one with `git config --global core.sshCommand C:/Windows/System32/OpenSSH/ssh.exe`.

Point clients at a different server with `--server` or `TS_SSH_AGENT_SERVER`
(default `http://ts-ssh-agent`).

## Limitations

- Key constraints (`ssh-add -c`, `-t`) are refused rather than silently ignored.
- `ssh-add -x` (lock) only locks the local agent, not the keys on the server.
- FIDO/security-key (`sk-*`) keys aren't supported, since the server can't touch your hardware token.

## Development

```sh
go test ./...
go build ./cmd/ts-ssh-agent
```

CI (`.github/workflows/build.yml`) cross-compiles Linux amd64 and Windows
amd64/arm64 from one Ubuntu job, and publishes a GitHub release for `v*` tags.
