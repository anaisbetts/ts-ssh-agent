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

## Quick Start

You need [Tailscale](https://tailscale.com/download) on every machine you'll
ssh *from*. Grab a package or binary from the
[releases page](https://github.com/anaisbetts/ts-ssh-agent/releases).

**1. Run the key server** on an always-on machine. Either install the package
and let it walk you through adding the server to your tailnet:

```sh
sudo apt install ./ts-ssh-agent_*_$(dpkg --print-architecture).deb   # or: sudo pacman -U ts-ssh-agent-*-$(uname -m).pkg.tar.zst
ts-ssh-agent server-setup
```

or use Docker, then open the login link it prints:

```sh
docker run -d --name ts-ssh-agent --restart unless-stopped \
  -v ts-ssh-agent:/var/lib/ts-ssh-agent ghcr.io/anaisbetts/ts-ssh-agent:latest
docker logs -f ts-ssh-agent
```

**2. On each machine you ssh from**, install the package (or put the binary on
your `PATH`) and add this to your shell rc:

```sh
eval "$(ts-ssh-agent shell)"
```

**3. Upload your keys** once, from any of those machines:

```sh
ts-ssh-agent whoami    # should print your Tailscale login
ts-ssh-agent add       # uploads ~/.ssh/id_ed25519 etc.; or name key files
ssh-add -l             # the keys now come from the server
```

Every machine where you're logged in to Tailscale as yourself can now use the
keys. Once they're uploaded you can delete the local copies, but keep a backup
somewhere safe: if you lose the server's state, the keys are gone.

On Windows, see [Windows](#windows) below.

## Server

```sh
TS_AUTHKEY=tskey-auth-... TS_SSH_AGENT_STORE_PASSPHRASE=... docker compose up -d
```

The server joins the tailnet as `ts-ssh-agent` (via `tsnet`, no tailscaled
needed in the container) and listens on port 80 of its tailnet address only.
Traffic is encrypted by WireGuard.

Images are published to `ghcr.io/anaisbetts/ts-ssh-agent` for linux/amd64 and
linux/arm64: `latest` and `vX.Y.Z` for each release, and `main` for every push
to `main`.

| Env var | Purpose |
| --- | --- |
| `TS_AUTHKEY` | Auth key for first login (state persists in the volume afterwards) |
| `TS_SSH_AGENT_STORE_PASSPHRASE` | Encrypts private keys at rest. Recommended |
| `TS_SSH_AGENT_ALLOWED_USERS` | Comma-separated login names allowed in; empty means any user |
| `TS_SSH_AGENT_HOSTNAME` | Tailnet hostname (default `ts-ssh-agent`) |

Restrict who can reach it with your tailnet policy as well, e.g. only allow
`autogroup:member` to `tag:ssh-agent:80`.

`TS_AUTHKEY` is optional. Without it, the server logs a Tailscale login link
on first start. If you add the server through that link, the machine belongs
to you and its Tailscale key expires after 180 days by default. Turn on
"Disable key expiry" for it in the admin console, or use a tagged auth key
instead.

### Without Docker

The `.deb` and Arch packages from the releases page also ship a systemd user
unit for the server. `ts-ssh-agent server-setup` configures and starts it:

- It asks for an optional auth key and store passphrase, and saves them to
  `~/.config/ts-ssh-agent/server.env`. You can also edit that file by hand
  using the env vars above.
- It starts `ts-ssh-agent-server.service` and shows you the Tailscale login
  link if one is needed.
- It reminds you to enable lingering, so the server keeps running when you're
  logged out.

State lives in `~/.local/state/ts-ssh-agent-server`.

## Client

The client machine must be on the tailnet (regular Tailscale install).

Add this to your shell rc. It starts the agent if it isn't already running and
sets `SSH_AUTH_SOCK`:

```sh
eval "$(ts-ssh-agent shell)"
```

The `.deb` and Arch packages ship a `ts-ssh-agent.service` systemd user unit,
and `shell` starts that when it's installed. Otherwise, for example when you
use the bare binary or are on macOS, `shell` spawns its own background agent,
which logs to `~/.cache/ts-ssh-agent/agent.log`.

The agent doesn't need Tailscale to be up when it starts; it only reaches the
key server when ssh asks it for something.

```sh
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
ts-ssh-agent shell | Invoke-Expression                                # in your $PROFILE
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

CI (`.github/workflows/build.yml`) cross-compiles Linux and Windows for amd64
and arm64 from one Ubuntu job, builds `.deb` and Arch packages for both, and
pushes the `main` image. To release,
publish a GitHub release (e.g. `gh release create v1.2.3 --generate-notes`);
CI attaches the binaries and pushes the `v1.2.3` and `latest` images.
