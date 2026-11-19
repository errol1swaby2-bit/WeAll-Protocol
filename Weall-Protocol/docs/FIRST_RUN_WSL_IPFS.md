# Local IPFS prerequisite setup for Ubuntu / WSL (Path A only)

This page supplies the missing installation and recovery steps for `docs/NEW_NODE_OPERATOR_QUICKSTART.md` **Path A**. Follow that guide for the backend installation and account/PoH workflow. This page only sets up an IPFS service for the **disposable single-computer** Genesis-plus-observer rehearsal. It does not establish public network availability, production security, or an independently operated node.

## Choose exactly one provider

| Provider | When to choose it | Check |
| --- | --- | --- |
| Docker Desktop + Docker Compose (Windows/WSL integration) | Already using Docker and the engine is running | `docker info` and `docker compose version` must both work inside Ubuntu |
| Native Kubo (`ipfs` binary inside Ubuntu) | No Docker installed; minimize extra Docker/WSL runtime overhead | `ipfs version` must work in the same Ubuntu session |

The existing `scripts/devnet_local_two_frontend_rehearsal.sh` chooses **Docker whenever the `docker` command exists**, before considering native `ipfs`. A present Docker CLI with a stopped/inaccessible engine will therefore *not* automatically fall back to native Kubo. Fix Docker access or use the native-only environment before proceeding. Do not run `docker info` as a mandatory command when using native Kubo.

Do **not** install a second Ubuntu distribution merely for this test. Do **not** install `sudo snap install ipfs` based only on the Ubuntu “command not found” suggestion without deciding which implementation/version it will provide.

### Version and security boundary

`docker-compose.ipfs.yml` currently selects `ipfs/kubo:v0.29.0`. For **version-parity comparison only**, the native example below defaults to **v0.29.0**. This is an older version, **not a statement of current security support**, and it should be limited to controlled local testing; do not expose it as a public or production service. A newer official Kubo release can be selected for a **separate compatibility experiment**, but its success cannot be reported as reproducing the repository's pinned Docker version. Record `ipfs version` in the test transcript.

The local launcher uses a dedicated repository under `Weall-Protocol/.weall-devnet/` rather than `~/.ipfs`. Keep local bootstrap frontends and the Kubo RPC API on loopback; they can expose sensitive development evidence or signing material. Do not expose them on a LAN, tunnel or public URL.

## Option 1: Docker Desktop / WSL

1. Install and start Docker Desktop on Windows. In Docker Desktop **Settings → Resources → WSL Integration**, enable integration for the Ubuntu distribution in use. If the setting is absent, confirm Docker Desktop is using the WSL 2 engine.
2. Restart the Ubuntu terminal. From Ubuntu, run:

```bash
docker info --format '{{.ServerVersion}}'
docker compose version
```

Both commands must succeed. If they fail, record the Docker error before attempting the local launcher; missing WSL integration is an infrastructure blocker, not a WeAll consensus failure.

## Option 2: Native Kubo inside Ubuntu (no Docker)

Official sources: [Kubo installation guide](https://docs.ipfs.tech/install/command-line/), [Kubo distribution](https://dist.ipfs.tech/kubo/), [official Kubo GitHub releases](https://github.com/ipfs/kubo/releases).

### Install a verified binary

The following complete block runs in a **child Bash process** so a failed download will **not close the interactive Ubuntu terminal**. It tries the official IPFS distribution first, then GitHub Releases, downloads a matching SHA-512 checksum file, and **refuses to extract or install unless verification succeeds**.

```bash
bash <<'WEALL_KUBO_INSTALL'
set -Eeuo pipefail

KUBO_VERSION="v0.29.0"  # Matches docker-compose.ipfs.yml; local parity test only.
KUBO_ARCHIVE="kubo_${KUBO_VERSION}_linux-amd64.tar.gz"
STAGING="$(mktemp -d)"
trap 'rm -rf -- "$STAGING"' EXIT
cd "$STAGING"

verified=0
for BASE in \
  "https://dist.ipfs.tech/kubo/${KUBO_VERSION}" \
  "https://github.com/ipfs/kubo/releases/download/${KUBO_VERSION}"; do
  rm -f -- "$KUBO_ARCHIVE" "$KUBO_ARCHIVE.sha512"
  echo "Trying: $BASE"
  if curl -fL --retry 3 --retry-all-errors --retry-delay 2 \
      --connect-timeout 20 -o "$KUBO_ARCHIVE" "$BASE/$KUBO_ARCHIVE" &&
     curl -fL --retry 3 --retry-all-errors --retry-delay 2 \
      --connect-timeout 20 -o "$KUBO_ARCHIVE.sha512" "$BASE/$KUBO_ARCHIVE.sha512" &&
     sha512sum --check "$KUBO_ARCHIVE.sha512"; then
    verified=1
    break
  fi
  echo "This source failed download or checksum verification; trying the next."
done

if [ "$verified" -ne 1 ]; then
  echo "STOP: No verified Kubo archive was obtained. Nothing installed." >&2
  exit 1
fi

tar -xzf "$KUBO_ARCHIVE"
mkdir -p "$HOME/.local/bin"
install -m 0755 kubo/ipfs "$HOME/.local/bin/ipfs"
"$HOME/.local/bin/ipfs" version
WEALL_KUBO_INSTALL

export PATH="$HOME/.local/bin:$PATH"
command -v ipfs
ipfs version
```

The script deliberately does **not** initialize a global `~/.ipfs` store or start a daemon. The WeAll Path A launcher manages its own disposable Kubo state and starts the daemon when appropriate. If `command -v ipfs` fails, check that `$HOME/.local/bin` is on `PATH`. After opening a new terminal, repeat `export PATH="$HOME/.local/bin:$PATH"` before launching the rehearsal, or add that export to your shell's usual startup configuration.

**CPU architecture:** this example is for Linux x86_64/amd64. Check `uname -m` before using it; use the matching upstream archive for another architecture.

### If `curl: (35) Recv failure: Connection reset by peer` persists

This is a **download/HTTPS connection error**, not a Kubo installation failure and not a WeAll failure. Do not delete the repository, reinstall Ubuntu, use `curl -k`, or bypass the checksum.

If both official HTTPS endpoints fail from WSL, use a Windows browser to download **both** the archive and its matching `.sha512` file from [the official release assets](https://github.com/ipfs/kubo/releases) for your selected version, and save them in Windows Downloads. Then run in Ubuntu, replacing `YOUR_WINDOWS_USERNAME` with your real Windows username:

```bash
bash <<'WEALL_KUBO_WINDOWS_FILES'
set -Eeuo pipefail
KUBO_VERSION="v0.29.0"
KUBO_ARCHIVE="kubo_${KUBO_VERSION}_linux-amd64.tar.gz"
WIN_DOWNLOADS="/mnt/c/Users/YOUR_WINDOWS_USERNAME/Downloads"
cd "$WIN_DOWNLOADS"
test -f "$KUBO_ARCHIVE"
test -f "$KUBO_ARCHIVE.sha512"
sha512sum --check "$KUBO_ARCHIVE.sha512"

STAGING="$(mktemp -d)"
trap 'rm -rf -- "$STAGING"' EXIT
tar -xzf "$KUBO_ARCHIVE" -C "$STAGING"
mkdir -p "$HOME/.local/bin"
install -m 0755 "$STAGING/kubo/ipfs" "$HOME/.local/bin/ipfs"
"$HOME/.local/bin/ipfs" version
WEALL_KUBO_WINDOWS_FILES

export PATH="$HOME/.local/bin:$PATH"
ipfs version
```

An archive alone is **not sufficient**; if the checksum file is missing, stop and obtain a matching official checksum before installation. If the archive was only partly downloaded, the checksum check must fail closed. Do not substitute checksums from another release or architecture.

## Return to the documented rehearsal

From the same Ubuntu environment:

```bash
cd ~/WeAll-Protocol/Weall-Protocol
source .venv/bin/activate
ipfs version                         # Native path, not Docker
bash scripts/devnet_local_two_frontend_rehearsal.sh
```

For the Docker path, replace the `ipfs version` probe with `docker info` / `docker compose version`. The launcher is expected to report `Local two-frontend rehearsal ready` and the separate loopback observer/reviewer URLs. It can fail for reasons unrelated to package installation; preserve `.weall-devnet/logs/` (redacting secrets) and report the first failing command rather than marking readiness as proven.

The launcher's default accounts `@errol` and `@devnet-genesis` are provisioned test identities. They are **not proof of independent first-time-user signup or PoH**. Test any new self-created account separately in a clean browser profile and record the actual transaction confirmations. This local run is not a two-machine proof, production operator approval, public beta, or multi-validator BFT evidence.

## Record installation outcomes

For first-user reproducibility, record the Git commit, Ubuntu/WSL version, Python/Node/npm versions, chosen IPFS provider, Kubo version, checksum result, the failing URL and error (if any), whether the README/quickstart commands were copied verbatim, and the terminal output from the first failing step. Do **not** include recovered account keys, PoH recordings, Kubo API tokens, or development bootstrap secrets in shared evidence.
