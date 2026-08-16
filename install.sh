#!/usr/bin/env sh
# install.sh — one-command installer for `ds`.
#
# Default path: download a prebuilt release binary from GitHub, verify its
# SHA-256 checksum, and install to ~/.local/bin (or /usr/local/bin if
# writable). No Rust toolchain required.
#
# Fallback path (--from-source or no matching prebuilt binary exists): build
# from source via the official `rustup` installer (minimal profile) + cargo.
#
# Usage:
#   install.sh                          # install latest release
#   install.sh --version v0.1.0         # install a specific release tag
#   install.sh --from-source            # force source build
#   install.sh --repo user/repo         # use a non-default GitHub repo
#
# Environment:
#   DS_INSTALL_DIR       Override install directory (default: ~/.local/bin)
#   DS_GITHUB_REPO       Override repo (default: mirzasaikatahmmed/ds-cli)
#   DS_SKIP_CHECKSUM     Set to 1 to skip checksum verification
#
# Set -eu (treat unset vars as errors, exit on first failure).

set -eu

REPO="${DS_GITHUB_REPO:-mirzasaikatahmmed/ds-cli}"
VERSION=""
FROM_SOURCE=0
SKIP_CHECKSUM="${DS_SKIP_CHECKSUM:-0}"

while [ $# -gt 0 ]; do
    case "$1" in
        --version)
            VERSION="$2"
            shift 2
            ;;
        --from-source)
            FROM_SOURCE=1
            shift
            ;;
        --repo)
            REPO="$2"
            shift 2
            ;;
        --help|-h)
            cat <<EOF
install.sh — install ds (Domain Search CLI)

Usage:
  install.sh [--version TAG] [--from-source] [--repo OWNER/NAME]

Default: download the latest prebuilt release binary from GitHub Releases.
Fallback: build from source via rustup (minimal profile) + cargo.

Examples:
  ./install.sh
  ./install.sh --version v0.1.0
  ./install.sh --from-source
EOF
            exit 0
            ;;
        *)
            printf 'unknown argument: %s\n' "$1" >&2
            exit 1
            ;;
    esac
done

# ---------- helpers ----------

log() {
    printf '[ds install] %s\n' "$*"
}

err() {
    printf '[ds install] error: %s\n' "$*" >&2
}

# Detect OS+arch. Outputs a target triple subset that matches the
# GitHub release asset filenames.
detect_target() {
    os=$(uname -s 2>/dev/null || echo unknown)
    arch=$(uname -m 2>/dev/null || echo unknown)

    case "$os" in
        Linux)
            case "$arch" in
                x86_64|amd64) echo "x86_64-unknown-linux-gnu" ;;
                aarch64|arm64) echo "aarch64-unknown-linux-gnu" ;;
                *)
                    err "unsupported Linux arch: $arch"
                    return 1
                    ;;
            esac
            ;;
        Darwin)
            case "$arch" in
                x86_64) echo "x86_64-apple-darwin" ;;
                arm64|aarch64) echo "aarch64-apple-darwin" ;;
                *)
                    err "unsupported macOS arch: $arch"
                    return 1
                    ;;
            esac
            ;;
        *)
            err "unsupported OS: $os (use install.ps1 on Windows)"
            return 1
            ;;
    esac
}

# Resolve the install directory. Prefer ~/.local/bin if writable, else
# /usr/local/bin if writable, else the home-local path anyway.
install_dir() {
    if [ -n "${DS_INSTALL_DIR:-}" ]; then
        echo "$DS_INSTALL_DIR"
        return 0
    fi
    home_local="$HOME/.local/bin"
    if [ -d "$home_local" ] || mkdir -p "$home_local" 2>/dev/null; then
        echo "$home_local"
        return 0
    fi
    if [ -w /usr/local/bin ]; then
        echo "/usr/local/bin"
        return 0
    fi
    if [ -w /usr/local/bin ] || sudo -n true 2>/dev/null; then
        echo "/usr/local/bin"
        return 0
    fi
    echo "$home_local"
}

# Compute SHA-256 of a file. Prefer sha256sum, fall back to shasum.
sha256_of_file() {
    file="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$file" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$file" | awk '{print $1}'
    else
        err "no sha256 tool available"
        return 1
    fi
}

# ---------- prebuilt-binary install path ----------

install_prebuilt() {
    target=$(detect_target)
    log "detected target: $target"

    if [ -z "$VERSION" ]; then
        log "resolving latest release tag from $REPO"
        # GitHub redirect-based latest URL.
        latest_url="https://github.com/$REPO/releases/latest"
        # `curl -fsSL -o /dev/null -w '%{url_effective}'` returns the
        # final URL after the 302 to /tag/...
        VERSION=$(curl -fsSL -o /dev/null -w '%{url_effective}' "$latest_url" \
            | sed -n 's#.*/tag/##p')
        if [ -z "$VERSION" ]; then
            err "could not determine latest version"
            return 1
        fi
        log "latest version: $VERSION"
    fi

    # Asset filename pattern (matches .github/workflows/release.yml).
    archive="ds-$target.tar.gz"
    base_url="https://github.com/$REPO/releases/download/$VERSION"
    archive_url="$base_url/$archive"
    checksums_url="$base_url/SHASUMS256.txt"

    workdir=$(mktemp -d)
    trap 'rm -rf "$workdir"' EXIT

    log "downloading $archive"
    if ! curl -fsSL -o "$workdir/$archive" "$archive_url"; then
        err "download failed: $archive_url"
        err "no prebuilt binary available for $target"
        return 1
    fi

    if [ "$SKIP_CHECKSUM" != "1" ]; then
        log "verifying checksum"
        if ! curl -fsSL -o "$workdir/SHASUMS256.txt" "$checksums_url"; then
            err "could not download SHASUMS256.txt"
            err "set DS_SKIP_CHECKSUM=1 to install without verification"
            return 1
        fi
        expected=$(grep -F "  $archive" "$workdir/SHASUMS256.txt" | awk '{print $1}')
        if [ -z "$expected" ]; then
            err "no checksum entry for $archive in SHASUMS256.txt"
            return 1
        fi
        actual=$(sha256_of_file "$workdir/$archive")
        if [ "$expected" != "$actual" ]; then
            err "checksum mismatch!"
            err "  expected: $expected"
            err "  actual:   $actual"
            return 1
        fi
        log "checksum OK"
    else
        log "skipping checksum verification (DS_SKIP_CHECKSUM=1)"
    fi

    log "extracting"
    tar -xzf "$workdir/$archive" -C "$workdir"

    bin_path="$workdir/ds-$target/$([ "$target" = "x86_64-pc-windows-msvc" ] && echo ds.exe || echo ds)"
    if [ ! -f "$bin_path" ]; then
        err "extracted binary not found at $bin_path"
        return 1
    fi

    dest=$(install_dir)
    mkdir -p "$dest"
    dest_bin="$dest/ds"
    log "installing to $dest_bin"
    cp "$bin_path" "$dest_bin"
    chmod +x "$dest_bin"

    print_done "$dest_bin"
}

# ---------- source-build fallback path ----------

install_from_source() {
    log "building from source"

    if ! command -v cargo >/dev/null 2>&1; then
        log "cargo not found; installing rustup (minimal profile)"
        if ! command -v curl >/dev/null 2>&1; then
            err "curl is required to install rustup"
            return 1
        fi
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
        # shellcheck disable=SC1091
        . "$HOME/.cargo/env"
    fi

    if ! command -v cargo >/dev/null 2>&1; then
        err "still no cargo after rustup install"
        return 1
    fi

    # Find the source tree. The script lives at the repo root.
    src_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
    if [ ! -f "$src_dir/Cargo.toml" ]; then
        err "no Cargo.toml at $src_dir — run install.sh from a ds checkout"
        return 1
    fi

    log "running cargo install --path $src_dir --locked"
    cargo install --path "$src_dir" --locked

    # cargo install puts the binary in ~/.cargo/bin by default.
    cargo_bin="$HOME/.cargo/bin/ds"
    if [ ! -f "$cargo_bin" ]; then
        err "cargo install succeeded but $cargo_bin not found"
        return 1
    fi

    print_done "$cargo_bin"
}

# ---------- finish ----------

print_done() {
    dest="$1"
    log "installed: $dest"
    # Verify it's on PATH (informational).
    case ":$PATH:" in
        *":$(dirname "$dest"):"*)
            log "verify: ds --version"
            if ds --version >/dev/null 2>&1; then
                ds --version
            else
                # Fall back to running the binary directly.
                "$dest" --version 2>/dev/null || true
            fi
            ;;
        *)
            log "NOTE: $(dirname "$dest") is not on your PATH"
            log "add it with:  export PATH=\"$(dirname "$dest"):\$PATH\""
            ;;
    esac
}

# ---------- main ----------

if [ "$FROM_SOURCE" = "1" ]; then
    install_from_source
else
    if ! install_prebuilt; then
        log "prebuilt install failed; falling back to source build"
        install_from_source
    fi
fi
