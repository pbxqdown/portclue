#!/bin/sh
# Install PortClue from a GitHub Release archive after verifying SHA256SUMS.
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/pbxqdown/portclue/vX.Y.Z/scripts/install.sh | sh
#   curl -fsSL .../scripts/install.sh | sh -s -- --system
#   curl -fsSL .../scripts/install.sh | sh -s -- --uninstall
# Env:
#   PORTCLUE_VERSION     release version without leading v (default: latest)
#   PORTCLUE_INSTALL_DIR install directory (default: ~/.local/bin, or
#                        /usr/local/bin with --system)

set -eu

REPO="pbxqdown/portclue"
BASE_URL="https://github.com/${REPO}/releases"
USER_INSTALL_DIR="${HOME}/.local/bin"
SYSTEM_INSTALL_DIR="/usr/local/bin"
VERSION="${PORTCLUE_VERSION:-}"
MODE="user"

usage() {
	cat <<'EOF'
Install PortClue from GitHub Releases (checksum-verified).

Usage:
  install.sh              Install for the current user (~/.local/bin, no root)
  install.sh --system     Install system-wide, root-owned (/usr/local/bin)
  install.sh --uninstall  Remove a user install
  install.sh --system --uninstall
                          Remove a system install
  install.sh --help

Environment:
  PORTCLUE_VERSION      Version without leading "v" (default: latest release)
  PORTCLUE_INSTALL_DIR  Override the install directory for either mode

Modes:
  User mode installs a binary you own and runs without root. PortClue reports
  the most evidence as root, and sudo does not search ~/.local/bin, so use
  system mode when you want to run "sudo portclue".
EOF
}

error() {
	printf 'portclue-install: %s\n' "$*" >&2
	exit 1
}

need_cmd() {
	command -v "$1" >/dev/null 2>&1 || error "required command not found: $1"
}

# Run a command with root privileges only when needed (system mode).
privileged() {
	if [ "$(id -u)" -eq 0 ]; then
		"$@"
	elif command -v sudo >/dev/null 2>&1; then
		sudo "$@"
	else
		error "system install needs root; re-run as root or install sudo"
	fi
}

install_dir() {
	if [ -n "${PORTCLUE_INSTALL_DIR:-}" ]; then
		printf '%s\n' "$PORTCLUE_INSTALL_DIR"
	elif [ "$MODE" = "system" ]; then
		printf '%s\n' "$SYSTEM_INSTALL_DIR"
	else
		printf '%s\n' "$USER_INSTALL_DIR"
	fi
}

bin_path() {
	printf '%s/portclue\n' "$(install_dir)"
}

detect_arch() {
	machine="$(uname -m)"
	case "$machine" in
	x86_64 | amd64) printf 'amd64\n' ;;
	aarch64 | arm64) printf 'arm64\n' ;;
	*) error "unsupported architecture: ${machine} (need x86_64 or aarch64)" ;;
	esac
}

resolve_version() {
	if [ -n "$VERSION" ]; then
		printf '%s\n' "${VERSION#v}"
		return
	fi
	need_cmd curl
	# Follow the latest-release redirect and parse the tag from the final URL.
	final_url="$(curl -fsSL -o /dev/null -w '%{url_effective}' "${BASE_URL}/latest")"
	tag="${final_url##*/}"
	case "$tag" in
	v[0-9]*) printf '%s\n' "${tag#v}" ;;
	*) error "could not resolve latest release from ${BASE_URL}/latest" ;;
	esac
}

download() {
	src="$1"
	dest="$2"
	curl -fsSL --proto '=https' --tlsv1.2 -o "$dest" "$src" || error "download failed: ${src}"
}

uninstall() {
	target="$(bin_path)"
	if [ ! -e "$target" ] && [ ! -L "$target" ]; then
		printf 'Nothing to remove at %s\n' "$target"
		return
	fi
	if [ "$MODE" = "system" ]; then
		privileged rm -f "$target"
	else
		rm -f "$target"
	fi
	printf 'Removed %s\n' "$target"
}

path_hint() {
	dir="$(install_dir)"
	case ":${PATH}:" in
	*":${dir}:"*) ;;
	*)
		printf '\n%s is not in PATH. Add it for the current shell:\n' "$dir"
		printf '  export PATH="%s:$PATH"\n' "$dir"
		;;
	esac
}

post_install_hint() {
	if [ "$MODE" = "system" ]; then
		printf '\nRun with full evidence:\n  sudo portclue\n'
		return
	fi
	path_hint
	# In user mode the binary is user-writable and sudo does not search
	# ~/.local/bin, so do not recommend running this copy as root.
	printf '\nRun (non-root reports available evidence and notes what is missing):\n'
	printf '  portclue\n'
	printf '\nFor the most complete result as root, install system-wide instead:\n'
	printf '  curl -fsSL https://raw.githubusercontent.com/%s/v%s/scripts/install.sh | sh -s -- --system\n' "$REPO" "$version"
	printf '  sudo portclue\n'
}

install_portclue() {
	need_cmd uname
	need_cmd curl
	need_cmd tar
	need_cmd mktemp
	need_cmd install

	os="$(uname -s)"
	[ "$os" = "Linux" ] || error "PortClue release installs support Linux only (found ${os})"

	if command -v sha256sum >/dev/null 2>&1; then
		checksum_cmd="sha256sum"
	elif command -v shasum >/dev/null 2>&1; then
		checksum_cmd="shasum -a 256"
	else
		error "required command not found: sha256sum (or shasum)"
	fi

	arch="$(detect_arch)"
	version="$(resolve_version)"
	archive="portclue-${version}-linux-${arch}.tar.gz"
	asset_base="${BASE_URL}/download/v${version}"
	tmpdir="$(mktemp -d)"
	trap 'rm -rf "$tmpdir"' EXIT INT HUP TERM

	printf 'Downloading PortClue v%s (%s)...\n' "$version" "$arch"
	download "${asset_base}/SHA256SUMS" "${tmpdir}/SHA256SUMS"
	download "${asset_base}/${archive}" "${tmpdir}/${archive}"

	(
		cd "$tmpdir"
		# Verify only the archive we downloaded.
		grep -E "[[:space:]]${archive}\$" SHA256SUMS >SHA256SUMS.selected ||
			error "SHA256SUMS does not list ${archive}"
		$checksum_cmd -c SHA256SUMS.selected >/dev/null
	) || error "checksum verification failed for ${archive}"

	tar -xzf "${tmpdir}/${archive}" -C "$tmpdir"
	extracted="${tmpdir}/portclue-${version}-linux-${arch}/portclue"
	[ -f "$extracted" ] || error "archive did not contain portclue binary"

	dir="$(install_dir)"
	if [ "$MODE" = "system" ]; then
		# Root-owned binary in a system directory: sudo resolves it and the
		# executable is not writable by an unprivileged user.
		privileged install -d -m 0755 "$dir"
		privileged install -o 0 -g 0 -m 0755 "$extracted" "$(bin_path)"
	else
		mkdir -p "$dir"
		install -m 0755 "$extracted" "$(bin_path)"
	fi

	printf 'Installed %s\n' "$(bin_path)"
	if "$(bin_path)" --version >/dev/null 2>&1; then
		printf 'Version: %s\n' "$("$(bin_path)" --version)"
	fi
	post_install_hint
	printf '\nUninstall:\n'
	if [ "$MODE" = "system" ]; then
		printf '  sudo rm %s\n' "$(bin_path)"
		printf '  # or: curl -fsSL https://raw.githubusercontent.com/%s/v%s/scripts/install.sh | sh -s -- --system --uninstall\n' "$REPO" "$version"
	else
		printf '  rm %s\n' "$(bin_path)"
		printf '  # or: curl -fsSL https://raw.githubusercontent.com/%s/v%s/scripts/install.sh | sh -s -- --uninstall\n' "$REPO" "$version"
	fi
}

main() {
	action="install"
	for arg in "$@"; do
		case "$arg" in
		-h | --help)
			usage
			exit 0
			;;
		--system)
			MODE="system"
			;;
		--uninstall)
			action="uninstall"
			;;
		*)
			error "unknown argument: ${arg} (try --help)"
			;;
		esac
	done

	case "$action" in
	install) install_portclue ;;
	uninstall) uninstall ;;
	esac
}

main "$@"
