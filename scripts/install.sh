#!/bin/sh
# Install PortClue from a GitHub Release archive after verifying SHA256SUMS.
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/pbxqdown/portclue/vX.Y.Z/scripts/install.sh | sh
#   curl -fsSL .../scripts/install.sh | sh -s -- --uninstall
# Env:
#   PORTCLUE_VERSION     release version without leading v (default: latest)
#   PORTCLUE_INSTALL_DIR install directory (default: ~/.local/bin)

set -eu

REPO="pbxqdown/portclue"
BASE_URL="https://github.com/${REPO}/releases"
DEFAULT_INSTALL_DIR="${HOME}/.local/bin"
INSTALL_DIR="${PORTCLUE_INSTALL_DIR:-$DEFAULT_INSTALL_DIR}"
VERSION="${PORTCLUE_VERSION:-}"

usage() {
	cat <<'EOF'
Install PortClue from GitHub Releases (checksum-verified).

Usage:
  install.sh
  install.sh --uninstall
  install.sh --help

Environment:
  PORTCLUE_VERSION      Version without leading "v" (default: latest release)
  PORTCLUE_INSTALL_DIR  Directory for the portclue binary (default: ~/.local/bin)
EOF
}

error() {
	printf 'portclue-install: %s\n' "$*" >&2
	exit 1
}

need_cmd() {
	command -v "$1" >/dev/null 2>&1 || error "required command not found: $1"
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

bin_path() {
	printf '%s/portclue\n' "$INSTALL_DIR"
}

uninstall() {
	target="$(bin_path)"
	if [ -e "$target" ] || [ -L "$target" ]; then
		rm -f "$target"
		printf 'Removed %s\n' "$target"
	else
		printf 'Nothing to remove at %s\n' "$target"
	fi
}

path_hint() {
	case ":${PATH}:" in
	*":${INSTALL_DIR}:"*) ;;
	*)
		printf '\n%s is not in PATH. Add it for the current shell:\n' "$INSTALL_DIR"
		printf '  export PATH="%s:$PATH"\n' "$INSTALL_DIR"
		;;
	esac
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

	mkdir -p "$INSTALL_DIR"
	install -m 0755 "$extracted" "$(bin_path)"

	printf 'Installed %s\n' "$(bin_path)"
	if "$(bin_path)" --version >/dev/null 2>&1; then
		printf 'Version: %s\n' "$("$(bin_path)" --version)"
	fi
	path_hint
	printf '\nUninstall:\n  rm %s\n' "$(bin_path)"
	printf '  # or: curl -fsSL https://raw.githubusercontent.com/%s/v%s/scripts/install.sh | sh -s -- --uninstall\n' "$REPO" "$version"
}

main() {
	action="install"
	for arg in "$@"; do
		case "$arg" in
		-h | --help)
			usage
			exit 0
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
