#!/bin/sh
set -eu

VERSION="${VERSION:-}"
if [ -z "${VERSION}" ]; then
	VERSION="$(awk '/^VERSION[[:space:]]+/ { print $2; exit }' configure.acr)"
fi

PLUGIN_ID="r2mcp"
ARCHIVE_BASENAME="${PLUGIN_ID}-codex-plugin-${VERSION}"
OUTPUT_DIR="release"
STAGE_ROOT="${OUTPUT_DIR}/.${ARCHIVE_BASENAME}.tmp"
STAGE_DIR="${STAGE_ROOT}/${PLUGIN_ID}"
SOURCE_DIR="dist/codex-plugin"
TAR_PATH="${OUTPUT_DIR}/${ARCHIVE_BASENAME}.tar.gz"
ZIP_PATH="${OUTPUT_DIR}/${ARCHIVE_BASENAME}.zip"

rm -rf "${STAGE_ROOT}"
mkdir -p "${STAGE_DIR}"
cp -R "${SOURCE_DIR}/." "${STAGE_DIR}/"

mkdir -p "${OUTPUT_DIR}"
rm -f "${TAR_PATH}" "${ZIP_PATH}" "${TAR_PATH}.sha256" "${ZIP_PATH}.sha256"

tar -C "${STAGE_ROOT}" -czf "${TAR_PATH}" "${PLUGIN_ID}"
(cd "${STAGE_ROOT}" && zip -qr "../../${ZIP_PATH}" "${PLUGIN_ID}")

if command -v sha256sum >/dev/null 2>&1; then
	sha256sum "${TAR_PATH}" > "${TAR_PATH}.sha256"
	sha256sum "${ZIP_PATH}" > "${ZIP_PATH}.sha256"
elif command -v shasum >/dev/null 2>&1; then
	shasum -a 256 "${TAR_PATH}" > "${TAR_PATH}.sha256"
	shasum -a 256 "${ZIP_PATH}" > "${ZIP_PATH}.sha256"
fi

rm -rf "${STAGE_ROOT}"
printf '%s\n' "${TAR_PATH}" "${ZIP_PATH}"
