#!/usr/bin/env bash
set -euo pipefail

APP_ROOT="RedoorApp/RedoorApp"
PROFILE_FILE="${APP_ROOT}/Core/IdentitySecurityProfile.swift"
KEYCHAIN_GATE_FILE="${APP_ROOT}/Core/RedoorFFI.swift"

if [[ ! -d "${APP_ROOT}" ]]; then
  echo "::error::Missing app root: ${APP_ROOT}"
  exit 1
fi

failed=0

if command -v rg >/dev/null 2>&1; then
  SEARCH_TOOL="rg"
else
  SEARCH_TOOL="grep"
  echo "rg not found; using grep fallback for RAM-only policy checks."
fi

echo "Checking for forbidden CoreData model bundles..."
if find "${APP_ROOT}" -type d -name "*.xcdatamodeld" | grep -q .; then
  echo "::error::CoreData model bundles are forbidden in RAM-only mode."
  find "${APP_ROOT}" -type d -name "*.xcdatamodeld" -print
  failed=1
fi

declare -a checks=(
  "UserDefaults usage::\\bUserDefaults\\b"
  "AppStorage usage::@AppStorage\\b"
  "CoreData import::^\\s*import\\s+CoreData\\b"
  "CoreData managed object usage::\\bNSManagedObject(Context|Model)?\\b"
  "Persistent container usage::\\bNSPersistent(Container|StoreCoordinator|CloudKitContainer)\\b"
  "Direct file write usage::\\.write\\s*\\(\\s*to:\\s*"
  "Disk directory usage::(documentsDirectory|cachesDirectory|applicationSupportDirectory)"
)

for item in "${checks[@]}"; do
  name="${item%%::*}"
  pattern="${item##*::}"

  if [[ "${SEARCH_TOOL}" == "rg" ]]; then
    matches="$(
      rg -n \
        --glob "*.swift" \
        --glob "!**/*Tests.swift" \
        "${pattern}" \
        "${APP_ROOT}" \
        || true
    )"
  else
    matches="$(
      grep -RInE \
        --include="*.swift" \
        --exclude="*Tests.swift" \
        "${pattern}" \
        "${APP_ROOT}" \
        || true
    )"
  fi

  if [[ -n "${matches}" ]]; then
    echo "::error::${name} is forbidden by RAM-only policy."
    echo "${matches}"
    failed=1
  fi
done

echo "Checking Keychain API usage is profile-gated..."
keychain_pattern='(SecItem(Add|CopyMatching|Delete|Update)|kSec(Class|Attr|Value|ReturnData|MatchLimit))'
if [[ "${SEARCH_TOOL}" == "rg" ]]; then
  keychain_matches="$(
    rg -n \
      --glob "*.swift" \
      --glob "!**/*Tests.swift" \
      "${keychain_pattern}" \
      "${APP_ROOT}" \
      || true
  )"
else
  keychain_matches="$(
    grep -RInE \
      --include="*.swift" \
      --exclude="*Tests.swift" \
      "${keychain_pattern}" \
      "${APP_ROOT}" \
      || true
  )"
fi

if [[ -n "${keychain_matches}" ]]; then
  disallowed_keychain_matches="$(echo "${keychain_matches}" | grep -v "^${KEYCHAIN_GATE_FILE}:" || true)"
  if [[ -n "${disallowed_keychain_matches}" ]]; then
    echo "::error::Keychain API usage is only allowed in ${KEYCHAIN_GATE_FILE} with explicit profile gates."
    echo "${disallowed_keychain_matches}"
    failed=1
  fi
fi

if [[ ! -f "${KEYCHAIN_GATE_FILE}" ]]; then
  echo "::error::Missing Keychain gate file: ${KEYCHAIN_GATE_FILE}"
  failed=1
elif ! grep -q "guard profile\\.allowsPersistentIdentityMaterial else" "${KEYCHAIN_GATE_FILE}"; then
  echo "::error::Keychain operations must be explicitly gated by identity profile."
  failed=1
fi

if [[ ! -f "${PROFILE_FILE}" ]]; then
  echo "::error::Missing identity profile definition file: ${PROFILE_FILE}"
  failed=1
elif ! grep -q "return \\.strictEphemeral" "${PROFILE_FILE}"; then
  echo "::error::Identity profile default must remain strict_ephemeral."
  failed=1
fi

if [[ "${failed}" -ne 0 ]]; then
  echo "RAM-only policy check failed."
  exit 1
fi

echo "RAM-only policy check passed."
