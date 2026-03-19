#!/usr/bin/env bash

# Resolve key material from one of: explicit input, local generator, environment variable, or provider command.
resolve_key_material() {
  local mode="$1"
  local explicit_value="$2"
  local env_var_name="$3"
  local provider_cmd="$4"
  local local_generator_fn="$5"

  if [[ -n "$explicit_value" ]]; then
    printf '%s' "$explicit_value"
    return 0
  fi

  case "$mode" in
    local)
      if [[ -z "$local_generator_fn" ]] || ! declare -F "$local_generator_fn" >/dev/null 2>&1; then
        echo "Local key generator function is not available." >&2
        return 1
      fi
      "$local_generator_fn"
      ;;
    env)
      if [[ -z "$env_var_name" ]]; then
        echo "--key-env-var (or KEY_ENV_VAR) is required when --key-mode env is used." >&2
        return 1
      fi
      local env_value="${!env_var_name:-}"
      if [[ -z "$env_value" ]]; then
        echo "Environment variable '$env_var_name' is empty or unset." >&2
        return 1
      fi
      printf '%s' "$env_value"
      ;;
    provider)
      if [[ -z "$provider_cmd" ]]; then
        echo "--provider-cmd (or KEY_PROVIDER_CMD) is required when --key-mode provider is used." >&2
        return 1
      fi
      bash -c "$provider_cmd"
      ;;
    *)
      echo "Unsupported key mode: $mode (expected: local|env|provider)." >&2
      return 1
      ;;
  esac
}
