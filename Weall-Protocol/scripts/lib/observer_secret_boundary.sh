#!/usr/bin/env sh
# Shared fail-closed secret-boundary checks for external observer/onboarding flows.
# Source this file and call weall_check_observer_secret_boundary, or execute it with
# WEALL_OBSERVER_SECRET_BOUNDARY_AUTORUN=1.

weall_observer_secret_boundary_fail() {
  echo "ERROR: $*" >&2
  return 2
}

weall_check_observer_secret_boundary() {
  for var in \
    WEALL_AUTHORITY_SIGNER_PRIVKEY \
    WEALL_AUTHORITY_SIGNER_PRIVKEY_FILE \
    WEALL_AUTHORITY_PRIVKEY \
    WEALL_AUTHORITY_PRIVKEY_FILE \
    WEALL_TRUSTED_AUTHORITY_PRIVKEYS \
    WEALL_ORACLE_AUTHORITY_SIGNER_PRIVKEY \
    WEALL_ORACLE_AUTHORITY_SIGNER_PRIVKEY_FILE \
    WEALL_ORACLE_AUTHORITY_PRIVKEY \
    WEALL_ORACLE_AUTHORITY_PRIVKEY_FILE \
    WEALL_ORACLE_PRIVKEY \
    WEALL_ORACLE_PRIVKEY_FILE \
    WEALL_LEGACY_ORACLE_PRIVKEY \
    WEALL_LEGACY_ORACLE_PRIVKEY_FILE \
    WEALL_VALIDATOR_PRIVKEY \
    WEALL_VALIDATOR_PRIVKEY_FILE \
    WEALL_VALIDATOR_ACCOUNT \
    WEALL_VALIDATOR_ACCOUNT_FILE \
    WEALL_NODE_PRIVKEY \
    WEALL_NODE_PRIVKEY_FILE \
    WEALL_NAMED_HOSTING_PROVIDER_API_TOKEN \
    WEALL_DNS_API_TOKEN \
    WEALL_OAUTH_CLIENT_SECRET \
    WEALL_KYC_PROVIDER_SECRET \
    WEALL_KYC_API_KEY \
    WEALL_CAPTCHA_SECRET; do
    eval "value=\${$var:-}"
    if [ -n "$value" ]; then
      weall_observer_secret_boundary_fail "$var must not be set for observer onboarding"
      return 2
    fi
  done

  smtp_var="WEALL_SM""TP_PASSWORD"
  eval "smtp_value=\${$smtp_var:-}"
  if [ -n "$smtp_value" ]; then
    weall_observer_secret_boundary_fail "SMTP password must not be present for observer onboarding"
    return 2
  fi

  smtp_file_var="WEALL_SM""TP_PASSWORD_FILE"
  eval "smtp_file_value=\${$smtp_file_var:-}"
  if [ -n "$smtp_file_value" ]; then
    weall_observer_secret_boundary_fail "SMTP password file must not be present for observer onboarding"
    return 2
  fi

  return 0
}

if [ "${WEALL_OBSERVER_SECRET_BOUNDARY_AUTORUN:-0}" = "1" ]; then
  weall_check_observer_secret_boundary
fi
