package main

import (
	"errors"
	"strings"

	"github.com/soroauth/soroauth-go"
)

const jsonErrorSchemaVersion = 1

type jsonErrorFields struct {
	SchemaVersion int    `json:"schema_version"`
	Code          string `json:"code"`
	Message       string `json:"message"`
	Field         string `json:"field"`
	ExitCode      int    `json:"exit_code"`
}

type sentinelJSONError struct {
	err     error
	code    string
	field   string
	message string
}

var sentinelJSONErrors = []sentinelJSONError{
	{soroauth.ErrSourceAccountCredentials, "source_account_credentials", "--entry", "credentials are source-account, which carry no signature payload"},
	{soroauth.ErrUnsupportedCredentials, "unsupported_credentials", "--entry", "unsupported credentials type"},
	{soroauth.ErrNoMatchingCredentialNode, "no_matching_credential_node", "--entry", "no credential node matches the target address"},
	{soroauth.ErrDuplicateDelegate, "duplicate_delegate", "--delegate", "duplicate delegate address at the same level"},
	{soroauth.ErrSignatureMismatch, "signature_mismatch", "--entry", "signature does not verify against the payload"},
	{soroauth.ErrMissingSigner, "missing_signer", "--secret-env", "no signer for address"},
	{soroauth.ErrAlreadySigned, "already_signed", "--entry", "credential node is already signed"},
	{soroauth.ErrInvalidExpiration, "invalid_expiration", "--valid-until", "invalid signature expiration ledger"},
	{soroauth.ErrTooManySignatures, "too_many_signatures", "--secret-env", "too many signatures for a classic account"},
	{soroauth.ErrDecodeLimit, "decode_limit", "--entry", "untrusted input exceeds a decode limit"},
	{soroauth.ErrNoInvokeOperation, "no_invoke_operation", "--entry", "envelope carries no invokeHostFunction operation"},
	{soroauth.ErrUnsupportedEnvelope, "unsupported_envelope", "--entry", "unsupported transaction envelope type"},
	{soroauth.ErrUnsignedCredentialNode, "unsigned_credential_node", "--entry", "credential node was left unsigned"},
	{soroauth.ErrDelegatePlanUnmatched, "delegate_plan_unmatched", "--entries", "delegate plan address matches no entry in the batch"},
	{soroauth.ErrNonceAlreadyReserved, "nonce_already_reserved", "", "nonce already reserved for this address"},
	{soroauth.ErrWebAuthnMalformedJSON, "webauthn_malformed_json", "--assertion", "webauthn assertion is not valid JSON"},
	{soroauth.ErrWebAuthnMissingField, "webauthn_missing_field", "--assertion", "webauthn assertion is missing a field"},
	{soroauth.ErrWebAuthnMalformedField, "webauthn_malformed_field", "--assertion", "webauthn assertion field is not valid base64url"},
	{soroauth.ErrWebAuthnTruncatedAuthenticatorData, "webauthn_truncated_authenticator_data", "--assertion", "webauthn authenticatorData is shorter than its 37-byte fixed prefix"},
	{soroauth.ErrWebAuthnChallengeMismatch, "webauthn_challenge_mismatch", "--assertion", "webauthn challenge does not match the expected payload"},
	{soroauth.ErrSignerAddressMismatch, "signer_address_mismatch", "--secret-env", "signer public key does not match the configured address"},
	{soroauth.ErrVaultUnauthorized, "vault_unauthorized", "", "vault rejected the token"},
	{soroauth.ErrVaultKeyNotFound, "vault_key_not_found", "", "vault transit key not found"},
	{soroauth.ErrVaultKeyType, "vault_key_type", "", "vault transit key is not an ed25519 key"},
	{soroauth.ErrLedgerUnavailable, "ledger_unavailable", "--secret-env", "ledger device is unavailable"},
	{soroauth.ErrLedgerLocked, "ledger_locked", "--secret-env", "ledger device is locked"},
	{soroauth.ErrLedgerWrongApp, "ledger_wrong_app", "--secret-env", "ledger device is not running the Stellar app"},
	{soroauth.ErrLedgerBlindSigningDisabled, "ledger_blind_signing_disabled", "--secret-env", "blind signing is disabled in the Ledger Stellar app settings"},
	{soroauth.ErrLedgerDenied, "ledger_denied", "--secret-env", "the request was rejected on the ledger device"},
	{soroauth.ErrAttestationMalformed, "attestation_malformed", "--attestation", "webauthn attestation is malformed"},
	{soroauth.ErrAttestationInvalid, "attestation_invalid", "--attestation", "webauthn attestation failed verification"},
	{soroauth.ErrAttestationUnsupportedFormat, "attestation_unsupported_format", "--attestation", "webauthn attestation format or algorithm is not supported"},
	{soroauth.ErrPolicyRefusal, "policy_refusal", "--secret-env", "signing refused by policy"},
	{soroauth.ErrSignerTransient, "signer_transient", "--secret-env", "transient signer failure"},
	{soroauth.ErrChainExhausted, "chain_exhausted", "--secret-env", "every signer in the chain failed"},
	{soroauth.ErrQuorumNotMet, "quorum_not_met", "--secret-env", "signer quorum was not met"},
	{soroauth.ErrQuorumDisagreement, "quorum_disagreement", "--secret-env", "signers disagree on the signature"},
}

func machineError(err error) jsonErrorFields {
	exitCode := ExitCode(err)
	fields := jsonErrorFields{
		SchemaVersion: jsonErrorSchemaVersion,
		Code:          "command_failed",
		Message:       "command failed",
		Field:         fieldForError(err),
		ExitCode:      exitCode,
	}
	switch exitCode {
	case ExitUsageError:
		fields.Code = "usage_error"
		fields.Message = "invalid command usage"
	case ExitSigningRefusal:
		fields.Code = "signing_refused"
		fields.Message = "signing was refused"
	case ExitVerificationFailed:
		fields.Code = "verification_failed"
		fields.Message = "verification failed"
	}
	for _, item := range sentinelJSONErrors {
		if errors.Is(err, item.err) {
			fields.Code = item.code
			fields.Message = item.message
			if fields.Field == "" {
				fields.Field = item.field
			}
			break
		}
	}
	return fields
}

func fieldForError(err error) string {
	if err == nil {
		return ""
	}
	var inputErr *inputFieldError
	if errors.As(err, &inputErr) {
		return inputErr.field
	}
	message := err.Error()
	for _, spec := range commandSpecs {
		for _, flag := range spec.Flags {
			name := "--" + flag.Name
			at := strings.Index(message, name)
			if at >= 0 && (at+len(name) == len(message) ||
				(message[at+len(name)] < 'a' || message[at+len(name)] > 'z') &&
					(message[at+len(name)] < 'A' || message[at+len(name)] > 'Z') &&
					(message[at+len(name)] < '0' || message[at+len(name)] > '9') &&
					message[at+len(name)] != '-') {
				return name
			}
		}
	}
	return ""
}

type inputFieldError struct {
	field string
	err   error
}

func (e *inputFieldError) Error() string { return e.err.Error() }

func (e *inputFieldError) Unwrap() error { return e.err }

func withField(field string, err error) error {
	if err == nil {
		return nil
	}
	return &inputFieldError{field: field, err: err}
}

type jsonErrorOutput struct {
	jsonErrorFields
	Error string `json:"error"`
}

func newJSONErrorOutput(err error) jsonErrorOutput {
	fields := machineError(err)
	return jsonErrorOutput{jsonErrorFields: fields, Error: fields.Message}
}
