// Command soroauth builds, signs and inspects Soroban authorization entries
// from the shell.
//
// Entries are passed and printed as base64 XDR, so the tool composes with
// anything that can produce or consume that: an RPC client, jq, or another
// invocation of soroauth.
//
// Secrets are never accepted as flag values. The sign subcommand reads a seed
// from a named environment variable instead, which keeps it out of shell
// history, out of the process table, and out of any transcript of the session.
// No subcommand prints a secret, including on the error paths.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// Exit codes for distinct failure classes.
const (
	ExitOK                 = 0 // success
	ExitGeneralError       = 1 // internal or unclassified error
	ExitUsageError         = 2 // invalid flags, missing required flags, malformed input
	ExitSigningRefusal     = 3 // refused to sign (no matching node, already signed, unsupported credentials, etc.)
	ExitVerificationFailed = 4 // signature verification failed, invalid expiration, etc.
)

// cliError wraps an error with an exit code. It implements the error interface.
type cliError struct {
	err      error
	exitCode int
}

func (e *cliError) Error() string {
	return e.err.Error()
}

func (e *cliError) Unwrap() error {
	return e.err
}

// ExitCode returns the exit code for this error, or ExitOK if err is nil.
func ExitCode(err error) int {
	if err == nil {
		return ExitOK
	}
	var ce *cliError
	if errors.As(err, &ce) {
		return ce.exitCode
	}
	return ExitGeneralError
}

// newError wraps an error with the given exit code.
func newError(exitCode int, format string, args ...any) error {
	return &cliError{err: fmt.Errorf(format, args...), exitCode: exitCode}
}

// newErrorf wraps an error with the given exit code (alias for newError).
func newErrorf(exitCode int, format string, args ...any) error {
	return &cliError{err: fmt.Errorf(format, args...), exitCode: exitCode}
}

const usage = `soroauth builds, signs and inspects Soroban authorization entries.

usage:
  soroauth <command> [flags]

commands:
  payload        print the signing preimage and payload hash for an entry
  sign           sign an entry with a seed read from an environment variable
  delegates      wrap an entry in a delegated-signer credential
  inspect        print an entry's structure as JSON
  doctor         check the local environment for common first-run problems
  cross-compile  build soroauth for multiple targets

run "soroauth <command> -h" for the flags of a command.

exit codes:
  0  success
  1  general error (internal or unclassified)
  2  usage error (invalid flags, missing required flags, malformed input)
  3  signing refused (no matching node, already signed, unsupported credentials, duplicate delegate)
  4  verification failed (signature mismatch, invalid expiration, too many signatures)
`

func main() {
	err := run(os.Args[1:], os.Stdout, os.Stderr, os.Getenv)
	if err != nil {
		// If the error was already written as JSON to stdout by writeJSONError,
		// don't print to stderr again.
		var jsonHandled *jsonErrorHandled
		if !errors.As(err, &jsonHandled) {
			fmt.Fprintf(os.Stderr, "soroauth: %v\n", err)
		}
		os.Exit(ExitCode(err))
	}
}

// run holds the dispatch so tests can drive it without touching the process.
// getenv is injected for the same reason: sign reads its seed from the
// environment, and a test must be able to supply one without mutating the real
// environment of the test binary.
func run(args []string, stdout, stderr io.Writer, getenv func(string) string) error {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return newErrorf(ExitUsageError, "no command given")
	}

	switch args[0] {
	case "payload":
		return runPayload(args[1:], stdout, stderr)
	case "sign":
		return runSign(args[1:], stdout, stderr, getenv)
	case "delegates":
		return runDelegates(args[1:], stdout, stderr)
	case "inspect":
		return runInspect(args[1:], stdout, stderr)
	case "doctor":
		return runDoctor(args[1:], stdout, stderr, getenv)
	case "cross-compile":
		return runCrossCompile(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return nil
	default:
		fmt.Fprint(stderr, usage)
		return newErrorf(ExitUsageError, "unknown command %q", args[0])
	}
}

// resolveNetwork turns the --network flag into a passphrase. The two named
// networks are shorthands; anything else is taken as a literal passphrase, so
// futurenet, a standalone network or a quickstart container all work without
// this tool needing to know about them.
func resolveNetwork(value string) (string, error) {
	switch value {
	case "":
		return "", newErrorf(ExitUsageError, "--network is required (testnet, public, or a literal passphrase)")
	case "testnet":
		return network.TestNetworkPassphrase, nil
	case "public":
		return network.PublicNetworkPassphrase, nil
	default:
		return value, nil
	}
}

// decodeEntry parses a base64 authorization entry from a flag value.
func decodeEntry(value string) (xdr.SorobanAuthorizationEntry, error) {
	if value == "" {
		return xdr.SorobanAuthorizationEntry{}, newErrorf(ExitUsageError, "--entry is required")
	}
	var entry xdr.SorobanAuthorizationEntry
	if err := xdr.SafeUnmarshalBase64(value, &entry); err != nil {
		return xdr.SorobanAuthorizationEntry{}, newErrorf(ExitUsageError, "decoding --entry: %w", err)
	}
	return entry, nil
}

// encodeEntry renders an entry as base64 for printing.
func encodeEntry(entry xdr.SorobanAuthorizationEntry) (string, error) {
	encoded, err := xdr.MarshalBase64(entry)
	if err != nil {
		return "", fmt.Errorf("encoding the entry: %w", err)
	}
	return encoded, nil
}

// jsonErrorHandled is a sentinel error returned by writeJSONError when it has
// already written the error as JSON to stdout. main() checks for this and
// skips printing to stderr.
type jsonErrorHandled struct{ error }

func (e *jsonErrorHandled) Unwrap() error { return e.error }

// writeJSONError writes a JSON error object to stdout if jsonFlag is true,
// otherwise returns the error for the caller to print to stderr.
// When jsonFlag is true, it returns a jsonErrorHandled sentinel so that
// main() knows not to print to stderr again.
func writeJSONError(stdout io.Writer, jsonFlag bool, err error) error {
	if jsonFlag {
		type jsonError struct {
			Error string `json:"error"`
		}
		enc := json.NewEncoder(stdout)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(jsonError{Error: err.Error()})
		return &jsonErrorHandled{err}
	}
	return err
}
