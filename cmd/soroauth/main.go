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
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/soroauth/soroauth-go"
	"github.com/stellar/go-stellar-sdk/clients/rpcclient"
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

// newErrorf wraps an error with the given exit code.
func newErrorf(exitCode int, format string, args ...any) error {
	return &cliError{err: fmt.Errorf(format, args...), exitCode: exitCode}
}

const usage = `soroauth builds, signs and inspects Soroban authorization entries.

usage:
  soroauth <command> [flags]

commands:
  payload        print the signing preimage and payload hash for an entry
  sign           sign an entry with a seed read from an environment variable
  simulate       run the record pass and print what the host recorded
  submit         enforce, sign, send and poll a transaction
  delegates      wrap an entry in a delegated-signer credential
  inspect        print an entry's structure as JSON
  verify         check an entry's signatures without submitting it
  diff           compare two entries and report what changed
  tree           render an entry's delegate tree as ASCII, DOT, or JSON
  tui            interactive TUI for inspecting and signing an entry
  doctor         check the local environment for common first-run problems
  cross-compile  build soroauth for multiple targets
  completions    emit a shell completion script (bash, zsh, fish)
  man            emit a roff man page
  wasm-budget    measure the wasm core against a size ceiling

run "soroauth <command> -h" for the flags of a command.

flags:
  --version      print the build version, commit and Go version
  -h, --help     print this help

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
	return runWithStdin(args, stdout, stderr, getenv, os.Stdin)
}

// runWithStdin is run with the standard input it reads `--entry -` (and the
// batch flags' "-") from injected, so a test can pipe one subcommand's output
// into the next without replacing the process's real os.Stdin. Replacing it is
// not safe here: the test binary runs cases in parallel and os.Stdin is shared,
// so a swap made by one case is visible to every other one.
//
// The subcommands that read stdin — payload, sign, delegates, inspect, verify
// and diff — are dispatched with it; the remaining subcommands are dispatched
// exactly as run would dispatch them.
func runWithStdin(args []string, stdout, stderr io.Writer, getenv func(string) string, stdin io.Reader) error {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return newErrorf(ExitUsageError, "no command given")
	}

	if args[0] == "__complete-addresses" {
		return runCompleteAddresses(args[1:], stdout)
	}
	if command, ok := cliSubcommands[args[0]]; ok {
		cleaned, level, err := splitVerbosity(args[0], args[1:])
		if err != nil {
			return err
		}
		commandOut, commandErr, flush := verbosityOutput(stdout, stderr, level)
		err = command(cleaned, commandOut, commandErr, getenv, stdin)
		if level.verbose && !hasHelpFlag(cleaned) {
			verboseResult(stderr, args[0], err)
		}
		flush(err)
		return err
	}

	switch args[0] {
	case "--version", "-version":
		return runVersion(stdout)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return nil
	default:
		fmt.Fprint(stderr, usage)
		return newErrorf(ExitUsageError, "unknown command %q", args[0])
	}
}

// hasHelpFlag reports whether the command was asked for help, in which case
// --verbose has no verdict to explain.
func hasHelpFlag(args []string) bool {
	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			return true
		}
	}
	return false
}

type cliSubcommand func([]string, io.Writer, io.Writer, func(string) string, io.Reader) error

// cliSubcommands is the dispatcher registry for user-facing commands. Keeping
// dispatch and test enumeration on the same registry ensures every new command
// inherits the CLI's secret-leak regression test.
var cliSubcommands = map[string]cliSubcommand{
	"payload":   runPayloadWithStdin,
	"sign":      runSignWithStdin,
	"simulate":  runSimulate,
	"submit":    runSubmit,
	"delegates": runDelegatesWithStdin,
	"inspect":   runInspect,
	"diff":      runDiff,
	"verify":    runVerify,
	"tree": func(args []string, stdout, stderr io.Writer, getenv func(string) string, _ io.Reader) error {
		return runTree(args, stdout, stderr, getenv)
	},
	"tui": func(args []string, stdout, stderr io.Writer, getenv func(string) string, _ io.Reader) error {
		return runTUI(args, stdout, stderr, getenv)
	},
	"doctor": func(args []string, stdout, stderr io.Writer, getenv func(string) string, _ io.Reader) error {
		return runDoctor(args, stdout, stderr, getenv)
	},
	"cross-compile": func(args []string, stdout, stderr io.Writer, _ func(string) string, _ io.Reader) error {
		return runCrossCompile(args, stdout, stderr)
	},
	"completions": func(args []string, stdout, stderr io.Writer, _ func(string) string, _ io.Reader) error {
		return runCompletions(args, stdout, stderr)
	},
	"man": func(args []string, stdout, stderr io.Writer, _ func(string) string, _ io.Reader) error {
		return runMan(args, stdout, stderr)
	},
	"wasm-budget": func(args []string, stdout, stderr io.Writer, _ func(string) string, _ io.Reader) error {
		return runWASMBudget(args, stdout, stderr)
	},
}

// networkResolver fetches the network passphrase from an RPC endpoint.
// It is a function type so the resolve path can be exercised without a network.
type networkResolver func(ctx context.Context, rpcURL string) (string, error)

// fetchNetworkPassphrase asks an RPC endpoint for its network passphrase.
//
// The endpoint is whatever the caller passed to --rpc-url or set in
// SOROAUTH_RPC_URL; this command does not invent one. The network passphrase
// is read-only, so no credential is involved and nothing here signs.
func fetchNetworkPassphrase(ctx context.Context, rpcURL string) (string, error) {
	client := rpcclient.NewClient(rpcURL, nil)
	defer func() { _ = client.Close() }()

	net, err := client.GetNetwork(ctx)
	if err != nil {
		return "", fmt.Errorf("soroauth: rpc %s: getNetwork: %w", rpcURL, err)
	}
	if net.Passphrase == "" {
		return "", fmt.Errorf("soroauth: rpc %s: getNetwork returned empty passphrase", rpcURL)
	}
	return net.Passphrase, nil
}

// resolveNetwork turns the --network flag into a passphrase. The three named
// networks are shorthands; "rpc" fetches the passphrase from the configured
// RPC endpoint; anything else is taken as a literal passphrase, so a
// standalone network or a quickstart container all work without this tool
// needing to know about them.
//
// When "rpc" is given, the resolved passphrase is printed so the user sees
// which network they are about to commit to. A fetch failure is an error,
// never a fall-through to a default network.
func resolveNetwork(ctx context.Context, value string, rpcURL string, stderr io.Writer, getenv func(string) string, fetch networkResolver) (string, error) {
	switch value {
	case "":
		return "", newErrorf(ExitUsageError, "--network is required (testnet, futurenet, public, rpc, or a literal passphrase)")
	case "testnet":
		return network.TestNetworkPassphrase, nil
	case "futurenet":
		return network.FutureNetworkPassphrase, nil
	case "public":
		return network.PublicNetworkPassphrase, nil
	case "rpc":
		if rpcURL == "" {
			rpcURL = resolveRPCURL("", getenv)
		}
		if rpcURL == "" {
			return "", newErrorf(ExitUsageError,
				"--network rpc resolves against an RPC endpoint and needs one: "+
					"pass --rpc-url <url> or set SOROAUTH_RPC_URL")
		}
		passphrase, err := fetch(ctx, rpcURL)
		if err != nil {
			return "", newErrorf(ExitGeneralError,
				"--network rpc could not fetch the network passphrase from %s: %w", rpcURL, err)
		}
		// Report the resolved passphrase so the user sees which network they
		// are about to commit to. This is the point: a silent correct answer
		// teaches the user nothing.
		fmt.Fprintf(stderr, "soroauth: resolved network passphrase from %s: %s\n", rpcURL, passphrase)
		return passphrase, nil
	default:
		return value, nil
	}
}

// readEntryFlag reads the entry value from stdin if value is "-", otherwise
// returns value.
//
// This is the path for the subcommands that do not inject their own reader —
// tree — plus the helpers whose callers do not carry a stream. It delegates
// to resolveEntryArg rather than reading os.Stdin itself so that there is one
// definition of what `--entry -` means, including the whitespace trimming a
// pipeline depends on; the two used to diverge, and `soroauth delegates … |
// soroauth inspect --entry -` failed with "input not fully consumed" on the
// trailing newline.
func readEntryFlag(value string) (string, error) {
	return readEntryFlagFrom(value, os.Stdin)
}

// readEntryFlagFrom is readEntryFlag with the input stream injected, so the
// dispatcher can hand each subcommand the same stdin its tests drive.
func readEntryFlagFrom(value string, stdin io.Reader) (string, error) {
	resolved, err := resolveEntryArg(value, stdin)
	if err != nil {
		return "", fmt.Errorf("reading from stdin: %w", err)
	}
	return resolved, nil
}

// classifyInput says which of the two ways an --entry value failed to decode,
// and returns err itself for a third that is neither.
//
// "This is not base64" and "this is base64 but is not <want>" used to produce
// the same message, and they call for completely different fixes: retype or
// re-copy the blob, versus hand over the right XDR type. The classification is
// made by asking the base64 decoder directly rather than by reading the
// underlying error's text, because that error comes from a third party and its
// wording is not a contract this CLI can rely on.
//
// A refusal at one of the library's decode limits is passed through unchanged:
// the input was well-formed enough to reach the limit, and calling that
// "not base64" would send the caller looking at the wrong thing.
//
// Neither branch echoes the input. An --entry value may be a signed entry, so
// repeating it would put it in a terminal scrollback, a CI log, or a shell
// session — the underlying error describes the failure and never quotes the
// blob.
func classifyInput(value, want string, err error) error {
	if errors.Is(err, soroauth.ErrDecodeLimit) {
		return err
	}
	if _, base64Err := base64.StdEncoding.DecodeString(value); base64Err != nil {
		return fmt.Errorf("input is not valid base64: %w", err)
	}
	return fmt.Errorf("input is valid base64 but is not %s: %w", want, err)
}

// decodeEntry parses a base64 authorization entry from a flag value.
//
// The entry comes from the command line, which means it came from somewhere
// else: a simulation, another tool, a transcript. It is decoded through the
// library's bounded decoder rather than xdr.SafeUnmarshalBase64 directly, so a
// pathological entry is refused at a deliberate limit instead of at the SDK's
// much looser default. Errors that match ErrDecodeLimit get the usage exit
// code, since the input is what is wrong and no retry against the same input
// can succeed.
func decodeEntry(value string) (xdr.SorobanAuthorizationEntry, error) {
	return decodeEntryNamed("--entry", value)
}

// decodeEntryNamed is decodeEntry with the flag it is reading named, for the
// subcommands that take more than one entry. The name goes into every message,
// so a caller is sent to the flag that is actually wrong rather than to
// "--entry", which diff does not have.
func decodeEntryNamed(name, value string) (xdr.SorobanAuthorizationEntry, error) {
	return decodeEntryNamedFrom(name, value, os.Stdin)
}

// decodeEntryNamedFrom is decodeEntryNamed with the input stream injected, so
// a caller that received stdin from the dispatcher (diff) reads from that
// stream rather than the process's.
func decodeEntryNamedFrom(name, value string, stdin io.Reader) (xdr.SorobanAuthorizationEntry, error) {
	if value == "" {
		return xdr.SorobanAuthorizationEntry{}, newErrorf(ExitUsageError, "%s is required", name)
	}
	val, err := readEntryFlagFrom(value, stdin)
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, newErrorf(ExitUsageError, "%w", err)
	}
	entry, err := soroauth.DecodeAuthorizationEntry(val)
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, newErrorf(ExitUsageError,
			"decoding %s: %w", name, classifyInput(val, "a Soroban authorization entry", err))
	}
	return entry, nil
}

// decodedInput is a base64 blob that was either an authorization entry or a
// transaction envelope, together with which of the two it turned out to be.
type decodedInput struct {
	Entry      xdr.SorobanAuthorizationEntry
	Envelope   xdr.TransactionEnvelope
	IsEnvelope bool
}

// decodeEntryOrEnvelope parses the --entry flag, which accepts either an
// authorization entry or a whole transaction envelope.
//
// Both are base64 XDR unions whose first byte is a small discriminant, so a
// blob has to be tried against both shapes and judged on what it decodes to:
// EnvelopeType values 0, 2 and 5 overlap the credential discriminants 0 to 3.
// An envelope only wins when it decodes AND carries an invokeHostFunction
// operation, which an authorization entry does not look like by any reading;
// when that test fails the blob is read as an entry. If neither reading works,
// the entry error is reported, since --entry has always meant an entry and a
// caller who passed an envelope with nothing to authorize should hear why.
func decodeEntryOrEnvelope(value string) (decodedInput, error) {
	return decodeEntryOrEnvelopeFrom(value, os.Stdin)
}

// decodeEntryOrEnvelopeFrom is decodeEntryOrEnvelope with the input stream
// injected, so a subcommand dispatched with a stdin gets it here too.
func decodeEntryOrEnvelopeFrom(value string, stdin io.Reader) (decodedInput, error) {
	if value == "" {
		return decodedInput{}, newErrorf(ExitUsageError, "--entry is required")
	}
	val, err := readEntryFlagFrom(value, stdin)
	if err != nil {
		return decodedInput{}, newErrorf(ExitUsageError, "%w", err)
	}

	var envelope xdr.TransactionEnvelope
	envelopeErr := xdr.SafeUnmarshalBase64(val, &envelope)

	var entry xdr.SorobanAuthorizationEntry
	entryErr := xdr.SafeUnmarshalBase64(val, &entry)

	// An envelope only wins when it decodes and carries an invokeHostFunction
	// operation. A blob that decodes as an envelope but has nothing to
	// authorize, and does not decode as an entry either, is reported as the
	// envelope problem it is; anything else that fails both readings gets the
	// entry error, since --entry has always meant an entry.
	if envelopeErr == nil {
		if _, entriesErr := soroauth.EnvelopeEntries(envelope); entriesErr == nil {
			return decodedInput{Envelope: envelope, IsEnvelope: true}, nil
		} else if entryErr != nil {
			return decodedInput{}, newErrorf(ExitUsageError, "decoding --entry as an envelope: %w", entriesErr)
		}
	}

	if entryErr != nil {
		return decodedInput{}, newErrorf(ExitUsageError, "decoding --entry: %w",
			classifyInput(val,
				"a Soroban authorization entry or a transaction envelope with an invokeHostFunction operation",
				entryErr))
	}
	return decodedInput{Entry: entry}, nil
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
		enc := json.NewEncoder(stdout)
		enc.SetEscapeHTML(false)
		if encodeErr := enc.Encode(newJSONErrorOutput(err)); encodeErr != nil {
			return newErrorf(ExitGeneralError, "encoding the JSON error: %w", encodeErr)
		}
		return &jsonErrorHandled{err}
	}
	return err
}

// runTUI runs the interactive TUI command.
func runTUI(args []string, stdout, stderr io.Writer, getenv func(string) string) error {
	// Parse flags manually since we don't use flag package for subcommands
	var entryB64 string
	var validUntilLedger uint32
	var networkPassphrase string
	var secretEnvVar string
	var forAddress string
	var configFlag string
	var rpcURL string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--entry":
			if i+1 < len(args) {
				entryB64 = args[i+1]
				i++
			}
		case "--valid-until":
			if i+1 < len(args) {
				// A malformed value leaves validUntilLedger at zero, which the
				// required-flag check below refuses. The TUI parses its own
				// flags rather than using the flag package, so there is no
				// parse error to surface here.
				_, _ = fmt.Sscanf(args[i+1], "%d", &validUntilLedger)
				i++
			}
		case "--network":
			if i+1 < len(args) {
				networkPassphrase = args[i+1]
				i++
			}
		case "--rpc-url":
			if i+1 < len(args) {
				rpcURL = args[i+1]
				i++
			}
		case "--secret-env":
			if i+1 < len(args) {
				secretEnvVar = args[i+1]
				i++
			}
		case "--for":
			if i+1 < len(args) {
				forAddress = args[i+1]
				i++
			}
		case "--config":
			if i+1 < len(args) {
				configFlag = args[i+1]
				i++
			}
		case "--quiet", "--verbose", "--quiet=true", "--verbose=true", "--quiet=false", "--verbose=false":
			// The dispatcher consumes these before runTUI. Keep the cases so a
			// direct caller of runTUI, and the usage-driven spec test, still
			// accept what the CLI advertises.
		case "--help", "-h":
			fmt.Fprint(stdout, tuiUsage)
			return nil
		}
	}

	cfg, err := loadConfig(configFlag, getenv)
	if err != nil {
		return err
	}
	netVal := resolveNetworkValue(nil, networkPassphrase, getenv, cfg).Value
	secVal := resolveSecretEnvValue(nil, secretEnvVar, getenv, cfg).Value
	rpcVal := resolveRPCURLValue(nil, rpcURL, getenv, cfg, "").Value

	if entryB64 == "" || validUntilLedger == 0 || netVal == "" || secVal == "" {
		fmt.Fprint(stderr, tuiUsage)
		return newErrorf(ExitUsageError, "missing required flags")
	}

	// Resolve network passphrase
	passphrase, err := resolveNetwork(context.Background(), netVal, rpcVal, stderr, getenv, fetchNetworkPassphrase)
	if err != nil {
		return err
	}

	return soroauth.TUIWithOutput(context.Background(), entryB64, validUntilLedger, passphrase, secVal, forAddress, stdout)
}

const tuiUsage = `usage: soroauth tui --entry <base64> --valid-until <ledger> --network <passphrase> --secret-env <var> [--for <addr>] [--config <path>]

Interactive TUI for inspecting and signing an authorization entry.

flags:
  --entry        base64-encoded authorization entry (required)
  --valid-until  signature expiration ledger (required)
  --network      network passphrase: testnet, futurenet, public, rpc, or literal (required)
  --rpc-url      RPC endpoint used to resolve --network rpc (default $SOROAUTH_RPC_URL)
  --secret-env   name of environment variable holding the secret seed (required)
  --for          target address to sign for (optional, defaults to signer's address)
  --config       path to CLI configuration file (default $SOROAUTH_CONFIG or ~/.config/soroauth/config.json)
  --quiet        print nothing on success; the exit code is the result
  --verbose      explain the verdict on stderr without printing the entry or a secret

The seed is read from the named environment variable and is never prompted for
or echoed. If stdin is not a TTY, the command degrades to non-interactive output
(equivalent to running inspect and sign).
`
