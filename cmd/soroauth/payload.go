package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

const payloadUsage = `soroauth payload — print what a signer would have to sign.

usage:
  soroauth payload --entry <base64> --valid-until <ledger> --network <name|passphrase> [--json]

Prints the HashIdPreimage as base64 and its SHA-256 payload as hex. Nothing is
signed and no key is involved, so this is the subcommand to use when checking
what an offline or hardware signer is being asked to approve.

With --json, prints a single JSON object with fields "preimage" and "payload".
On error, prints a JSON object with field "error" to stdout and exits non-zero.
`

type payloadOutput struct {
	Preimage string `json:"preimage,omitempty"`
	Payload  string `json:"payload,omitempty"`
	Error    string `json:"error,omitempty"`
}

func runPayload(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("payload", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprint(stderr, payloadUsage)
		fmt.Fprintln(stderr, "\nflags:")
		flags.PrintDefaults()
	}

	entryFlag := flags.String("entry", "", "the authorization entry, as base64 XDR")
	validUntil := flags.Uint("valid-until", 0, "the last ledger at which the signature is valid")
	networkFlag := flags.String("network", "", "testnet, public, or a literal network passphrase")
	jsonFlag := flags.Bool("json", false, "output as JSON")

	if err := flags.Parse(args); err != nil {
		return newErrorf(ExitUsageError, "%w", err)
	}

	entry, err := decodeEntry(*entryFlag)
	if err != nil {
		return writeJSONError(stdout, *jsonFlag, err)
	}
	passphrase, err := resolveNetwork(*networkFlag)
	if err != nil {
		return writeJSONError(stdout, *jsonFlag, err)
	}
	if *validUntil == 0 {
		return writeJSONError(stdout, *jsonFlag, newErrorf(ExitUsageError, "--valid-until is required and must be greater than zero"))
	}

	preimage, err := soroauth.Preimage(entry, uint32(*validUntil), passphrase)
	if err != nil {
		// Classify the error for exit code
		var exitCode int
		if errors.Is(err, soroauth.ErrSourceAccountCredentials) || errors.Is(err, soroauth.ErrUnsupportedCredentials) {
			exitCode = ExitSigningRefusal
		} else {
			exitCode = ExitVerificationFailed
		}
		return writeJSONError(stdout, *jsonFlag, newErrorf(exitCode, "%w", err))
	}
	payload, err := soroauth.Payload(preimage)
	if err != nil {
		return writeJSONError(stdout, *jsonFlag, newErrorf(ExitGeneralError, "%w", err))
	}
	encoded, err := xdr.MarshalBase64(preimage)
	if err != nil {
		return writeJSONError(stdout, *jsonFlag, newErrorf(ExitGeneralError, "encoding the preimage: %w", err))
	}

	if *jsonFlag {
		out := payloadOutput{Preimage: encoded, Payload: hex.EncodeToString(payload[:])}
		enc := json.NewEncoder(stdout)
		enc.SetEscapeHTML(false)
		return enc.Encode(out)
	}

	fmt.Fprintf(stdout, "preimage: %s\n", encoded)
	fmt.Fprintf(stdout, "payload:  %s\n", hex.EncodeToString(payload[:]))
	return nil
}
