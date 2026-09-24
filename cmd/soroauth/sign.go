package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/stellar/go-stellar-sdk/keypair"

	"github.com/soroauth/soroauth-go"
)

const signUsage = `soroauth sign — sign an authorization entry.

usage:
  soroauth sign --entry <base64> --valid-until <ledger> --network <name|passphrase> \
                --secret-env <VAR> [--for <address>] [--json]

The signing seed is read from the environment variable named by --secret-env.
There is deliberately no flag that takes a seed as a value: a flag value ends up
in shell history, in the process table, and in any transcript of the session.

The signature is written only onto credential nodes whose address matches the
signer's own address, or the address given by --for. If no node matches, the
command fails rather than signing something else.

Prints the signed entry as base64. With --json, prints a JSON object with field
"signed_entry". On error, prints a JSON object with field "error" to stdout and
exits non-zero.
`

type signOutput struct {
	SignedEntry string `json:"signed_entry,omitempty"`
	Error       string `json:"error,omitempty"`
}

func runSign(args []string, stdout, stderr io.Writer, getenv func(string) string) error {
	flags := flag.NewFlagSet("sign", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprint(stderr, signUsage)
		fmt.Fprintln(stderr, "\nflags:")
		flags.PrintDefaults()
	}

	entryFlag := flags.String("entry", "", "the authorization entry, as base64 XDR")
	validUntil := flags.Uint("valid-until", 0, "the last ledger at which the signature is valid")
	networkFlag := flags.String("network", "", "testnet, public, or a literal network passphrase")
	secretEnv := flags.String("secret-env", "", "name of the environment variable holding the S… seed")
	forAddress := flags.String("for", "", "credential node to sign, when it is not the signer's own address")
	jsonFlag := flags.Bool("json", false, "output as JSON")

	if err := flags.Parse(args); err != nil {
		return err
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
		return writeJSONError(stdout, *jsonFlag, fmt.Errorf("--valid-until is required and must be greater than zero"))
	}
	if *secretEnv == "" {
		return writeJSONError(stdout, *jsonFlag, fmt.Errorf("--secret-env is required: name the environment variable holding the seed"))
	}

	seed := getenv(*secretEnv)
	if seed == "" {
		return writeJSONError(stdout, *jsonFlag, fmt.Errorf("environment variable %s is empty or unset", *secretEnv))
	}

	// keypair.Parse's error can quote what it was given, so it is deliberately
	// not wrapped: the message names the variable, never its contents.
	parsed, err := keypair.Parse(seed)
	if err != nil {
		return writeJSONError(stdout, *jsonFlag, fmt.Errorf("the value of %s is not a valid Stellar key", *secretEnv))
	}
	full, ok := parsed.(*keypair.Full)
	if !ok {
		return writeJSONError(stdout, *jsonFlag, fmt.Errorf("the value of %s is a public key; a secret seed (S…) is required", *secretEnv))
	}

	var opts []soroauth.AuthorizeOption
	if *forAddress != "" {
		opts = append(opts, soroauth.ForAddress(*forAddress))
	}

	signed, err := soroauth.AuthorizeEntry(context.Background(), entry,
		soroauth.NewEd25519Signer(full), uint32(*validUntil), passphrase, opts...)
	if err != nil {
		return writeJSONError(stdout, *jsonFlag, err)
	}

	encoded, err := encodeEntry(signed)
	if err != nil {
		return writeJSONError(stdout, *jsonFlag, err)
	}

	if *jsonFlag {
		out := signOutput{SignedEntry: encoded}
		enc := json.NewEncoder(stdout)
		enc.SetEscapeHTML(false)
		return enc.Encode(out)
	}

	fmt.Fprintln(stdout, encoded)
	return nil
}
