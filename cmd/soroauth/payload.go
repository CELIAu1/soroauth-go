package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

const payloadUsage = `soroauth payload — print what a signer would have to sign.

usage:
  soroauth payload --entry <base64> --valid-until <ledger> --network <name|passphrase>

Prints the HashIdPreimage as base64 and its SHA-256 payload as hex. Nothing is
signed and no key is involved, so this is the subcommand to use when checking
what an offline or hardware signer is being asked to approve.
`

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

	if err := flags.Parse(args); err != nil {
		return err
	}

	entry, err := decodeEntry(*entryFlag)
	if err != nil {
		return err
	}
	passphrase, err := resolveNetwork(*networkFlag)
	if err != nil {
		return err
	}
	if *validUntil == 0 {
		return fmt.Errorf("--valid-until is required and must be greater than zero")
	}

	preimage, err := soroauth.Preimage(entry, uint32(*validUntil), passphrase)
	if err != nil {
		return err
	}
	payload, err := soroauth.Payload(preimage)
	if err != nil {
		return err
	}
	encoded, err := xdr.MarshalBase64(preimage)
	if err != nil {
		return fmt.Errorf("encoding the preimage: %w", err)
	}

	fmt.Fprintf(stdout, "preimage: %s\n", encoded)
	fmt.Fprintf(stdout, "payload:  %s\n", hex.EncodeToString(payload[:]))
	return nil
}
