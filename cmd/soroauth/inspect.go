package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/soroauth/soroauth-go"
)

const inspectUsage = `soroauth inspect — print an entry's structure as JSON.

usage:
  soroauth inspect --entry <base64>

Reports the credential arm, whether the payload is address-bound, the address,
nonce and expiration ledger, which nodes carry signatures, the delegate tree,
and the shape of the invocation tree.

This is structural only. It reports which contract and function are being
called, not what they do or whether the arguments are reasonable, so it is a
check that an entry is the one you meant to submit — the right arm, the right
address, signed in the right places — and not a substitute for understanding
the call.

Nothing is signed and no key is involved.
`

func runInspect(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("inspect", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprint(stderr, inspectUsage)
		fmt.Fprintln(stderr, "\nflags:")
		flags.PrintDefaults()
	}

	entryFlag := flags.String("entry", "", "the authorization entry, as base64 XDR")

	if err := flags.Parse(args); err != nil {
		return err
	}

	entry, err := decodeEntry(*entryFlag)
	if err != nil {
		return err
	}

	info, err := soroauth.Inspect(entry)
	if err != nil {
		return err
	}

	encoded, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding the report: %w", err)
	}
	fmt.Fprintln(stdout, string(encoded))
	return nil
}
