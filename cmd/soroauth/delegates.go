package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/soroauth/soroauth-go"
)

const delegatesUsage = `soroauth delegates — wrap an entry in a delegated-signer credential.

usage:
  soroauth delegates --entry <base64> --valid-until <ledger> \
                     --delegate <address> [--delegate <address> ...]

Converts an ADDRESS or ADDRESS_V2 entry into ADDRESS_WITH_DELEGATES (CAP-71-01),
with the delegates sorted into the order the protocol requires. Pass --delegate
once per address; the order they are given in does not matter.

The delegate signatures are left as placeholders. Fill each one afterwards with:

  soroauth sign --entry <wrapped> --for <delegate address> ...

Only a flat list of delegates can be expressed here. Nested delegates — a
delegate that itself delegates — are supported by the library
(soroauth.Delegate.Nested) but have no command-line syntax yet.

Note that wrapping a legacy ADDRESS entry makes its payload address-bound, so
any signature already on the entry would stop verifying; such an entry is
rejected rather than silently rewrapped.

Prints the wrapped entry as base64.
`

// addressList collects a flag that may be repeated.
type addressList []string

func (a *addressList) String() string { return fmt.Sprint(*a) }

func (a *addressList) Set(value string) error {
	if value == "" {
		return fmt.Errorf("--delegate needs an address")
	}
	*a = append(*a, value)
	return nil
}

func runDelegates(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("delegates", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprint(stderr, delegatesUsage)
		fmt.Fprintln(stderr, "\nflags:")
		flags.PrintDefaults()
	}

	entryFlag := flags.String("entry", "", "the authorization entry, as base64 XDR")
	validUntil := flags.Uint("valid-until", 0, "the last ledger at which the signatures are valid")
	var delegates addressList
	flags.Var(&delegates, "delegate", "a delegate address; repeat for several")

	if err := flags.Parse(args); err != nil {
		return err
	}

	entry, err := decodeEntry(*entryFlag)
	if err != nil {
		return err
	}
	if *validUntil == 0 {
		return fmt.Errorf("--valid-until is required and must be greater than zero")
	}
	if len(delegates) == 0 {
		return fmt.Errorf("at least one --delegate is required")
	}

	tree := make([]soroauth.Delegate, 0, len(delegates))
	for _, address := range delegates {
		tree = append(tree, soroauth.Delegate{Address: address})
	}

	wrapped, err := soroauth.WithDelegates(entry, uint32(*validUntil), tree, nil)
	if err != nil {
		return err
	}

	encoded, err := encodeEntry(wrapped)
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, encoded)
	return nil
}
