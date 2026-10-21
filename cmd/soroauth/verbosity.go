package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// verbosity is the output level shared by every subcommand.
//
// Quiet and verbose are mutually exclusive because they answer opposite
// questions: quiet is for a script that reads the exit code, verbose is for a
// person asking why the exit code is what it is. Accepting both would leave the
// implementation to invent a precedence, so it is a usage error instead.
type verbosity struct {
	quiet   bool
	verbose bool
}

const quietFlagUsage = "print nothing on success; the exit code is the result"
const verboseFlagUsage = "explain the verdict on stderr without printing the entry or a secret"

// registerVerbosityFlags adds the flags to a subcommand's FlagSet. The
// dispatcher strips them before dispatch, but registering them keeps -h, the
// man page and the completion specs honest about what the command accepts.
func registerVerbosityFlags(flags *flag.FlagSet) {
	flags.Bool("quiet", false, quietFlagUsage)
	flags.Bool("verbose", false, verboseFlagUsage)
}

// splitVerbosity removes --quiet and --verbose from args, including the
// --flag=true spelling, and reports the selected level.
//
// The command's spec is used to avoid mistaking a flag value for a verbosity
// flag: --for --quiet names an address, not a request for silence. Arguments
// after "--" are left untouched for the same reason.
func splitVerbosity(command string, args []string) ([]string, verbosity, error) {
	var level verbosity
	spec, ok := findCommandSpec(command)
	if !ok {
		// Unknown commands are reported by the dispatcher. Treat every
		// verbosity-looking token as a flag here so the unknown command error
		// is not hidden by an argument that happens to be named --quiet.
		spec = commandSpec{}
	}
	takesValue := make(map[string]bool, len(spec.Flags))
	for _, flag := range spec.Flags {
		takesValue["--"+flag.Name] = flag.TakesValue
	}

	cleaned := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			cleaned = append(cleaned, args[i:]...)
			break
		}
		name, value, hasValue := strings.Cut(arg, "=")
		switch name {
		case "--quiet":
			parsed, err := parseVerbosityValue(value, hasValue, "--quiet")
			if err != nil {
				return nil, verbosity{}, err
			}
			level.quiet = parsed
			continue
		case "--verbose":
			parsed, err := parseVerbosityValue(value, hasValue, "--verbose")
			if err != nil {
				return nil, verbosity{}, err
			}
			level.verbose = parsed
			// Leave the flag in place: the command's FlagSet registers it and
			// uses flagVerbose to write the detail behind its verdict. Quiet
			// is removed because the dispatcher owns its buffering.
		}
		cleaned = append(cleaned, arg)
		if takesValue[name] && !hasValue && i+1 < len(args) {
			i++
			cleaned = append(cleaned, args[i])
		}
	}
	if level.quiet && level.verbose {
		return nil, verbosity{}, newErrorf(ExitUsageError, "--quiet and --verbose are mutually exclusive")
	}
	return cleaned, level, nil
}

// flagVerbose reports whether the subcommand's FlagSet saw --verbose.
func flagVerbose(flags *flag.FlagSet) bool {
	flag := flags.Lookup("verbose")
	if flag == nil {
		return false
	}
	return flag.Value.String() == "true"
}

func parseVerbosityValue(value string, hasValue bool, name string) (bool, error) {
	if !hasValue {
		return true, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, newErrorf(ExitUsageError, "%s expects true or false, got %q", name, value)
	}
	return parsed, nil
}

func findCommandSpec(name string) (commandSpec, bool) {
	for _, spec := range commandSpecs {
		if spec.Name == name {
			return spec, true
		}
	}
	return commandSpec{}, false
}

// verbosityOutput decides where a subcommand's output goes. Quiet buffers both
// streams until the command finishes: success discards them, failure flushes
// them so the reason is still visible. The network resolver writes to stderr
// directly through the writer it is given, so buffering here covers it too.
func verbosityOutput(stdout, stderr io.Writer, level verbosity) (io.Writer, io.Writer, func(error)) {
	if !level.quiet {
		return stdout, stderr, func(error) {}
	}
	var outBuffer, errBuffer bytes.Buffer
	return &outBuffer, &errBuffer, func(err error) {
		if err == nil {
			return
		}
		_, _ = io.Copy(stdout, &outBuffer)
		_, _ = io.Copy(stderr, &errBuffer)
	}
}

// verboseResult writes the one-line verdict that --verbose adds. It names the
// command and whether it succeeded; commands add their own detail to stderr
// while they run. It deliberately never includes an argument, because an
// argument may be an entry.
func verboseResult(stderr io.Writer, command string, err error) {
	if err == nil {
		fmt.Fprintf(stderr, "soroauth: %s: ok\n", command)
		return
	}
	fmt.Fprintf(stderr, "soroauth: %s: exit %d\n", command, ExitCode(err))
}
