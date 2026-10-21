package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// maxBatchLine is the longest line a batch file may carry. It sits a little
// above the base64 form of the library's 1 MiB decoded-input limit
// (DecodeAuthorizationEntry refuses a larger blob before decoding it), so the
// batch boundary is never the thing that rejects an entry the decoder would
// have accepted.
const maxBatchLine = 2 << 20

// Batch mode
//
// inspect, verify, sign and diff can read many entries in one run instead of
// one entry per process. The input is a file named by --entries
// (--before-entries and --after-entries for diff), read from stdin when the
// value is "-":
//
//   - one base64 XDR authorization entry per line;
//   - blank lines skipped, surrounding whitespace trimmed (base64 XDR never
//     contains whitespace, and every subcommand prints a trailing newline);
//   - a line is never a transaction envelope: an envelope expands to several
//     entries, and batch mode promises exactly one result per line, so a
//     caller who has an envelope selects the entries first;
//   - a line longer than maxBatchLine is refused.
//
// Inputs are numbered from 1 in file order, blank lines excluded, and that
// index labels every result and every error. One failing input never ends the
// run: every input is attempted, every outcome is reported, and the process
// exits non-zero with the exit code of the FIRST failure, so the code
// classifies the input a caller looks at first.
//
// sign is the one exception to one-result-per-input: a batch that cannot be
// fully signed writes no signed output at all (the library's all-or-nothing
// rule for signing), only the failures, because a half-signed batch must never
// look like a complete one to whatever consumes the output.
//
// The output is one result per input:
//
//   - without --json, each result is preceded by an "entry N:" header and a
//     failed input is reported on stderr with the same header;
//   - with --json, stdout carries one array with one object per input:
//     {"entry": N, "result": ...} for a result — result is exactly what the
//     subcommand prints for a single entry — or {"entry": N, "error": "..."}
//     for a failure. In JSON mode nothing is written to stderr.
//
// No message ever quotes an input's bytes: an entry may be signed, and a
// terminal, a CI log or a shell transcript is the wrong place for it. The
// index, the flag and the failure are enough to find the line.

// batchInput is one non-blank line of a batch file: the entry it decoded to,
// or the error reading or decoding it produced, with its 1-based position
// among the non-blank lines.
type batchInput struct {
	Index int
	Entry xdr.SorobanAuthorizationEntry
	Err   error
}

// batchResult is one element of a batch JSON report: the input's index and
// exactly one of its result or its error.
type batchResult struct {
	Entry         int    `json:"entry"`
	Result        any    `json:"result,omitempty"`
	Error         string `json:"error,omitempty"`
	SchemaVersion int    `json:"schema_version,omitempty"`
	Code          string `json:"code,omitempty"`
	Message       string `json:"message,omitempty"`
	Field         string `json:"field,omitempty"`
	ExitCode      int    `json:"exit_code,omitempty"`
}

// batchRun accumulates the per-input outcomes of one batch subcommand and
// renders them in the shared report format.
type batchRun struct {
	total   int
	results []batchResult
	failed  int
	first   error
}

func newBatchRun(total int) *batchRun {
	return &batchRun{total: total, results: make([]batchResult, 0, total)}
}

// result records an input that produced a result.
func (b *batchRun) result(index int, result any) {
	b.results = append(b.results, batchResult{Entry: index, Result: result})
}

// fail records an input that produced no result, carrying its error into the
// report. The first failure also decides the run's exit code.
func (b *batchRun) fail(index int, err error) {
	fields := machineError(err)
	b.results = append(b.results, batchResult{
		Entry:         index,
		Error:         fields.Message,
		SchemaVersion: fields.SchemaVersion,
		Code:          fields.Code,
		Message:       fields.Message,
		Field:         fields.Field,
		ExitCode:      fields.ExitCode,
	})
	b.recordFailure(err)
}

// recordFailure marks a failure that still has a result (a verification
// verdict that is not a pass, a diff whose payload moved under a signature).
// It counts towards the exit code without adding an error object to the JSON
// report, because the result carries the reason.
func (b *batchRun) recordFailure(err error) {
	if b.failed == 0 {
		b.first = err
	}
	b.failed++
}

// finish writes the JSON report when jsonMode is set and returns the error the
// run should surface: nil on complete success, otherwise a summary carrying
// the first failure's exit code.
func (b *batchRun) finish(stdout io.Writer, jsonMode bool) error {
	if jsonMode {
		enc := json.NewEncoder(stdout)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(b.results); err != nil {
			return newErrorf(ExitGeneralError, "encoding the batch report: %w", err)
		}
		if b.failed == 0 {
			return nil
		}
		// The array on stdout already carries every error; the summary is
		// returned for its exit code, and main must not print it as well.
		return &jsonErrorHandled{b.summary()}
	}
	return b.summary()
}

// summary is the error a batch with failures returns: a count, plus the exit
// code of the first failure.
func (b *batchRun) summary() error {
	if b.failed == 0 {
		return nil
	}
	code := ExitGeneralError
	if b.first != nil {
		code = ExitCode(b.first)
	}
	return newErrorf(code, "%d of %d entries failed", b.failed, b.total)
}

// signSummary is the error a failed sign batch returns. Sign is
// all-or-nothing, so a caller gets no results at all when anything failed;
// the message is therefore the whole report and carries every failing input
// with its position, on stderr in text mode and in the "error" field under
// --json. Only the failures are in the report — in this path the batchRun
// holds nothing else, because encoded results are withheld until the whole
// batch succeeds.
func (b *batchRun) signSummary() error {
	parts := make([]string, 0, b.failed)
	for _, r := range b.results {
		if r.Error != "" {
			parts = append(parts, fmt.Sprintf("entry %d: %s", r.Entry, r.Error))
		}
	}
	code := ExitGeneralError
	if b.first != nil {
		code = ExitCode(b.first)
	}
	return withField("--entries", newErrorf(code,
		"no signed output was written: %d of %d entries could not be signed: %s",
		b.failed, b.total, strings.Join(parts, "; ")))
}

// labelBatchError prefixes a per-input error with the flag that read it. It is
// for the one subcommand with two batch files, diff, where "entry 3: ..."
// alone would not say which side is wrong.
func labelBatchError(flagName string, err error) error {
	return newErrorf(ExitCode(err), "%s: %w", flagName, err)
}

// reportBatchFailure writes the text-mode line for a failed input. In JSON
// mode the error is already in the array, so nothing is written.
func reportBatchFailure(stderr io.Writer, jsonMode bool, index int, err error) {
	if jsonMode {
		return
	}
	fmt.Fprintf(stderr, "entry %d: %v\n", index, err)
}

// readBatchEntries reads a batch file named name ("-" for stdin): one base64
// authorization entry per non-blank line. flagName is the flag being read, for
// run-level messages only.
//
// A file that cannot be opened is a run-level usage error, because no input
// could be processed. Once scanning has begun, a read failure is reported as
// the next input's error instead: entries already read are still reported, and
// the failure is not silent.
func readBatchEntries(flagName, name string, stdin io.Reader) ([]batchInput, error) {
	var r io.Reader
	if name == "-" {
		r = stdin
	} else {
		f, err := os.Open(name)
		if err != nil {
			return nil, newErrorf(ExitUsageError, "opening %s file: %w", flagName, err)
		}
		defer f.Close()
		r = f
	}

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), maxBatchLine)

	var inputs []batchInput
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		inputs = append(inputs, decodeBatchLine(len(inputs)+1, line))
	}
	if err := scanner.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			err = fmt.Errorf("a line is longer than the %d MiB line limit", maxBatchLine>>20)
		}
		inputs = append(inputs, batchInput{
			Index: len(inputs) + 1,
			Err: newErrorf(ExitGeneralError,
				"reading %s: %v; the rest of the input was not read", batchSourceName(name), err),
		})
	}
	return inputs, nil
}

// decodeBatchLine decodes one batch line as a single authorization entry.
//
// A line that decodes as a transaction envelope carrying entries gets its own
// refusal rather than the generic wrong-type message: batch mode promises one
// result per line, and the fix is to select the entries out of the envelope,
// which the generic message would not say. The envelope test is the same one
// decodeEntryOrEnvelope uses — an envelope only wins when it decodes AND
// carries an invokeHostFunction operation — so a single entry whose bytes
// happen to decode as an envelope shape is not misreported.
func decodeBatchLine(index int, line string) batchInput {
	in := batchInput{Index: index}

	entry, err := soroauth.DecodeAuthorizationEntry(line)
	if err == nil {
		in.Entry = entry
		return in
	}

	var envelope xdr.TransactionEnvelope
	if envelopeErr := xdr.SafeUnmarshalBase64(line, &envelope); envelopeErr == nil {
		if entries, entriesErr := soroauth.EnvelopeEntries(envelope); entriesErr == nil {
			in.Err = newErrorf(ExitUsageError,
				"input is a transaction envelope carrying %d authorization entries; batch mode takes one entry per line",
				len(entries))
			return in
		}
	}

	in.Err = newErrorf(ExitUsageError, "%w",
		classifyInput(line, "a Soroban authorization entry", err))
	return in
}

// batchSourceName is how a batch source is named in messages: stdin for "-",
// the file name otherwise.
func batchSourceName(name string) string {
	if name == "-" {
		return "stdin"
	}
	return name
}

// emptyBatchError is the run-level error for a batch file with nothing in it.
// An empty batch is refused rather than reported as an empty success, because
// it is almost always a mistake (the wrong file, a pipeline that produced
// nothing) and succeeding would hide it.
func emptyBatchError(flagName, name string) error {
	return newErrorf(ExitUsageError, "%s (%s) contains no entries",
		flagName, batchSourceName(name))
}
