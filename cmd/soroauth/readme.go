package main

import (
	"fmt"
	"os"
	"strings"
	"unicode/utf8"
)

const (
	readmeFlagsStart = "<!-- BEGIN GENERATED CLI FLAGS -->"
	readmeFlagsEnd   = "<!-- END GENERATED CLI FLAGS -->"
	readmePath       = "../../README.md"
)

func renderREADMEFlagReference(specs []commandSpec) string {
	rows := [][]string{{"Command", "Flag", "Value", "Description"}}
	for _, spec := range specs {
		for _, flag := range spec.Flags {
			value := "—"
			if flag.TakesValue {
				value = "<value>"
			}
			rows = append(rows, []string{spec.Name, "--" + flag.Name, value, flag.Description})
		}
	}
	rows = append(rows,
		[]string{"soroauth", "--help", "—", "Print this help"},
		[]string{"soroauth", "--version", "—", "Print the build version, commit and Go version"},
	)

	widths := make([]int, len(rows[0]))
	for _, row := range rows {
		for i, cell := range row {
			if width := utf8.RuneCountInString(cell); width > widths[i] {
				widths[i] = width
			}
		}
	}

	var out strings.Builder
	for i, row := range rows {
		if i == 1 {
			out.WriteByte('|')
			for _, width := range widths {
				out.WriteString(" ")
				out.WriteString(strings.Repeat("-", width))
				out.WriteString(" |")
			}
			out.WriteByte('\n')
		}
		out.WriteByte('|')
		for j, cell := range row {
			out.WriteByte(' ')
			out.WriteString(cell)
			out.WriteString(strings.Repeat(" ", widths[j]-utf8.RuneCountInString(cell)))
			out.WriteString(" |")
		}
		out.WriteByte('\n')
	}
	return out.String()
}

func replaceREADMEFlagReference(readme string, specs []commandSpec) (string, error) {
	start := strings.Index(readme, readmeFlagsStart)
	end := strings.Index(readme, readmeFlagsEnd)
	if start < 0 || end < 0 || end <= start {
		return "", fmt.Errorf("README is missing the generated CLI flag markers")
	}
	start += len(readmeFlagsStart)
	return readme[:start] + "\n\n" + renderREADMEFlagReference(specs) + "\n" +
		readme[end:], nil
}

func checkREADMEFlagReference() error {
	readme, err := os.ReadFile(readmePath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", readmePath, err)
	}
	updated, err := replaceREADMEFlagReference(string(readme), commandSpecs)
	if err != nil {
		return err
	}
	if updated == string(readme) {
		return nil
	}
	if os.Getenv("UPDATE_CLI_REFERENCE") == "1" {
		if err := os.WriteFile(readmePath, []byte(updated), 0o644); err != nil {
			return fmt.Errorf("writing %s: %w", readmePath, err)
		}
		return nil
	}
	return fmt.Errorf("README CLI flag table differs from commandSpecs; regenerate with UPDATE_CLI_REFERENCE=1 go test ./cmd/soroauth -run '^TestREADMEFlagReference$' -count=1")
}
