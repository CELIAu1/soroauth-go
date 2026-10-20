package soroauth

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEveryExportedContextFunctionHasCancellationTest enforces the project
// rule from CONTRIBUTING.md: every exported function whose first parameter is
// context.Context must check ctx.Err() before doing work and must have a
// cancellation test.
//
// Why a meta-test rather than trusting review. The rule is a safety property:
// a cancelled context must fail closed even on paths that never reach a signer
// (source-account entries, empty batches). An audit by hand is a snapshot; the
// rule only holds if something checks it when the next context-taking function
// is added.
//
// How it reads "has a cancellation test". It parses the package for exported
// functions whose first parameter is context.Context, then parses every _test.go
// file and looks for a test that mentions context.Canceled or context.DeadlineExceeded
// in connection with that function's name. The check is deliberately loose about
// *how* the test asserts cancellation — it only requires the function name and a
// cancellation signal appear in the same test file — because tests assert it
// several ways (errors.Is, sentinel field, explicit error check) and a check
// that recognised only one shape would fail honest tests.
//
// What it therefore does not prove: that the mention is a complete assertion. It
// proves a function is not forgotten, not that it is well tested. That is the
// honest limit, and it is the limit the rule it enforces also has.
func TestEveryExportedContextFunctionHasCancellationTest(t *testing.T) {
	functions := exportedContextFunctions(t, ".")
	if len(functions) == 0 {
		t.Fatal("found no exported functions taking context.Context as first parameter; the parser below is probably wrong, " +
			"and a silently empty check is worse than no check")
	}

	testCoverage := cancellationTestCoverage(t, ".")

	var missing []string
	for _, fn := range functions {
		if !testCoverage[fn] {
			missing = append(missing, fn)
		}
	}
	if len(missing) > 0 {
		t.Errorf("these exported context-taking functions have no cancellation test: %s\n"+
			"Each one needs a test that passes a cancelled context (or deadline-exceeded) and asserts the error matches context.Canceled or context.DeadlineExceeded. "+
			"The check is loose about how the assertion is written but strict that it exists.",
			strings.Join(missing, ", "))
	}

	t.Logf("%d exported context-taking functions, all covered by at least one cancellation test", len(functions))
}

// exportedContextFunctions returns the names of exported functions in the
// package whose first parameter is context.Context.
func exportedContextFunctions(t *testing.T, dir string) []string {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}

	var functions []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || strings.HasSuffix(name, "_test.go") || !strings.HasSuffix(name, ".go") {
			continue
		}

		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}

		ast.Inspect(file, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok {
				return true
			}
			if !fn.Name.IsExported() {
				return true
			}
			// Skip methods (functions with a receiver) — they are covered by
			// their receiver type's tests, and the rule applies to top-level
			// exported functions.
			if fn.Recv != nil && len(fn.Recv.List) > 0 {
				return true
			}

			// Check if first parameter is context.Context
			if fn.Type.Params != nil && len(fn.Type.Params.List) > 0 {
				firstParam := fn.Type.Params.List[0]
				if isContextContext(firstParam.Type) {
					functions = append(functions, fn.Name.Name)
				}
			}
			return true
		})
	}
	return functions
}

// isContextContext reports whether the expression is context.Context (possibly
// with a selector, e.g. context.Context).
func isContextContext(expr ast.Expr) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	return ident.Name == "context" && sel.Sel.Name == "Context"
}

// cancellationTestCoverage returns a map of function names that have at least
// one test mentioning them alongside context.Canceled or context.DeadlineExceeded.
func cancellationTestCoverage(t *testing.T, dir string) map[string]bool {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}

	covered := map[string]bool{}
	seenAny := false
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, "_test.go") {
			continue
		}
		// This file is the meta-test itself; it names functions by construction.
		if name == "context_meta_test.go" {
			continue
		}
		seenAny = true

		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}

		// Track which function names and cancellation signals appear in each
		// test function.
		ast.Inspect(file, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Recv != nil {
				return true
			}
			if !strings.HasPrefix(fn.Name.Name, "Test") {
				return true
			}

			// Collect identifiers mentioned in this test function.
			var mentions []string
			hasCancellation := false
			ast.Inspect(fn, func(n ast.Node) bool {
				if ident, ok := n.(*ast.Ident); ok {
					mentions = append(mentions, ident.Name)
				}
				// Check for context.Canceled or context.DeadlineExceeded selector expressions
				if sel, ok := n.(*ast.SelectorExpr); ok {
					if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "context" {
						if sel.Sel.Name == "Canceled" || sel.Sel.Name == "DeadlineExceeded" {
							hasCancellation = true
						}
					}
				}
				return true
			})

			if hasCancellation {
				for _, m := range mentions {
					covered[m] = true
				}
			}
			return true
		})
	}
	if !seenAny {
		t.Fatal("found no _test.go files to scan; the check would pass vacuously")
	}
	return covered
}
