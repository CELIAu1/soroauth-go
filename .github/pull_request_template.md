## What this changes

<!-- One or two sentences. If it fixes an issue, link it. -->

## Why

<!-- What was wrong, or what could not be done before. -->

## Evidence

<!--
Commands you ran and their real output, or the file and line you read. Claims
about host or protocol behaviour need a source — the CAP, the rs-soroban-env
file and function, or the SDK file and line. Not memory.
-->

## Checklist

- [ ] `gofmt -l .` prints nothing, `go vet ./...` and `go test -race ./...` pass
- [ ] New behaviour has tests, and failure cases assert *which* failure, not just that something failed
- [ ] If this adds a guard, I broke it deliberately, confirmed the test failed, and said so above — and did not commit the break
- [ ] Any function returning a modified entry deep-copies first and has a test proving the caller's input is byte-identical afterwards
- [ ] Errors wrap a sentinel where one applies, so `errors.Is` works
- [ ] No golden vector was edited by hand; if vectors changed, the generator changed and they were regenerated
- [ ] No secret is accepted as a flag value, printed, logged, or written to disk
- [ ] Ambiguity was resolved by failing closed, and the commit message says which reading I chose

## Wire format

- [ ] This does not change the bytes soroauth emits.
- [ ] It does, and here is the CAP that requires it: <!-- CAP number and section -->
