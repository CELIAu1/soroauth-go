# RPC fixtures

`rpcflow/rpcfixture` records Stellar RPC JSON-RPC exchanges over HTTP and
replays them through a real `rpcclient.Client`. The goal is to test the RPC flow
against bytes a real RPC returned, while keeping unit tests offline and
deterministic.

## Recording

Wrap the transport of the client used for the recording:

```go
recorder := rpcfixture.NewRecorder(http.DefaultTransport)
client := rpcclient.NewClient(rpcURL, &http.Client{Transport: recorder})
response, err := client.SimulateTransaction(ctx, request)
```

The recorder stores each request's `method` and `params` and the response's raw
`result` or `error`. It does not decode and re-encode the result, so the replay
sees the bytes the RPC sent.

Record against testnet, and record the provenance needed to interpret the
fixture with a separate (unrecorded) client:

```go
version, _ := client.GetVersionInfo(ctx)
network, _ := client.GetNetwork(ctx)
ledger, _ := client.GetLatestLedger(ctx)
fixture, _ := recorder.Fixture(rpcfixture.Metadata{
    RPCVersion:        version.Version,
    ProtocolVersion:   int(version.ProtocolVersion),
    NetworkPassphrase: network.Passphrase,
    LatestLedger:      ledger.Sequence,
    RecordedAt:        time.Now().UTC().Format(time.RFC3339),
})
fixture.WriteFile("rpcflow/rpcfixture/testdata/simulate_record_testnet.json")
```

`Fixture.Validate` refuses a fixture with no RPC version, protocol version,
network passphrase or ledger. A fixture without that metadata cannot be checked
for relevance later, so it is rejected rather than treated as anonymous bytes.

## Scrubbing before commit

A fixture is committed source. Before adding one:

1. Read every `params` value. It is the request your code actually sent.
   Transaction envelopes contain public keys and signatures, not secret seeds,
   but application-level parameters can still carry something sensitive.
2. Remove RPC URLs containing API keys. The fixture format has no URL field for
   this reason; do not add one.
3. Check `git diff` for base64 that decodes to a secret. A Stellar secret seed
   starts with `S` when strkey-encoded; a raw 32-byte seed has no such marker,
   so do not commit a params field you did not produce yourself.
4. Record only the exchanges the test needs. The fixture is evidence, not a
   packet capture.

The committed fixture in this repository is a testnet `simulateTransaction`
record pass. Its metadata records RPC version
`30.0.0-13e53516633c3ce1281c7edbacb607107d3a4e55`, protocol 29 and a testnet
ledger sequence. No secret was used to create it.

## Replaying

```go
fixture, err := rpcfixture.LoadFile("rpcflow/rpcfixture/testdata/simulate_record_testnet.json")
replayer, err := rpcfixture.NewReplayer(fixture)
client := rpcclient.NewClient("https://fixture.invalid", &http.Client{Transport: replayer})
```

The replayer matches on `method` and JSON `params`. A request the fixture does
not describe returns an error naming the method and params; it is never treated
as a cache miss that falls through to the network. Each exchange is consumed
once, so a test that makes an extra call fails instead of silently reusing a
stale response. `Unused` and `Mismatches` report what the replay did not consume
or could not match.

`rpcflow/fixture_test.go` runs the real `rpcflow.SimulateRecord` against the
committed fixture through `rpcclient.NewClient`; it does not use the
hand-written fakes. Those fakes remain for failure injection — a fixture can
record a real RPC error, but it cannot exercise a transport failure on demand.
