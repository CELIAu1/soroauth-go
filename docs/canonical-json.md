# Canonical JSON

`MarshalCanonicalJSON` renders a `SorobanAuthorizationEntry` as JSON, and
`UnmarshalCanonicalJSON` parses it back. The encoding is lossless: an entry that
is encoded and decoded again has byte-identical XDR. It is meant for review,
diffing, storage and templating, not as a replacement for XDR.

The format is versioned. Every document carries `schema_version`, currently `1`.
A reader refuses a version it does not implement rather than guessing at the
field meanings.

## Document shape

```json
{
  "schema_version": 1,
  "credentials": {
    "type": "address_v2",
    "address": { "type": "account", "account": "G..." },
    "nonce": "1234567890123456789",
    "signature_expiration_ledger": 1234567,
    "signature": { "type": "void" }
  },
  "root_invocation": {
    "function": {
      "type": "contract_fn",
      "contract_address": { "type": "contract", "contract": "C..." },
      "function_name": { "utf8": "transfer" },
      "args": [{ "type": "u32", "u32": 7 }]
    },
    "sub_invocations": []
  }
}
```

Field order is fixed by the Go structs and is part of the canonical output. A
consumer may compare two documents byte for byte.

## Credentials

`credentials.type` is one of:

| Type                     | Fields                                                                      |
| ------------------------ | --------------------------------------------------------------------------- |
| `source_account`         | none                                                                        |
| `address`                | `address`, `nonce`, `signature_expiration_ledger`, `signature`              |
| `address_v2`             | same as `address`                                                           |
| `address_with_delegates` | `address`, `nonce`, `signature_expiration_ledger`, `signature`, `delegates` |

A delegate is `{ "address": ..., "signature": ..., "nested": [...] }`. The
delegates are encoded in the order they appear in the XDR; this API does not
reorder them. Use `WithDelegates` and `ValidateDelegateOrder` for the protocol's
ordering rules.

`nonce` is a decimal string so an `int64` outside JavaScript's safe integer
range, including a negative nonce, is preserved exactly. The expiration is a
JSON number because the wire value is an unsigned 32-bit integer.

## Addresses and text

An `ScAddress` is one of:

- `{ "type": "account", "account": "G..." }`
- `{ "type": "contract", "contract": "C..." }`
- `{ "type": "xdr", "xdr": "<base64>" }` for an arm with no stable strkey form,
  such as a muxed address.

Text that is valid UTF-8 is `{ "utf8": "..." }`. A string or symbol that is not
valid UTF-8 is `{ "base64": "..." }`; base64 is also accepted on input, and must
be canonical. This keeps invalid UTF-8 byte sequences reproducible instead of
replacing them.

## ScVal

Every `ScVal` arm has a `type` and exactly one value field (except `void` and
`ledger_key_contract_instance`, which carry none):

| Type                                  | Value                                                                |
| ------------------------------------- | -------------------------------------------------------------------- |
| `bool`                                | `bool`                                                               |
| `void`                                | none                                                                 |
| `u32`, `i32`                          | JSON number                                                          |
| `u64`, `i64`, `timepoint`, `duration` | decimal string                                                       |
| `u128`, `i128`                        | `{ "hi": "...", "lo": "..." }`                                       |
| `u256`, `i256`                        | `{ "hi_hi": "...", "hi_lo": "...", "lo_hi": "...", "lo_lo": "..." }` |
| `bytes`                               | canonical base64                                                     |
| `string`, `symbol`, `executable_tag`  | text object                                                          |
| `vec`                                 | array, or `"nil": true` when the XDR optional vector is absent       |
| `map`                                 | array of `{ "key": ..., "val": ... }`, or `"nil": true`              |
| `address`                             | address object                                                       |
| `contract_instance`                   | `{ "executable": ..., "storage": ... }`                              |
| `ledger_key_contract_instance`        | none                                                                 |
| `error`                               | `xdr` object field, canonical base64 of the whole `ScVal`            |
| `ledger_key_nonce`                    | `xdr` object field, canonical base64 of the whole `ScVal`            |

Empty and absent vectors/maps are distinct on the wire, so they are distinct
here: `{ "type": "vec", "vec": [] }` versus `{ "type": "vec", "nil": true }`.

The `error` and `ledger_key_nonce` arms use a base64 XDR fallback because their
nested types have no stable, reviewable JSON spelling in this schema. The
fallback is exact: the decoder re-encodes the value and requires the same bytes,
so a base64 string naming a different encoding of the same Go value is refused.

## Invocations

`root_invocation.function.type` is one of:

- `contract_fn`: `contract_address`, `function_name`, `args`
- `create_contract_host_fn`: `contract_id_preimage`, `executable`
- `create_contract_v2_host_fn`: `contract_id_preimage`, `executable`,
  `constructor_args`

A contract ID preimage is
`{ "type": "from_address", "address": ..., "salt": "<hex>" }` or
`{ "type": "from_asset", "xdr": "<base64>" }`. An executable is
`{ "type": "wasm", "wasm_hash": "<hex>" }`, `{ "type": "stellar_asset" }`, or
`{ "type": "external_ref", "owner": ..., "tag": ... }`.

`sub_invocations` is always present and preserves order and depth.

## Refusal rules

`UnmarshalCanonicalJSON` refuses, rather than repairing:

- unknown fields, duplicate object keys, and trailing data;
- a schema version other than `1`;
- an unknown credential, function, address, preimage, executable or `ScVal`
  type;
- a value field that is missing, duplicated across arms, or present on the wrong
  arm;
- a non-canonical decimal, hex, base64 or strkey value;
- an XDR fallback that does not re-encode byte-identically;
- documents over `MaxCanonicalJSONBytes`, and trees deeper than
  `MaxDecodeDepth`.

It also re-encodes the finished entry to XDR before returning it, so a document
that parses but cannot be represented on the wire is never returned.

## Limits

`MaxCanonicalJSONBytes` is 8 MiB. `MaxDecodeDepth` (64) bounds the recursive
invocation, delegate, `ScVal`, and JSON scan depth. A refusal for either bound
matches `ErrDecodeLimit` with `errors.Is`.
