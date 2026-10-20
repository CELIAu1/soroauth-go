// Golden-vector generator for soroauth-go.
//
// @stellar/stellar-sdk is the reference implementation this library is proven
// against. Every vector written here is produced by the JS SDK, and
// golden_test.go asserts that the Go code reproduces the preimage, the payload
// hash and the final signed entry byte for byte. If the two ever disagree, the
// Go side is wrong until proven otherwise.
//
// Never edit a file in testdata/vectors by hand. Regenerate with:
//
//     cd testdata/gen && npm ci && node gen.mjs
//
// CI runs exactly that and then `git diff --exit-code testdata/vectors`, so a
// hand-edited or stale vector fails the build.
//
// Every input is fixed so the output is reproducible: ed25519 signatures are
// deterministic (RFC 8032), so identical inputs give identical signature bytes
// in any correct implementation.
//
// TEST KEYS. Every key below is derived from a label committed here in plain
// text, so they are PUBLIC: anyone can derive them and spend from them. Never
// fund them on mainnet. The derivation and the rules for adding keys are in
// "Deterministic test keys" in CONTRIBUTING.md (CONTRIBUTING.md#deterministic-test-keys).

import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  Address,
  Keypair,
  Networks,
  StrKey,
  authorizeEntry,
  buildAuthorizationEntryPreimage,
  buildWithDelegatesEntry,
  hash,
  xdr,
} from "@stellar/stellar-sdk";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT_DIR = join(HERE, "..", "vectors");

// The exact version this generator is pinned to. Vectors are only meaningful
// if they came from a known reference build.
const REQUIRED_SDK_VERSION = "17.1.0";

// Read the version from the package that was actually loaded, rather than
// trusting a hand-typed constant.
const loadedVersion = JSON.parse(
  readFileSync(
    join(HERE, "node_modules", "@stellar", "stellar-sdk", "package.json"),
    "utf8",
  ),
).version;

if (loadedVersion !== REQUIRED_SDK_VERSION) {
  console.error(
    `refusing to generate vectors: @stellar/stellar-sdk is ${loadedVersion}, ` +
      `this generator is pinned to ${REQUIRED_SDK_VERSION}. ` +
      `Run \`npm ci\` in testdata/gen.`,
  );
  process.exit(1);
}

const SDK = `@stellar/stellar-sdk@${loadedVersion}`;

// SCHEMA_VERSION is the version stamped into every vector. golden_test.go
// asserts it, so the two move together or the drift check fails.
const SCHEMA_VERSION = 1;

// ---------------------------------------------------------------------------
// Fixed inputs
// ---------------------------------------------------------------------------

const sha256 = (label) => createHash("sha256").update(label).digest();

const keypairFor = (label) => Keypair.fromRawEd25519Seed(sha256(label));

const SIGNER_1 = "soroauth-vector-signer-1";
const SIGNER_2 = "soroauth-vector-signer-2";

// One fixed expiration ledger for every vector, so a payload that differs
// differs for a reason the vector names.
const VALID_UNTIL_LEDGER = 1234567;

// Per-case override for validUntilLedger. Used for expiration boundary
// vectors (#116).
const caseValidUntilLedger = (name) => {
  if (name === "v2_expiration_boundary_1") return 1;
  if (name === "v2_expiration_boundary_max") return 4294967295;
  return VALID_UNTIL_LEDGER;
};

// Fixed nonces, chosen to cover the interesting int64 values: an ordinary
// positive one, the maximum, and the minimum (negative). A nonce is a signed
// int64 on the wire, so sign handling is part of what these vectors prove.
const NONCE_ORDINARY = 1234567890123456789n;
const NONCE_MAX = 9223372036854775807n; // 2^63 - 1
const NONCE_MIN = -9223372036854775808n; // -2^63

const scAddress = (label) => new Address(keypairFor(label).publicKey()).toScAddress();

const contractAddress = (label) =>
  new Address(Address.contract(sha256(label)).toString()).toScAddress();

// A muxed (M…) address as an ScVal, for testing that invocation arguments
// can carry muxed addresses even though ParseAddress rejects them for credentials.
const muxedAddressScVal = () => {
  const kp = keypairFor("soroauth-vector-muxed-arg");
  const raw = Buffer.from(StrKey.decodeEd25519PublicKey(kp.publicKey()));
  const muxedEd25519 = new xdr.MuxedEd25519Account({
    id: xdr.Uint64(1234n),
    ed25519: raw,
  });
  const scAddress = xdr.ScAddress.scAddressTypeMuxedAccount(muxedEd25519);
  return xdr.ScVal.scvAddress(scAddress);
};

// An invocation carrying a deliberately wide spread of ScVal types, so the
// vectors exercise the encoder rather than just the common i128 transfer.
const invocationWithManyArgTypes = () =>
  new xdr.SorobanAuthorizedInvocation({
    function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
      new xdr.InvokeContractArgs({
        contractAddress: contractAddress("soroauth-vector-contract-1"),
        functionName: "transfer",
        args: [
          xdr.ScVal.scvVoid(),
          xdr.ScVal.scvBool(true),
          xdr.ScVal.scvU32(7),
          xdr.ScVal.scvI32(-7),
          xdr.ScVal.scvU64(xdr.Uint64(18446744073709551615n)),
          xdr.ScVal.scvI64(xdr.Int64(-9007199254740993n)),
          xdr.ScVal.scvSymbol("transfer"),
          xdr.ScVal.scvString("a string argument"),
          xdr.ScVal.scvBytes(Buffer.from("soroauth", "utf8")),
          xdr.ScVal.scvAddress(scAddress(SIGNER_2)),
          xdr.ScVal.scvAddress(contractAddress("soroauth-vector-contract-2")),
          xdr.ScVal.scvVec([xdr.ScVal.scvU32(1), xdr.ScVal.scvU32(2)]),
          xdr.ScVal.scvMap([
            new xdr.ScMapEntry({
              key: xdr.ScVal.scvSymbol("amount"),
              val: xdr.ScVal.scvI128(
                new xdr.Int128Parts({ hi: xdr.Int64(-1n), lo: xdr.Uint64(42n) }),
              ),
            }),
          ]),
        ],
      }),
    ),
    subInvocations: [],
  });

// A call tree two levels deep, so the recursive part of the encoding is covered.
const invocationWithSubInvocations = () => {
  const leaf = (name, contractLabel) =>
    new xdr.SorobanAuthorizedInvocation({
      function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
        new xdr.InvokeContractArgs({
          contractAddress: contractAddress(contractLabel),
          functionName: name,
          args: [xdr.ScVal.scvU32(1)],
        }),
      ),
      subInvocations: [],
    });

  const middle = new xdr.SorobanAuthorizedInvocation({
    function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
      new xdr.InvokeContractArgs({
        contractAddress: contractAddress("soroauth-vector-contract-2"),
        functionName: "approve",
        args: [xdr.ScVal.scvSymbol("inner")],
      }),
    ),
    subInvocations: [
      leaf("deep_one", "soroauth-vector-contract-3"),
      leaf("deep_two", "soroauth-vector-contract-4"),
    ],
  });

  return new xdr.SorobanAuthorizedInvocation({
    function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
      new xdr.InvokeContractArgs({
        contractAddress: contractAddress("soroauth-vector-contract-1"),
        functionName: "swap",
        args: [xdr.ScVal.scvAddress(scAddress(SIGNER_1))],
      }),
    ),
    subInvocations: [middle],
  });
};

// A create-contract invocation, which uses a different authorized-function arm
// entirely.
const invocationCreateContract = () =>
  new xdr.SorobanAuthorizedInvocation({
    function:
      xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeCreateContractHostFn(
        new xdr.CreateContractArgs({
          contractIdPreimage: xdr.ContractIdPreimage.contractIdPreimageFromAddress(
            new xdr.ContractIdPreimageFromAddress({
              address: scAddress(SIGNER_1),
              salt: sha256("soroauth-vector-salt"),
            }),
          ),
          executable: xdr.ContractExecutable.contractExecutableWasm(
            sha256("soroauth-vector-wasm-hash"),
          ),
        }),
      ),
    subInvocations: [],
  });

// A contract call with no arguments at all, the empty-list boundary the
// encoder has to special-case.
const invocationWithEmptyArgs = () =>
  new xdr.SorobanAuthorizedInvocation({
    function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
      new xdr.InvokeContractArgs({
        contractAddress: contractAddress("soroauth-vector-contract-empty-args"),
        functionName: "noop",
        args: [],
      }),
    ),
    subInvocations: [],
  });

// An invocation with a muxed (M…) address as one of its arguments.
// This tests that muxed addresses are legal in arguments even though
// ParseAddress rejects them for credentials.
const invocationWithMuxedAddressArg = () =>
  new xdr.SorobanAuthorizedInvocation({
    function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
      new xdr.InvokeContractArgs({
        contractAddress: contractAddress("soroauth-vector-contract-muxed-arg"),
        functionName: "transfer_with_muxed",
        args: [
          xdr.ScVal.scvU32(1),
          muxedAddressScVal(),
          xdr.ScVal.scvSymbol("memo"),
        ],
      }),
    ),
    subInvocations: [],
  });

const DELEGATE_1 = "soroauth-vector-delegate-1";
const DELEGATE_2 = "soroauth-vector-delegate-2";
const DELEGATE_3 = "soroauth-vector-delegate-3";
const DELEGATE_NESTED = "soroauth-vector-delegate-nested-1";

// A delegate descriptor, recorded in the vector exactly as written here — in
// input order, before any sorting. The Go side passes the same unsorted tree to
// WithDelegates, so the recorded unsigned entry proves both implementations
// sort and nest identically, rather than Go merely re-reading JS's output.
const delegate = (label, nested = []) => ({
  label,
  address: keypairFor(label).publicKey(),
  nested,
});

// The deepest delegate nesting all three layers agree on, and the depth the
// vector's name records.
//
// This is a measured disagreement, not a free choice. The pinned JS SDK imposes
// no policy cap at all — its only bound is the XDR codec's 1500-frame recursion
// guard, and it happily builds chains of a thousand delegates. The Go library
// refuses them in two places, and the tighter one wins:
//
//   - DecodeAuthorizationEntry applies a 64-frame XDR bound, and each delegate
//     costs roughly two frames, so a chain of 58 is the first it refuses; 57 is
//     the deepest it decodes.
//   - WithDelegates applies the MaxDecodeDepth = 64 traversal bound, allowing a
//     chain of 63 before its own guard bites on the empty level below the leaf.
//
// So the deepest nesting the pipeline accepts end to end is 57. That the JS SDK
// will produce trees the library refuses is the finding this vector records;
// see docs/parity.md.
const MAX_VECTOR_DELEGATE_DEPTH = 57;

const delegateChainLabel = (level) => `soroauth-vector-delegate-chain-${level}`;

// delegateChain builds a single chain of `depth` nested delegates: level 1
// delegates to level 2, which delegates to level 3, and so on to the leaf.
const delegateChain = (depth) => {
  let node = delegate(delegateChainLabel(depth));
  for (let level = depth - 1; level >= 1; level--) {
    node = delegate(delegateChainLabel(level), [node]);
  }
  return node;
};

// ---------------------------------------------------------------------------
// Classic-account multisig signatures
// ---------------------------------------------------------------------------
//
// The host decodes a classic account's signature as a vector of
// {public_key, signature} maps, sorted strictly ascending by raw public key,
// and refuses more than MAX_ACCOUNT_SIGNATURES = 20 of them
// (rs-soroban-env soroban-env-host/src/builtin_contracts/account_contract.rs).
// The pinned JS SDK's authorizeEntry signs with a single Keypair, so a
// multisig vector is assembled here from the SDK's own signing primitive; the
// Go side reproduces it with NewAccountMultiSigner, which sorts the same way.

const MULTISIG_ACCOUNT = "soroauth-vector-multisig-account";

const MULTISIG_KEY_COUNT = 20;

const MULTISIG_KEYS = Array.from(
  { length: MULTISIG_KEY_COUNT },
  (_, i) => `soroauth-vector-multisig-key-${String(i).padStart(2, "0")}`,
);

// accountSignatureScVal builds the single {public_key, signature} map the host
// decodes as one AccountEd25519Signature. Keys are symbols written in key
// order — "public_key" before "signature" — because an ScMap must be sorted.
const accountSignatureScVal = (rawPublicKey, signature) =>
  xdr.ScVal.scvMap([
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol("public_key"),
      val: xdr.ScVal.scvBytes(rawPublicKey),
    }),
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol("signature"),
      val: xdr.ScVal.scvBytes(signature),
    }),
  ]);

// multisigSignatures signs payload with every label and returns the signature
// vector, ordered by raw public key exactly as the Go library orders it.
const multisigSignatures = (payload, labels) => {
  const keys = labels
    .map((label) => {
      const kp = keypairFor(label);
      return { raw: kp.rawPublicKey(), kp };
    })
    .sort((a, b) => Buffer.compare(a.raw, b.raw));
  return xdr.ScVal.scvVec(
    keys.map(({ raw, kp }) => accountSignatureScVal(raw, kp.sign(payload))),
  );
};

// withMultisigSignature writes a multisig signature vector onto a V2 entry,
// with the stored expiration the Go side also stores, so the recorded signed
// entry is what Go's AuthorizeEntry produces.
const withMultisigSignature = (entry, payload, validUntil, labels) => {
  const signed = xdr.SorobanAuthorizationEntry.fromXDR(entry.toXDR());
  signed.credentials.addressV2.signature = multisigSignatures(payload, labels);
  signed.credentials.addressV2.signatureExpirationLedger = validUntil;
  return signed;
};

// Converts a recorded descriptor tree into the shape buildWithDelegatesEntry
// expects. Signatures are left out, so each node starts as an scvVoid
// placeholder to be filled by authorizeEntry.
const toSdkDelegates = (delegates) =>
  delegates.map((d) => ({
    address: d.address,
    nestedDelegates: toSdkDelegates(d.nested ?? []),
  }));

// ---------------------------------------------------------------------------
// Entry construction
// ---------------------------------------------------------------------------

const addressCredentials = (label, nonce) =>
  new xdr.SorobanAddressCredentials({
    address: scAddress(label),
    nonce: xdr.Int64(nonce),
    // Both are placeholders that authorizeEntry replaces; they match what
    // simulation hands back.
    signatureExpirationLedger: 0,
    signature: xdr.ScVal.scvVec([]),
  });

// A source-account entry passes through unchanged.
const sourceAccountEntry = (signerLabel) =>
  new xdr.SorobanAuthorizationEntry({
    rootInvocation: invocationWithManyArgTypes(),
    credentials: xdr.SorobanCredentials.sorobanCredentialsSourceAccount(),
  });

// authV2 is always passed explicitly, never left to the default, so a change
// to that default in a future SDK cannot silently change these vectors.
const unsignedEntry = ({ signerLabel, nonce, invocation, authV2 }) => {
  const credentials = addressCredentials(signerLabel, nonce);
  return new xdr.SorobanAuthorizationEntry({
    rootInvocation: invocation,
    credentials: authV2
      ? xdr.SorobanCredentials.sorobanCredentialsAddressV2(credentials)
      : xdr.SorobanCredentials.sorobanCredentialsAddress(credentials),
  });
};

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

const CASES = [
  // §5.9 case 1: legacy arm, single G signer, testnet.
  {
    name: "legacy_single_testnet",
    networkPassphrase: Networks.TESTNET,
    entry: () =>
      unsignedEntry({
        signerLabel: SIGNER_1,
        nonce: NONCE_ORDINARY,
        invocation: invocationWithManyArgTypes(),
        authV2: false,
      }),
    steps: [{ signerLabel: SIGNER_1, forAddress: null }],
  },
  // §5.9 case 2: legacy arm, public passphrase.
  {
    name: "legacy_single_public",
    networkPassphrase: Networks.PUBLIC,
    entry: () =>
      unsignedEntry({
        signerLabel: SIGNER_1,
        nonce: NONCE_ORDINARY,
        invocation: invocationWithManyArgTypes(),
        authV2: false,
      }),
    steps: [{ signerLabel: SIGNER_1, forAddress: null }],
  },
  // §5.9 case 3: V2 arm, single G signer, testnet.
  {
    name: "v2_single_testnet",
    networkPassphrase: Networks.TESTNET,
    entry: () =>
      unsignedEntry({
        signerLabel: SIGNER_1,
        nonce: NONCE_ORDINARY,
        invocation: invocationWithManyArgTypes(),
        authV2: true,
      }),
    steps: [{ signerLabel: SIGNER_1, forAddress: null }],
  },
  // §5.9 case 4: V2 arm, sub-invocation tree.
  {
    name: "v2_sub_invocations",
    networkPassphrase: Networks.TESTNET,
    entry: () =>
      unsignedEntry({
        signerLabel: SIGNER_1,
        nonce: 42n,
        invocation: invocationWithSubInvocations(),
        authV2: true,
      }),
    steps: [{ signerLabel: SIGNER_1, forAddress: null }],
  },
  // §5.9 case 5: V2 arm, create-contract invocation.
  {
    name: "v2_create_contract",
    networkPassphrase: Networks.TESTNET,
    entry: () =>
      unsignedEntry({
        signerLabel: SIGNER_1,
        nonce: NONCE_MAX,
        invocation: invocationCreateContract(),
        authV2: true,
      }),
    steps: [{ signerLabel: SIGNER_1, forAddress: null }],
  },
  // §5.9 case 9: legacy arm, negative nonce.
  {
    name: "legacy_negative_nonce",
    networkPassphrase: Networks.TESTNET,
    entry: () =>
      unsignedEntry({
        signerLabel: SIGNER_1,
        nonce: NONCE_MIN,
        invocation: invocationWithManyArgTypes(),
        authV2: false,
      }),
    steps: [{ signerLabel: SIGNER_1, forAddress: null }],
  },
  // §5.9 case 6: delegates arm, three unsorted delegates with one nested.
  {
    name: "delegates_unsorted_with_nested",
    networkPassphrase: Networks.TESTNET,
    entry: () =>
      unsignedEntry({
        signerLabel: SIGNER_1,
        nonce: NONCE_ORDINARY,
        invocation: invocationWithManyArgTypes(),
        authV2: true,
      }),
    delegates: [
      delegate(DELEGATE_3),
      delegate(DELEGATE_1, [delegate(DELEGATE_NESTED)]),
      delegate(DELEGATE_2),
    ],
    steps: [
      { signerLabel: DELEGATE_1, forAddress: keypairFor(DELEGATE_1).publicKey() },
      { signerLabel: DELEGATE_2, forAddress: keypairFor(DELEGATE_2).publicKey() },
      { signerLabel: DELEGATE_3, forAddress: keypairFor(DELEGATE_3).publicKey() },
      {
        signerLabel: DELEGATE_NESTED,
        forAddress: keypairFor(DELEGATE_NESTED).publicKey(),
      },
    ],
  },
  // §5.9 case 7: one address at two nesting levels.
  {
    name: "delegates_same_address_two_levels",
    networkPassphrase: Networks.TESTNET,
    entry: () =>
      unsignedEntry({
        signerLabel: SIGNER_1,
        nonce: 42n,
        invocation: invocationWithSubInvocations(),
        authV2: true,
      }),
    delegates: [
      delegate(DELEGATE_1),
      delegate(DELEGATE_2, [delegate(DELEGATE_1)]),
    ],
    steps: [
      { signerLabel: DELEGATE_1, forAddress: keypairFor(DELEGATE_1).publicKey() },
    ],
  },
  // §5.9 case 8: legacy entry wrapped into the delegates arm.
  {
    name: "delegates_from_legacy",
    networkPassphrase: Networks.TESTNET,
    entry: () =>
      unsignedEntry({
        signerLabel: SIGNER_1,
        nonce: NONCE_ORDINARY,
        invocation: invocationWithManyArgTypes(),
        authV2: false,
      }),
    delegates: [
      delegate(DELEGATE_1),
      delegate(DELEGATE_2, [delegate(DELEGATE_3), delegate(DELEGATE_NESTED)]),
    ],
    steps: [
      { signerLabel: DELEGATE_1, forAddress: keypairFor(DELEGATE_1).publicKey() },
      { signerLabel: DELEGATE_2, forAddress: keypairFor(DELEGATE_2).publicKey() },
      { signerLabel: DELEGATE_3, forAddress: keypairFor(DELEGATE_3).publicKey() },
      {
        signerLabel: DELEGATE_NESTED,
        forAddress: keypairFor(DELEGATE_NESTED).publicKey(),
      },
    ],
  },
  // #115: source-account arm vectors pass through unchanged.
  // The signed_entry_xdr must equal the unsigned_entry_xdr.
  {
    name: "source_account_testnet",
    networkPassphrase: Networks.TESTNET,
    entry: () => sourceAccountEntry(SIGNER_1),
    steps: [],
  },
  {
    name: "source_account_public",
    networkPassphrase: Networks.PUBLIC,
    entry: () => sourceAccountEntry(SIGNER_1),
    steps: [],
  },
  // #116: expiration boundary vectors.
  // Expiration 1 is the minimum valid value (see ExpirationAfter).
  {
    name: "v2_expiration_boundary_1",
    networkPassphrase: Networks.TESTNET,
    validUntilLedger: 1,
    entry: () =>
      unsignedEntry({
        signerLabel: SIGNER_1,
        nonce: NONCE_ORDINARY,
        invocation: invocationWithManyArgTypes(),
        authV2: true,
      }),
    steps: [{ signerLabel: SIGNER_1, forAddress: null }],
  },
  // MaxUint32 expiration: near the maximum ledger value.
  {
    name: "v2_expiration_boundary_max",
    networkPassphrase: Networks.TESTNET,
    validUntilLedger: 4294967295,
    entry: () =>
      unsignedEntry({
        signerLabel: SIGNER_1,
        nonce: NONCE_ORDINARY,
        invocation: invocationWithManyArgTypes(),
        authV2: true,
      }),
    steps: [{ signerLabel: SIGNER_1, forAddress: null }],
  },
  // #366: exactly MAX_ACCOUNT_SIGNATURES = 20 account signatures. The host's
  // account contract refuses a 21st, which NewAccountMultiSigner checks up
  // front (see TestGoldenStructuralBoundaries).
  {
    name: "v2_account_multisig_20_signatures",
    networkPassphrase: Networks.TESTNET,
    entry: () =>
      unsignedEntry({
        signerLabel: MULTISIG_ACCOUNT,
        nonce: NONCE_ORDINARY,
        invocation: invocationWithManyArgTypes(),
        authV2: true,
      }),
    multisigKeys: MULTISIG_KEYS,
    steps: [
      {
        signerLabel: MULTISIG_ACCOUNT,
        multisig: { signer_labels: MULTISIG_KEYS },
      },
    ],
  },
  // #366: an empty argument list.
  {
    name: "v2_empty_args",
    networkPassphrase: Networks.TESTNET,
    entry: () =>
      unsignedEntry({
        signerLabel: SIGNER_1,
        nonce: NONCE_ORDINARY,
        invocation: invocationWithEmptyArgs(),
        authV2: true,
      }),
    steps: [{ signerLabel: SIGNER_1, forAddress: null }],
  },
  // #366: a single-delegate tree, the shallowest delegates arm.
  {
    name: "delegates_single_node",
    networkPassphrase: Networks.TESTNET,
    entry: () =>
      unsignedEntry({
        signerLabel: SIGNER_1,
        nonce: NONCE_ORDINARY,
        invocation: invocationWithManyArgTypes(),
        authV2: true,
      }),
    delegates: [delegate(DELEGATE_1)],
    steps: [
      { signerLabel: DELEGATE_1, forAddress: keypairFor(DELEGATE_1).publicKey() },
    ],
  },
  // #366: the deepest nesting both implementations accept. The depth is in
  // the name because that is how the next person finds it.
  {
    name: `delegates_chain_depth_${MAX_VECTOR_DELEGATE_DEPTH}`,
    networkPassphrase: Networks.TESTNET,
    entry: () =>
      unsignedEntry({
        signerLabel: SIGNER_1,
        nonce: NONCE_ORDINARY,
        invocation: invocationWithManyArgTypes(),
        authV2: true,
      }),
    delegates: [delegateChain(MAX_VECTOR_DELEGATE_DEPTH)],
    steps: [
      {
        signerLabel: delegateChainLabel(MAX_VECTOR_DELEGATE_DEPTH),
        forAddress: keypairFor(delegateChainLabel(MAX_VECTOR_DELEGATE_DEPTH)).publicKey(),
      },
    ],
  },
  // #391: V2 arm with a muxed (M…) address in an invocation argument.
  // ParseAddress rejects muxed addresses for credentials, but they are legal
  // inside arguments because an argument is a different position with a different
  // rule — the argument is data being approved, not an identity authorizing.
  {
    name: "v2_muxed_address_in_argument",
    networkPassphrase: Networks.TESTNET,
    entry: () =>
      unsignedEntry({
        signerLabel: SIGNER_1,
        nonce: NONCE_ORDINARY,
        invocation: invocationWithMuxedAddressArg(),
        authV2: true,
      }),
    steps: [{ signerLabel: SIGNER_1, forAddress: null }],
  },
];

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

const generate = async (testCase) => {
  // Per-case expiration ledger, used for boundary vectors (#116).
  const validUntil = caseValidUntilLedger(testCase.name);

  // A case that declares delegates is built in two stages, and both are
  // recorded: the address entry before wrapping, and the wrapped entry. That
  // lets the Go side reproduce the wrap itself rather than starting from JS's
  // already-wrapped output.
  let preWrapEntry = null;
  let entry;
  if (testCase.delegates) {
    preWrapEntry = testCase.entry();
    entry = buildWithDelegatesEntry({
      entry: preWrapEntry,
      validUntilLedgerSeq: validUntil,
      delegates: toSdkDelegates(testCase.delegates),
      // signature omitted, so the top-level node is scvVoid
    });
  } else {
    entry = testCase.entry();
  }

  const unsignedXdr = entry.toXDR("base64");

  // Source-account entries have no preimage or payload; they pass through
  // unchanged. See Preimage() which returns ErrSourceAccountCredentials.
  const isSourceAccount =
    entry.credentials.type ===
    "sorobanCredentialsSourceAccount";

  let preimageXdr = "";
  let payloadHex = "";
  let payload = null;

  if (!isSourceAccount) {
    const preimage = buildAuthorizationEntryPreimage(
      entry,
      validUntil,
      testCase.networkPassphrase,
    );
    preimageXdr = preimage.toXDR("base64");
    payload = hash(preimage.toXDR());
    payloadHex = Buffer.from(payload).toString("hex");
  }

  // Each step signs the entry produced by the step before it, which is how a
  // delegate tree gets filled in one signer at a time. The multisig case is
  // the exception: the pinned SDK signs with one Keypair, so the 20-signature
  // vector is assembled from the SDK's signing primitive instead.
  let signed = entry;
  if (testCase.multisigKeys) {
    signed = withMultisigSignature(entry, payload, validUntil, testCase.multisigKeys);
  } else {
    for (const step of testCase.steps) {
      signed = await authorizeEntry(
        signed,
        keypairFor(step.signerLabel),
        validUntil,
        testCase.networkPassphrase,
        step.forAddress ?? undefined,
      );
    }
  }

  const signedXdr = signed.toXDR("base64");

  return {
    // The vector schema's version, written by the generator so that a reader
    // can tell which shape it is holding. golden_test.go refuses a vector
    // whose version it does not know, rather than silently reading fields
    // that may have moved. Bump it when a field is renamed, removed, or
    // changes meaning; adding an optional field does not need a bump.
    schema_version: SCHEMA_VERSION,
    name: testCase.name,
    sdk: SDK,
    network_passphrase: testCase.networkPassphrase,
    valid_until_ledger: validUntil,
    pre_wrap_entry_xdr: preWrapEntry ? preWrapEntry.toXDR("base64") : "",
    unsigned_entry_xdr: unsignedXdr,
    delegates: testCase.delegates ?? [],
    steps: testCase.steps.map((step) => ({
      signer_label: step.signerLabel,
      for_address: step.forAddress ?? null,
      ...(step.multisig ? { multisig: step.multisig } : {}),
    })),
    preimage_xdr: preimageXdr,
    payload_hex: payloadHex,
    signed_entry_xdr: signedXdr,
  };
};

mkdirSync(OUT_DIR, { recursive: true });

for (const testCase of CASES) {
  const vector = await generate(testCase);
  const path = join(OUT_DIR, `${vector.name}.json`);
  writeFileSync(path, `${JSON.stringify(vector, null, 2)}\n`);
  console.log(`wrote ${vector.name}.json  payload=${vector.payload_hex}`);
}

console.log(`\n${CASES.length} vectors generated with ${SDK}`);
