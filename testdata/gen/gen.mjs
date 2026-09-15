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
// TEST KEYS. Every keypair below is derived as
// Keypair.fromRawEd25519Seed(sha256(label)) from a label that is committed to
// this repository in plain text. They are therefore PUBLIC keys that anyone can
// derive and spend from. They exist only to make signatures reproducible.
// Never send real value to them, and never fund them on mainnet.

import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  Address,
  Keypair,
  Networks,
  authorizeEntry,
  buildAuthorizationEntryPreimage,
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

// Fixed nonces, chosen to cover the interesting int64 values: an ordinary
// positive one, the maximum, and the minimum (negative). A nonce is a signed
// int64 on the wire, so sign handling is part of what these vectors prove.
const NONCE_ORDINARY = 1234567890123456789n;
const NONCE_MAX = 9223372036854775807n; // 2^63 - 1
const NONCE_MIN = -9223372036854775808n; // -2^63

const scAddress = (label) => new Address(keypairFor(label).publicKey()).toScAddress();

const contractAddress = (label) =>
  new Address(Address.contract(sha256(label)).toString()).toScAddress();

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
  {
    // Identical to the case above apart from the network. The payload must
    // differ, or a signature would replay from testnet onto the public network.
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
  {
    // Same invocation and nonce as legacy_single_testnet, on the V2 arm. The
    // payload must differ, because V2 binds the address into the signed bytes.
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
  {
    // Also carries the maximum int64 nonce.
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
  {
    // The minimum int64 nonce. Differs from legacy_single_testnet only in the
    // nonce, so it isolates sign handling in the encoding.
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
];

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

const generate = async (testCase) => {
  const entry = testCase.entry();
  const unsignedXdr = entry.toXDR("base64");

  const preimage = buildAuthorizationEntryPreimage(
    entry,
    VALID_UNTIL_LEDGER,
    testCase.networkPassphrase,
  );
  const payload = hash(preimage.toXDR());

  // Each step signs the entry produced by the step before it, which is how a
  // delegate tree gets filled in one signer at a time.
  let signed = entry;
  for (const step of testCase.steps) {
    signed = await authorizeEntry(
      signed,
      keypairFor(step.signerLabel),
      VALID_UNTIL_LEDGER,
      testCase.networkPassphrase,
      step.forAddress ?? undefined,
    );
  }

  return {
    name: testCase.name,
    sdk: SDK,
    network_passphrase: testCase.networkPassphrase,
    valid_until_ledger: VALID_UNTIL_LEDGER,
    unsigned_entry_xdr: unsignedXdr,
    delegates: testCase.delegates ?? [],
    steps: testCase.steps.map((step) => ({
      signer_label: step.signerLabel,
      for_address: step.forAddress ?? null,
    })),
    preimage_xdr: preimage.toXDR("base64"),
    payload_hex: Buffer.from(payload).toString("hex"),
    signed_entry_xdr: signed.toXDR("base64"),
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
