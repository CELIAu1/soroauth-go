package soroauth

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// ChangeKind classifies one difference DiffEntries found.
//
// The kinds are split along the line that matters: whether the change moves the
// bytes a signer committed to. Under CAP-46-11 and CAP-71-01 the signed payload
// is SHA-256(XDR(HashIdPreimage)), and the only entry-derived fields inside that
// preimage are the credential arm (which selects the variant), the nonce, the
// signature expiration ledger, the root invocation, and — for the address-bound
// variants — the top-level address. Everything else in an entry, the delegate
// tree included, is outside the payload.
type ChangeKind string

const (
	// ChangeKindArm is a different credential arm. It always moves the payload,
	// because the arm selects the HashIdPreimage variant: legacy signs
	// ENVELOPE_TYPE_SOROBAN_AUTHORIZATION, while V2 and the delegates arm sign
	// ENVELOPE_TYPE_SOROBAN_AUTHORIZATION_WITH_ADDRESS (CAP-71-01).
	ChangeKindArm ChangeKind = "arm"

	// ChangeKindAddress is a different top-level address. It moves the payload
	// for the address-bound arms, where the address is inside the preimage, and
	// not for the legacy arm, where it is not.
	ChangeKindAddress ChangeKind = "address"

	// ChangeKindNonce is a different nonce. It always moves the payload.
	ChangeKindNonce ChangeKind = "nonce"

	// ChangeKindExpiration is a different signature expiration ledger. It
	// always moves the payload, which is why re-signing one node of a delegates
	// entry at a new expiration invalidates every other node.
	ChangeKindExpiration ChangeKind = "expiration"

	// ChangeKindInvocation is a difference inside the root invocation tree. It
	// always moves the payload: the whole tree is inside the preimage, so a
	// changed argument three levels down counts as much as a changed contract.
	ChangeKindInvocation ChangeKind = "invocation"

	// ChangeKindDelegateAdded is a delegate node present in b and not in a.
	// It does not move the payload — every delegate signs the same
	// address-bound payload as the top-level node (CAP-71-01), so the tree's
	// membership is not part of what anyone signed.
	ChangeKindDelegateAdded ChangeKind = "delegate_added"

	// ChangeKindDelegateRemoved is a delegate node present in a and not in b.
	// Like ChangeKindDelegateAdded, it does not move the payload.
	ChangeKindDelegateRemoved ChangeKind = "delegate_removed"

	// ChangeKindSignature is a different signature value on a node that exists
	// in both entries. It never moves the payload: a signature is not signed
	// over.
	ChangeKindSignature ChangeKind = "signature"
)

// Change is one difference between two entries.
type Change struct {
	// Kind is what changed.
	Kind ChangeKind `json:"kind"`

	// Path locates the change inside the entry, using the XDR field names:
	// "credentials", "credentials.nonce", "credentials.delegates[G…]",
	// "rootInvocation.subInvocations[0].functionName". Delegate nodes are keyed
	// by address rather than by index, because the protocol sorts them by
	// address and an inserted delegate would otherwise renumber every node
	// after it and read as a change.
	Path string `json:"path"`

	// From is the value in the first entry, rendered for reading. A signature
	// is rendered as its shape and a short SHA-256 fingerprint rather than its
	// bytes, which can be arbitrarily large.
	From string `json:"from,omitempty"`

	// To is the value in the second entry, rendered the same way.
	To string `json:"to,omitempty"`

	// AffectsPayload is whether this change moves the bytes a signer commits
	// to. This is the field that decides whether a signature carried across the
	// two entries still verifies, and it is derived from the preimage's own
	// fields rather than assumed per kind — ChangeKindAddress, for one, affects
	// the payload on the address-bound arms and not on the legacy arm.
	AffectsPayload bool `json:"affects_payload"`
}

// EntryDiff is the result of DiffEntries.
//
// The first three fields are the answer; Changes is the evidence. They are
// ordered that way because the question a reviewer actually has is "does this
// still verify", and a list of field differences does not answer it: a changed
// expiration and a changed signature look equally small in a field list, and
// only one of them silently invalidates every other signature in the entry.
type EntryDiff struct {
	// Identical is whether the two entries are byte-identical.
	Identical bool `json:"identical"`

	// PayloadChanged is whether any field inside the HashIdPreimage differs, so
	// that the two entries would produce different signing payloads on the same
	// network. Every signature made against the first entry is invalid on the
	// second when this is true.
	//
	// The network passphrase is the one preimage field not carried in an entry,
	// so this compares the entry-derived fields only. Two entries that differ
	// in nothing here still have different payloads if signed for different
	// networks; see Note, which says so whenever this is false.
	PayloadChanged bool `json:"payload_changed"`

	// SignaturesChanged is whether any node present in both entries carries a
	// different signature value.
	SignaturesChanged bool `json:"signatures_changed"`

	// StaleSignatures lists the paths of nodes that carry the same signature in
	// both entries while PayloadChanged is true. These are the dangerous ones:
	// the entry reads as signed, the signature bytes were never touched, and
	// they commit to a payload the second entry no longer has — so they will
	// fail in the host rather than locally.
	//
	// It is empty when PayloadChanged is false, and also when a payload change
	// came with fresh signatures on every signed node, which is what a correct
	// re-sign looks like.
	StaleSignatures []string `json:"stale_signatures,omitempty"`

	// Changes is every difference found, payload-affecting ones first, then by
	// path. It is empty when Identical is true.
	Changes []Change `json:"changes,omitempty"`

	// Summary is the one-line verdict, the same sentence String() leads with.
	Summary string `json:"summary"`

	// Note carries a caveat about the comparison itself rather than about the
	// entries, such as the network passphrase not being comparable offline.
	Note string `json:"note,omitempty"`
}

// topLevelNodePath is the path of an entry's own credential node, as opposed to
// a delegate's. Every address arm has exactly one; the source-account arm has
// none, because the transaction envelope's signature authorizes it.
const topLevelNodePath = "credentials"

// diffNode is one signature-bearing node, with the path that identifies it
// across two entries.
type diffNode struct {
	path      string
	signature xdr.ScVal
}

// diffNodesOf walks a delegate tree and returns one node per delegate at every
// depth, keyed by address path.
//
// A duplicate address at one level is invalid under CAP-71-01, which requires
// strictly ascending order, but an entry handed to this function came from
// somewhere else and may carry one. Rather than let two nodes collide onto one
// path and silently compare the wrong pair, the second and later occurrences
// get a "#n" suffix.
func diffNodesOf(prefix string, delegates []xdr.SorobanDelegateSignature, depth int) ([]diffNode, error) {
	if err := checkTraversalDepth(depth); err != nil {
		return nil, err
	}

	seen := make(map[string]int, len(delegates))
	var out []diffNode
	for i := range delegates {
		address, err := FormatAddress(delegates[i].Address)
		if err != nil {
			return nil, err
		}
		path := fmt.Sprintf("%s[%s]", prefix, address)
		seen[path]++
		if n := seen[path]; n > 1 {
			path = fmt.Sprintf("%s#%d", path, n)
		}

		out = append(out, diffNode{path: path, signature: delegates[i].Signature})

		nested, err := diffNodesOf(path+".nested", delegates[i].NestedDelegates, depth+1)
		if err != nil {
			return nil, err
		}
		out = append(out, nested...)
	}
	return out, nil
}

// diffNodes returns every signature-bearing node of an entry with its path. The
// source-account arm has none: it carries no signature of its own, because the
// transaction envelope's signature authorizes it.
func diffNodes(entry xdr.SorobanAuthorizationEntry) ([]diffNode, error) {
	if entry.Credentials.Type == xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount {
		return nil, nil
	}
	credentials, err := addressCredentials(entry.Credentials)
	if err != nil {
		return nil, err
	}
	nodes := []diffNode{{path: topLevelNodePath, signature: credentials.Signature}}
	if entry.Credentials.Type == xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates {
		delegates, err := diffNodesOf("credentials.delegates", entry.Credentials.AddressWithDelegates.Delegates, 1)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, delegates...)
	}
	return nodes, nil
}

// renderSignature describes a signature value for a diff line.
//
// The bytes are not printed. A signature is an ScVal whose shape the account
// logic defines, so it has no bounded size, and a diff that dumped two of them
// would bury the finding it exists to report. The shape comes from
// DescribeSignature and the fingerprint is the first four bytes of the SHA-256
// of the value's XDR encoding — enough to see that two values differ, not
// enough to mistake for the signature itself.
func renderSignature(value xdr.ScVal) string {
	if !isSigned(value) {
		return "unsigned"
	}
	shape := DescribeSignature(value)
	encoded, err := value.MarshalBinary()
	if err != nil {
		return fmt.Sprintf("%s (unencodable)", shape.Description)
	}
	sum := sha256.Sum256(encoded)
	// The description, not the Type: DescribeSignature classifies a classic
	// account's vector-of-maps signature as SignatureShapeUnknown, which is
	// right for a shape report and useless in a diff line, where "unknown"
	// would read as a problem rather than as the ordinary case.
	return fmt.Sprintf("%s (sha256:%s)", shape.Description, hex.EncodeToString(sum[:4]))
}

// diffInvocation compares two invocation trees recursively and appends a change
// per difference found. Every such change affects the payload: the whole tree is
// inside the HashIdPreimage.
func diffInvocation(path string, a, b xdr.SorobanAuthorizedInvocation, depth int, changes *[]Change) error {
	if err := checkTraversalDepth(depth); err != nil {
		return err
	}

	add := func(kind ChangeKind, p, from, to string) {
		*changes = append(*changes, Change{Kind: kind, Path: p, From: from, To: to, AffectsPayload: true})
	}

	if a.Function.Type != b.Function.Type {
		add(ChangeKindInvocation, path+".function", functionTypeName(a.Function.Type), functionTypeName(b.Function.Type))
		return nil
	}

	switch a.Function.Type {
	case xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn:
		left, right := a.Function.ContractFn, b.Function.ContractFn
		switch {
		case left == nil || right == nil:
			// A declared ContractFn arm with a nil body is malformed rather
			// than a difference to describe field by field, so it is reported
			// as one opaque change rather than dereferenced.
			add(ChangeKindInvocation, path, presence(left != nil), presence(right != nil))
		default:
			if err := diffContractFn(path, *left, *right, add); err != nil {
				return err
			}
		}
	default:
		// CreateContractHostFn and CreateContractV2HostFn carry a wasm hash,
		// salt and constructor arguments whose field-by-field rendering would
		// be a second diff engine. A byte comparison still reports the change
		// honestly, and says where it is.
		same, err := xdrEqual(a.Function, b.Function)
		if err != nil {
			return err
		}
		if !same {
			add(ChangeKindInvocation, path+".function", functionTypeName(a.Function.Type)+" (differs)", functionTypeName(b.Function.Type)+" (differs)")
		}
	}

	if len(a.SubInvocations) != len(b.SubInvocations) {
		add(ChangeKindInvocation, path+".subInvocations",
			fmt.Sprintf("%d sub-invocations", len(a.SubInvocations)),
			fmt.Sprintf("%d sub-invocations", len(b.SubInvocations)))
		return nil
	}
	for i := range a.SubInvocations {
		sub := fmt.Sprintf("%s.subInvocations[%d]", path, i)
		if err := diffInvocation(sub, a.SubInvocations[i], b.SubInvocations[i], depth+1, changes); err != nil {
			return err
		}
	}
	return nil
}

// diffContractFn compares the contract, function name and arguments of two
// contract-function invocations.
func diffContractFn(path string, a, b xdr.InvokeContractArgs, add func(ChangeKind, string, string, string)) error {
	left, err := FormatAddress(a.ContractAddress)
	if err != nil {
		return err
	}
	right, err := FormatAddress(b.ContractAddress)
	if err != nil {
		return err
	}
	if left != right {
		add(ChangeKindInvocation, path+".contractAddress", left, right)
	}
	if a.FunctionName != b.FunctionName {
		add(ChangeKindInvocation, path+".functionName", string(a.FunctionName), string(b.FunctionName))
	}
	if len(a.Args) != len(b.Args) {
		add(ChangeKindInvocation, path+".args",
			fmt.Sprintf("%d arguments", len(a.Args)),
			fmt.Sprintf("%d arguments", len(b.Args)))
		return nil
	}
	for i := range a.Args {
		same, err := xdrEqual(a.Args[i], b.Args[i])
		if err != nil {
			return err
		}
		if !same {
			// Arguments are ScVals of any type and depth. Reporting which
			// argument changed, with its type on each side, locates the change
			// without this becoming an ScVal pretty-printer.
			add(ChangeKindInvocation, fmt.Sprintf("%s.args[%d]", path, i),
				a.Args[i].Type.String(), b.Args[i].Type.String())
		}
	}
	return nil
}

// xdrEqual compares two XDR values by their encodings, which is the same
// comparison the host makes and the only one that is exact for ScVals.
func xdrEqual(a, b interface{ MarshalBinary() ([]byte, error) }) (bool, error) {
	left, err := a.MarshalBinary()
	if err != nil {
		return false, fmt.Errorf("encoding: %w", err)
	}
	right, err := b.MarshalBinary()
	if err != nil {
		return false, fmt.Errorf("encoding: %w", err)
	}
	return bytes.Equal(left, right), nil
}

func presence(present bool) string {
	if present {
		return "present"
	}
	return "absent"
}

// functionTypeName names an authorized function type for a diff line.
func functionTypeName(t xdr.SorobanAuthorizedFunctionType) string {
	switch t {
	case xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn:
		return "contract_fn"
	case xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeCreateContractHostFn:
		return "create_contract_host_fn"
	default:
		return fmt.Sprintf("function type %d", int32(t))
	}
}

// DiffEntries reports what differs between two authorization entries, and
// separates the differences that invalidate signatures from the ones that do
// not.
//
// Why this exists: reviewing a re-signed, upgraded or wrapped entry otherwise
// means comparing two base64 blobs. The question behind that review is almost
// always "is anything signed here now stale", and that is not visible in a field
// list — a changed expiration and a changed signature are both one line, and
// only the first silently invalidates every other signature in a delegates
// entry, because under CAP-71-01 every node commits to the same payload and
// that payload includes the expiration ledger.
//
// So the report leads with PayloadChanged, SignaturesChanged and
// StaleSignatures, and each Change carries its own AffectsPayload. A signature
// that is byte-identical across the two entries while the payload moved is
// listed in StaleSignatures: it reads as signed, it was never touched, and it
// will be rejected by the host rather than locally.
//
// What is not compared: the network passphrase, which is the one HashIdPreimage
// field an entry does not carry. Two entries identical here still have
// different payloads if they were signed for different networks, and Note says
// so whenever PayloadChanged is false.
//
// Neither entry is modified, and nothing in the result aliases either one.
// Either entry may be any of the four arms, including source-account on one side
// and an address arm on the other; any other credentials value returns
// ErrUnsupportedCredentials.
//
// A worked example of the four ways two entries can differ, assuming an
// address-bound arm and a top-level node that keeps its signature bytes:
//
//	changed field                  PayloadChanged  carried-over signature
//	nothing (Identical)            false           valid
//	signature only                 false           valid
//	payload field only (e.g.       true            stale — listed in
//	  nonce, expiration, args)                       StaleSignatures
//	payload field and a fresh      true            valid — the re-sign case
//	  signature on every node
//
// The middle two rows are the distinction the report exists to draw: a diff
// shows two lines either way, and only the payload row means the entry will//	fail in the host.
func DiffEntries(a, b xdr.SorobanAuthorizationEntry) (EntryDiff, error) {
	armA, err := armName(a.Credentials.Type)
	if err != nil {
		return EntryDiff{}, fmt.Errorf("soroauth: diff entries: first entry: %w", err)
	}
	armB, err := armName(b.Credentials.Type)
	if err != nil {
		return EntryDiff{}, fmt.Errorf("soroauth: diff entries: second entry: %w", err)
	}

	identical, err := xdrEqual(a, b)
	if err != nil {
		return EntryDiff{}, fmt.Errorf("soroauth: diff entries: %w", err)
	}

	var changes []Change
	if armA != armB {
		changes = append(changes, Change{
			Kind: ChangeKindArm, Path: "credentials.type", From: armA, To: armB,
			// The arm selects the HashIdPreimage variant, so it always moves
			// the payload — except between two arms that have no payload at
			// all, which cannot happen here since armA != armB.
			AffectsPayload: true,
		})
	}

	// Credential fields exist only on the address arms. When one side is
	// source-account the arm change above already says so, and there is nothing
	// to compare field by field.
	if armA != CredentialTypeSourceAccount && armB != CredentialTypeSourceAccount {
		credsA, err := addressCredentials(a.Credentials)
		if err != nil {
			return EntryDiff{}, fmt.Errorf("soroauth: diff entries: first entry: %w", err)
		}
		credsB, err := addressCredentials(b.Credentials)
		if err != nil {
			return EntryDiff{}, fmt.Errorf("soroauth: diff entries: second entry: %w", err)
		}

		addressA, err := FormatAddress(credsA.Address)
		if err != nil {
			return EntryDiff{}, fmt.Errorf("soroauth: diff entries: first entry: %w", err)
		}
		addressB, err := FormatAddress(credsB.Address)
		if err != nil {
			return EntryDiff{}, fmt.Errorf("soroauth: diff entries: second entry: %w", err)
		}
		if addressA != addressB {
			// The address is inside the preimage for the address-bound arms
			// only (CAP-71-01). On the legacy arm it is not signed over, which
			// is the replay case V2 closes, so a changed address there is a
			// real change that does not invalidate the signature.
			bound := isAddressBoundArm(armA) && isAddressBoundArm(armB)
			changes = append(changes, Change{
				Kind: ChangeKindAddress, Path: "credentials.address",
				From: addressA, To: addressB, AffectsPayload: bound,
			})
		}
		if credsA.Nonce != credsB.Nonce {
			changes = append(changes, Change{
				Kind: ChangeKindNonce, Path: "credentials.nonce",
				From: fmt.Sprintf("%d", int64(credsA.Nonce)), To: fmt.Sprintf("%d", int64(credsB.Nonce)),
				AffectsPayload: true,
			})
		}
		if credsA.SignatureExpirationLedger != credsB.SignatureExpirationLedger {
			changes = append(changes, Change{
				Kind: ChangeKindExpiration, Path: "credentials.signatureExpirationLedger",
				From: fmt.Sprintf("%d", uint32(credsA.SignatureExpirationLedger)),
				To:   fmt.Sprintf("%d", uint32(credsB.SignatureExpirationLedger)),
				// The expiration is inside both preimage variants, so this is
				// the change that invalidates a whole delegate tree at once.
				AffectsPayload: true,
			})
		}
	}

	if err := diffInvocation("rootInvocation", a.RootInvocation, b.RootInvocation, 1, &changes); err != nil {
		return EntryDiff{}, fmt.Errorf("soroauth: diff entries: %w", err)
	}

	nodesA, err := diffNodes(a)
	if err != nil {
		return EntryDiff{}, fmt.Errorf("soroauth: diff entries: first entry: %w", err)
	}
	nodesB, err := diffNodes(b)
	if err != nil {
		return EntryDiff{}, fmt.Errorf("soroauth: diff entries: second entry: %w", err)
	}

	nodeChanges, carriedOver, signaturesChanged, signedBefore, err := diffNodeSets(nodesA, nodesB)
	if err != nil {
		return EntryDiff{}, fmt.Errorf("soroauth: diff entries: %w", err)
	}
	changes = append(changes, nodeChanges...)

	payloadChanged := false
	for _, change := range changes {
		if change.AffectsPayload {
			payloadChanged = true
			break
		}
	}

	diff := EntryDiff{
		Identical:         identical,
		PayloadChanged:    payloadChanged,
		SignaturesChanged: signaturesChanged,
		Changes:           sortChanges(changes),
	}
	if payloadChanged {
		// Only a signature that survived unchanged is stale. One that was
		// replaced was presumably re-made against the new payload, which is
		// what a correct re-sign looks like, and this function cannot verify
		// either way — VerifyEntry can, for classic-account shapes.
		diff.StaleSignatures = carriedOver
	} else {
		diff.Note = "the network passphrase is not carried in an entry, so it is not compared: " +
			"two entries that are otherwise identical still have different payloads on different networks"
	}
	diff.Summary = summarize(diff, signedBefore)
	return diff, nil
}

// diffNodeSets pairs the credential nodes of two entries by path and reports
// what happened to each. carriedOver lists the paths whose signature is present
// and byte-identical on both sides, which is what makes a signature stale when
// the payload moved. signedBefore says whether the first entry carried any
// signature at all, which is what separates a first signing from a re-sign:
// both move the payload and change a signature, and only one of them could
// have invalidated something.
func diffNodeSets(a, b []diffNode) (changes []Change, carriedOver []string, signaturesChanged, signedBefore bool, err error) {
	left := make(map[string]xdr.ScVal, len(a))
	order := make([]string, 0, len(a))
	for _, node := range a {
		left[node.path] = node.signature
		order = append(order, node.path)
		if isSigned(node.signature) {
			signedBefore = true
		}
	}
	right := make(map[string]xdr.ScVal, len(b))
	for _, node := range b {
		right[node.path] = node.signature
		if _, ok := left[node.path]; !ok {
			order = append(order, node.path)
		}
	}

	for _, path := range order {
		before, inA := left[path]
		after, inB := right[path]

		// The top-level node exists for every address arm and for no
		// source-account entry, so whether it is present is a function of the
		// arm alone. Its appearance or disappearance is therefore already
		// reported as ChangeKindArm, and repeating it here as an added or
		// removed *delegate* would be wrong twice over: it is not a delegate,
		// and it is not an independent change.
		if path == topLevelNodePath && inA != inB {
			continue
		}

		switch {
		case inA && !inB:
			changes = append(changes, Change{
				Kind: ChangeKindDelegateRemoved, Path: path,
				From: renderSignature(before), To: "absent", AffectsPayload: false,
			})
		case !inA && inB:
			changes = append(changes, Change{
				Kind: ChangeKindDelegateAdded, Path: path,
				From: "absent", To: renderSignature(after), AffectsPayload: false,
			})
		default:
			same, equalErr := xdrEqual(before, after)
			if equalErr != nil {
				return nil, nil, false, false, equalErr
			}
			if same {
				if isSigned(before) {
					carriedOver = append(carriedOver, path)
				}
				continue
			}
			signaturesChanged = true
			changes = append(changes, Change{
				Kind: ChangeKindSignature, Path: path + ".signature",
				From: renderSignature(before), To: renderSignature(after),
				// A signature is never signed over, so replacing one cannot
				// move the payload.
				AffectsPayload: false,
			})
		}
	}
	return changes, carriedOver, signaturesChanged, signedBefore, nil
}

// sortChanges puts payload-affecting changes first, then orders by path, so the
// differences that invalidate signatures are never buried under a long list of
// ones that do not.
func sortChanges(changes []Change) []Change {
	if len(changes) == 0 {
		return nil
	}
	sorted := make([]Change, len(changes))
	copy(sorted, changes)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].AffectsPayload != sorted[j].AffectsPayload {
			return sorted[i].AffectsPayload
		}
		return sorted[i].Path < sorted[j].Path
	})
	return sorted
}

// summarize writes the one-line verdict. It is the first thing String() prints
// and a field of the JSON, so neither output can be read without it.
func summarize(d EntryDiff, signedBefore bool) string {
	switch {
	case d.Identical:
		return "identical: the two entries encode to the same bytes"
	case d.PayloadChanged && len(d.StaleSignatures) > 0:
		return fmt.Sprintf(
			"PAYLOAD CHANGED and %s carried over unchanged: %s no longer valid",
			plural(len(d.StaleSignatures), "signature", "signatures"),
			isAre(len(d.StaleSignatures)))
	case d.PayloadChanged && d.SignaturesChanged && !signedBefore:
		// Nothing was signed before, so no signature could be invalidated.
		// Calling this a re-sign would describe a risk that is not there.
		return "payload changed, and the entry went from unsigned to signed: consistent with a first signing"
	case d.PayloadChanged && d.SignaturesChanged:
		return "payload changed, and every signature present was replaced: consistent with a re-sign"
	case d.PayloadChanged:
		return "payload changed, and no signature was carried over: consistent with an unsigned edit"
	case d.SignaturesChanged:
		return "signatures changed, payload unchanged: any other signature in the entry is unaffected"
	default:
		return "no payload or signature change: the difference is structural only"
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

func isAre(n int) string {
	if n == 1 {
		return "it is"
	}
	return "they are"
}

// String renders the diff for a terminal, verdict first.
//
// The verdict line is deliberately the whole point: a reviewer who reads only
// the first line of this output still learns whether anything signed went
// stale, which is the question that brought them here.
func (d EntryDiff) String() string {
	var out strings.Builder
	out.WriteString(d.Summary)
	out.WriteString("\n")

	if len(d.StaleSignatures) > 0 {
		out.WriteString("\nstale signatures (committed to the old payload):\n")
		for _, path := range d.StaleSignatures {
			fmt.Fprintf(&out, "  %s\n", path)
		}
	}

	if len(d.Changes) > 0 {
		out.WriteString("\nchanges:\n")
		for _, change := range d.Changes {
			marker := " "
			if change.AffectsPayload {
				marker = "!"
			}
			fmt.Fprintf(&out, "  %s %-14s %s\n", marker, change.Kind, change.Path)
			fmt.Fprintf(&out, "      %s -> %s\n", change.From, change.To)
		}
		out.WriteString("\n  ! marks a change inside the signed payload\n")
	}

	if d.Note != "" {
		fmt.Fprintf(&out, "\nnote: %s\n", d.Note)
	}
	return out.String()
}

// armName maps a credentials type to the stable name Inspect also reports, and
// refuses anything else rather than describing it as unknown: a diff that
// reported an arm it cannot read would be a diff a caller could trust less than
// it appears.
func armName(t xdr.SorobanCredentialsType) (string, error) {
	switch t {
	case xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount:
		return CredentialTypeSourceAccount, nil
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddress:
		return CredentialTypeAddress, nil
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2:
		return CredentialTypeAddressV2, nil
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates:
		return CredentialTypeAddressWithDelegates, nil
	default:
		return "", ErrUnsupportedCredentials
	}
}

// isAddressBoundArm reports whether an arm's payload includes the signer's
// address, which is true of the two CAP-71 arms and false of legacy.
func isAddressBoundArm(arm string) bool {
	return arm == CredentialTypeAddressV2 || arm == CredentialTypeAddressWithDelegates
}
