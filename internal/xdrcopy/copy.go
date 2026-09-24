// Package xdrcopy deep-copies XDR values by round-tripping them through their
// canonical binary encoding.
//
// soroauth never mutates caller input (see the package documentation of
// soroauth). That rule needs real deep copies: the go-stellar-sdk XDR types are
// trees of pointers and slices, so assigning one to a new variable copies only
// the top struct and leaves every pointer and slice header aliasing the
// caller's memory. xdr.SorobanAuthorizedFunction, for example, reaches its
// payload through *InvokeContractArgs, and xdr.SorobanAuthorizedInvocation
// holds a []SorobanAuthorizedInvocation; writing through either would be
// visible to the caller.
//
// Marshalling and unmarshalling is used rather than reflection because XDR is
// the format this library is defined by: if a value cannot survive the
// round-trip it cannot be signed or submitted either, so the copy fails for the
// same reason the entry would have failed later, but earlier and with an error
// instead of a bad signature.
//
// The transport buffers of that round-trip — the encoding buffer, the encoder,
// the decoding reader and decoder — are pooled rather than allocated per call.
// They are pure scratch: nothing in the decoded result points into them (strings
// and opaque values are decoded into fresh memory), so returning them to a pool
// cannot alias the copy that is handed back. The tree itself is still allocated
// fresh on every call, which is what makes the copy a deep copy.
package xdrcopy

import (
	"fmt"
	"sync"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// The pools hold one scratch set per concurrent caller, obtained and released
// around a single Copy. They are not type-specific: an encoder buffer and a
// decoder are valid for every go-stellar-sdk XDR type.
var (
	encoderPool = sync.Pool{New: func() any { return xdr.NewEncodingBuffer() }}
	decoderPool = sync.Pool{New: func() any { return xdr.NewBytesDecoder() }}
)

// Copy returns a deep copy of v that shares no memory with it.
//
// The type parameters say that a pointer to the value encodes to the XDR
// binary format and decodes back from it, which is how the go-stellar-sdk XDR
// types are generated (EncodeTo on the pointer, DecodeFrom on the pointer). PT
// is inferred from T, so callers write xdrcopy.Copy(entry).
//
// The copy is byte-identical to v under XDR, which is the property soroauth
// depends on. It is not necessarily reflect.DeepEqual to v: XDR does not
// distinguish an empty slice from an absent one, so a non-nil empty slice
// decodes back as nil. Both encode to the same four zero bytes, so signatures
// and submitted transactions are unaffected.
//
// An error is returned rather than a partial value if any step fails; the
// returned value is then the zero value of T. The decode step also fails
// closed if it does not consume exactly the bytes the encode step produced:
// a round-trip that reads back less than it wrote would hand back a silently
// truncated value, and a truncated value signed is worse than an error.
func Copy[T any, PT interface {
	*T
	xdr.EncoderTo
	xdr.DecoderFrom
}](v T) (T, error) {
	var zero T

	enc := encoderPool.Get().(*xdr.EncodingBuffer)
	defer encoderPool.Put(enc)

	// The bytes alias enc's buffer, so enc must not go back into the pool
	// until the decode below has read them. The deferred Put does that.
	b, err := enc.UnsafeMarshalBinary(PT(&v))
	if err != nil {
		return zero, fmt.Errorf("soroauth: xdrcopy: marshal %T: %w", v, err)
	}

	var out T
	dec := decoderPool.Get().(*xdr.BytesDecoder)
	defer decoderPool.Put(dec)

	n, err := dec.DecodeBytes(PT(&out), b)
	if err != nil {
		return zero, fmt.Errorf("soroauth: xdrcopy: unmarshal %T: %w", v, err)
	}
	if n != len(b) {
		return zero, fmt.Errorf(
			"soroauth: xdrcopy: unmarshal %T: consumed %d of the %d encoded bytes",
			v, n, len(b))
	}

	return out, nil
}
