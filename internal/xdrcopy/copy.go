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
package xdrcopy

import (
	"encoding"
	"fmt"
)

// Copy returns a deep copy of v that shares no memory with it.
//
// The type parameters say that the value marshals itself and a pointer to it
// unmarshals into itself, which is how the go-stellar-sdk XDR types are
// generated (MarshalBinary on the value, UnmarshalBinary on the pointer). PT is
// inferred from T, so callers write xdrcopy.Copy(entry).
//
// The copy is byte-identical to v under XDR, which is the property soroauth
// depends on. It is not necessarily reflect.DeepEqual to v: XDR does not
// distinguish an empty slice from an absent one, so a non-nil empty slice
// decodes back as nil. Both encode to the same four zero bytes, so signatures
// and submitted transactions are unaffected.
//
// An error is returned rather than a partial value if either half of the
// round-trip fails; the returned value is then the zero value of T.
func Copy[T encoding.BinaryMarshaler, PT interface {
	*T
	encoding.BinaryUnmarshaler
}](v T) (T, error) {
	var zero T

	b, err := v.MarshalBinary()
	if err != nil {
		return zero, fmt.Errorf("soroauth: xdrcopy: marshal %T: %w", v, err)
	}

	var out T
	if err := PT(&out).UnmarshalBinary(b); err != nil {
		return zero, fmt.Errorf("soroauth: xdrcopy: unmarshal %T: %w", v, err)
	}

	return out, nil
}
