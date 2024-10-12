// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package secp256k1

import (
	"errors"
	"testing"
)

// TestErrorKindStringer tests the stringized output for the ErrorKind type.
func TestErrorKindStringer(t *testing.T) {
	tests := []struct {
		in   ErrorKind
		want string
	}{
		{ErrPubKeyInvalidLen, "ErrPubKeyInvalidLen"},
		{ErrPubKeyInvalidFormat, "ErrPubKeyInvalidFormat"},
		{ErrPubKeyXTooBig, "ErrPubKeyXTooBig"},
		{ErrPubKeyYTooBig, "ErrPubKeyYTooBig"},
		{ErrPubKeyNotOnCurve, "ErrPubKeyNotOnCurve"},
		{ErrPubKeyMismatchedOddness, "ErrPubKeyMismatchedOddness"},
		{ErrSigTooShort, "ErrSigTooShort"},
		{ErrSigTooLong, "ErrSigTooLong"},
		{ErrSigInvalidSeqID, "ErrSigInvalidSeqID"},
		{ErrSigInvalidDataLen, "ErrSigInvalidDataLen"},
		{ErrSigMissingSTypeID, "ErrSigMissingSTypeID"},
		{ErrSigMissingSLen, "ErrSigMissingSLen"},
		{ErrSigInvalidSLen, "ErrSigInvalidSLen"},
		{ErrSigInvalidRIntID, "ErrSigInvalidRIntID"},
		{ErrSigZeroRLen, "ErrSigZeroRLen"},
		{ErrSigNegativeR, "ErrSigNegativeR"},
		{ErrSigTooMuchRPadding, "ErrSigTooMuchRPadding"},
		{ErrSigRIsZero, "ErrSigRIsZero"},
		{ErrSigRTooBig, "ErrSigRTooBig"},
		{ErrSigInvalidSIntID, "ErrSigInvalidSIntID"},
		{ErrSigZeroSLen, "ErrSigZeroSLen"},
		{ErrSigNegativeS, "ErrSigNegativeS"},
		{ErrSigTooMuchSPadding, "ErrSigTooMuchSPadding"},
		{ErrSigSIsZero, "ErrSigSIsZero"},
		{ErrSigSTooBig, "ErrSigSTooBig"},
		{ErrSigInvalidLen, "ErrSigInvalidLen"},
		{ErrSigInvalidRecoveryCode, "ErrSigInvalidRecoveryCode"},
		{ErrSigOverflowsPrime, "ErrSigOverflowsPrime"},
		{ErrPointNotOnCurve, "ErrPointNotOnCurve"},
	}

	for i, test := range tests {
		result := test.in.Error()
		if result != test.want {
			t.Errorf("#%d: got: %s want: %s", i, result, test.want)
			continue
		}
	}
}

// TestError tests the error output for the Error type.
func TestError(t *testing.T) {
	tests := []struct {
		in   Error
		want string
	}{{
		Error{Description: "some error"},
		"some error",
	}, {
		Error{Description: "human-readable error"},
		"human-readable error",
	}}

	for i, test := range tests {
		result := test.in.Error()
		if result != test.want {
			t.Errorf("#%d: got: %s want: %s", i, result, test.want)
			continue
		}
	}
}

// TestErrorKindIsAs ensures both ErrorKind and Error can be identified as being
// a specific error kind via errors.Is and unwrapped via errors.As.
func TestErrorKindIsAs(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		target    error
		wantMatch bool
		wantAs    ErrorKind
	}{{
		name:      "ErrPubKeyInvalidLen == ErrPubKeyInvalidLen",
		err:       ErrPubKeyInvalidLen,
		target:    ErrPubKeyInvalidLen,
		wantMatch: true,
		wantAs:    ErrPubKeyInvalidLen,
	}, {
		name:      "Error.ErrPubKeyInvalidLen == ErrPubKeyInvalidLen",
		err:       makeError(ErrPubKeyInvalidLen, ""),
		target:    ErrPubKeyInvalidLen,
		wantMatch: true,
		wantAs:    ErrPubKeyInvalidLen,
	}, {
		name:      "Error.ErrPubKeyInvalidLen == Error.ErrPubKeyInvalidLen",
		err:       makeError(ErrPubKeyInvalidLen, ""),
		target:    makeError(ErrPubKeyInvalidLen, ""),
		wantMatch: true,
		wantAs:    ErrPubKeyInvalidLen,
	}, {
		name:      "ErrPubKeyInvalidFormat != ErrPubKeyInvalidLen",
		err:       ErrPubKeyInvalidFormat,
		target:    ErrPubKeyInvalidLen,
		wantMatch: false,
		wantAs:    ErrPubKeyInvalidFormat,
	}, {
		name:      "Error.ErrPubKeyInvalidFormat != ErrPubKeyInvalidLen",
		err:       makeError(ErrPubKeyInvalidFormat, ""),
		target:    ErrPubKeyInvalidLen,
		wantMatch: false,
		wantAs:    ErrPubKeyInvalidFormat,
	}, {
		name:      "ErrPubKeyInvalidFormat != Error.ErrPubKeyInvalidLen",
		err:       ErrPubKeyInvalidFormat,
		target:    makeError(ErrPubKeyInvalidLen, ""),
		wantMatch: false,
		wantAs:    ErrPubKeyInvalidFormat,
	}, {
		name:      "Error.ErrPubKeyInvalidFormat != Error.ErrPubKeyInvalidLen",
		err:       makeError(ErrPubKeyInvalidFormat, ""),
		target:    makeError(ErrPubKeyInvalidLen, ""),
		wantMatch: false,
		wantAs:    ErrPubKeyInvalidFormat,
	}, {
		name:      "ErrSigTooShort == ErrSigTooShort",
		err:       ErrSigTooShort,
		target:    ErrSigTooShort,
		wantMatch: true,
		wantAs:    ErrSigTooShort,
	}, {
		name:      "Error.ErrSigTooShort == ErrSigTooShort",
		err:       signatureError(ErrSigTooShort, ""),
		target:    ErrSigTooShort,
		wantMatch: true,
		wantAs:    ErrSigTooShort,
	}, {
		name:      "Error.ErrSigTooShort == Error.ErrSigTooShort",
		err:       signatureError(ErrSigTooShort, ""),
		target:    signatureError(ErrSigTooShort, ""),
		wantMatch: true,
		wantAs:    ErrSigTooShort,
	}, {
		name:      "ErrSigTooLong != ErrSigTooShort",
		err:       ErrSigTooLong,
		target:    ErrSigTooShort,
		wantMatch: false,
		wantAs:    ErrSigTooLong,
	}, {
		name:      "Error.ErrSigTooLong != ErrSigTooShort",
		err:       signatureError(ErrSigTooLong, ""),
		target:    ErrSigTooShort,
		wantMatch: false,
		wantAs:    ErrSigTooLong,
	}, {
		name:      "ErrSigTooLong != Error.ErrSigTooShort",
		err:       ErrSigTooLong,
		target:    signatureError(ErrSigTooShort, ""),
		wantMatch: false,
		wantAs:    ErrSigTooLong,
	}, {
		name:      "Error.ErrSigTooLong != Error.ErrSigTooShort",
		err:       signatureError(ErrSigTooLong, ""),
		target:    signatureError(ErrSigTooShort, ""),
		wantMatch: false,
		wantAs:    ErrSigTooLong,
	}}

	for _, test := range tests {
		// Ensure the error matches or not depending on the expected result.
		result := errors.Is(test.err, test.target)
		if result != test.wantMatch {
			t.Errorf("%s: incorrect error identification -- got %v, want %v",
				test.name, result, test.wantMatch)
			continue
		}

		// Ensure the underlying error code can be unwrapped and is the expected
		// code.
		var kind ErrorKind
		if !errors.As(test.err, &kind) {
			t.Errorf("%s: unable to unwrap to error code", test.name)
			continue
		}
		if kind != test.wantAs {
			t.Errorf("%s: unexpected unwrapped error code -- got %v, want %v",
				test.name, kind, test.wantAs)
			continue
		}
	}
}
