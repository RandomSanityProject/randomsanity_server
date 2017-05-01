// Fast, simple statistical tests for short (e.g. 256-bit) bitstreams
//
// These are written for a 1-in-2^60 (one in a quintillion) false
// positive rate, approximately, overall. Since multiple tests are
// run, the false positive rate for each should be evern lower;
// individual tests work on 8 byte chunks so have a 1-in-2^64
// false positive rate.
//
// They are meant to catch catastrophic failures of software or hardware,
// NOT to detect subtle biases.
//
// If you want to detect subtle biases, use one of these extensive
// test suites:
//    NIST SP 800-22
//    DieHarder
//    TestU01
//
// If you are a certain type of programmer, you will be tempted to optimize
// the snot out of these; there are lots of clever optimizations that could
// make some of these tests an order or three of magnitude faster.
// Don't.  Find something more productive to do. CPU time is really cheap;
// finding somebody willing to spend a half a day reviewing your awesomely
// clever algorithm for detecting stuck bits is expensive.
package randomsanity

import (
	"encoding/binary"
)

type decodeF func([]byte) uint64

func incrementing(b []byte, bytesPerNum int, fp decodeF) bool {
	// Need at least one number plus 64-bits-worth of items
	// to be under the 2^60 false positive rate
	if len(b) < bytesPerNum+8 {
		return false
	}
	first := fp(b[0:bytesPerNum])
	nNums := len(b) / bytesPerNum
	allmatch := true
	for i := 1; i < nNums && allmatch; i++ {
		n := fp(b[bytesPerNum*i : bytesPerNum*(i+1)])
		if first+uint64(i) != n {
			allmatch = false
		}
	}
	return allmatch
}

// Counting returns true if b contains bytes that can be interpreted
// as incrementing numbers: 8/16/32/64 bytes, big or little endian.
// It is meant to catch programming errors where an array index is used
// instead of some source of random bytes.
func Counting(b []byte) bool {
	if incrementing(b, 1, func(b []byte) uint64 { return uint64(b[0]) }) {
		return true
	}
	if incrementing(b, 2, func(b []byte) uint64 { return uint64(binary.LittleEndian.Uint16(b[0:2])) }) {
		return true
	}
	if incrementing(b, 2, func(b []byte) uint64 { return uint64(binary.BigEndian.Uint16(b[0:2])) }) {
		return true
	}
	if incrementing(b, 4, func(b []byte) uint64 { return uint64(binary.LittleEndian.Uint32(b[0:4])) }) {
		return true
	}
	if incrementing(b, 4, func(b []byte) uint64 { return uint64(binary.BigEndian.Uint32(b[0:4])) }) {
		return true
	}
	if incrementing(b, 8, func(b []byte) uint64 { return uint64(binary.LittleEndian.Uint64(b[0:8])) }) {
		return true
	}
	if incrementing(b, 8, func(b []byte) uint64 { return uint64(binary.BigEndian.Uint64(b[0:8])) }) {
		return true
	}
	return false
}

// Repeated returns true if b contains long runs of repeated bytes
func Repeated(b []byte) bool {
	nBytes := len(b)
	nRepeated := 0

	for i := 1; i <= nBytes; i++ {
		if b[i-1] == b[i%nBytes] {
			nRepeated += 1
			if nRepeated >= 8 {
				return true
			}
		} else {
			nRepeated = 0
		}
	}
	return false
}

// BitStuck returns true and which bit is stuck if b contains
// long runs of bytes with the same bit set or unset
func BitStuck(b []byte) (bool, uint) {
	if len(b) < 64 {
		return false, 0
	}
	// Create a new byte array with all the low bits,
	// etc. Then use Repeated to look for runs of
	// zero or one.
	for bit := uint(0); bit < uint(8); bit++ {
		bb := make([]byte, (len(b)+7)/8)
		for i, v := range b {
			bb[i/8] |= ((v >> bit) & 0x01) << uint(i%8)
		}
		if Repeated(bb) {
			return true, bit
		}
	}
	return false, 0
}

// LooksRandom returns true and an empty string if b passes all
// the tests; otherwise it returns false and a short string describing
// which test failed.
func LooksRandom(b []byte) (bool, string) {
	if Repeated(b) {
		return false, "Repeated bytes"
	}
	if Counting(b) {
		return false, "Counting"
	}
	stuck, _ := BitStuck(b)
	if stuck {
		return false, "Bit stuck"
	}

	return true, ""
}
