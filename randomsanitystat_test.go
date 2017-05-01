package randomsanity

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
)

func TestLooksRandom(t *testing.T) {
	var tests = []struct {
		hexbytes string
		want     bool
	}{
		// Software failure: use counter instead of random source
		// (rngstat.Counting tests)

		// 8-bit: start with a random 8-bit value,
		// chances that the next 8 bytes (64 bits) happen to look like
		// counting up are 1 in 2^64, less than our false-positive rate
		{"01 02 03 04 05 06 07 08 09", false},
		{"18 19 1a 1b 1c 1d 1e 1f 20", false},

		// 16-bit:
		{"0000 0001 0002 0003 0004", false}, // big-endian
		{"9991 9992 9993 9994 9995", false},
		{"0000 0100 0200 0300 0400", false}, // little-endian
		{"9199 9299 9399 9499 9599", false},

		// 32-bit:
		{"00000001 00000002 00000003", false}, // big-endian
		{"1111111f 11111120 11111121", false},
		{"01000000 02000000 03000000", false}, // little-endian
		{"1f111111 20111111 21111111", false},

		// 64-bit. Just one 64-bit sequence is enough to be under the
		// 2^60 false positive rate.
		{"0000000000000001 0000000000000002", false}, // big-endian
		{"ac80d400f8cd5946 ac80d400f8cd5947", false},
		{"4edc2837e54241ff 4edc2837e5424200", false},
		{"0100000000000000 0200000000000000", false}, // little-endian
		{"ff4132e53728dc4e 004232e53728dc4e", false},

		// repeated bytes tests
		// (rngstat.Repeated tests)
		{"00", true},
		{"ff", true},
		{"00000000000000", true},
		{"0000000000000000", false},
		{"ffffffffffffffff", false},
		{"fffffffeffffffff", true},
		{"0100000000000000", true},
		{"ff000000000000000000ff", false},
		{"00ffffffffffffffffff00", false},
		{"aaaaaaaaaaaaaaab", true},
		{"aaaaaaaaaaaaaaaa", false},
		{"ffaaaaaaaaaaaaaaaaaabb", false},
		{"39393939393939ab", true},
		{"3939393939393939", false},
		{"ff393939393939393939bb", false},

		// stuck bits tests (need 64 bytes or more)
		{"136d3d153516244b2a366d7b401131523d453b701f4b7c6d39480710561b5e0a136d3d153516244b2a366d7b401131523d453b701f4b7c6d39480710561b5e0a", false}, // 0x80 bit unset
		{"13adbd95b516248baa36ad3b8011b1123d053bb09f0b3c2db9080790961b1e0a13adbd95b516248baa36ad3b8011b1123d053bb09f0b3c2db9080790961b1e0a", false}, // 0x40 bit unset
		{"13cd9d95951604cb8a16cd5bc01191521d451bd09f4b5c4d99480790d61b5e0a13cd9d95951604cb8a16cd5bc01191521d451bd09f4b5c4d99480790d61b5e0a", false}, // 0x20 bit unset
		{"11edbd95b51424c9a834ed79c011b1503d4539f09d497c6db9480590d4195c0811edbd95b51424c9a834ed79c011b1503d4539f09d497c6db9480590d4195c08", false}, // 0x02 bit unset
		{"12ecbc94b41624caaa36ec7ac010b0523c443af09e4a7c6cb8480690d61a5e0a12ecbc94b41624caaa36ec7ac010b0523c443af09e4a7c6cb8480690d61a5e0a", false}, // 0x01 bit unset
		{"13efbf97b71626cbaa36ef7bc213b3523f473bf29f4b7e6fbb4a0792d61b5e0a13efbf97b71626cbaa36ef7bc213b3523f473bf29f4b7e6fbb4a0792d61b5e0a", false}, // 0x02 bit set

		// Actual random bitstreams, 1 to 32 bytes
		{"8b", true},
		{"6c72", true},
		{"307dd9", true},
		{"69f3171e", true},
		{"64980ad616", true},
		{"bb039395f8de", true},
		{"0eee58c404c82b", true},
		{"b45b237eeca0c59d", true},
		{"1d69df683069246282", true},
		{"81a6cefa3675ed6f04b9", true},
		{"143d92cc0ac0c594169967", true},
		{"a3d5be02d5b77a44793dccb4", true},
		{"98aa8d91d6d732d88c39c8ceec", true},
		{"3b1d9551df40c9330541c17a7ed2", true},
		{"356982f3f3a0a48a13df95245a7330", true},
		{"e47d253e45ccfa65f44493677aaf56ae", true},
		{"92f4752dbfcc23da433c9a8759cc67b330", true},
		{"17c7a1fae0f4a2d9efab4e4081f61afc4970", true},
		{"da8445a72b1c80affd49346f36cb63429eae10", true},
		{"be5d96f4a70273c960b3ce27997d6e388aac5e6b", true},
		{"17872e3aadb230cdeec35335fc6d3e4bf4ccc45b29", true},
		{"e9c5f8819c861b6e58af10e77233eac07328a1b51466", true},
		{"48fd3700fea9515416527f5834519ab25ce418e152e7c2", true},
		{"db80540a4bca01e1f218fb3162afe3ed6d4552fea89228bb", true},
		{"c96c862bc74fa6d6d2f026868b7a611e1650ab28500eb161db", true},
		{"44fce84f7a38be9532caf56ad5b8911f5756629e8402778a61f1", true},
		{"8d637674c809bd2ab7b20a6dae939176a4ed7fb54e95e1a4a31db6", true},
		{"4e811093195e9e7236a071c6c386650c374661d50cd802b86cfbe4a3", true},
		{"194d61bdd628f380916746f6804eaa83f7919fa87dffd3bee80c1b4be8", true},
		{"d1d648be784a79b0fde0a2f79562c1576643f0d322ff73163dd960c9a7a0", true},
		{"4724b307af612288395831874016ede4f3ba2d41df40c3884f1ff1b9c05ac3", true},
		{"13edbd95b51624cbaa36ed7bc011b1523d453bf09f4b7c6db9480790d61b5e0a", true},
	}

	for _, test := range tests {
		b, err := hex.DecodeString(strings.Replace(test.hexbytes, " ", "", -1))
		if err != nil {
			panic(err)
		}
		if got, which := LooksRandom(b); got != test.want {
			if which != "" {
				t.Errorf("LooksRandom(%q) = %v (%s)", test.hexbytes, got, which)
			} else {
				t.Errorf("LooksRandom(%q) = %v", test.hexbytes, got)
			}
		}
	}
}

func BenchmarkLooksRandom(b *testing.B) {
	var rhash [128]byte
	for i := 0; i < b.N; i++ {
		_, err := rand.Read(rhash[:])
		if err != nil {
			panic(err)
		}
		r, t := LooksRandom(rhash[:])
		if r == false {
			b.Errorf("%s failed LooksRandom (%s)", hex.EncodeToString(rhash[:]), t)
		}
	}
}
