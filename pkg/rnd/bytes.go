package rnd

import (
	crand "crypto/rand"
	"encoding/binary"
	"math/rand"
)

// RandomBytes generates a random byte sequence of the requested length
func RandomBytes(numbytes int) []byte {
	randBytes := make([]byte, numbytes)
	binary.Read(crand.Reader, binary.BigEndian, &randBytes)
	return randBytes
}

// XorBytesWithBytes xor encodes a byte array with another byte array
func XorBytesWithBytes(src []byte, key []byte) []byte {
	dst := make([]byte, len(src))
	ksz := len(key)
	for i := 0; i < len(src); i++ {
		dst[i] = src[i] ^ key[i%ksz]
	}
	return dst
}

// SeedMathRand seeds the PRNG for things like transaction IDs
func SeedMathRand() {
	var randomSeed int64
	binary.Read(crand.Reader, binary.BigEndian, &randomSeed)
	rand.Seed(randomSeed)
}
