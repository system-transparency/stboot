package testing

import (
	"encoding/base64"
	"math/big"
	"math/rand"
)

func GenerateBigInt(rand *rand.Rand, bits uint) *big.Int {
	ret := big.NewInt(0)
	one := big.NewInt(1)
	bound := one.Lsh(one, bits)
	return ret.Rand(rand, bound)
}

func GenerateBytes(rand *rand.Rand, min, max int) []byte {
	l := rand.Intn(max-min) + min
	b := make([]byte, l)

	rand.Read(b)
	return b
}

func GenerateBase64(rand *rand.Rand, min, max int) string {
	return base64.StdEncoding.EncodeToString(GenerateBytes(rand, min, max))
}
