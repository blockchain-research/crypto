package ccs08

import (
	"crypto/sha256"
	"math/big"
)

var k1 = new(big.Int).SetBit(big.NewInt(0), 160, 1) // 2^160, security parameter that should match prover

func CalculateHash(b1 *big.Int, b2 *big.Int) (*big.Int, error) {

	digest := sha256.New()
	digest.Write(b1.Bytes())
	if b2 != nil {
		digest.Write(b2.Bytes())
	}
	output := digest.Sum(nil)
	tmp := output[0:len(output)]
	return new(big.Int).SetBytes(tmp), nil
}

/**
 * Returns base**exponent mod |modulo| also works for negative exponent (contrary to big.Int.Exp)
 */
func ModPow(base *big.Int, exponent *big.Int, modulo *big.Int) *big.Int {

	var returnValue *big.Int

	if exponent.Cmp(big.NewInt(0)) >= 0 {
		returnValue = new(big.Int).Exp(base, exponent, modulo)
	} else {
		// Exp doesn't support negative exponent so instead:
		// use positive exponent than take inverse (modulo)..
		returnValue = ModInverse(new(big.Int).Exp(base, new(big.Int).Abs(exponent), modulo), modulo)
	}
	return returnValue
}

func Add(x *big.Int, y *big.Int) *big.Int {
	return new(big.Int).Add(x, y)
}

func Sub(x *big.Int, y *big.Int) *big.Int {
	return new(big.Int).Sub(x, y)
}

func Mod(base *big.Int, modulo *big.Int) *big.Int {
	return new(big.Int).Mod(base, modulo)
}

func Multiply(factor1 *big.Int, factor2 *big.Int) *big.Int {
	return new(big.Int).Mul(factor1, factor2)
}

func ModInverse(base *big.Int, modulo *big.Int) *big.Int {
	return new(big.Int).ModInverse(base, modulo)
}
