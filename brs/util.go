package brs

import (
	"crypto/sha256"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
)

/*
Hash is responsible for the computing a Zp element given elements from curve btcec s256.
*/
func Hash(a []*big.Int) *big.Int {
	digest := sha256.New()
	for i := range a {
		digest.Write(a[i].Bytes())
	}
	output := digest.Sum(nil)
	tmp := output[0:len(output)]
	return new(big.Int).SetBytes(tmp)
}

/*
HashBigInt is responsible for the computing a Zp element given a message byte and array of Zp elements.
*/
func HashBigInt(a []*big.Int) *big.Int {
	digest := sha256.New()
	for i := range a {
		digest.Write(a[i].Bytes())
	}

	output := digest.Sum(nil)
	tmp := output[0:len(output)]
	return new(big.Int).SetBytes(tmp)
}

/*
HashMsg is responsible for the computing a Zp element given a message byte and array of Zp elements.
*/
func HashMsg(msg []byte, a []*big.Int) *big.Int {
	digest := sha256.New()
	digest.Write(msg)
	for i := range a {
		digest.Write(a[i].Bytes())
	}

	output := digest.Sum(nil)
	tmp := output[0:len(output)]
	return new(big.Int).SetBytes(tmp)
}

/*
HashMsgPubKey
*/
func HashMsgVerificationKey(msg []byte, keys []*btcec.PublicKey) *big.Int {
	a := []*big.Int{}
	for i := range keys {
		a = append(a, keys[i].X)
		a = append(a, keys[i].Y)
	}
	return HashMsg(msg, a)
}

/*
Commit method corresponds to the Pedersen commitment scheme. Namely, given input
message x, and randomness r, it outputs g^x.h^r.
*/
func Commit(x, r, hx, hy *big.Int) (*big.Int, *big.Int) {
	s256 := btcec.S256()
	x1, y1 := s256.ScalarBaseMult(r.Bytes())
	x2, y2 := s256.ScalarMult(hx, hy, x.Bytes())

	z1, z2 := s256.Add(x1, y1, x2, y2)
	return z1, z2
}

/*
Read big integer in base 10 from string.
*/
func GetBigInt(value string) *big.Int {
	i := new(big.Int)
	i.SetString(value, 10)
	return i
}

/* base u representation for l bits
 */
func GetBaseRepresentation(value *big.Int, u int64, l int64) ([]*big.Int, []*big.Int) {
	v := []*big.Int{}
	m := []*big.Int{}
	var i int64
	res := new(big.Int).Set(value)
	m0 := new(big.Int).SetInt64(1)
	for i = 0; i < l; i++ {
		v = append(v, new(big.Int).Rem(res, new(big.Int).SetInt64(u)))
		res = new(big.Int).Div(res, new(big.Int).SetInt64(u))
		m = append(m, m0)
		m0 = new(big.Int).Mul(m0, new(big.Int).SetInt64(u))
	}

	return v, m
}
