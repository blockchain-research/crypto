package ccs08

import (
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/blockchain-research/crypto/bn256"
)

type keypair struct {
	pubk  *bn256.G1
	privk *big.Int
}

func keygen() (keypair, error) {
	var (
		kp  keypair
		e   error
		res bool
	)
	kp.privk, e = rand.Int(rand.Reader, bn256.Order)
	if e != nil {
		return kp, e
	}
	kp.pubk, res = new(bn256.G1).Unmarshal(new(bn256.G1).ScalarBaseMult(kp.privk).Marshal())
	if !res {
		return kp, errors.New("Could not compute scalar multiplication.")
	}
	return kp, e
}

/*
sign receives as input a message and a private key and outputs a digital signature.
*/
func sign(m *big.Int, privk *big.Int) (*bn256.G2, error) {
	var (
		res       bool
		signature *bn256.G2
	)
	inv := ModInverse(Mod(Add(m, privk), bn256.Order), bn256.Order)
	signature, res = new(bn256.G2).Unmarshal(new(bn256.G2).ScalarBaseMult(inv).Marshal())
	if res != false {
		return signature, nil
	} else {
		return nil, errors.New("Error while computing signature.")
	}
}

/*
verify receives as input the digital signature, the message and the public key. It outputs
true if and only if the signature is valid.
*/
func verify(signature *bn256.G2, m *big.Int, pubk *bn256.G1) (bool, error) {
	// e(y.g^m, sig) = e(g1,g2)
	var (
		gm     *bn256.G1
		e, res bool
	)
	// g^m
	gm, e = new(bn256.G1).Unmarshal(new(bn256.G1).ScalarBaseMult(m).Marshal())
	// y.g^m
	gm = gm.Add(gm, pubk)
	// e(y.g^m, sig)
	p1 := bn256.Pair(gm, signature)
	// e(g1,g2)
	g1 := new(bn256.G1).ScalarBaseMult(new(big.Int).SetInt64(1))
	g2 := new(bn256.G2).ScalarBaseMult(new(big.Int).SetInt64(1))
	p2 := bn256.Pair(g1, g2)
	// p1 == p2?
	p2 = p2.Neg(p2)
	p1 = p1.Add(p1, p2)
	res = p1.IsOne()
	if e != false {
		return res, nil
	}
	return false, errors.New("Error while computing signature.")
}
