// Reference package https://github.com/ing-bank/zkrangeproof/

/*
This file contains the implementation of the ZKRP scheme proposed in the paper:
Efficient Protocols for Set Membership and Range Proofs
Jan Camenisch, Rafik Chaabouni, abhi shelat
Asiacrypt 2008
*/

package ccs08

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strconv"

	"github.com/blockchain-research/crypto/bn256"
)

//SetupUL,ProveUL and VerifyUL generates the parameters, generate proof, verify proof
//for the case where the range is in [0,u^l)

/*
SetupUL generates the signature for the interval [0,u^l).
The value of u should be roughly b/log(b), but we can choose smaller values in
order to get smaller parameters, at the cost of having worse performance.
SetupUL returns Prover and Verifier struct
*/
func SetupUL(u, l int64) (*Prover, *Verifier, error) {

	var (
		i   int64
		err error
	)
	prover := &Prover{
		params: &ParamsULProver{},
	}
	verifier := &Verifier{
		params: &ParamsULVerifier{},
	}

	prover.params.kp, err = keygen()
	if err != nil {
		return nil, nil, err
	}

	prover.params.signatures = make(map[string]*bn256.G2)
	for i = 0; i < u; i++ {
		sig_i, err := sign(new(big.Int).SetInt64(i), prover.params.kp.privk)
		if err != nil {
			return nil, nil, err
		}
		prover.params.signatures[strconv.FormatInt(i, 10)] = sig_i
	}
	//TODO: protect the 'master' key
	h := GetBigInt("18560948149108576432482904553159745978835170526553990798435819795989606410925")
	prover.params.H = new(bn256.G2).ScalarBaseMult(h)
	prover.params.u = u
	prover.params.l = l

	verifier.params.H = prover.params.H
	verifier.params.u = prover.params.u
	verifier.params.l = prover.params.l
	verifier.params.pubk = prover.params.kp.pubk

	return prover, verifier, nil
}

/*
ProveUL method is used to produce the ZKRP proof that secret x belongs to the interval [0,U^L].
*/
func (p *Prover) ProveUL(x, r *big.Int, cm *bn256.G2) (*ProofUL, error) {
	var (
		i         int64
		v         []*big.Int
		proof_out ProofUL
	)
	decx, err := Decompose(x, p.params.u, p.params.l)
	if err != nil {
		return nil, err
	}

	// Initialize variables
	v = make([]*big.Int, p.params.l, p.params.l)
	proof_out.V = make([]*bn256.G2, p.params.l, p.params.l)
	proof_out.a = make([]*bn256.GT, p.params.l, p.params.l)
	s := make([]*big.Int, p.params.l, p.params.l)
	t := make([]*big.Int, p.params.l, p.params.l)
	proof_out.zsig = make([]*big.Int, p.params.l, p.params.l)
	proof_out.zv = make([]*big.Int, p.params.l, p.params.l)
	proof_out.D = new(bn256.G2)
	proof_out.D.SetInfinity()
	m, err := rand.Int(rand.Reader, bn256.Order)
	if err != nil {
		return nil, err
	}

	// D = H^m
	D := new(bn256.G2).ScalarMult(p.params.H, m)
	for i = 0; i < p.params.l; i++ {
		v[i], err = rand.Int(rand.Reader, bn256.Order)
		if err != nil {
			return nil, err
		}
		A, ok := p.params.signatures[strconv.FormatInt(decx[i], 10)]
		if ok {
			proof_out.V[i] = new(bn256.G2).ScalarMult(A, v[i])
			s[i], err = rand.Int(rand.Reader, bn256.Order)
			if err != nil {
				return nil, err
			}
			t[i], err = rand.Int(rand.Reader, bn256.Order)
			if err != nil {
				return nil, err
			}
			proof_out.a[i] = bn256.Pair(G1, proof_out.V[i])
			proof_out.a[i].ScalarMult(proof_out.a[i], s[i])
			proof_out.a[i].Invert(proof_out.a[i])
			proof_out.a[i].Add(proof_out.a[i], new(bn256.GT).ScalarMult(E, t[i]))

			ui := new(big.Int).Exp(new(big.Int).SetInt64(p.params.u), new(big.Int).SetInt64(i), nil)
			muisi := new(big.Int).Mul(s[i], ui)
			muisi = Mod(muisi, bn256.Order)
			aux := new(bn256.G2).ScalarBaseMult(muisi)
			D.Add(D, aux)
		} else {
			return nil, errors.New("Could not generate proof. Element does not belong to the interval.")
		}
	}
	proof_out.D.Add(proof_out.D, D)

	// Consider passing C as input,
	// so that it is possible to delegate the commitment computation to an external party.
	proof_out.C = cm //Commit(x, r, p.H)
	// Fiat-Shamir heuristic
	proof_out.c, err = Hash(proof_out.a, proof_out.D)
	if err != nil {
		return nil, err
	}
	proof_out.c = Mod(proof_out.c, bn256.Order)

	proof_out.zr = Sub(m, Multiply(r, proof_out.c))
	proof_out.zr = Mod(proof_out.zr, bn256.Order)
	for i = 0; i < p.params.l; i++ {
		proof_out.zsig[i] = Sub(s[i], Multiply(new(big.Int).SetInt64(decx[i]), proof_out.c))
		proof_out.zsig[i] = Mod(proof_out.zsig[i], bn256.Order)
		proof_out.zv[i] = Sub(t[i], Multiply(v[i], proof_out.c))
		proof_out.zv[i] = Mod(proof_out.zv[i], bn256.Order)
	}

	return &proof_out, nil
}

/*
VerifyUL is used to validate the ZKRP proof. It returns true iff the proof is valid.
*/
func (v *Verifier) VerifyUL(proof *ProofUL) (bool, error) {
	var (
		i      int64
		D      *bn256.G2
		r1, r2 bool
		p1, p2 *bn256.GT
	)
	// D == C^c.h^ zr.g^zsig ?
	D = new(bn256.G2).ScalarMult(proof.C, proof.c)
	D.Add(D, new(bn256.G2).ScalarMult(v.params.H, proof.zr))
	for i = 0; i < v.params.l; i++ {
		ui := new(big.Int).Exp(new(big.Int).SetInt64(v.params.u), new(big.Int).SetInt64(i), nil)
		muizsigi := new(big.Int).Mul(proof.zsig[i], ui)
		muizsigi = Mod(muizsigi, bn256.Order)
		aux := new(bn256.G2).ScalarBaseMult(muizsigi)
		D.Add(D, aux)
	}

	DBytes := D.Marshal()
	pDBytes := proof.D.Marshal()
	r1 = bytes.Equal(DBytes, pDBytes)

	r2 = true
	for i = 0; i < v.params.l; i++ {
		// a == [e(V,y)^c].[e(V,g)^-zsig].[e(g,g)^zv]
		p1 = bn256.Pair(v.params.pubk, proof.V[i])
		p1.ScalarMult(p1, proof.c)
		p2 = bn256.Pair(G1, proof.V[i])
		p2.ScalarMult(p2, proof.zsig[i])
		p2.Invert(p2)
		p1.Add(p1, p2)
		p1.Add(p1, new(bn256.GT).ScalarMult(E, proof.zv[i]))

		pBytes := p1.Marshal()
		aBytes := proof.a[i].Marshal()
		r2 = r2 && bytes.Equal(pBytes, aBytes)
	}
	return r1 && r2, nil
}

//Setup, Prove, Verify generates the parameters, generate proof, verify proof
//for the case where the range is in [a,b)
/*
Setup receives integers a and b, and configures the parameters for the rangeproof scheme.
*/
func Setup(a, b int64) (*Prover, *Verifier, error) {
	// Compute optimal values for u and l
	var (
		u, l int64
		logb float64
		//p    *params
	)
	if a > b {
		return nil, nil, errors.New("a must be less than or equal to b")
	}

	//	p = new(params)
	logb = math.Log(float64(b))
	if logb != 0 {
		// TODO: understand how to find optimal parameters
		//u = b / int64(logb)
		u = 100
		if u != 0 {
			l = 0
			for i := b; i > 0; i = i / u {
				l = l + 1
			}
			prover, verifier, err := SetupUL(u, l)
			prover.a = a
			prover.b = b
			verifier.a = a
			verifier.b = b
			if err != nil {
				fmt.Println("SetupUL error")
				return nil, nil, err
			}
			return prover, verifier, nil
		}
		return nil, nil, errors.New("u is zero")
	}
	return nil, nil, errors.New("log(b) is zero")
}

/*
Prove method is responsible for generating the zero knowledge proof.
*/
func (prover *Prover) Prove(x, r *big.Int) (*Proof, error) {
	ul := new(big.Int).Exp(new(big.Int).SetInt64(prover.params.u), new(big.Int).SetInt64(prover.params.l), nil)

	// x - b + ul
	xb := new(big.Int).Sub(x, new(big.Int).SetInt64(prover.b))
	xb.Add(xb, ul)
	cmfirst, _ := Commit(xb, r, prover.params.H)
	first, err := prover.ProveUL(xb, r, cmfirst)
	if err != nil {
		fmt.Println("Failed to proveUL")
		return nil, err
	}

	// x - a
	xa := new(big.Int).Sub(x, new(big.Int).SetInt64(prover.a))
	cmsecond, _ := Commit(xa, r, prover.params.H)
	second, err := prover.ProveUL(xa, r, cmsecond)
	if err != nil {
		fmt.Println("Failed to proveUL")
		return nil, err
	}
	proof := &Proof{
		proof1: first,
		proof2: second,
	}
	return proof, nil
}

/*
Verify is responsible for validating the proof.
*/
func (verifier *Verifier) Verify(proof *Proof) (bool, error) {
	first, err := verifier.VerifyUL(proof.proof1)
	if err != nil {
		fmt.Println("Failed to verifyUL")
		return false, err
	}
	second, err := verifier.VerifyUL(proof.proof2)
	if err != nil {
		fmt.Println("Failed to verifyUL")
		return false, err
	}
	return first && second, nil
}
