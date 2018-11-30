package ccs08

import (
	"encoding/binary"
	"math/big"

	"github.com/blockchain-research/crypto/bn256"
)

/*
Marshal is for marshaling the ProofULVerifier into []byte
*/
func (p *ProofUL) Marshal() []byte {
	const bLInt int = 32
	var ret []byte

	//processing V
	for _, element := range p.V {
		bV := element.Marshal()
		ret = append(ret, bV...)
	}

	//processing D
	bD := p.D.Marshal()
	ret = append(ret, bD...)

	//processing C
	bC := p.C.Marshal()
	ret = append(ret, bC...)

	//processing a
	for _, element := range p.a {
		ba := element.Marshal()
		ret = append(ret, ba...)
	}

	//processing zsig
	for _, element := range p.zsig {
		bzsig := make([]byte, bLInt, bLInt)
		b := element.Bytes()
		copy(bzsig[bLInt-len(b):], b)
		ret = append(ret, bzsig...)
	}

	//processing zv
	for _, element := range p.zv {
		bzv := make([]byte, bLInt, bLInt)
		b := element.Bytes()
		copy(bzv[bLInt-len(b):], b)
		ret = append(ret, bzv...)
	}

	//processing c, m, zr
	bc := make([]byte, bLInt, bLInt)
	b := p.c.Bytes()
	copy(bc[bLInt-len(b):], b)
	ret = append(ret, bc...)

	bzr := make([]byte, bLInt, bLInt)
	b = p.zr.Bytes()
	copy(bzr[bLInt-len(b):], b)
	ret = append(ret, bzr...)

	return ret
}

/*
UnMarshal is for converting []byte back into proofUL
proof byte size: (l+2)|G2| + l|GT| + (2l+2)|BINT|
*/
func Unmarshal(m []byte, p *ProofUL) {
	const bLG2 int64 = 128
	const bLGT int64 = 384
	const bLInt int64 = 32
	var i int64
	L := (int64(len(m)) - 2*bLG2 - 2*bLInt) / (bLG2 + bLGT + 2*bLInt)
	//getting V
	for i = 0; i < L; i++ {
		v, _ := new(bn256.G2).Unmarshal(m[i*bLG2 : (i+1)*bLG2])
		p.V = append(p.V, v)
	}

	//getting D
	p.D, _ = new(bn256.G2).Unmarshal(m[L*bLG2 : (L+1)*bLG2])

	//getting C
	p.C, _ = new(bn256.G2).Unmarshal(m[(L+1)*bLG2 : (L+2)*bLG2])

	//getting a
	index := (L + 2) * bLG2
	for i = 0; i < L; i++ {
		a, _ := new(bn256.GT).Unmarshal(m[index+i*bLGT : index+(i+1)*bLGT])
		p.a = append(p.a, a)
	}

	//get zsig
	index = (L+2)*bLG2 + L*bLGT
	for i = 0; i < L; i++ {
		zsig := new(big.Int).SetBytes(m[index+i*bLInt : index+(i+1)*bLInt])
		p.zsig = append(p.zsig, zsig)
	}

	//get zv
	index = (L+2)*bLG2 + L*bLGT + L*bLInt
	for i = 0; i < L; i++ {
		zv := new(big.Int).SetBytes(m[index+i*bLInt : index+(i+1)*bLInt])
		p.zv = append(p.zv, zv)
	}

	//get c, m, zr
	index = (L+2)*bLG2 + L*bLGT + (L*2)*bLInt
	p.c = new(big.Int).SetBytes(m[index : index+bLInt])

	index = (L+2)*bLG2 + L*bLGT + (L*2+1)*bLInt
	p.zr = new(big.Int).SetBytes(m[index : index+bLInt])
	return
}

/*
Marshal is for marshaling the ParamsULVerifier into []byte
*/
func (v *Verifier) Marshal() []byte {
	const bLInt64 int = binary.MaxVarintLen64
	var ret []byte
	//processing H
	bH := v.params.H.Marshal()
	ret = append(ret, bH...)

	//processing pubk
	bpubk := v.params.pubk.Marshal()
	ret = append(ret, bpubk...)

	//processing u
	bu := make([]byte, bLInt64, bLInt64)
	binary.PutVarint(bu, v.params.u)
	ret = append(ret, bu...)

	//processing l
	bl := make([]byte, bLInt64, bLInt64)
	binary.PutVarint(bl, v.params.l)
	ret = append(ret, bl...)

	return ret
}

/*
UnMarshal is for converting []byte back into ParamsULVerifier
*/
func (v *Verifier) Unmarshal(m []byte) {
	const bLInt64 int64 = binary.MaxVarintLen64
	const bLG2 int64 = 128
	const bLG1 int64 = 64

	if v.params == nil {
		v.params = &ParamsULVerifier{}
	}
	//getting H
	v.params.H, _ = new(bn256.G2).Unmarshal(m[0:bLG2])

	//getting pubk
	v.params.pubk, _ = new(bn256.G1).Unmarshal(m[bLG2 : bLG1+bLG2])

	//getting u
	v.params.u, _ = binary.Varint(m[bLG1+bLG2 : bLG1+bLG2+bLInt64])

	//getting l
	v.params.l, _ = binary.Varint(m[bLG1+bLG2+bLInt64 : bLG1+bLG2+2*bLInt64])
	return
}
