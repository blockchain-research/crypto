/*
Implements the borromean ring signature
*/
package brs

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
)

type SignerParams struct {
	curve   *btcec.KoblitzCurve
	pubkey  [][]*btcec.PublicKey //Pi,j
	length  []int64              //the length of each Pi vector: 0<=j<len[i]
	index   []int64              //the index of x's pubkey in Pi
	privkey []*btcec.PrivateKey  //user's private key at index
}

type VerifierParams struct {
	curve  *btcec.KoblitzCurve
	pubkey [][]*btcec.PublicKey //Pi,j
	length []int64              //the length of each Pi vector: 0<=j<len[i]
}

type Signature struct {
	e0 *big.Int
	s  [][]*big.Int
}

/*
ring: [[0,1,2],[1,2,3]] means {P0 or P1 or P2} and {P1 or P2 or P3}
P1 can make a valid signature; P2 can make a valid signature; P0 and P3 can together make a valid signature
xid: id of signer at each ring [1,1] means P1 signs for both sub-ring; [0,3] means P0 signs subring1 and P3 signs subring3
N: total number of signers in the ring, 4
*/
func initRing(ring [][]int64, xid []int64, N int64) (*SignerParams, *VerifierParams, error) {
	var i int64
	var err error

	//initialize curve
	curve := btcec.S256()

	//initialize SignerPrams
	signer := &SignerParams{
		curve: curve,
	}

	//initialize VerifierParams
	verifier := &VerifierParams{
		curve: curve,
	}

	//initialize P, len, index
	L := len(ring)
	P := make([][]*btcec.PublicKey, L)
	length := make([]int64, L)
	index := make([]int64, L)
	x := make([]*btcec.PrivateKey, L)

	//initialize N public keys
	priv := make([]*btcec.PrivateKey, N)
	pub := make([]*btcec.PublicKey, N)
	for i = 0; i < N; i++ {
		priv[i], err = btcec.NewPrivateKey(curve)
		if err != nil {
			fmt.Errorf("error generating private key")
			return signer, verifier, err
		}
		pub[i] = priv[i].PubKey()
	}

	//calculate P, len and index based on ring
	for j := range ring {
		length[j] = int64(len(ring[j]))
		P[j] = make([]*btcec.PublicKey, len(ring[j]))

		for k := range ring[j] {
			P[j][k] = pub[ring[j][k]]
			if ring[j][k] == xid[j] {
				index[j] = int64(k)
				x[j] = priv[xid[j]]
			}
		}
	}

	signer.index = index
	signer.length = length
	signer.pubkey = P
	signer.privkey = x

	verifier.length = length
	verifier.pubkey = P

	return signer, verifier, nil

}

func (signer *SignerParams) Sign(msg []byte) *Signature {
	var j int64
	L := len(signer.pubkey)

	//initialize k len: l
	var k = make([]*big.Int, L)
	//initialize kG len: l
	var kGx = make([]*big.Int, L)
	var kGy = make([]*big.Int, L)

	//initialize e
	e := make([][]*big.Int, L)
	for i := range e {
		e[i] = make([]*big.Int, signer.length[i])
	}
	//initialize s
	s := make([][]*big.Int, L)
	for i := range s {
		s[i] = make([]*big.Int, signer.length[i])
	}

	//compute M as the hash of the message and the set of verification keys
	Parr := []*btcec.PublicKey{}
	for i := range signer.pubkey {
		for j = 0; j < signer.length[i]; j++ {
			Parr = append(Parr, signer.pubkey[i][j])
		}
	}
	M := HashMsgVerificationKey(msg, Parr)

	//Step2 for 0<=i<=n-1
	for i := range signer.pubkey {
		//a choose scalar ki uniformly at random
		k[i], _ = rand.Int(rand.Reader, signer.curve.N)

		//b set e(i,index[i]+1) = H(M || kiG || i ||index(i))
		kGx[i], kGy[i] = signer.curve.ScalarBaseMult(k[i].Bytes())
		if signer.index[i] < signer.length[i]-1 {
			e[i][signer.index[i]+1] = HashBigInt(
				[]*big.Int{
					M,
					kGx[i],
					kGy[i],
					new(big.Int).SetInt64(int64(i)),
					new(big.Int).SetInt64(signer.index[i]),
				},
			)
		}

		//c for index[i]+1 <= j < len[i]-1
		for j = signer.index[i] + 1; j < signer.length[i]-1; j++ {
			//choose sij at random
			s[i][j], _ = rand.Int(rand.Reader, signer.curve.N)

			//compute e(i,j+1) = H(M || sijG+eijPij || i || j)
			sGx, sGy := signer.curve.ScalarBaseMult(s[i][j].Bytes())
			ePx, ePy := signer.curve.ScalarMult(signer.pubkey[i][j].X, signer.pubkey[i][j].Y, e[i][j].Bytes())
			sumx, sumy := signer.curve.Add(sGx, sGy, ePx, ePy)
			e[i][j+1] = HashBigInt(
				[]*big.Int{
					M,
					sumx,
					sumy,
					new(big.Int).SetInt64(int64(i)),
					new(big.Int).SetInt64(j),
				},
			)
		}

	}

	//step 3
	bintArr := []*big.Int{}
	for i := range signer.pubkey {
		j = signer.length[i] - 1
		if signer.index[i] < signer.length[i]-1 {
			//choose s[i][len[i]-1] at random
			s[i][j], _ = rand.Int(rand.Reader, signer.curve.N)
			//calculate s(i,len[i]-1)G+e(i,len[i]-1)P(i,len[i]-1)
			sGx, sGy := signer.curve.ScalarBaseMult(s[i][j].Bytes())
			ePx, ePy := signer.curve.ScalarMult(signer.pubkey[i][j].X, signer.pubkey[i][j].Y, e[i][j].Bytes())
			sumx, sumy := signer.curve.Add(sGx, sGy, ePx, ePy)
			bintArr = append(bintArr, sumx)
			bintArr = append(bintArr, sumy)
		} else {
			//if signer is the last in the ring
			bintArr = append(bintArr, kGx[i])
			bintArr = append(bintArr, kGy[i])
		}
	}
	e0 := HashBigInt(bintArr)

	//step 4
	for i := range signer.pubkey {
		//a for 0<=j<index[i]
		e[i][0] = e0
		for j = 0; j < signer.index[i]; j++ {
			//choose sij at ramdom
			s[i][j], _ = rand.Int(rand.Reader, signer.curve.N)

			//compute e(i,j+1) = H(M || sijG+eijPij || i || j)
			sGx, sGy := signer.curve.ScalarBaseMult(s[i][j].Bytes())
			ePx, ePy := signer.curve.ScalarMult(signer.pubkey[i][j].X, signer.pubkey[i][j].Y, e[i][j].Bytes())
			sumx, sumy := signer.curve.Add(sGx, sGy, ePx, ePy)
			e[i][j+1] = HashBigInt(
				[]*big.Int{
					M,
					sumx,
					sumy,
					new(big.Int).SetInt64(int64(i)),
					new(big.Int).SetInt64(j),
				},
			)
		}

		//b set s[i][index[i]] = k[i] - xe[i][index[i]]
		product := new(big.Int).Mul(signer.privkey[i].D, e[i][signer.index[i]])
		s[i][signer.index[i]] = new(big.Int).Sub(k[i], product)
		s[i][signer.index[i]] = new(big.Int).Mod(s[i][signer.index[i]], signer.curve.N)
	}

	return &Signature{
		e0: e0,
		s:  s,
	}
}

func (verifier *VerifierParams) Verify(msg []byte, sig *Signature) bool {
	L := len(verifier.pubkey)

	//initialize e
	e := make([][]*big.Int, L)
	for i := range e {
		e[i] = make([]*big.Int, verifier.length[i])
	}
	//initialize Rx
	Rx := make([][]*big.Int, L)
	for i := range Rx {
		Rx[i] = make([]*big.Int, verifier.length[i])
	}
	//initialize R
	Ry := make([][]*big.Int, L)
	for i := range Ry {
		Ry[i] = make([]*big.Int, verifier.length[i])
	}

	var j int64
	//compute M as the hash of the message and the set of verification keys
	Parr := []*btcec.PublicKey{}
	for i := range verifier.pubkey {
		for j = 0; j < verifier.length[i]; j++ {
			Parr = append(Parr, verifier.pubkey[i][j])
		}
	}
	M := HashMsgVerificationKey(msg, Parr)

	//for 0<=i <n-1
	for i := range verifier.pubkey {
		//for 0<=j<=len[i]-1
		e[i][0] = sig.e0
		for j = 0; j <= verifier.length[i]-1; j++ {
			//compute R[i][j] = s[i][j]G+e[i][j]P[i][j]
			sGx, sGy := verifier.curve.ScalarBaseMult(sig.s[i][j].Bytes())
			ePx, ePy := verifier.curve.ScalarMult(verifier.pubkey[i][j].X, verifier.pubkey[i][j].Y, e[i][j].Bytes())
			Rx[i][j], Ry[i][j] = verifier.curve.Add(sGx, sGy, ePx, ePy)

			if j != verifier.length[i]-1 {
				//compute e[i][j+1] = H(M || R[i][j] || i || j)
				e[i][j+1] = HashBigInt(
					[]*big.Int{
						M,
						Rx[i][j],
						Ry[i][j],
						new(big.Int).SetInt64(int64(i)),
						new(big.Int).SetInt64(j),
					},
				)
			}

		}
	}

	//calculate e0hat=H(R[0][len[0]-1]||...||R[n-1][len[n01]-1])
	bintArr := []*big.Int{}
	for i := range verifier.pubkey {
		bintArr = append(bintArr, Rx[i][verifier.length[i]-1])
		bintArr = append(bintArr, Ry[i][verifier.length[i]-1])
	}
	e0hat := HashBigInt(bintArr)

	if sig.e0.Cmp(e0hat) == 0 {
		return true
	}
	return false
}
