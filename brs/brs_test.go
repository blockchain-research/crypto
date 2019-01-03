package brs

import (
	"testing"
)

func TestSignature(t *testing.T) {
	//Ring [[0,1,2],[1,2,3]] means {P0 or P1 or P2} and {P1 or P2 or P3}
	ring := [][]int64{[]int64{0, 1, 2}, []int64{1, 2, 3}}

	//so P1 can make a valid signature
	signer1, verifier, err := initRing(ring, []int64{1, 1}, 4)
	if err != nil {
		t.FailNow()
	}
	signature1 := signer1.Sign([]byte("ddd"))
	result1 := verifier.Verify([]byte("ddd"), signature1)
	if !result1 {
		t.FailNow()
	}

	//P2 can make a valid signature
	signer2, verifier2, err := initRing(ring, []int64{2, 2}, 4)
	if err != nil {
		t.FailNow()
	}
	signature2 := signer2.Sign([]byte("ddd"))
	result2 := verifier2.Verify([]byte("ddd"), signature2)
	if !result2 {
		t.FailNow()
	}

	//P0 and P3 can together make a valid signature
	signer03, verifier03, err := initRing(ring, []int64{0, 3}, 4)
	if err != nil {
		t.FailNow()
	}
	signature03 := signer03.Sign([]byte("ddd"))
	result03 := verifier03.Verify([]byte("ddd"), signature03)
	if !result03 {
		t.FailNow()
	}
}
