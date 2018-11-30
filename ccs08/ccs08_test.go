package ccs08

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/blockchain-research/crypto/bn256"
)

/*
Tests the ZK Range Proof building block, where the interval is [0, U^L).
*/
func TestZKRP_UL(t *testing.T) {
	prover, verifier, err := SetupUL(10, 5)
	if err != nil {
		t.Errorf("failed to setup")
		t.FailNow()
	}

	//generate the pedersen commitment
	r, _ := rand.Int(rand.Reader, bn256.Order)
	x := new(big.Int).SetInt64(176)
	cm, _ := Commit(x, r, prover.params.H)

	//prover generate the proof
	proof, err := prover.ProveUL(x, r, cm)
	if err != nil {
		t.Errorf("failed to prove")
		t.FailNow()
	}

	//verifier verify the proof
	result, err := verifier.VerifyUL(proof)
	if err != nil {
		t.Errorf("failed to verify")
		t.FailNow()
	}
	fmt.Println("ZKRP UL result: ")
	fmt.Println(result)
	if result != true {
		t.Errorf("Assert failure: expected true, actual: %t", result)
	}
}

func TestZKRP_UL_Marshal(t *testing.T) {
	prover, verifier, err := SetupUL(10, 5)
	if err != nil {
		t.Errorf("failed to setup")
		t.FailNow()
	}

	//generate the pedersen commitment
	r, _ := rand.Int(rand.Reader, bn256.Order)
	x := new(big.Int).SetInt64(176)
	cm, _ := Commit(x, r, prover.params.H)

	//prover generate the proof
	proof, err := prover.ProveUL(x, r, cm)
	if err != nil {
		t.Errorf("failed to prove")
		t.FailNow()
	}

	//marshal and unmarshal verifier
	paramBytes := verifier.Marshal()
	verifier2 := &Verifier{}
	verifier2.Unmarshal(paramBytes)

	//marshal and unmarshal proof
	proofBytes := proof.Marshal()
	proof2 := &ProofUL{}
	Unmarshal(proofBytes, proof2)

	//verifier verify the proof
	result, err := verifier2.VerifyUL(proof2)
	if err != nil {
		t.Errorf("failed to verify")
		t.FailNow()
	}
	fmt.Println("ZKRP UL result: ")
	fmt.Println(result)
	if result != true {
		t.Errorf("Assert failure: expected true, actual: %t", result)
	}
}

/*
Tests the ZK Range Proof building block, where the interval is [a,b).
*/
func TestZKRP(t *testing.T) {
	prover, verifier, err := Setup(0, 100)
	if err != nil {
		t.Errorf("failed to setup")
		t.FailNow()
	}

	//generate the pedersen commitment
	r, _ := rand.Int(rand.Reader, bn256.Order)
	x := new(big.Int).SetInt64(76)
	//cm, _ := Commit(x, r, prover.params.H)

	//prover generate the proof
	proof, err := prover.Prove(x, r)
	if err != nil {
		t.Errorf("failed to prove")
		t.FailNow()
	}

	//verifier verify the proof
	result, err := verifier.Verify(proof)
	if err != nil {
		t.Errorf("failed to verify")
		t.FailNow()
	}
	fmt.Println("ZKRP UL result: ")
	fmt.Println(result)
	if result != true {
		t.Errorf("Assert failure: expected true, actual: %t", result)
	}
	t.Log("The value is in the range [a,b)")
}
