package brs

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"testing"
	"time"
)

func TestSample(t *testing.T) {
	brs := SetupUL(2, 1)
	k, _ := rand.Int(rand.Reader, brs.curve.N)
	e, _ := rand.Int(rand.Reader, brs.curve.N)
	einverse := new(big.Int).ModInverse(e, brs.curve.N)
	keinverse := new(big.Int).Mul(k, einverse)
	keinverse = keinverse.Mod(keinverse, brs.curve.N)
	keGx, keGy := brs.curve.ScalarBaseMult(keinverse.Bytes())

	kGx, kGy := brs.curve.ScalarBaseMult(k.Bytes())
	keGx2, keGy2 := brs.curve.ScalarMult(kGx, kGy, einverse.Bytes())

	fmt.Println(keGx, keGy)
	fmt.Println(keGx2, keGy2)
}

func TestRange(t *testing.T) {
	brs := SetupUL(10, 8) //range should be within [0,u^l), [0,10^2)
	value, _ := rand.Int(rand.Reader, new(big.Int).SetInt64(100))

	//generate proof
	start := time.Now()
	proof, rsum := brs.ProveUL(value)
	elapsed := time.Since(start)
	log.Printf("Prove took %s", elapsed)

	//calculate commitment
	cmx1, cmy1 := Commit(value, rsum, brs.hx, brs.hy)

	//verify proof
	start2 := time.Now()
	result := brs.VerifyUL(proof, cmx1, cmy1)
	elapsed2 := time.Since(start2)
	log.Printf("Verify took %s", elapsed2)

	if result != true {
		t.Errorf("Proof verification failed")
	}

}
