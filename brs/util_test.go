package brs

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/stretchr/testify/assert"
)

func TestNeg(t *testing.T) {
	h := GetBigInt("18560948149108576432482904553159745978835170526553990798435819795989606410925")
	s256 := btcec.S256()
	hx, hy := s256.ScalarBaseMult(h.Bytes())
	a := new(big.Int).SetInt64(110)
	ax, ay := s256.ScalarMult(hx, hy, a.Bytes())
	b := new(big.Int).SetInt64(-110)
	bx, by := s256.ScalarMult(hx, hy, b.Bytes())
	fmt.Println(a)
	fmt.Println(ax)
	fmt.Println(ay)
	fmt.Println(b)
	fmt.Println(bx)
	fmt.Println(by)

	array := []string{"111", "222"}
	fmt.Println(array[len(array)-1])
}
func TestCommit(t *testing.T) {
	//set up h
	s0 := sha256.Sum256(new(big.Int).SetInt64(0).Bytes())
	fmt.Println(s0)
	s1 := sha256.Sum256(new(big.Int).SetInt64(1).Bytes())
	fmt.Println(s1)

	h := GetBigInt("18560948149108576432482904553159745978835170526553990798435819795989606410925")
	s256 := btcec.S256()
	hx, hy := s256.ScalarBaseMult(h.Bytes())

	//commit to x1, r1
	x1 := new(big.Int).SetInt64(110)
	r1, _ := rand.Int(rand.Reader, s256.N)
	cmx1, cmy1 := Commit(x1, r1, hx, hy)

	//commit to x2, r2
	x2 := new(big.Int).SetInt64(90)
	r2, _ := rand.Int(rand.Reader, s256.N)
	cmx2, cmy2 := Commit(x2, r2, hx, hy)

	//commit to x1+x2, r1+r2
	xSum := new(big.Int).Add(x1, x2)
	rSum := new(big.Int).Add(r1, r2)
	cmxSum, cmySum := Commit(xSum, rSum, hx, hy)
	fmt.Println(cmxSum)
	fmt.Println(cmySum)

	//add commitment1 and commitment2 together
	x3, y3 := s256.Add(cmx1, cmy1, cmx2, cmy2)
	fmt.Println(x3)
	fmt.Println(y3)

	if cmxSum.Cmp(x3) != 0 || cmySum.Cmp(y3) != 0 {
		t.Errorf("Additive homormophism check fail")
	}

}

func TestBase(t *testing.T) {
	//commit to x1, r1
	x := new(big.Int).SetInt64(8734)

	vBase := []*big.Int{
		new(big.Int).SetInt64(4),
		new(big.Int).SetInt64(3),
		new(big.Int).SetInt64(7),
		new(big.Int).SetInt64(8),
		new(big.Int).SetInt64(0),
	}
	mBase := []*big.Int{
		new(big.Int).SetInt64(1),
		new(big.Int).SetInt64(10),
		new(big.Int).SetInt64(100),
		new(big.Int).SetInt64(1000),
		new(big.Int).SetInt64(10000),
	}

	v, m := GetBaseRepresentation(x, 10, 5)
	fmt.Println(v)
	fmt.Println(m)
	assert.Equal(t, vBase, v, "The two arrays should be the same.")
	assert.Equal(t, mBase, m, "The two arrays should be the same.")

}
