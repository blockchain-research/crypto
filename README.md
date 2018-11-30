# crypto
Crypto components for blockchain based use case

## bn256

The bn256 folder is an implementation of a particular bilinear group at the 128-bit security level. It is a modification of the official version at https://golang.org/x/crypto/bn256, which supports negative number operations.

## ccs08

This implementation is only a modified version from https://github.com/ing-bank/zkrangeproof/ to make it work and easier to use. The ccs08 folder is an implementaion of zero-knowledge range proof based on Boneh-Boyen signature. It implements the paper "Efficient Protocols for Set Membership and Range Proofs" by IBM. 

Basic idea of the paper is : the veirifier fist sends the prover a Boneh-Boyen signature of every element in the set. The prover receives a signature on the particular element to which C is a commitment. The prover then “blinds” this received signature and performs a proof of knowledge that she possesses a signature on the committed element.

The `SetupUL`, `ProveUL` and `VerifyUL` set up the parameters, generate the proof and verify the proof for the range of [0,u^l). The proof size is (l+2)|G2| + l|GT| + (2l+2)|BINT|.

The `Setup`, `Prove` and `Verify` set up the parameters, generate the proof and verify the proof for the range of [a,b).

## brs

The brs folder is an implementation of the Borromean ring signature http://diyhpl.us/~bryan/papers2/bitcoin/Borromean%20ring%20signatures.pdf. We corrected a few notations and equations in the original algorithm and put it in this folder https://github.com/blockchain-research/brs/blob/master/brs.pdf

The range proof based on Borromean ring signature is described in the Confidential Asset paper https://blockstream.com/bitcoin17-final41.pdf. We implemented the range proof method following the paper's algorithm. The performance is around ~20 times better than ccs08. Note compared to ccs08, brs based zk-range proof does not require trusted setup. 
