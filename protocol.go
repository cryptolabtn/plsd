package main

import (
	"crypto/rand"
	"fmt"
	"io/ioutil"

	"github.com/gaetanorusso/public_ledger_sensitive_data/miracl/go/core/BN254"
	"golang.org/x/crypto/sha3"
)

//constants

//BITLEN curve bn254 modulus bit len
const BITLEN = 254

//PadSize byte size of each shard
var PadSize = 64

//MaxShards maximum number of shards
var MaxShards = 10000

//MOD modulus of curve BN254
var MOD *BN254.BIG = BN254.NewBIGints(BN254.Modulus)

//ORDER order of curve BN254
var ORDER *BN254.BIG = BN254.NewBIGints(BN254.CURVE_Order)

//B1 G1 generator
var B1 *BN254.ECP = BN254.ECP_generator()

//B2 G2 generator
var B2 *BN254.ECP2 = BN254.ECP2_generator()

//FP12LEN array len FP12 elements
const FP12LEN = BN254.MODBYTES*11 + 32

//goodExp check that e is in [2..ORDER -1]
//e exponent to be checked
//return true iff e is in [2..ORDER -1]
func goodExp(e *BN254.BIG) bool {
	if BN254.Comp(e, BN254.NewBIGint(1)) > 0 {
		return BN254.Comp(e, ORDER) < 0
	}
	return false
}

//GenExp generate cryptographically secure random exponent
//result uniform in [2..ORDER-1]
func GenExp() *BN254.BIG {
	entropy := make([]byte, BN254.MODBYTES)
	r := BN254.NewBIGint(0)
	//continue generating until the value is in [2..ORDER-1]
	for !goodExp(r) {
		_, err := rand.Read(entropy)
		if err != nil {
			fmt.Println("Error generating random exponent:", err)
			panic(err)
		}
		r = BN254.FromBytes(entropy)
	}
	return r
}

//shardUpdate update a masking shard
//index of the shard that is being updated
//old current value of the masking shard
//s old time-key
//sNew new time-key
//returns shard struct with same index and the encoding of the new masking shard
func shardUpdate(index int, old *BN254.ECP, s, sNew *BN254.BIG) shard {
	inv := BN254.NewBIGcopy(s)
	inv.Invmodp(ORDER)
	new := BN254.G1mul(old, sNew)
	new = BN254.G1mul(new, inv)
	//encode
	encoded := make([]byte, BN254.MODBYTES+1)
	new.ToBytes(encoded, true)
	return shard{index, string(encoded)}
}

//FracMult multiplies element for fraction num/den
//used both for updating keys, and for unlocking them for decryption
//el ECP2 element to multiply
//den denominator of the fraction
//num numerator of the fraction
//returns (num/den)*el
func FracMult(el *BN254.ECP2, den, num *BN254.BIG) *BN254.ECP2 {
	inv := BN254.NewBIGcopy(den)
	inv.Invmodp(ORDER)
	result := BN254.G2mul(el, inv)
	result = BN254.G2mul(result, num)
	return result
}

//TokenGen generate the encryption token
//pubKey public key of the user that requested the token
//s time-key
//returns the encryption token
func TokenGen(pubKey *BN254.ECP2, s *BN254.BIG) *BN254.ECP2 {
	inv := BN254.NewBIGcopy(s)
	inv.Invmodp(ORDER)
	token := BN254.G2mul(pubKey, inv)
	return token
}

//HashAte computes the Ate-pairing, then it hash the result to create the pad
//eps masking shard
//key encryption key
//return the pad for encryption/decryption
func HashAte(eps *BN254.ECP, key *BN254.ECP2) []byte {
	var gtB [FP12LEN]byte
	//NB: to compute the pairing correctly the final exp has to be done explicitly
	gt := BN254.Ate(key, eps)
	gt = BN254.Fexp(gt)
	gt.ToBytes(gtB[:])
	h := sha3.Sum512(gtB[:])
	return h[:PadSize]
}

//TruncXor xor byte slices truncating the longest
//outputs the xor of the first n bytes of the two inputs
//where n is the length of the shortest input
func TruncXor(a, b []byte) []byte {
	//compute shortest length
	n := len(a)
	if len(b) < len(a) {
		n = len(b)
	}
	//compute bytewise xor
	res := make([]byte, n)
	for i := 0; i < n; i++ {
		res[i] = a[i] ^ b[i]
	}
	return res
}

//OneTimePad xor data with the pad computed as described in the protocol
//used for both encryption and decryption
//data what to encrypt/decrypt
//eps masking shard
//key encryption key
//return the processed data
func OneTimePad(data []byte, eps *BN254.ECP, key *BN254.ECP2) []byte {
	h := HashAte(eps, key)
	res := TruncXor(data, h[:]) //handle error
	return res
}

//FileDigest compute SHA3 digest of a file
//filename path to file
//returns the 64 byte digest
func FileDigest(filename string) []byte {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Println("File reading error", err)
		return nil
	}
	h := sha3.Sum512(data)
	return h[:]
}
