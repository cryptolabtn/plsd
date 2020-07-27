package main

import (
	"crypto/rand"
	"fmt"
	"io/ioutil"

	curve "github.com/gaetanorusso/public_ledger_sensitive_data/miracl/go/core/BN254"
	"golang.org/x/crypto/sha3"
)

//constants

//BITLEN curve bn254 modulus bit len
const BITLEN = 254

//HashLen size of hash digest in bytes
const HashLen = 64

//Hash hash function used for integrity Checks
var Hash func([]byte) [HashLen]byte = sha3.Sum512

//PadSize byte size of each shard
var PadSize = 96

//MapHash XOF hash function used to build the uniform mapping used in encryption
var MapHash func([]byte, []byte) = sha3.ShakeSum256

//MaxShards maximum number of shards
var MaxShards = 10000

//MOD modulus of curve
var MOD *curve.BIG = curve.NewBIGints(curve.Modulus)

//ORDER order of curve
var ORDER *curve.BIG = curve.NewBIGints(curve.CURVE_Order)

//B1 G1 generator
var B1 *curve.ECP = curve.ECP_generator()

//B2 G2 generator
var B2 *curve.ECP2 = curve.ECP2_generator()

//FP12LEN array len FP12 elements
const FP12LEN = curve.MODBYTES*11 + 32

//GenExp generate cryptographically secure random exponent
//result uniform in [2..ORDER-1]
func GenExp() *curve.BIG {
	entropy := make([]byte, curve.MODBYTES)
	r := curve.NewBIGint(0)
	//continue generating until the value is in [2..ORDER-1]
	for curve.Comp(r, curve.NewBIGint(1)) <= 0 {
		_, err := rand.Read(entropy)
		if err != nil {
			fmt.Println("Error generating random exponent:", err)
			panic(err)
		}
		r = curve.FromBytes(entropy)
		r.Mod(ORDER)
	}
	return r
}

//shardUpdate update a masking shard
//index of the shard that is being updated
//old current value of the masking shard
//s old time-key
//sNew new time-key
//returns shard struct with same index and the encoding of the new masking shard
func shardUpdate(index int, old *curve.ECP2, s, sNew *curve.BIG) shard {
	inv := curve.NewBIGcopy(s)
	inv.Invmodp(ORDER)
	new := curve.G2mul(old, sNew)
	new = curve.G2mul(new, inv)
	//encode
	encoded := make([]byte, 2*curve.MODBYTES+1)
	new.ToBytes(encoded, true)
	return shard{index, string(encoded)}
}

//FracMult multiplies element for fraction num/den
//used both for updating keys, and for unlocking them for decryption
//el ECP2 element to multiply
//den denominator of the fraction
//num numerator of the fraction
//returns (num/den)*el
func FracMult(el *curve.ECP, den, num *curve.BIG) *curve.ECP {
	inv := curve.NewBIGcopy(den)
	inv.Invmodp(ORDER)
	result := curve.G1mul(el, inv)
	result = curve.G1mul(result, num)
	return result
}

//TokenGen generate the encryption token
//pubKey public key of the user that requested the token
//s time-key
//returns the encryption token
func TokenGen(pubKey *curve.ECP, s *curve.BIG) *curve.ECP {
	inv := curve.NewBIGcopy(s)
	inv.Invmodp(ORDER)
	token := curve.G1mul(pubKey, inv)
	return token
}

//HashAte computes the Ate-pairing, then it hash the result to create the pad
//eps masking shard
//key encryption key
//return the pad for encryption/decryption
func HashAte(eps *curve.ECP2, key *curve.ECP) []byte {
	var gtB [FP12LEN]byte
	//NB: to compute the pairing correctly the final exp has to be done explicitly
	gt := curve.Ate(eps, key)
	gt = curve.Fexp(gt)
	gt.ToBytes(gtB[:])
	//apply uniform mapping
	digest := make([]byte, PadSize)
	MapHash(digest, gtB[:])
	return digest
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
func OneTimePad(data []byte, eps *curve.ECP2, key *curve.ECP) []byte {
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
	h := Hash(data)
	return h[:]
}
