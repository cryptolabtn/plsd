package main

import (
	"crypto/rand"
	"fmt"

	"github.com/gaetanorusso/public_ledger_sensitive_data/miracl/go/core/BN254"
	"golang.org/x/crypto/sha3"
)

//constants

//BITLEN curve bn254 modulus bit len
const BITLEN = 254

//ShardSize byte size of each shard
const ShardSize = 64

//MaxShards maximum number of shards
const MaxShards = 10

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

func main() {
	fmt.Println("Private Ledger: Welcome!")

	/* try this if you want to test */
	//generate shards and get time-key
	s := InitUpdLedger("test/shards.enc")
	//read masking shards from file
	eps := GetShards("test/shards.enc", MaxShards)

	//generate user keys
	u := GenUser()
	//compute encryption token
	token := TokenGen(u.PublicKey, s)
	//generate encryption key
	key := BN254.G2mul(token, GenExp())
	//compute the encapsulated key
	keyEnc := u.EncapsulateKey(key)
	//save encapsulated key on the ledger
	keyIndex := AppendEncapsulatedKey("test/keys.enc", keyEnc)
	//encrypt file
	EncryptFile("test/test.txt", "test/out.txt", eps[:], key)
	//unlock key from the ledger
	unlock := u.UnlockKey(GetEncKey("test/keys.enc", keyIndex))
	//decrypt file
	EncryptFile("test/out.txt", "test/dec.txt", eps[:], unlock)
	//update ledger
	sNew := UpdateLedger("test/keys.enc", "test/shards.enc", s)
	//compare time keys
	fmt.Println(s.ToString())
	fmt.Println(sNew.ToString())
	//get updated encapsulated key from ledger
	keyEncNew := GetEncKey("test/keys.enc", keyIndex)
	//unlock key
	unlockNew := u.UnlockKey(keyEncNew)
	//get updated shards from ledger
	epsNew := GetShards("test/shards.enc", MaxShards)
	//decrypt file again
	EncryptFile("test/out.txt", "test/dec2.txt", epsNew[:], unlockNew)
}

//goodExp check that e is in [2..ORDER -1]
func goodExp(e *BN254.BIG) bool {
	if BN254.Comp(e, BN254.NewBIGint(1)) > 0 {
		return BN254.Comp(e, ORDER) < 0
	}
	return false
}

//GenExp generate cryptographically secure random exponent
//result uniform in [2..ORDER - 1]
func GenExp() *BN254.BIG {
	entropy := make([]byte, BN254.MODBYTES)
	r := BN254.NewBIGint(0)
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

//shardUpdate update a shard
//sNew new time-key
//s old time-key
//esp shard value
//output channel where to feed the updated shard
func shardUpdate(index int, old *BN254.ECP, s, sNew *BN254.BIG) shard {
	inv := BN254.NewBIGcopy(s)
	inv.Invmodp(ORDER)
	temp := BN254.G1mul(old, sNew)
	new := BN254.G1mul(temp, inv)
	encoded := make([]byte, BN254.MODBYTES+1)
	new.ToBytes(encoded, true)
	return shard{index, string(encoded)}
}

//KeyUpdate this function is used for both update and unlock the key for decryption
//toInv is the element to be INVERTED, num is the element at the numerator
func KeyUpdate(token *BN254.ECP2, toInv, num *BN254.BIG) *BN254.ECP2 {
	inv := BN254.NewBIGcopy(toInv)
	inv.Invmodp(ORDER)
	tUpdate := BN254.G2mul(token, inv)
	tUpdate = BN254.G2mul(tUpdate, num)
	return tUpdate
}

//TokenGen this function generates the encryption token
func TokenGen(ql *BN254.ECP2, st *BN254.BIG) *BN254.ECP2 {
	inv := BN254.NewBIGcopy(st)
	inv.Invmodp(ORDER)
	token := BN254.G2mul(ql, inv)
	return token
}

//HashAte this function computes the Ate-pairing of the elements in input then it hashes the result
func HashAte(eps *BN254.ECP, token *BN254.ECP2) []byte {
	var gtB [FP12LEN]byte
	gt := BN254.Ate(token, eps)
	gt = BN254.Fexp(gt)
	gt.ToBytes(gtB[:])
	h := sha3.Sum512(gtB[:])
	return h[:ShardSize]
}

//OneTimePad this function is used to xor a data input with the output of the HashAte function. It can be
//used for both encryption and decryption
func OneTimePad(data []byte, eps *BN254.ECP, token *BN254.ECP2) []byte {
	h := HashAte(eps, token)
	res := TruncXor(data, h[:]) //handle error
	return res
}
