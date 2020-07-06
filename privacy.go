package main

import (
	"crypto/rand"
	"fmt"
	"sync"

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
	s := InitUpdLedger("shards.enc")
	//read masking shards from file
	eps := GetShards("shards.enc", MaxShards)

	//generate user keys
	u := GenUser()
	//compute encryption token
	token := TokenGen(u.PublicKey, s)
	//generate encryption key
	key := BN254.G2mul(token, GenExp())
	//compute the encapsulated key
	keyEnc := u.EncapsulateKey(key)
	//save encapsulated key on the ledger
	keyIndex := AppendEncapsulatedKeys("keys.enc", keyEnc)
	//encrypt file
	EncryptFile("test.txt", "out.txt", eps[:], key)
	//unlock key from the ledger
	unlock := u.UnlockKey(GetEncKey("keys.enc", keyIndex))
	//decrypt file
	EncryptFile("out.txt", "dec.txt", eps[:], unlock)
	//update ledger
	sNew := UpdateLedger("keys.enc", "shards.enc", s)
	//compare time keys
	fmt.Println(s.ToString())
	fmt.Println(sNew.ToString())
	//get updated encapsulated key from ledger
	keyEncNew := GetEncKey("keys.enc", keyIndex)
	//unlock key
	unlockNew := u.UnlockKey(keyEncNew)
	//get updated shards from ledger
	epsNew := GetShards("shards.enc", MaxShards)
	//decrypt file again
	EncryptFile("out.txt", "dec2.txt", epsNew[:], unlockNew)
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

//genShard generate a shard cuncurrently
//output channel to return results
//s time-key
func genShard(output chan *BN254.ECP, wg *sync.WaitGroup, s *BN254.BIG) {
	temp := BN254.G1mul(B1, GenExp())
	output <- BN254.G1mul(temp, s)
	wg.Done()
}

//collectShards collect shards generated concurrently
func collectShards(input chan *BN254.ECP, eps []BN254.ECP, done chan bool) {
	i := 0
	for shard := range input {
		eps[i] = *shard
		i++
	}
	done <- true
}

//maskingShardsGen function used to generate the masking shards
func maskingShardsGen(s *BN254.BIG, eps []BN254.ECP) {
	//concurrently generate each shard
	var wg sync.WaitGroup
	shardChannel := make(chan *BN254.ECP, len(eps))
	for i := 0; i < len(eps); i++ {
		wg.Add(1)
		go genShard(shardChannel, &wg, s)
	}
	//collect results
	done := make(chan bool)
	go collectShards(shardChannel, eps, done)
	wg.Wait()
	close(shardChannel)
	<-done
}

type mask struct {
	index int
	eps   *BN254.ECP
}

//shardUpdate concurrently update a shard
//sNew new time-key
//s old time-key
//esp shard value
//output channel where to feed the updated shard
func shardUpdate(old mask, s, sNew *BN254.BIG) shard {
	inv := BN254.NewBIGcopy(s)
	inv.Invmodp(ORDER)
	temp := BN254.G1mul(old.eps, sNew)
	new := BN254.G1mul(temp, inv)
	encoded := make([]byte, BN254.MODBYTES+1)
	new.ToBytes(encoded, true)
	return shard{old.index, string(encoded)}
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

//encryps 64 byte message taken in input
// func ShardEncrypt(m []byte, k BN254.BIG, eps *BN254.ECP, token *BN254.ECP2) []byte {
// 	t := BN254.G2mul(token, &k)
// 	h := HashAte(eps, t)
// 	c, _ := xor.XORBytes(m[:], h[:]) //handle error
// 	return c
// }

// func KeyEncaps(token *BN254.ECP2, k BN254.BIG, ql *BN254.ECP2, mu BN254.BIG, v BN254.BIG) *BN254.ECP2 {
// 	inv := BN254.NewBIGcopy(&mu)
// 	inv.Invmodp(ORDER)
// 	temp := BN254.G2mul(token, inv)
// 	temp = BN254.G2mul(temp, &v)
// 	k := BN254.G2mul(token, &k)
// 	return k
// }

// func ShardDecrypt(c []byte, eps *BN254.ECP, token *BN254.ECP2) []byte {
// 	h := HashAte(eps, token)
// 	m, _ := xor.XORBytes(c[:], h[:]) //handle error
// 	return m
// }
