package main

import (
	"fmt"
	"math/rand"
	"time"

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

var mod *BN254.BIG = BN254.NewBIGints(BN254.Modulus)       //modulus
var order *BN254.BIG = BN254.NewBIGints(BN254.CURVE_Order) //order
//B1 G1 generator
var B1 *BN254.ECP = BN254.ECP_generator()

//B2 G2 generator
var B2 *BN254.ECP2 = BN254.ECP2_generator()

//FP12LEN array len FP12 elements
const FP12LEN = BN254.MODBYTES*11 + 32

func main() {
	fmt.Println("Private Ledger: Welcome!")

	/* try this if you want to test */
	//number of block
	const BLOCKNUM = 10
	//generate u
	var u [BLOCKNUM]BN254.BIG
	temp := []int{57263860497805553, 58260159264966455, 46818232996227961,
		2760510972643679, 14189843376587853, 63718175164549167,
		49812870265570060, 42530229109475574, 19855063947903198,
		44752620663305274}
	for i := 0; i < BLOCKNUM; i++ {
		u[i] = *BN254.NewBIGint(temp[i])
	}
	//generate s_0
	s := BN254.NewBIGint(52010173955080549)
	//initialize void vecotr eps and random exponents u
	var eps [BLOCKNUM]BN254.ECP
	//generate masking shards using random time-key s
	MaskingShards(s, u[:], eps[:])
	//generate a "random" message (questa libreria per random fa abbastanza ridere ;))
	message := make([]byte, 64)
	rand.Read(message)
	fmt.Println("Message:\n", message)
	//generate public/private key
	mu := BN254.NewBIGint(986789921)
	v := BN254.NewBIGint(3455621)
	//generate random exponent
	k := BN254.NewBIGint(321231)
	//compute public key
	ql := BN254.G2mul(B2, mu)
	//compute encryption token time 0
	token := TokenGen(ql, s)
	//multply token by k
	t := BN254.G2mul(token, k)
	// c := ShardEncrypt(message[:], *k, &eps[0], token)
	c := OneTimePad(message, &eps[0], t)
	fmt.Println("Ciphertext:\n", c)
	//compute the encapsulated key multiplying the token by vl/ul and then by k
	keyEnc := KeyUpdate(token, mu, v)
	keyEnc = BN254.G2mul(keyEnc, k)
	//compute unlocked key for decryption multiplying the previous key by ul/vl
	unlock := KeyUpdate(keyEnc, v, mu)
	m := OneTimePad(c, &eps[0], unlock)
	// m := ShardDecrypt(c, &eps[0], unlock)
	fmt.Println("Plaintext:\n", m)
	EncryptFile("test.txt", "out.txt", eps[:], t)
	EncryptFile("out.txt", "dec.txt", eps[:], unlock)
}

//modify this random generation with a true random
//"random" u generation for testing
//use this function to generate a vector u of BIG. You need to pass a void array in input.
func uGen(u []BN254.BIG) {
	for i := 0; i < len(u); i++ {
		source := rand.NewSource(time.Now().UnixNano())
		r := rand.New(source)
		u[i] = *BN254.NewBIGint(r.Int())
	}
}

//MaskingShards function used to generate the masking shards: epsilon = (ui.st_0)B1
func MaskingShards(s *BN254.BIG, u []BN254.BIG, eps []BN254.ECP) {
	for i := 0; i < len(u); i++ {
		temp := BN254.G1mul(B1, &u[i])
		eps[i] = *(BN254.G1mul(temp, s))
	}
	return
}

//ShardsUpdate this function is used to periodically updates the shards choosing a new time-key
//st1 time-key at time t+1
//st time-key at time t
//esp is overridden
func ShardsUpdate(eps []BN254.ECP, st1 *BN254.BIG, st *BN254.BIG) {
	// var eps_up [delta]BN254.ECP
	inv := BN254.NewBIGcopy(st)
	inv.Invmodp(order)
	for i := 0; i < len(eps); i++ {
		temp := BN254.G1mul(&eps[i], st1)
		temp = BN254.G1mul(temp, inv)
		eps[i] = *temp
	}
	// return eps_up
}

//KeyUpdate this function is used for both update and unlock the key for decryption
//toInv is the element to be INVERTED, num is the element at the numerator
func KeyUpdate(token *BN254.ECP2, toInv *BN254.BIG, num *BN254.BIG) *BN254.ECP2 {
	inv := BN254.NewBIGcopy(toInv)
	inv.Invmodp(order)
	tUpdate := BN254.G2mul(token, inv)
	tUpdate = BN254.G2mul(tUpdate, num)
	return tUpdate
}

//TokenGen this function generates the encryption token
func TokenGen(ql *BN254.ECP2, st *BN254.BIG) *BN254.ECP2 {
	inv := BN254.NewBIGcopy(st)
	inv.Invmodp(order)
	token := BN254.G2mul(ql, inv)
	return token
}

//HashAte this function computes the Ate-pairing of the elements in input then it hashes the result
func HashAte(eps *BN254.ECP, token *BN254.ECP2) []byte {
	var gtB [FP12LEN]byte
	gt := BN254.Ate(token, eps)
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
// 	inv.Invmodp(order)
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
