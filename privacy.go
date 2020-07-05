package main

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/gaetanorusso/public_ledger_sensitive_data/miracl/go/core/BN254"
	"github.com/hashicorp/vault/helper/xor"
	"golang.org/x/crypto/sha3"
)

//constants
const BITLEN = 254 //curve bn254 modulus bit len
const BufferSize = 512

var mod *BN254.BIG = BN254.NewBIGints(BN254.Modulus)       //modulus
var order *BN254.BIG = BN254.NewBIGints(BN254.CURVE_Order) //order
var B1 *BN254.ECP = BN254.ECP_generator()                  //G1 generator
var B2 *BN254.ECP2 = BN254.ECP2_generator()                //G2 generator
const FP12LEN = BN254.MODBYTES*11 + 32                     //array len FP12 elements

func main() {
	fmt.Println("Private Ledger: Welcome!")

	/* try this if you want to test */
	//number og block
	const BLOCKNUM = 10
	//generate u_i
	var u_i [BLOCKNUM]BN254.BIG
	temp := []int{57263860497805553, 58260159264966455, 46818232996227961,
		2760510972643679, 14189843376587853, 63718175164549167,
		49812870265570060, 42530229109475574, 19855063947903198,
		44752620663305274}
	for i := 0; i < BLOCKNUM; i++ {
		u_i[i] = *BN254.NewBIGint(temp[i])
	}
	//generate s_0
	s_t0 := BN254.NewBIGint(52010173955080549)
	//initialize void vecotr eps and random exponents u_i
	var eps [BLOCKNUM]BN254.ECP
	//generate masking shards using random time-key s_t0
	MaskingShards(s_t0, u_i[:], eps[:])
	//generate a "random" message (questa libreria per random fa abbastanza ridere ;))
	message := make([]byte, 64)
	rand.Read(message)
	fmt.Println("Message:\n", message)
	//generate public/private key
	u_l := BN254.NewBIGint(986789921)
	v_l := BN254.NewBIGint(3455621)
	//generate random exponent
	k_b := BN254.NewBIGint(321231)
	//compute public key
	ql := BN254.G2mul(B2, u_l)
	//compute encryption token time 0
	token := TokenGen(ql, s_t0)
	//multply token by k_b
	t := BN254.G2mul(token, k_b)
	// c := ShardEncrypt(message[:], *k_b, &eps[0], token)
	c := OneTimePad(message, &eps[0], t)
	fmt.Println("Ciphertext:\n", c)
	//compute the encapsulated key multiplying the token by vl/ul and then by k_b
	key_enc := KeyUpdate(token, u_l, v_l)
	key_enc = BN254.G2mul(key_enc, k_b)
	//compute unlocked key for decryption multiplying the previous key by ul/vl
	unlock := KeyUpdate(key_enc, v_l, u_l)
	m := OneTimePad(c, &eps[0], unlock)
	// m := ShardDecrypt(c, &eps[0], unlock)
	fmt.Println("Plaintext:\n", m)


}

//modify this random generation with a true random
//"random" u_i generation for testing
//use this function to generate a vector u_i of BIG. You need to pass a void array in input.
func ui_gen(u_i []BN254.BIG) {
	for i := 0; i < len(u_i); i++ {
		source := rand.NewSource(time.Now().UnixNano())
		r := rand.New(source)
		u_i[i] = *BN254.NewBIGint(r.Int())
	}
}

//function used to generate the masking shards: epsilon = (ui.st_0)B1
func MaskingShards(s_t0 *BN254.BIG, u_i []BN254.BIG, eps []BN254.ECP) {
	for i := 0; i < len(u_i); i++ {
		temp := BN254.G1mul(B1, &u_i[i])
		eps[i] = *(BN254.G1mul(temp, s_t0))
	}
	return
}

//this function is used to periodically updates the shards choosing a new time-key
//s_t1 time-key at time t+1
//s_t time-key at time t
//esp is overridden
func ShardsUpdate(eps []BN254.ECP, s_t1 *BN254.BIG, s_t *BN254.BIG) {
	// var eps_up [delta]BN254.ECP
	inv := BN254.NewBIGcopy(s_t)
	inv.Invmodp(order)
	for i := 0; i < len(eps); i++ {
		temp := BN254.G1mul(&eps[i], s_t1)
		temp = BN254.G1mul(temp, inv)
		eps[i] = *temp
	}
	// return eps_up
}

//this function is used for both update and unlock the key for decryption
//to inv is the element to be INVERTED, num is the element at the numerator
func KeyUpdate(token *BN254.ECP2, to_inv *BN254.BIG, num *BN254.BIG) *BN254.ECP2 {
	inv := BN254.NewBIGcopy(to_inv)
	inv.Invmodp(order)
	t_update := BN254.G2mul(token, inv)
	t_update = BN254.G2mul(t_update, num)
	return t_update
}

//this function generates the encryption token
func TokenGen(ql *BN254.ECP2, s_t *BN254.BIG) *BN254.ECP2 {
	inv := BN254.NewBIGcopy(s_t)
	inv.Invmodp(order)
	token := BN254.G2mul(ql, inv)
	return token
}

//this function computes the Ate-pairing of the elements in input then it hashes the result
func HashAte(eps *BN254.ECP, token *BN254.ECP2) []byte {
	var g_tB [FP12LEN]byte
	g_t := BN254.Ate(token, eps)
	g_t.ToBytes(g_tB[:])
	h := sha3.Sum512(g_tB[:])
	return h[:]
}

//this function is used to xor a data input with the output of the HashAte function. It can be
//used for both encryption and decryption
func OneTimePad(data []byte, eps *BN254.ECP, token *BN254.ECP2) []byte {
	h := HashAte(eps, token)
	res, _ := xor.XORBytes(data, h[:]) //handle error
	return res
}

//encryps 64 byte message taken in input
// func ShardEncrypt(m []byte, k_b BN254.BIG, eps *BN254.ECP, token *BN254.ECP2) []byte {
// 	t := BN254.G2mul(token, &k_b)
// 	h := HashAte(eps, t)
// 	c, _ := xor.XORBytes(m[:], h[:]) //handle error
// 	return c
// }

// func KeyEncaps(token *BN254.ECP2, k_b BN254.BIG, ql *BN254.ECP2, u_l BN254.BIG, v_l BN254.BIG) *BN254.ECP2 {
// 	inv := BN254.NewBIGcopy(&u_l)
// 	inv.Invmodp(order)
// 	temp := BN254.G2mul(token, inv)
// 	temp = BN254.G2mul(temp, &v_l)
// 	k := BN254.G2mul(token, &k_b)
// 	return k
// }

// func ShardDecrypt(c []byte, eps *BN254.ECP, token *BN254.ECP2) []byte {
// 	h := HashAte(eps, token)
// 	m, _ := xor.XORBytes(c[:], h[:]) //handle error
// 	return m
// }
