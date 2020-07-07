package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/gaetanorusso/public_ledger_sensitive_data/miracl/go/core/BN254"
)

//User struct that contains public and private keys of a user
type User struct {
	PublicKey *BN254.ECP2
	mu        *BN254.BIG
	v         *BN254.BIG
}

//EncapsulateKey encapsulated an encryption key
func (u User) EncapsulateKey(key *BN254.ECP2) *BN254.ECP2 {
	return KeyUpdate(key, u.mu, u.v)
}

//UnlockKey unlock an encapsulated key for decryption
func (u User) UnlockKey(keyEnc *BN254.ECP2) *BN254.ECP2 {
	return KeyUpdate(keyEnc, u.v, u.mu)
}

//GenUser generate new random keys
func GenUser() *User {
	mu := GenExp()
	v := GenExp()
	pk := BN254.G2mul(B2, mu)
	return &User{pk, mu, v}
}

//AddBlock encrypt a file and add it to the ledger
func (u User) AddBlock(ledger Ledger, token *BN254.ECP2, fileName string) int64 {
	//generate encryption key
	key := BN254.G2mul(token, GenExp())
	//compute the encapsulated key
	keyEnc := u.EncapsulateKey(key)
	//save encapsulated key on the ledger
	keyIndex := ledger.AppendEncapsulatedKey(keyEnc)
	//read masking shards from file
	eps := ledger.GetShards(MaxShards)
	//compute ciphertext file name
	ctName := strconv.FormatInt(keyIndex, 16) + ".enc"
	//encrypt file
	EncryptFile(fileName, ctName, eps[:], key)
	//compute content concatenating digests
	//first hash of previous block
	content := FileDigest(ledger.RootName + strconv.FormatInt(keyIndex, 16))
	//then plaintext and ciphertext
	content = append(content, FileDigest(fileName)...)
	content = append(content, FileDigest(ctName)...)
	//finally control shard
	content = append(content, HashAte(&eps[keyIndex%MaxShards], keyEnc)...)
	//write block on file
	blockName := ledger.RootName + strconv.FormatInt(keyIndex+1, 16)
	//open file
	file, err := os.OpenFile(blockName, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		panic(err)
	}
	//close file on exit
	defer func() {
		if err = file.Close(); err != nil {
			fmt.Println("Error closing file:", err)
		}
	}()
	//write content
	_, err = file.Write(content)
	if err != nil {
		panic(err)
	}
	return keyIndex
}
