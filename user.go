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

//GenUser generate new random keys
func GenUser() *User {
	//generate random private keys
	mu := GenExp()
	v := GenExp()
	//compute public key
	pk := BN254.G2mul(B2, mu)
	return &User{pk, mu, v}
}

//EncapsulateKey encapsulated an encryption key
//key encryption key to be encapsulated
//private keys are taken from User struct u
//return encapsulated key
func (u User) EncapsulateKey(key *BN254.ECP2) *BN254.ECP2 {
	return FracMult(key, u.mu, u.v)
}

//UnlockKey unlock an encapsulated key for decryption
//keyEnc encapsulated key to be unlocked
//private keys are taken from User struct u
//return unlocked key
func (u User) UnlockKey(keyEnc *BN254.ECP2) *BN254.ECP2 {
	return FracMult(keyEnc, u.v, u.mu)
}

//EncryptFile read file and ecrypt/decrypt concurrently
//then collect results and write on file
//inptutFile path to input file
//outputFile path to output file
//eps masking shards for encryption
//key encryption key
func EncryptFile(inputFile, outputFile string, eps []BN254.ECP, key *BN254.ECP2) {
	//compute file size, terminate if too big (not enough shards to process it)
	fi, err := os.Stat(inputFile)
	if err != nil {
		fmt.Println(err)
		return
	}
	//count number of shards necessary, including possibly partial last chunk
	numShards := (int(fi.Size())-1)/ShardSize + 1
	if numShards > MaxShards {
		fmt.Println("File too big!")
		return
	}
	encr := func(inp shard) shard {
		//encrypt using appropriate masking shard
		ct := OneTimePad([]byte(inp.value), &eps[inp.index], key)
		//feed result to output channel
		return shard{inp.index, string(ct)}
	}
	ProcessFile(inputFile, outputFile, encr, numShards, ShardSize)
}

//AddBlock encrypt a file and add it to the ledger
//ledger struct with file paths of the ledger
//token encryption token given by filekeeper
//fileName path to file to encrypt
//return the index of the added block (and corresponding encapsulated key)
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
	ctName := ledger.EncryptPath + strconv.FormatInt(keyIndex, 16) + ".enc"
	//encrypt file
	EncryptFile(fileName, ctName, eps[:], key)
	//compute content concatenating digests
	//first hash of previous block
	content := FileDigest(ledger.RootPath + strconv.FormatInt(keyIndex, 16))
	//then plaintext and ciphertext
	content = append(content, FileDigest(fileName)...)
	content = append(content, FileDigest(ctName)...)
	//finally control shard
	content = append(content, HashAte(&eps[keyIndex%MaxShards], keyEnc)...)
	//write block on file
	blockName := ledger.RootPath + strconv.FormatInt(keyIndex+1, 16)
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
