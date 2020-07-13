package main

import (
	"fmt"
	"os"
	"strconv"

	curve "github.com/gaetanorusso/public_ledger_sensitive_data/miracl/go/core/BN254"
)

//User struct that contains public and private keys of a user
type User struct {
	PublicKey *curve.ECP2
	mu        *curve.BIG
	v         *curve.BIG
}

//GenUser generate new random keys
func GenUser() *User {
	//generate random private keys
	mu := GenExp()
	v := GenExp()
	//compute public key
	pk := curve.G2mul(B2, mu)
	return &User{pk, mu, v}
}

//EncapsulateKey encapsulated an encryption key
//key encryption key to be encapsulated
//private keys are taken from User struct u
//return encapsulated key
func (u User) EncapsulateKey(key *curve.ECP2) *curve.ECP2 {
	return FracMult(key, u.mu, u.v)
}

//UnlockKey unlock an encapsulated key for decryption
//keyEnc encapsulated key to be unlocked
//private keys are taken from User struct u
//return unlocked key
func (u User) UnlockKey(keyEnc *curve.ECP2) *curve.ECP2 {
	return FracMult(keyEnc, u.v, u.mu)
}

//CountShards compute number of shards necessary to encrypt a file
//filePath path to file
//return number of shards necessary to encrypt
//including the possibly partial last chunk
func CountShards(filePath string) int {
	//compute file size
	fi, err := os.Stat(filePath)
	if err != nil {
		panic(err)
	}
	return (int(fi.Size())-1)/PadSize + 1
}

//EncryptFile read file and ecrypt/decrypt concurrently
//then collect results and write on file
//inptutFile path to input file
//outputFile path to output file
//eps masking shards for encryption
//key encryption key
func EncryptFile(inputFile, outputFile string, eps []curve.ECP, key *curve.ECP2) {
	//check that there are enough masking shards to encrypt
	numShards := CountShards(inputFile)
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
	ProcessFile(inputFile, outputFile, encr, numShards, PadSize)
}

//AddBlock encrypt a file and add it to the ledger
//ledger struct with file paths of the ledger
//token encryption token given by filekeeper
//fileName path to file to encrypt
//return the index of the added block (and corresponding encapsulated key)
func (u User) AddBlock(ledger Ledger, token *curve.ECP2, fileName string) int64 {
	//compute no. of shards necessary, for checking and optimal reading
	numShards := CountShards(fileName)
	//generate encryption key
	key := curve.G2mul(token, GenExp())
	//compute the encapsulated key
	keyEnc := u.EncapsulateKey(key)
	//save encapsulated key on the ledger
	keyIndex := ledger.AppendEncapsulatedKey(keyEnc)
	//read masking shards from file
	eps := ledger.GetShards(numShards)
	//compute ciphertext file name
	ctName := ledger.EncryptPath + strconv.FormatInt(keyIndex, 16) + ".enc"
	//encrypt file
	EncryptFile(fileName, ctName, eps[:], key)
	//compute content concatenating digests
	//first hash of previous block
	content := FileDigest(ledger.RootPath + strconv.FormatInt(keyIndex, 16))
	//then ciphertext and plaintext
	content = append(content, FileDigest(ctName)...)
	content = append(content, FileDigest(fileName)...)
	//finally control shard
	i := keyIndex % int64(MaxShards)
	if i < int64(numShards) {
		content = append(content, HashAte(&eps[i], keyEnc)...)
	} else {
		content = append(content, HashAte(ledger.GetSingleShard(i), keyEnc)...)
	}
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
