package main

import (
	"fmt"
	"os"

	"github.com/gaetanorusso/public_ledger_sensitive_data/miracl/go/core/BN254"
)

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

//encrypt concurrently encrypt each chunk
func encrypt(pt shard, eps []BN254.ECP, key *BN254.ECP2) shard {
	//encrypt using appropriate shard
	ct := OneTimePad([]byte(pt.value), &eps[pt.index], key)
	//feed result to output channel
	return shard{pt.index, string(ct)}
}

//EncryptFile read file and ecrypt concurrently
//then collect results and write on file
//cleartextFile path to input file
//ciphertextFile path to output file
//eps slice of shards for encryption
//key encryption key
func EncryptFile(cleartextFile, ciphertextFile string, eps []BN254.ECP, key *BN254.ECP2) {
	//compute file size, terminate if too big (not enough shards to encrypt it)
	fi, err := os.Stat(cleartextFile)
	if err != nil {
		fmt.Println(err)
		return
	}
	//compute number of shards counting possible incomplete last shard
	numShards := (int(fi.Size())-1)/ShardSize + 1
	if numShards > MaxShards {
		fmt.Println("File too big!")
		return
	}
	encr := func(inp shard) shard {
		return encrypt(inp, eps, key)
	}
	ProcessFile(cleartextFile, ciphertextFile, encr, numShards, ShardSize)
}
