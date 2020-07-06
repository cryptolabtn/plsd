package main

import (
	"bufio"
	"fmt"
	"io"
	"os"

	"github.com/gaetanorusso/public_ledger_sensitive_data/miracl/go/core/BN254"
)

//InitUpdLedger set up the updating ledger
//generate the masking shards, save them on shardsFile
//return secret time-key st
func InitUpdLedger(shardsFile string) *BN254.BIG {
	//set up the shards
	var eps [MaxShards]BN254.ECP
	//generate time-key
	s := GenExp()
	//compute masking shards
	maskingShardsGen(s, eps[:])
	//open output file
	file, err := os.OpenFile(shardsFile, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	//close file on exit
	defer func() {
		if err = file.Close(); err != nil {
			fmt.Println("Error closing file:", err)
		}
	}()
	//write shards on file
	encoded := make([]byte, BN254.MODBYTES+1)
	for _, shard := range eps {
		//encode shard as compressed curve point
		shard.ToBytes(encoded, true)
		_, err = file.Write(encoded)
		if err != nil {
			fmt.Println(err)
			return nil
		}
	}
	return s
}

//GetShards read masking shards from shardsFile
//numShards number of shards to read
func GetShards(shardsFile string, numShards int) []BN254.ECP {
	//open shardsFile
	file, err := os.Open(shardsFile)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return nil
	}
	//close file on exit
	defer func() {
		if err = file.Close(); err != nil {
			fmt.Println("Error closing file:", err)
		}
	}()

	//buffered reading
	reader := bufio.NewReader(file)
	buffer := make([]byte, BN254.MODBYTES+1)
	shards := make([]BN254.ECP, numShards)
	for i := 0; i < numShards; i++ {
		n, err := reader.Read(buffer)
		if n < len(buffer) {
			fmt.Println("Error reading file: incomplete shard!")
			return nil
		}
		if err != nil {
			if err != io.EOF {
				fmt.Println("Error reading file:", err)
				return nil
			}
			break
		} else {
			//decode shard
			shards[i] = *BN254.ECP_fromBytes(buffer)
		}
	}
	return shards
}

//WriteEncapsulatedKeys write the encapsulated keys on file
//keyEncFile output file path
//encKeys slice of encapsulated keys
func WriteEncapsulatedKeys(keyEncFile string, encKeys []BN254.ECP2) {
	//open output file
	file, err := os.OpenFile(keyEncFile, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		fmt.Println(err)
		return
	}
	//close file on exit
	defer func() {
		if err = file.Close(); err != nil {
			fmt.Println("Error closing file:", err)
		}
	}()
	//write encapsulated keys on file
	encoded := make([]byte, 2*BN254.MODBYTES+1)
	for _, key := range encKeys {
		//encode shard as compressed curve point
		key.ToBytes(encoded, true)
		_, err = file.Write(encoded)
		if err != nil {
			fmt.Println(err)
			return
		}
	}
}

//AppendEncapsulatedKeys append newest encapsulated key on key-file
//keyEncFile output file path
//encKey encapsulated key to append
//returns the index of the written key
func AppendEncapsulatedKeys(keyEncFile string, encKey *BN254.ECP2) int64 {
	//open output file
	file, err := os.OpenFile(keyEncFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
	if err != nil {
		fmt.Println(err)
		return -1
	}
	//close file on exit
	defer func() {
		if err = file.Close(); err != nil {
			fmt.Println("Error closing file:", err)
		}
	}()
	fileinfo, err := file.Stat()
	if err != nil {
		fmt.Println(err)
		return -1
	}
	//write encapsulated key on file
	size := 2*BN254.MODBYTES + 1
	encoded := make([]byte, size)

	//encode shard as compressed curve point
	encKey.ToBytes(encoded, true)
	_, err = file.Write(encoded)
	if err != nil {
		fmt.Println(err)
		return -1

	}
	return fileinfo.Size() / int64(size)
}

//GetEncKey read from file the value of the encapsulated key
//keyEncFile input file
//index index of the key to read
func GetEncKey(keyEncFile string, index int64) *BN254.ECP2 {
	//open input file
	file, err := os.Open(keyEncFile)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return nil
	}
	//close file on exit
	defer func() {
		if err = file.Close(); err != nil {
			fmt.Println("Error closing file:", err)
		}
	}()

	//offset reading
	size := 2*BN254.MODBYTES + 1
	buffer := make([]byte, size)
	n, err := file.ReadAt(buffer, index*int64(size))
	if n < int(size) {
		fmt.Println("Error reading file: incomplete key!")
		return nil
	}
	//decode key
	return BN254.ECP2_fromBytes(buffer)
}

//UpdateLedger update shards and keys, and generate new time-key
//keyEncFile file containing encapsulated keys
//shardsFile file containing masking shards
//s current time-key
//return new time-key
func UpdateLedger(keyEncFile, shardsFile string, s *BN254.BIG) *BN254.BIG {
	//generate time-key
	sNew := GenExp()
	//process shard file concurrently
	shardUpd := func(inp shard) shard {
		old := mask{inp.index, BN254.ECP_fromBytes([]byte(inp.value))}
		return shardUpdate(old, s, sNew)
	}
	ProcessFile(shardsFile, shardsFile, shardUpd, MaxShards, int(BN254.MODBYTES+1))

	//process encapsulated key file cuncurrently
	//compute file size to determine concurrency
	fi, err := os.Stat(keyEncFile)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	//compute number of keys
	sizeKey := int(2*BN254.MODBYTES + 1)
	numKey := int(fi.Size()) / sizeKey
	updKey := func(inp shard) shard {
		//import old key
		old := BN254.ECP2_fromBytes([]byte(inp.value))
		//update key
		new := KeyUpdate(old, sNew, s)
		//encode key
		encoded := make([]byte, sizeKey)
		new.ToBytes(encoded, true)
		return shard{inp.index, string(encoded)}
	}
	ProcessFile(keyEncFile, keyEncFile, updKey, numKey, sizeKey)
	return sNew
}
