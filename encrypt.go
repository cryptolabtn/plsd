package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/gaetanorusso/public_ledger_sensitive_data/miracl/go/core/BN254"
)

type shard struct {
	index int
	value string
}

//ReadChunks read filename splitting it in chunks
//each chunk is ShardSize (global const) bytes long
//and fed to output channel for concurrent processing
func readChunks(filename string, output chan shard) {
	//close channel on exit to signal end of input operations
	defer close(output)
	//open filename
	file, err := os.Open(filename)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	//close file on exit
	defer func() {
		if err = file.Close(); err != nil {
			fmt.Println("Error closing file:", err)
		}
	}()

	//buffered reading
	reader := bufio.NewReader(file)
	buffer := make([]byte, ShardSize)
	for i := 0; ; i++ {
		n, err := reader.Read(buffer)
		if err != nil {
			if err != io.EOF {
				fmt.Println("Error reading file:", err)
			}
			break
		} else {
			//feed chunk to channel
			output <- shard{i, string(buffer[0:n])}
		}
	}
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

//encrypt concurrently encrypt each chunk
func encrypt(inputs chan shard, results chan shard, wg *sync.WaitGroup, eps []BN254.ECP, key *BN254.ECP2) {
	for pt := range inputs {
		//encrypt using appropriate shard
		ct := OneTimePad([]byte(pt.value), &eps[pt.index], key)
		//feed result to output channel
		results <- shard{pt.index, string(ct)}
	}
	wg.Done()
}

//WriteEncryption collect results of concurrent encryption and write on file
//filename path of output file
//results channel that feeds the results to collect
//done channel to signal completion: true for success, false for failure
func writeEncryption(results chan shard, filename string, done chan bool) {
	//collect results with a map
	result := make(map[int]string)
	for ct := range results {
		result[ct.index] = ct.value
	}
	//open output file
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		fmt.Println(err)
		done <- false
		return
	}
	//close file on exit
	defer func() {
		if err = file.Close(); err != nil {
			fmt.Println("Error closing file:", err)
			done <- false
		}
	}()
	//write results on file in the correct order
	for i := 0; i < len(result); i++ {
		_, err = file.WriteString(result[i])
		if err != nil {
			fmt.Println(err)
			done <- false
			break
		}
	}
	//signal succesful completion of writing
	done <- true
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
	//channels for feeding plaintexts and ciphertexts to the routines
	readChannel := make(chan shard, numShards)
	encryptChannel := make(chan shard, numShards)
	//read file
	go readChunks(cleartextFile, readChannel)

	//concurrently encrypt each shard
	var wg sync.WaitGroup
	for i := 0; i < numShards; i++ {
		wg.Add(1)
		go encrypt(readChannel, encryptChannel, &wg, eps, key)
	}
	//collect results and write them on file
	writingSuccessful := make(chan bool)
	go writeEncryption(encryptChannel, ciphertextFile, writingSuccessful)
	//wait for every encryption to finish
	wg.Wait()
	//signal end of encryption to finalise result collection and writing
	close(encryptChannel)
	//wait for writing completion
	if <-writingSuccessful {
		fmt.Println("encryption written successfully!")
	}
}
