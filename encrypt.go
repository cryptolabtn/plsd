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

func readChunks(filename string, output chan shard) {
	file, err := os.Open(filename)
	if err != nil {
		fmt.Println("Error opening file:", err)
		close(output)
		return
	}
	defer close(output)
	defer func() {
		if err = file.Close(); err != nil {
			fmt.Println("Error closing file:", err)
		}
	}()

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
			//fmt.Println(string(buffer[0:n]))
			output <- shard{i, string(buffer[0:n])}
		}
	}
}

func myXor(a, b []byte) []byte {
	n := len(a)
	if len(b) < len(a) {
		n = len(b)
	}
	res := make([]byte, n)
	for i := 0; i < n; i++ {
		res[i] = a[i] ^ b[i]
	}
	return res
}

func encrypt(inputs chan shard, results chan shard, wg *sync.WaitGroup, eps *BN254.ECP, key *BN254.ECP2) {
	for pt := range inputs {
		results <- shard{pt.index, string(OneTimePad([]byte(pt.value), eps, key))}
	}
	wg.Done()
}

func writeEncryption(results chan shard, filename string, done chan bool) {
	result := make(map[int]string)
	for ct := range results {
		result[ct.index] = ct.value
	}
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		fmt.Println(err)
		done <- false
		return
	}
	defer func() {
		if err = file.Close(); err != nil {
			fmt.Println("Error closing file:", err)
			done <- false
		}
	}()
	for i := 0; i < len(result); i++ {
		_, err = file.WriteString(result[i])
		if err != nil {
			fmt.Println(err)
			done <- false
			break
		}
	}
	done <- true
}

//EncryptFile read file and ecrypt
func EncryptFile(cleartextFile, ciphertextFile string, eps *BN254.ECP, key *BN254.ECP2) {
	fi, err := os.Stat(cleartextFile)
	if err != nil {
		fmt.Println(err)
		return
	}
	numShards := (int(fi.Size())-1)/ShardSize + 1
	if numShards > MaxShards {
		fmt.Println("File too big!")
		return
	}
	readChannel := make(chan shard, numShards)
	encryptChannel := make(chan shard, numShards)
	go readChunks(cleartextFile, readChannel)

	var wg sync.WaitGroup
	for i := 0; i < numShards; i++ {
		wg.Add(1)
		go encrypt(readChannel, encryptChannel, &wg, eps, key)
	}
	writingSuccessful := make(chan bool)
	go writeEncryption(encryptChannel, ciphertextFile, writingSuccessful)
	wg.Wait()
	close(encryptChannel)
	if <-writingSuccessful {
		fmt.Println("encryption written successfully!")
	}
}
