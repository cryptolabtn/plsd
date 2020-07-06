package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"sync"
)

type shard struct {
	index int
	value string
}

//ReadChunks read filename splitting it in chunks
//each chunk is size bytes long
//and fed to output channel for concurrent processing
func readChunks(filename string, output chan shard, size int) {
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
	buffer := make([]byte, size)
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

//WriteResults collect results of concurrent encryption and write on file
//filename path of output file
//results channel that feeds the results to collect
//done channel to signal completion: true for success, false for failure
func writeResults(results chan shard, filename string, done chan bool) {
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

//ProcessFile read file and process it concurrently
//then collect results and write on file
//inputFile path to input file
//outputFile path to output file
//process function that processes each chunk
//num number of chunks to process concurrently
//size size of chunks to process
func ProcessFile(inputFile, outputFile string, process func(shard) shard, num, size int) {
	//channels for feeding plaintexts and ciphertexts to the routines
	readChannel := make(chan shard, num)
	resultChannel := make(chan shard, num)
	//read file
	go readChunks(inputFile, readChannel, size)

	//concurrently encrypt each shard
	var wg sync.WaitGroup
	for i := 0; i < num; i++ {
		wg.Add(1)
		go func() {
			for read := range readChannel {
				//process and feed result to output channel
				resultChannel <- process(read)
			}
			wg.Done()
		}()
	}
	//collect results and write them on file
	writingSuccessful := make(chan bool)
	go writeResults(resultChannel, outputFile, writingSuccessful)
	//wait for every encryption to finish
	wg.Wait()
	//signal end of encryption to finalise result collection and writing
	close(resultChannel)
	//wait for writing completion
	if <-writingSuccessful {
		fmt.Println("file written successfully!")
	}
}
