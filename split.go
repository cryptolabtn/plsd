package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"sync"
)

type chunk struct {
	bufsize int
	offset  int64
}

func splitfile(pathToFile string) {

	const BufferSize = 512
	file, err := os.Open(pathToFile)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer file.Close()

	fileinfo, err := file.Stat()
	if err != nil {
		fmt.Println(err)
		return
	}

	filesize := int(fileinfo.Size())
	// Number of go routines we need to spawn.
	concurrency := filesize / BufferSize
	// buffer sizes that each of the go routine below should use. ReadAt
	// returns an error if the buffer size is larger than the bytes returned
	// from the file.
	chunksizes := make([]chunk, concurrency)

	// All buffer sizes are the same in the normal case. Offsets depend on the
	// index. Second go routine should start at 100, for example, given our
	// buffer size of 100.
	for i := 0; i < concurrency; i++ {
		chunksizes[i].bufsize = BufferSize
		chunksizes[i].offset = int64(BufferSize * i)
	}

	// check for any left over bytes. Add the residual number of bytes as the
	// the last chunk size.
	if remainder := filesize % BufferSize; remainder != 0 {
		c := chunk{bufsize: remainder, offset: int64(concurrency * BufferSize)}
		concurrency++
		chunksizes = append(chunksizes, c)
	}

	var wg sync.WaitGroup
	wg.Add(concurrency)

	for i := 0; i < concurrency; i++ {
		go func(chunksizes []chunk, i int) {
			defer wg.Done()

			chunk := chunksizes[i]
			buffer := make([]byte, chunk.bufsize)
			_, err := file.ReadAt(buffer, chunk.offset)

			if err != nil {
				fmt.Println(err)
				return
			}
			// write file on disk
			partName := file.Name() + ".pt" + strconv.Itoa(i)
			_, error := os.Create(partName)

			if error != nil {
				fmt.Println(err)
				return
			}
			// write/save buffer to disk
			ioutil.WriteFile(partName, buffer, os.ModeAppend)

			// fmt.Println("bytes read, string(bytestream): ", bytesread)
			// fmt.Println("bytestream to string: ", string(buffer))
		}(chunksizes, i)
	}

	wg.Wait()
}

//GenFunc generic function on interfaces
type GenFunc func(input interface{}) interface{}

//ConcurrentWorker execute job concurrently
//inp input for the worker
//worker function that executes the job
//output channel to feed back the results
func ConcurrentWorker(inp interface{}, worker GenFunc, output chan interface{}, wg *sync.WaitGroup) {
	output <- worker(inp)
	wg.Done()
}

//CollectWork collect output of concurrent workers
//input channel that feeds the results
func CollectWork(input chan interface{}, collect GenFunc, done chan bool) {
	i := 0
	for shard := range input {
		fmt.Println(shard)
		i++
	}
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
