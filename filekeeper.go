package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strconv"
	"sync"

	"github.com/gaetanorusso/public_ledger_sensitive_data/miracl/go/core/BN254"
)

//Ledger struct that contains file names of the parts of the ledger
type Ledger struct {
	ShardsFile  string
	KeysFile    string
	RootPath    string
	EncryptPath string
}

//CheckConsistency check the consistency of a ledger and correct decryption
//target index of the block relative to the decrypted file being checked
//	if > 0 the static ledger is checked up to this index
//	use negative value to check only static ledger consistency
//ptDigest hash of the decrypted file to check, used only if index >=0
//return true if the static ledger up to index is consistent and the digest
//in input corresponds of the plaintext digest in the block
//if index < 0 just the consistency of the static blocks (all of them) is checked
//the consistency of encapsulated keys and masking shards is always checked
func (ledger Ledger) CheckConsistency(target int64, ptDigest []byte) bool {
	//check up to target if >= 0, otherwise check all blocks
	tot := target
	if target < 0 {
		//compute number of keys (and therefore blocks) present
		fi, err := os.Stat(ledger.KeysFile)
		if err != nil {
			fmt.Println(err)
			return false
		}
		tot = fi.Size() / int64(2*BN254.MODBYTES+1)
	}
	//read masking shards from file
	eps := ledger.GetShards(MaxShards)
	//check blocks consistency one by one
	for i := int64(0); i < tot; i++ {
		filename := ledger.RootPath + strconv.FormatInt(i+1, 16)
		content, err := ioutil.ReadFile(filename)
		if err != nil {
			fmt.Println("File reading error", err)
			return false
		}
		//check link with previous block
		prevDigest := FileDigest(ledger.RootPath + strconv.FormatInt(i, 16))
		if !bytes.Equal(prevDigest, content[:64]) {
			return false
		}
		//check hash of encrypted file
		ctName := ledger.EncryptPath + strconv.FormatInt(i, 16) + ".enc"
		ctDigest := FileDigest(ctName)
		if !bytes.Equal(ctDigest, content[64:128]) {
			return false
		}
		//check hash of plaintext if it is the target block
		if i == target {
			if !bytes.Equal(ptDigest, content[128:192]) {
				return false
			}
		}
		//check control shard
		control := HashAte(&eps[i%int64(MaxShards)], ledger.GetEncKey(i))
		if !bytes.Equal(control, content[192:192+PadSize]) {
			return false
		}
	}
	return true
}

//DecryptBlock given an unlocked key decrypt corresponding file
//index index of the block thar corresponds to the file
//unlocked unlocked key for decryption
//out path to file where to write decrypted file
//the shards are taken from the ledger
//correctly terminates only if the decryption is consistent with the static ledger
func (ledger Ledger) DecryptBlock(index int64, unlocked *BN254.ECP2, out string) {
	//get shards
	eps := ledger.GetShards(MaxShards)
	//decrypt file
	ctName := ledger.EncryptPath + strconv.FormatInt(index, 16) + ".enc"
	EncryptFile(ctName, out, eps[:], unlocked)
	//check integrity
	ptDigest := FileDigest(out)
	if !ledger.CheckConsistency(index, ptDigest) {
		panic("Inconsistent decryption!")
	}
}

//Init set up the updating ledger
//given the paths in Ledger struct sets up the files:
//generates empty root block,
//generate the masking shards, save them on shardsFile
//return secret time-key s
func (ledger Ledger) Init() *BN254.BIG {
	//create empty root block
	emptyFile, err := os.Create(ledger.RootPath + strconv.Itoa(0))
	if err != nil {
		panic(err)
	}
	emptyFile.Close()
	//generate time-key
	s := GenExp()
	//channels for concurrent generation
	shardChannel := make(chan shard, MaxShards)
	done := make(chan bool)
	//concurrently generate each shard
	var wg sync.WaitGroup
	for i := 0; i < MaxShards; i++ {
		wg.Add(1)
		go func(i int) {
			temp := BN254.G1mul(B1, GenExp())
			temp = BN254.G1mul(temp, s)
			encoded := make([]byte, BN254.MODBYTES+1)
			temp.ToBytes(encoded, true)
			shardChannel <- shard{i, string(encoded)}
			wg.Done()
		}(i)
	}
	//collect and write results
	go writeResults(shardChannel, ledger.ShardsFile, done)
	wg.Wait()
	close(shardChannel)
	if <-done {
		fmt.Println("Shards correctly written on file!")
		return s
	}
	return nil
}

//GetShards read masking shards from the ledger
//file path taken from Ledger struct
//numShards number of shards to read
//return slice containing the masking shards read
func (ledger Ledger) GetShards(numShards int) []BN254.ECP {
	//open shardsFile
	file, err := os.Open(ledger.ShardsFile)
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
	size := BN254.MODBYTES + 1
	buffer := make([]byte, size)
	shards := make([]BN254.ECP, numShards)
	for i := 0; i < numShards; i++ {
		_, err := io.ReadFull(reader, buffer)
		if err != nil {
			fmt.Println("Error reading file:", err)
			return nil
		}
		//decode shard
		shards[i] = *BN254.ECP_fromBytes(buffer)
	}
	return shards
}

//GetSingleShard read from file a single masking shard
//index index of the masking shard to read
//path to the file containing the masking shards taken from Ledger struct
//return the masking shard
func (ledger Ledger) GetSingleShard(index int64) *BN254.ECP {
	//read from file
	encoded := ReadValue(ledger.ShardsFile, index, int64(BN254.MODBYTES+1))
	//decode key
	return BN254.ECP_fromBytes(encoded)
}

//AppendEncapsulatedKey append newest encapsulated key on key-file
//keyEncFile output file path
//encKey encapsulated key to append
//returns the index of the written key
func (ledger Ledger) AppendEncapsulatedKey(encKey *BN254.ECP2) int64 {
	//open output file
	file, err := os.OpenFile(ledger.KeysFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
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
//index index of the key to read
//path to the file containing the encapsulated keys taken from Ledger struct
//return the encapsulated key
func (ledger Ledger) GetEncKey(index int64) *BN254.ECP2 {
	//read from file
	encoded := ReadValue(ledger.KeysFile, index, int64(2*BN254.MODBYTES+1))
	//decode key
	return BN254.ECP2_fromBytes(encoded)
}

//Update update shards and keys, and generate new time-key
//keyEncFile file containing encapsulated keys
//shardsFile file containing masking shards
//s current time-key
//return new time-key
func (ledger Ledger) Update(s *BN254.BIG) *BN254.BIG {
	//generate time-key
	sNew := GenExp()
	//process shard file concurrently
	shardUpd := func(inp shard) shard {
		old := BN254.ECP_fromBytes([]byte(inp.value))
		return shardUpdate(inp.index, old, s, sNew)
	}
	ProcessFile(ledger.ShardsFile, ledger.ShardsFile, shardUpd, MaxShards, int(BN254.MODBYTES+1))
	//process encapsulated key file cuncurrently
	//compute file size to determine concurrency
	fi, err := os.Stat(ledger.KeysFile)
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
		new := FracMult(old, sNew, s)
		//encode key
		encoded := make([]byte, sizeKey)
		new.ToBytes(encoded, true)
		return shard{inp.index, string(encoded)}
	}
	ProcessFile(ledger.KeysFile, ledger.KeysFile, updKey, numKey, sizeKey)
	return sNew
}
