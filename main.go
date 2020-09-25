package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	curve "github.com/gaetanorusso/public_ledger_sensitive_data/miracl/go/core/BN254"
)

//default path of settings file
const defSettings string = "test/settings.txt"

func main() {
	/* try this if you want to test */
	fmt.Println("Private Ledger: Welcome!")
	//flag -settings to set up the test
	settings := flag.String("settings", defSettings, "settings file path")
	flag.Parse()
	//load settings
	ledger := LoadSettings(*settings)
	fmt.Println("Loaded settings from:", *settings)
	//reset files
	toClean := []string{ledger.KeysFile, ledger.ShardsFile}
	for _, filename := range toClean {
		err := os.Remove(filename)
		if err != nil {
			fmt.Println(err)
		}
	}
	//generate shards and get time-key
	fmt.Println("Initiating ledger setup...")
	startTime := time.Now()
	s := ledger.Init()
	fmt.Println("Completed in", time.Now().Sub(startTime).Seconds(), "s")
	//generate user keys
	u := GenUser()
	//compute encryption token
	token := TokenGen(u.PublicKey, s)
	//ask the user which file to encrypt
	reader := bufio.NewReader(os.Stdin)
	defFile := "docs/private-ledger.pdf"
	fmt.Printf("Which file do you want to encrypt? (%s)\n", defFile)
	path, _ := reader.ReadString('\n')
	path = strings.Replace(path, "\n", "", -1)
	if path == "" {
		path = defFile
	}
	//add a block
	fmt.Println("Encrypting file", path)
	startTime = time.Now()
	index := u.AddBlock(ledger, token, path)
	fmt.Println("Block added with index", index)
	fmt.Println("Completed in", time.Now().Sub(startTime).Seconds(), "s")
	//unlock key from the ledger
	unlocked := u.UnlockKey(ledger.GetEncKey(index))
	//decrypt file
	decPath := "test/dec"
	fmt.Println("Testing decryption to", decPath)
	startTime = time.Now()
	ledger.DecryptBlock(index, unlocked, decPath)
	fmt.Println("Decryption Successful!")
	fmt.Println("Completed in", time.Now().Sub(startTime).Seconds(), "s")
	//update ledger
	fmt.Println("Initiating ledger update...")
	startTime = time.Now()
	sNew := ledger.Update(s)
	fmt.Println("Completed in", time.Now().Sub(startTime).Seconds(), "s")
	//compare time keys
	fmt.Println("Time keys:")
	fmt.Println(s.ToString())
	fmt.Println(sNew.ToString())
	//get updated encapsulated key from ledger
	keyEncNew := ledger.GetEncKey(index)
	//unlock key
	unlockedNew := u.UnlockKey(keyEncNew)
	//decrypt file again
	decPath = "test/dec2"
	fmt.Println("Testing decryption to", decPath)
	startTime = time.Now()
	ledger.DecryptBlock(index, unlockedNew, decPath)
	fmt.Println("Decryption Successful!")
	fmt.Println("Completed in", time.Now().Sub(startTime).Seconds(), "s")
}

//LoadSettings load settings for test from file
//settingsFile path to settings file
//returns a ledger struct
//also modifies global variables ShardSize and MaxShards
func LoadSettings(settingsFile string) Ledger {
	//open settings file
	file, err := os.Open(settingsFile)
	if err != nil {
		panic(err)
	}
	//close on exit
	defer func() {
		if err = file.Close(); err != nil {
			panic(err)
		}
	}()
	//read settings line by line
	scanner := bufio.NewScanner(file)
	//read pad size for encryption and decryption
	if !scanner.Scan() {
		panic(scanner.Err())
	}
	PadSize, err = strconv.Atoi(scanner.Text())
	if err != nil {
		panic(err)
	}
	if PadSize < int(2*curve.MODBYTES) {
		panic("Incorrect settings: Pad size outside limits")
	}
	//read number of shards to create
	if !scanner.Scan() {
		panic(scanner.Err())
	}
	MaxShards, err = strconv.Atoi(scanner.Text())
	if err != nil {
		panic(err)
	}
	if PadSize < 1 {
		panic("Incorrect settings: non-positive number of shards")
	}
	//read paths for the ledger struct
	if !scanner.Scan() {
		panic(scanner.Err())
	}
	shardsFile := scanner.Text()
	if !scanner.Scan() {
		panic(scanner.Err())
	}
	keysFile := scanner.Text()
	if !scanner.Scan() {
		panic(scanner.Err())
	}
	rootPath := scanner.Text()
	if !scanner.Scan() {
		panic(scanner.Err())
	}
	encryptPath := scanner.Text()
	//return ledger
	return Ledger{shardsFile, keysFile, rootPath, encryptPath}
}
