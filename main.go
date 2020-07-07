package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Println("Private Ledger: Welcome!")
	/* try this if you want to test */
	//reset files
	toClean := []string{"test/keys.enc"}
	for _, filename := range toClean {
		err := os.Remove(filename)
		if err != nil {
			fmt.Println(err)
		}
	}
	//init ledger
	ledger := Ledger{"test/shards.enc", "test/keys.enc", "test/block"}
	//generate shards and get time-key
	s := ledger.InitUpdate()
	//generate user keys
	u := GenUser()
	//compute encryption token
	token := TokenGen(u.PublicKey, s)
	//add a block
	index := u.AddBlock(ledger, token, "test/test.txt")
	fmt.Println(index)
	//unlock key from the ledger
	unlocked := u.UnlockKey(ledger.GetEncKey(index))
	//decrypt file
	ledger.DecryptBlock(index, unlocked, "test/dec.txt")
	//update ledger
	sNew := ledger.Update(s)
	//compare time keys
	fmt.Println(s.ToString())
	fmt.Println(sNew.ToString())
	//get updated encapsulated key from ledger
	keyEncNew := ledger.GetEncKey(index)
	//unlock key
	unlockedNew := u.UnlockKey(keyEncNew)
	//decrypt file again
	ledger.DecryptBlock(index, unlockedNew, "test/dec2.txt")
}
