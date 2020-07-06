package main

import (
	"github.com/gaetanorusso/public_ledger_sensitive_data/miracl/go/core/BN254"
)

//User struct that contains public and private keys of a user
type User struct {
	PublicKey *BN254.ECP2
	mu        *BN254.BIG
	v         *BN254.BIG
}

//EncapsulateKey encapsulated an encryption key
func (u User) EncapsulateKey(key *BN254.ECP2) *BN254.ECP2 {
	return KeyUpdate(key, u.mu, u.v)
}

//UnlockKey unlock an encapsulated key for decryption
func (u User) UnlockKey(keyEnc *BN254.ECP2) *BN254.ECP2 {
	return KeyUpdate(keyEnc, u.v, u.mu)
}

//GenUser generate new random keys
func GenUser() *User {
	mu := GenExp()
	v := GenExp()
	pk := BN254.G2mul(B2, mu)
	return &User{pk, mu, v}
}
