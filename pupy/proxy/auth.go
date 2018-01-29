package main

import (
	"crypto/rand"
	"encoding/hex"
	"log"
)

var (
	PSK Nonce
)

func init() {
	n, err := rand.Read(PSK[:])
	if n != len(PSK) || err != nil {
		panic("Couln't generate PSK")
	}

	log.Println("PSK:", hex.EncodeToString(PSK[:]))
}
