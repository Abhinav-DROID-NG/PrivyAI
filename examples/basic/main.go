package main

import (
	"fmt"
	"log"

	privyai "github.com/Abhinav-DROID-NG/PrivyAI"
)

func main() {
	fmt.Println("Send alice@example.com")
	engine, err := privyai.New(privyai.DefaultConfig())
	if err != nil {
		log.Fatal(err)
	}

	result, err := engine.Process("Send alice@example.com")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(result.Sanitized)
}
