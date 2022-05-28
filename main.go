package main

import (
	"log"
)

func main() {
	client, err := Dial(Config)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close()

	term := NewSSHTerminal(session)
	if err := term.Interact(Config.Commands); err != nil {
		log.Fatal(err)
	}
}
