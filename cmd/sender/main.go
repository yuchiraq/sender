package main

import (
	"fmt"
	"log"
	"os"

	"sender/internal/app"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "hash-password":
			if len(os.Args) != 3 {
				log.Fatal("usage: sender.exe hash-password <password>")
			}

			hash, err := app.HashPassword(os.Args[2])
			if err != nil {
				log.Fatalf("hash failed: %v", err)
			}

			fmt.Println(hash)
			return
		default:
			log.Fatalf("unknown command: %s", os.Args[1])
		}
	}

	service, err := app.New("config.json")
	if err != nil {
		log.Fatalf("startup failed: %v", err)
	}

	if err := service.Run(); err != nil {
		log.Fatalf("service stopped: %v", err)
	}
}
