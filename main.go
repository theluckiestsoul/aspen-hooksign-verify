package main

import (
	"fmt"
	"log"
	"net/http"

	"hooksign/hooksign"
)

func main() {
	addr := ":8080"
	fmt.Printf("HookSign API listening on %s\n", addr)
	log.Fatal(http.ListenAndServe(addr, hooksign.NewApp()))
}
