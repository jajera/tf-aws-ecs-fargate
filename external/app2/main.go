package main

import (
	"fmt"
	"net/http"
	"os"
)

func main() {
	port := os.Getenv("PORT")

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		hostname, _ := os.Hostname()
		fmt.Fprintf(w, "Hello, world from %s port %s!\n", hostname, port)
	})

	fmt.Printf("Server is listening on port %s...\n", port)
	http.ListenAndServe(":"+port, nil)
}