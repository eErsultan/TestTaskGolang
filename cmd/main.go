package main

import (
	"github.com/eErsultan/test-task/handler"
	"log"
	"net/http"
)

func main(){
	http.HandleFunc("/token", handler.Token)
	http.HandleFunc("/refresh-token", handler.RefreshToken)

	log.Fatal(http.ListenAndServe(":8080", nil))
}
