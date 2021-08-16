package main

import (
	"fmt"
	router "local.com/leobrada/ztsfc_http_pdp/router"
	"net/http"
	"os"
)

//func init() {
//
//}

func main() {
	router := router.NewRouter()
	if router == nil {
		fmt.Printf("BOHOOO\n")
		os.Exit(1)
	}

	http.Handle("/", router)

	err := router.ListenAndServeTLS()
	if err != nil {
		fmt.Printf("ListenAndServeTLS Error\n")
	}
}
