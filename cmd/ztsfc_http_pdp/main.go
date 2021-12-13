package main

import (
	"fmt"
	"net/http"
	"os"

    router "github.com/vs-uulm/ztsfc_http_pdp/internal/app/router"
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
