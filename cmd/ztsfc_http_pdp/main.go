package main

import (
	"fmt"
	"net/http"
	"os"

    "github.com/vs-uulm/ztsfc_http_pep/internal/app/config"
    router "github.com/vs-uulm/ztsfc_http_pdp/internal/app/router"
)

func init() {
    var confFilePath string

    flag.StringVar(&confFilePath, "c", "./config/conf.yml", "Path to user defined yaml config file")
    flag.Parse()

    err := config.LoadConfig(confFilePath)
    if err != nil {
        fmt.Fatalf("main: could not load config: %w", err)
    }

    fmt.Printf("Config.Config.Pdp.ListenAddr: "config.Config.Pdp.ListenAddr)
}

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
