package main

import (
	"crypto/x509"
	"flag"
	"log"
	"net/http"

	logger "github.com/vs-uulm/ztsfc_http_logger"
	"github.com/vs-uulm/ztsfc_http_pdp/internal/app/config"
	ini "github.com/vs-uulm/ztsfc_http_pdp/internal/app/init"
	"github.com/vs-uulm/ztsfc_http_pdp/internal/app/router"
	"github.com/vs-uulm/ztsfc_http_pdp/internal/app/yaml"
)

var (
	sysLogger *logger.Logger
)

func init() {
	var confFilePath string

	flag.StringVar(&confFilePath, "c", "./config/conf.yml", "Path to user defined yaml config file")
//	flag.StringVar(&policiesFilePath, "p", "./config/policies.yml", "Path to user defined yaml policy file")
	flag.Parse()

	err := yaml.LoadYamlFile(confFilePath, &config.Config)
	if err != nil {
		log.Fatalf("main: init(): could not load config: %w", err)
	}

	sysLogger, err = logger.New(config.Config.SysLogger.LogFilePath,
		config.Config.SysLogger.LogLevel,
		config.Config.SysLogger.IfTextFormatter,
		logger.Fields{"type": "system"},
	)

	if err != nil {
		log.Fatalf("main: init(): could not initialize logger: %w", err)
	}

	config.Config.Pdp.CaCertPoolPdpAcceptsFromPep = x509.NewCertPool()

	ini.InitSysLoggerParams()

	if err = ini.InitPdpParams(); err != nil {
		sysLogger.Fatalf("main: init(): could not initialize PDP params: %w", err)
	}

	sysLogger.Info("main: init(): initialization process successfully completed")
}

func main() {
	router := router.NewRouter(sysLogger)

	http.Handle("/", router)

	err := router.ListenAndServeTLS()
	if err != nil {
		sysLogger.Fatalf("main: main(): listen and serve failed: %w", err)
	}
}
