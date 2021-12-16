package main

import (
	"net/http"
    "flag"
    "log"
    "crypto/x509"

    "github.com/vs-uulm/ztsfc_http_pdp/internal/app/config"
    "github.com/vs-uulm/ztsfc_http_pdp/internal/app/router"
    ini "github.com/vs-uulm/ztsfc_http_pdp/internal/app/init"
    logger "github.com/vs-uulm/ztsfc_http_logger"
)

var (
    sysLogger *logger.Logger
)

func init() {
    var confFilePath string

    flag.StringVar(&confFilePath, "c", "./config/conf.yml", "Path to user defined yaml config file")
    flag.Parse()

    err := config.LoadConfig(confFilePath, &config.Config)
    if err != nil {
        log.Fatalf("main: init(): could not load config: %w", err)
    }

    sysLogger, err = logger.New(config.Config.SysLogger.LogFilePath,
        config.Config.SysLogger.LogLevel,
        config.Config.SysLogger.IfTextFormatter,
        logger.Fields{"type":"system"},
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
	router := router.NewRouter()

	http.Handle("/", router)

	err := router.ListenAndServeTLS()
	if err != nil {
		sysLogger.Fatalf("main: main(): listen and serve failed: %w", err)
	}
}
