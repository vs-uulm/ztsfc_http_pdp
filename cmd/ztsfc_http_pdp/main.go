package main

import (
	"crypto/x509"
	"flag"
	"log"
	"net/http"

	yaml "github.com/leobrada/yaml_tools"
	logger "github.com/vs-uulm/ztsfc_http_logger"
	"github.com/vs-uulm/ztsfc_http_pdp/internal/app/config"
	ini "github.com/vs-uulm/ztsfc_http_pdp/internal/app/init"
	"github.com/vs-uulm/ztsfc_http_pdp/internal/app/jsonlogsender"
	"github.com/vs-uulm/ztsfc_http_pdp/internal/app/policies"
	"github.com/vs-uulm/ztsfc_http_pdp/internal/app/router"
)

var (
	sysLogger *logger.Logger
	logSender *jsonlogsender.JSONLogSender
)

func init() {
	var confFilePath string
	var policiesFilePath string

	flag.StringVar(&confFilePath, "c", "./config/conf.yml", "Path to user defined yaml config file")
	flag.StringVar(&policiesFilePath, "p", "./policies/policies.yml", "Path to user defined yaml policy file")
	flag.Parse()

	// Loading the general config file
	err := yaml.LoadYamlFile(confFilePath, &config.Config)
	if err != nil {
		log.Fatalf("main: init(): could not load yaml file: %s", err.Error())
	}

	// Loading the policy file
	err = yaml.LoadYamlFile(policiesFilePath, &policies.Policies)
	if err != nil {
		log.Fatalf("main: init(): could not load yaml file: %s", err.Error())
	}

	// Creating the Logger
	ini.InitSysLoggerParams()
	sysLogger, err = logger.New(config.Config.SysLogger.LogFilePath,
		config.Config.SysLogger.LogLevel,
		config.Config.SysLogger.IfTextFormatter,
		logger.Fields{"type": "system"},
	)

	if err != nil {
		log.Fatalf("main: init(): could not initialize logger: %s", err.Error())
	}

	// Create empty CertPool that is needed for certificates the PDP accepts when from by the PEP
	config.Config.Pdp.CaCertPoolPdpAcceptsFromPep = x509.NewCertPool()
	config.Config.Pdp.CaCertPoolPdpAcceptsFromHook = x509.NewCertPool()

	if err = ini.InitConfig(); err != nil {
		sysLogger.Fatalf("main: init(): could not initialize PDP params: %s", err.Error())
	}

	if err = ini.InitPolicies(); err != nil {
		sysLogger.Fatalf("main: init(): could not initialize resource params: %s", err.Error())
	}

	ini.InitGUILoggerParams()
	logSender, err = jsonlogsender.New(config.Config.Pdp.LoggingHook.HookURL)
	if err != nil {
		sysLogger.Fatalf("main: init(): could not initialize log sender: %s", err.Error())
	}

	sysLogger.Info("main: init(): initialization process successfully completed")
}

func main() {
	router := router.NewRouter(sysLogger, logSender)

	http.Handle("/", router)

	err := router.ListenAndServeTLS()
	if err != nil {
		sysLogger.Fatalf("main: main(): listen and serve failed: %s", err.Error())
	}
}
