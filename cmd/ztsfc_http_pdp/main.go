package main

import (
	"crypto/x509"
	"flag"
	"log"
	"net/http"

	//racksec_syslog "github.com/RackSec/srslog" // Will be deleted after project demo
	yaml "github.com/leobrada/yaml_tools"
	//logrus_syslog "github.com/shinji62/logrus-syslog-ng" // will be deleted after project demo
	logger "github.com/vs-uulm/ztsfc_http_logger"
	"github.com/vs-uulm/ztsfc_http_pdp/internal/app/config"
	ini "github.com/vs-uulm/ztsfc_http_pdp/internal/app/init"
	"github.com/vs-uulm/ztsfc_http_pdp/internal/app/policies"
	"github.com/vs-uulm/ztsfc_http_pdp/internal/app/router"
)

var (
	sysLogger *logger.Logger
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
		log.Fatalf("main: init(): could not load yaml file: %v", err)
	}

	// Loading the policy file
	err = yaml.LoadYamlFile(policiesFilePath, &policies.Policies)
	if err != nil {
		log.Fatalf("main: init(): could not load yaml file: %v", err)
	}

	// Creating the Logger
	ini.InitSysLoggerParams()
	sysLogger, err = logger.New(config.Config.SysLogger.LogFilePath,
		config.Config.SysLogger.LogLevel,
		config.Config.SysLogger.IfTextFormatter,
		logger.Fields{"type": "system"},
	)

	if err != nil {
		log.Fatalf("main: init(): could not initialize logger: %v", err)
	}

	// Create empty CertPool that is needed for certificates the PDP accepts when from by the PEP
	config.Config.Pdp.CaCertPoolPdpAcceptsFromPep = x509.NewCertPool()

	if err = ini.InitConfig(); err != nil {
		sysLogger.Fatalf("main: init(): could not initialize PDP params: %v", err)
	}

	if err = ini.InitPolicies(); err != nil {
		sysLogger.Fatalf("main: init(): could not initialize resource params: %v", err)
	}

	// GRAYLOG HOOK WILL BE DELTED AFTER PROJECT DEMO
	//hook, err := logrus_syslog.NewSyslogHookTls("bwnet-srv3-1g.informatik.uni-ulm.de:1515", racksec_syslog.LOG_DEBUG, "tag", "./certs/graylog.pem", false)

	//if err == nil {
	//	sysLogger.AddHook(hook)
	//} else {
	//	sysLogger.Infof("Error occured: %v", err)
	//}

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
