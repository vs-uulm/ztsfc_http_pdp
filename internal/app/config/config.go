package config

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
)

var (
	Config ConfigT
)

type ConfigT struct {
	SysLogger sysLoggerT `yaml:"system_logger"`
	Pdp       PdpT       `yaml:"pdp"`
	Pip       PipT       `yaml:"pip"`
}

type sysLoggerT struct {
	LogLevel        string `yaml:"system_logger_logging_level"`
	LogFilePath     string `yaml:"system_logger_destination"`
	IfTextFormatter string `yaml:"system_logger_format"`
}

type PdpT struct {
	ListenAddr                    string   `yaml:"listen_addr"`
	CertsPdpAcceptsWhenShownByPep []string `yaml:"certs_pdp_accepts_when_shown_by_pep"`
	CertShownByPdpToPep           string   `yaml:"cert_shown_by_pdp_to_pep"`
	PrivkeyForCertShownByPdpToPep string   `yaml:"privkey_for_cert_shown_by_pdp_to_pep"`

	CaCertPoolPdpAcceptsFromPep *x509.CertPool
	X509KeyPairShownByPdpToPep  tls.Certificate
}

type PipT struct {
	TargetAddr           string `yaml:"target_addr"`
	DeviceEndpoint       string `yaml:"device_endpoint"`
	UpdateDeviceEndpoint string `yaml:"update_device_endpoint"`
	UserEndpoint         string `yaml:"user_endpoint"`
	SystemEndpoint       string `yaml:"system_endpoint"`

	CertsPdpAcceptsWhenShownByPip []string `yaml:"certs_pdp_accepts_when_shown_by_pip"`
	CertShownByPdpToPip           string   `yaml:"cert_shown_by_pdp_to_pip"`
	PrivkeyForCertShownByPdpToPip string   `yaml:"privkey_for_cert_shown_by_pdp_to_pip"`

	CaCertPoolPdpAcceptsFromPip *x509.CertPool
	X509KeyPairShownByPdpToPip  tls.Certificate

	PipClient *http.Client
}
