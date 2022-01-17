package config

import (
    "crypto/x509"
    "crypto/tls"
)

var (
    Config ConfigT
)

type ConfigT struct {
    SysLogger sysLoggerT `yaml:"system_logger"`
    Pdp PdpT `yaml:"pdp"`
}

type sysLoggerT struct {
        LogLevel        string `yaml:"system_logger_logging_level"`
        LogFilePath     string `yaml:"system_logger_destination"`
        IfTextFormatter string `yaml:"system_logger_format"`
}

type PdpT struct {
    ListenAddr  string `yaml:"listen_addr"`
    CertsPdpAcceptsWhenShownByPep []string `yaml:"certs_pdp_accepts_when_shown_by_pep"`
    CertShownByPdpToPep string  `yaml:"cert_shown_by_pdp_to_pep"`
    PrivkeyForCertShownByPdpToPep  string  `yaml:"privkey_for_cert_shown_by_pdp_to_pep"`

    CaCertPoolPdpAcceptsFromPep *x509.CertPool
    X509KeyPairShownByPdpToPep  tls.Certificate
}
