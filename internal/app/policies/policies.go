package config

import (
    "os"
    "fmt"
    "errors"
    "crypto/x509"
    "crypto/tls"

    "gopkg.in/yaml.v2"
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
    CertsPdpAcceptsWhenShownByPep []string `yaml:"certs_pep_accepts_when_shown_by_pep"`
    CertShownByPdpToPep string  `yaml:"cert_shown_by_pdp_to_pep"`
    PrivkeyForCertsShownByPdpToPep  string  `yaml:"privkey_for_certs_shown_by_pdp_to_pep"`

    CaCertPoolPdpAcceptsFromPep *x509.CertPool
    X509KeyPairShownByPdpToPep  tls.Certificate
}

func LoadConfig(configPath string, config *ConfigT) error {
    if configPath == "" {
        return errors.New("config: LoadConfig(): no config file path was provided")
    }

    if config == nil {
        return errors.New("config: LoadConfig(): provided config pointer is nil")
    }

    file, err := os.Open(configPath)
    if err != nil {
        return fmt.Errorf("config: LoadConfig(): could not open config file: %w", err)
    }
    defer file.Close()

    d := yaml.NewDecoder(file)

    err = d.Decode(config)
    if err != nil {
        return fmt.Errorf("config: LoadConfig(): could not decode config file: %w", err)
    }

    return nil
}
