package config

import (
    "os"
    "fmt"
    "errors"

    "gopkg.in/yaml.v2"
)

var (
    Config ConfigT
)

type ConfigT struct {
    Pdp PdpT `yaml:"pdp"`
}

type PdpT struct {
    ListenAddr  string `yaml:"listen_addr"`
    CertsPdpAcceptsWhenShownByPep []string `yaml:"certs_pep_accepts_when_shown_by_pep"`
    CertShownByPdpToPep string  `yaml:"cert_shown_by_pdp_to_pep"`
    PrivkeyForCertsShownByPdpToPep  string  `yaml:"privkey_for_certs_shown_by_pdp_to_pep"`
}

func LoadConfig(configPath string) error {
    if configPath == "" {
        return errors.New("config: no config file path was provided")
    }

    file, err := os.Open(configPath)
    if err != nil {
        return fmt.Errorf("config: could not open config file: %w", err)
    }
    defer file.Close()

    d := yaml.NewDecoder(file)

    err = d.Decode(&Config)
    if err != nil {
        return fmt.Errorf("config: could not decode config file: %w", err)
    }

    return nil
}
