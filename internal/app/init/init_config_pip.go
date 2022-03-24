package init

import (
    "fmt"
    "crypto/x509"

    "github.com/vs-uulm/ztsfc_http_pdp/internal/app/config"
    gct "github.com/leobrada/golang_convenience_tools"
)
func initPipParams() error {
    fields := ""
    var err error

    if config.Config.Pip.TargetAddr == "" {
        fields += "target_addr"
    }

    // TODO: add device endpoint? or is it ok if its left empty?

    if config.Config.Pip.CertsPdpAcceptsWhenShownByPip == nil {
        fields += "certs_pep_accepts_when_shown_by_pip"
    }

    if config.Config.Pip.CertShownByPdpToPip == "" {
        fields += "cert_shown_by_pdp_to_pip"
    }

    if config.Config.Pip.PrivkeyForCertShownByPdpToPip == "" {
        fields += "privkey_for_certs_shown_by_pdp_to_pip"
    }

    // Read CA certs and PDP certificate used for the PIP connection
    config.Config.Pip.CaCertPoolPdpAcceptsFromPip = x509.NewCertPool()
    for _, acceptedPipCert := range config.Config.Pip.CertsPdpAcceptsWhenShownByPip {
        if err = gct.LoadCACertificate(acceptedPipCert, config.Config.Pip.CaCertPoolPdpAcceptsFromPip); err != nil {
            return fmt.Errorf("initPipParams(): error loading certificates PDP accepts from PIP: %w", err)
        }
    }

    config.Config.Pip.X509KeyPairShownByPdpToPip, err = gct.LoadX509KeyPair(config.Config.Pip.CertShownByPdpToPip,
        config.Config.Pip.PrivkeyForCertShownByPdpToPip)

    config.Config.Pip.PipClient = gct.NewHTTPSClient(config.Config.Pip.CaCertPoolPdpAcceptsFromPip, config.Config.Pip.X509KeyPairShownByPdpToPip)

    return err
}
