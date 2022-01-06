package init

import (
    "fmt"
    "errors"
    "crypto/tls"
    "crypto/x509"
    "io/ioutil"
    "strings"
    "net"

    "golang.org/x/time/rate"

    "github.com/vs-uulm/ztsfc_http_pdp/internal/app/config"
    "github.com/vs-uulm/ztsfc_http_pdp/internal/app/policies"
)

func InitSysLoggerParams() {
        if config.Config.SysLogger.LogLevel == "" {
                config.Config.SysLogger.LogLevel = "error"
        }

        if config.Config.SysLogger.LogFilePath == "" {
                config.Config.SysLogger.LogFilePath = "stdout"
        }

        if config.Config.SysLogger.IfTextFormatter == "" {
                config.Config.SysLogger.IfTextFormatter = "json"
        }
}

func InitPdpParams() error {
    fields := ""
    var err error

    if config.Config.Pdp.ListenAddr == "" {
        fields += "listen_addr"
    }

    if config.Config.Pdp.CertsPdpAcceptsWhenShownByPep == nil {
        fields += "certs_pep_accepts_when_shown_by_pep"
    }


    if config.Config.Pdp.CertShownByPdpToPep == "" {
        fields += "cert_shown_by_pdp_to_pep"
    }

    if config.Config.Pdp.PrivkeyForCertsShownByPdpToPep == "" {
        fields += "privkey_for_certs_shown_by_pdp_to_pep"
    }

    // Read CA certs used for signing client certs and are accepted by the PEP
    for _, acceptedPepCert := range config.Config.Pdp.CertsPdpAcceptsWhenShownByPep {
        if err = loadCACertificate(acceptedPepCert, "client", config.Config.Pdp.CaCertPoolPdpAcceptsFromPep); err != nil {
            return fmt.Errorf("init: InitPdpParams(): error loading certificates PDP accepts from PEP: %w", err)
        }
    }

    config.Config.Pdp.X509KeyPairShownByPdpToPep, err = loadX509KeyPair(config.Config.Pdp.CertShownByPdpToPep,
        config.Config.Pdp.PrivkeyForCertsShownByPdpToPep, "PDP", "")

    return err
}

// All Policy Related Initialization Functions
func InitResourcesParams() error {
    if policies.Policies.Resources == nil {
        return errors.New("init: InitResourcesParams(): no resources defined")
    }

    // Iterates over all defined (by resName) resources
    for resName, resource := range policies.Policies.Resources {
        if resource == nil {
            return errors.New("init: InitResourcesParams(): resource '" + resName + "' is empty")
        }

        if resource.Actions == nil {
            return errors.New("init: InitResourcesParams(): for resource '" + resName + "' no actions are defined")
        }

        // Iterates over all defined actions for each resource
        for action, val := range resource.Actions {
            upperAction := strings.ToUpper(action)
            if upperAction != "GET" && upperAction != "POST" {
                return errors.New("init: InitResourcesParams(): action '" + action +
                    "' defined for resource '" + resName + "' is not valid")
            }

            if val.TrustThreshold <= 0 {
                return errors.New("init: InitResourcesParams(): for resource '" + resName +
                    "' and action '" + action + "' the trust threshold makes no sense")
            }
        }

        // Iterates over all trusted locations (for each resource) and tries to extract the IPNet from it
        for _, location := range resource.TrustedLocations {
            _, ipnet, err := net.ParseCIDR(location)
            if err != nil {
                return fmt.Errorf("init: InitResourcesParams(): %s is not in valid CIDR network notation: %v", location, err)
            }
            resource.TrustedIPNetworks = append(resource.TrustedIPNetworks, ipnet)
        }

        // Creates an empty ResourceAccessLimits map
        resource.ResourceAccessLimits = make(map[string]map[string]*rate.Limiter)
    }

    return nil
}

// function unifies the loading of CA certificates for different components
func loadCACertificate(certfile string, componentName string, certPool *x509.CertPool) error {
    caRoot, err := ioutil.ReadFile(certfile)
    if err != nil {
        return fmt.Errorf("loadCACertificate(): Loading %s CA certificate from %s error: %v", componentName, certfile, err)
    }

    certPool.AppendCertsFromPEM(caRoot)
    return nil
}

// function unifies the loading of X509 key pairs for different components
func loadX509KeyPair(certfile, keyfile, componentName, certAttr string) (tls.Certificate, error) {
    keyPair, err := tls.LoadX509KeyPair(certfile, keyfile)
    if err != nil {
        return keyPair, fmt.Errorf("loadX509KeyPair(): critical error when loading %s X509KeyPair for %s from %s and %s: %v", certAttr, componentName, certfile, keyfile, err)
    }

    return keyPair, nil
}
