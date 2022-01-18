package init

import (
    "fmt"
    "errors"

    "github.com/vs-uulm/ztsfc_http_pdp/internal/app/policies"
)

func initAttributesParams() error {
    if err := initUser(); err != nil {
        return fmt.Errorf("initAttributes(): %v", err)
    }
    if err := initDevice(); err != nil {
        return fmt.Errorf("initDevice(): %v", err)
    }
    if err := initSf(); err != nil {
        return fmt.Errorf("initSf(): %v", err)
    }
    return nil
}

func initUser() error {
    if policies.Policies.Attributes.User.PwAuthenticated < 0 {
        return errors.New("initUser(): attribute 'pw_authenticated' is negative")
    }
    if policies.Policies.Attributes.User.CertAuthenticated < 0 {
        return errors.New("initUser(): attribute 'cert_authenticated' is negative")
    }
    return nil
}

func initDevice() error {
    if policies.Policies.Attributes.Device.FromTrustedLocation < 0 {
        return errors.New("initUser(): attribute 'from_trusted_location' is negative")
    }
    if policies.Policies.Attributes.Device.NotWithinAllowedRequestRatePenalty < 0 {
        return errors.New("initUser(): attribute 'not_within_allowed_request_rate_penalty' is negative")
    }
    return nil
}

func initSf() error {
    if policies.Policies.Attributes.Sf == nil {
        return errors.New("initSf(): no 'sf' defined")
    }

    for sfName, sf := range policies.Policies.Attributes.Sf {
        if sf.Basic < 0 {
            return errors.New("initSf(): for " + sfName + " the attribute 'basic' is negative")
        }
        if sf.Advanced < 0 {
            return errors.New("initSf(): for " + sfName + " the attribute 'advanced' is negative")
        }
        if sf.Full < 0 {
            return errors.New("initSf(): for " + sfName + " the attribute 'full' is negative")
        }
    }
    return nil
}
