package authorization

/*
In this file, the trust score of a request is calculated. According to the trust score it is decided, if a request is
forwarded or blocked.
*/

import (
    "fmt"

    md "github.com/vs-uulm/ztsfc_http_pdp/internal/app/metadata"
    logger "github.com/vs-uulm/ztsfc_http_logger"
    rattr "github.com/vs-uulm/ztsfc_http_attributes"
    "github.com/vs-uulm/ztsfc_http_pdp/internal/app/policies"
    "github.com/vs-uulm/ztsfc_http_pdp/internal/app/trust_engine"
    "github.com/vs-uulm/ztsfc_http_pdp/internal/app/attributes"
)

type AuthResponse struct {
    Allow bool `json:"allow"`
    Sfc []Sf `json:"sfc"`
}

type Sf struct {
    Name string `json:"name"`
    Md string `json:"md"`
}

/*
This function decides based on the achieved trust score and the requested service, if the request should be directly
sent to the service, sent to the DPI or be blocked.

@param sysLogger: used to print debug messages
@param req: request of the user

@return forwardSFC: List of identifiers for service functions. nil if request is not allowed at all.
@return allow: False, when the request should be blocked; True, when the request should be forwarded
*/
func PerformAuthorization(sysLogger *logger.Logger, cpm *md.Cp_metadata) (AuthResponse, error) {
    var authResponse AuthResponse

    // Step 1: request user attributes
    // TODO: implement 

    // Step 2: request device attributes
    devAttributes, _ := rattr.NewEmptyDevice()
    err := attributes.RequestDeviceAttributes(sysLogger, cpm, devAttributes)
    if err != nil {
        return authResponse, fmt.Errorf("authorization: PerformAuthorization(): error requesting device attributes from PIP: %v", err)
    }

    // Step Y: check policie rules
    if devAttributes.Revoked {
        sysLogger.Infof("authorization: PerformAuthorization(): Requested was rejected since the involved device '%s' is revoked", devAttributes.DeviceID)
        authResponse.Allow = false
        return authResponse, nil
    }

    sysLogger.Debugf("authorization: calcUserTrust(): device attributes for '%s'=%v", cpm.Device, devAttributes)

    // Step B: calculate trust score
    totalTrustScore := trust_engine.CalcTrustScore(sysLogger, cpm)

    sysLogger.Debugf("authorization: calcUserTrust(): for user=%s, resource=%s and action=%s the calculated total trust score is %d",
        cpm.User, cpm.Resource, cpm.Action, totalTrustScore)

    trustThreshold := policies.Policies.Resources[cpm.Resource].Actions[cpm.Action].TrustThreshold
    if totalTrustScore >= trustThreshold {
        authResponse.Allow = true
        authResponse.Sfc = nil

        // Step X: update device attributes
        if err := attributes.UpdateDeviceAttributes(sysLogger, cpm, devAttributes); err != nil {
            return authResponse, fmt.Errorf("authorization: PerformAuthorization(): error updating device attributes to PIP: %v", err)
        }

        return authResponse, nil
    } else {
        authResponse.Allow = false
        return authResponse, nil

        /* Example for adding SFs to the SFC
        authResponse.Allow = true
        authResponse.Sfc = append(authResponse.Sfc, Sf{Name: "logger", Md: "basic"}, Sf{Name: "ips", Md: "basic"})
        return authResponse
        */
    }
}
