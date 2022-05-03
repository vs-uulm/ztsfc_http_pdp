package authorization

/*
In this file, the trust score of a request is calculated. According to the trust score it is decided, if a request is
forwarded or blocked.
*/

import (
    "fmt"
    "time"

    md "github.com/vs-uulm/ztsfc_http_pdp/internal/app/metadata"
    logger "github.com/vs-uulm/ztsfc_http_logger"
    rattr "github.com/vs-uulm/ztsfc_http_attributes"
    //"github.com/vs-uulm/ztsfc_http_pdp/internal/app/policies"
    "github.com/vs-uulm/ztsfc_http_pdp/internal/app/trust_engine"
    "github.com/vs-uulm/ztsfc_http_pdp/internal/app/attributes"
)

type AuthResponse struct {
    Allow bool `json:"allow"`
    Reason string `json:"reason"`
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
    // TODO DANI/GEORG: Immer das struct AuthReponsse wenn die Funktion returned
    var authResponse AuthResponse
    var devAttributes *rattr.Device = nil

    // Step 3: request system attributes
    system := rattr.NewEmptySystem()
    err := attributes.RequestSystemAttributes(sysLogger, system)
    if err != nil {
        return authResponse, fmt.Errorf("authorization: PerformAuthorization(): error requesting system attributes from PIP: %v", err)
    }

    // Step 1: request user attributes
    // TODO: implement 

    // Step 2: request device attributes
    if len(cpm.Device) == 0 {
    // sysLogger.Infof("authorization: PerformAuthorization(): user '%s' uses an unknown device from '%s' for their request",
    // cpm.User, cpm.Location)
        sysLogger.Infof("authorization: PerformAuthorization(): Requested was rejected since the involved device '%s' is not authenticated", cpm.Device)
        authResponse.Allow = false
        authResponse.Reason = "Your request was rejected since your device is not authenticated"
        sysLogger.Infof("GUI OUTPUT: %s, %d, %s, -, -, -, -, %s, %s, %v, %s, -", 
            time.Now(), system.ThreatLevel, cpm.User, cpm.Resource, cpm.Action, authResponse.Allow, authResponse.Reason)
        return authResponse, nil

    } else {
        devAttributes, _ = rattr.NewEmptyDevice()
        err := attributes.RequestDeviceAttributes(sysLogger, cpm, devAttributes)
        if err != nil {
            return authResponse, fmt.Errorf("authorization: PerformAuthorization(): error requesting device attributes from PIP: %v", err)
        }
        if len(devAttributes.DeviceID) == 0 {
            sysLogger.Infof("authorization: PerformAuthorization(): user '%s' uses a device PIP has no information about from '%s' for their request",
                cpm.User, cpm.Location)
        }
    }

    // Step Y: check policie rules
    if devAttributes != nil && len(devAttributes.DeviceID) == 0 {
        sysLogger.Infof("authorization: PerformAuthorization(): Requested was rejected since the involved device '%s' is not present in the device DB", cpm.Device)
        authResponse.Allow = false
        authResponse.Reason = "Your request was rejected since your device is not managed by the device DB"
        return authResponse, nil
    }
    // TODO DANi/GEORG: Die variable devAttributes.Revoked (boolean)
    if devAttributes != nil && devAttributes.Revoked {
        sysLogger.Infof("authorization: PerformAuthorization(): Requested was rejected since the involved device '%s' is revoked", devAttributes.DeviceID)
        authResponse.Allow = false
        authResponse.Reason = "Your request was rejected since your device is revoked"
        return authResponse, nil
    }

    sysLogger.Debugf("authorization: calcUserTrust(): device attributes for '%s'=%v", cpm.Device, devAttributes)

    // Step B: calculate trust score
    // TODO DANI/GEORG: totalTrustScore (int) pro anfrage; also immer hier wenn die funktion aufgerufen wird; 
    // In der Funktion hier sind auch noch zwei zu exportierenden Variablen.
    // Wenn die Policy oben in Step Y aber schon negativ ergibt was dann?
    totalTrustScore, userTrustScore, deviceTrustScore := trust_engine.ShowCaseCalcTrustScore(sysLogger, cpm)

    sysLogger.Debugf("authorization: calcUserTrust(): for user=%s, resource=%s and action=%s the calculated total trust score is %d",
        cpm.User, cpm.Resource, cpm.Action, totalTrustScore)

    // TODO DANI/GEORG: die variable system.ThreatLevel (int64) die im zeitlichen Verlauf dargestellt werden soll.
    // TODO DANI/GEORG: die variable trustThreshold (int)
    trustThreshold := trust_engine.CalcTrustThreshold(sysLogger, cpm, system)

    // Step Y: make authorization decision
    if totalTrustScore >= trustThreshold {
        authResponse.Allow = true
        authResponse.Sfc = nil
        sysLogger.Infof("GUI OUTPUT: %s, %d, %s, %d, %s, %d, %d, %s, %s, %v, %s, %v",
            time.Now(), system.ThreatLevel, cpm.User, userTrustScore, cpm.Device, deviceTrustScore, totalTrustScore,
            cpm.Resource, cpm.Action, authResponse.Allow, authResponse.Reason, authResponse.Sfc)

        // Step Z: update device attributes
        if err := attributes.UpdateDeviceAttributes(sysLogger, cpm, devAttributes); err != nil {
            return authResponse, fmt.Errorf("authorization: PerformAuthorization(): error updating device attributes to PIP: %v", err)
        }

        return authResponse, nil
    } else {
        authResponse.Allow = false
        authResponse.Reason = "Your request was rejected since your total trust score is too low"
        sysLogger.Infof("GUI OUTPUT: %s, %d, %s, %d, %s, %d, %d, %s, %s, %v, %s, %v",
            time.Now(), system.ThreatLevel, cpm.User, userTrustScore, cpm.Device, deviceTrustScore, totalTrustScore,
            cpm.Resource, cpm.Action, authResponse.Allow, authResponse.Reason, authResponse.Sfc)
        return authResponse, nil

        /* Example for adding SFs to the SFC
        authResponse.Allow = true
        authResponse.Sfc = append(authResponse.Sfc, Sf{Name: "logger", Md: "basic"}, Sf{Name: "ips", Md: "basic"})
        return authResponse
        */
    }
}
