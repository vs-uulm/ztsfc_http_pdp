package trust_engine

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
    "github.com/vs-uulm/ztsfc_http_pdp/internal/app/policies"
)

/*
In this function the totalTrustScore is calculated; it comprises of user and device trust score

@param sysLogger: used to print debug messages
@param cpm: holds all user and device metadata

@return trust: calculated total trust score 
*/
func CalcTrustScoreAdditive(sysLogger *logger.Logger, cpm *md.Cp_metadata, user *rattr.User, device *rattr.Device) int {
	userTrust := calcUserTrustAdditive(sysLogger, cpm, user)

	deviceTrust := calcDeviceTrustAdditive(sysLogger, cpm)

	totalTrustScore := userTrust + deviceTrust

    return totalTrustScore
}

/*
Considered Attributes:
    - PW Authentication
    - Usual Times
    - Usual Service
*/
func calcUserTrustAdditive(sysLogger *logger.Logger, cpm *md.Cp_metadata, user *rattr.User) (trust int) {
	trust = 0

    if cpm.PwAuthenticated {
        if user.FailedPWAuthentication <= policies.Policies.Attributes.User.PwAuthenticated {
            trust += policies.Policies.Attributes.User.PwAuthenticated - user.FailedPWAuthentication
        }
    }

    requestTime := time.Now().Hour()
    if requestTime >= user.UsualTimeBegin && requestTime <= user.UsualTimeEnd {
        trust += policies.Policies.Attributes.User.UsualTime
    }

    for _, service := range user.UsualServices {
        if cpm.Resource == service {
            trust += policies.Policies.Attributes.User.UsualService
        }
    }

    sysLogger.Debugf("trust_engine: calcUserTrust(): for user=%s, resource=%s and action=%s the calculated user score is %d",
        cpm.User, cpm.Resource, cpm.Action, trust)

    return trust

}

/*
Considered Attributes:
    - Device Certificate Authentication
    - Device Location
    - Request Rate
*/
func calcDeviceTrustAdditive(sysLogger *logger.Logger, cpm *md.Cp_metadata) (trust int) {
	trust = 0

    if cpm.CertAuthenticated {
        trust += policies.Policies.Attributes.Device.CertAuthenticated
    }

    if deviceAccessFromTrustedLocation(cpm) {
        trust += policies.Policies.Attributes.Device.FromTrustedLocation
    }

    if withinAllowedRequestRate(cpm) {
        trust += policies.Policies.Attributes.Device.WithinAllowedRequestRate

    }

    sysLogger.Debugf("trust_engine: calcDeviceTrust(): for user=%s, resource=%s and action=%s the calculated device score is %d",
        cpm.User, cpm.Resource, cpm.Action, trust)

	return trust
}

func CalcTrustThresholdAdditive(sysLogger *logger.Logger, cpm *md.Cp_metadata, system *rattr.System) (threshold int, err error) {
    threshold = 0
    err = nil

    threshold += policies.Policies.Resources[cpm.Resource].TargetSensitivity
    threshold += policies.Policies.Resources[cpm.Resource].ProtocolSecurity
    threshold += policies.Policies.Resources[cpm.Resource].TargetState
    threshold += policies.Policies.Resources[cpm.Resource].TargetHealth
    threshold += policies.Policies.Resources[cpm.Resource].TargetVuln

    if _, ok := policies.Policies.Resources[cpm.Resource].Actions[cpm.Action]; !ok {
        return 0, fmt.Errorf("trust_engine: CalcTrustThresholdAdditive(): for user=%s, resource=%s the action=%s is not defined in the policies",
            cpm.User, cpm.Resource, cpm.Action)
    }
    threshold += policies.Policies.Resources[cpm.Resource].Actions[cpm.Action].TrustThreshold

    // Dynamic attributes (will change later)
    threshold += (int(system.ThreatLevel) * 10)
    sysLogger.Debugf("trust_engine: CalcTrustThresholdAdditive(): for user=%s, resource=%s the action=%s the threat level was '%d'",
    cpm.User, cpm.Resource, cpm.Action, system.ThreatLevel)
    return threshold, nil
}
