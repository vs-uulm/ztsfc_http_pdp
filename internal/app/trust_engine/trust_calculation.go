package trust_engine

/*
In this file, the trust score of a request is calculated. According to the trust score it is decided, if a request is
forwarded or blocked.
*/

import (
    md "github.com/vs-uulm/ztsfc_http_pdp/internal/app/metadata"
    logger "github.com/vs-uulm/ztsfc_http_logger"
    "github.com/vs-uulm/ztsfc_http_pdp/internal/app/policies"
)

/*
In this function the totalTrustScore is calculated; it comprises of user and device trust score

@param sysLogger: used to print debug messages
@param cpm: holds all user and device metadata

@return trust: calculated total trust score 
*/
func CalcTrustScore(sysLogger *logger.Logger, cpm *md.Cp_metadata) int {
	userTrust := calcUserTrust(sysLogger, cpm)

	deviceTrust := calcDeviceTrust(sysLogger, cpm)

	totalTrustScore := userTrust + deviceTrust

    return totalTrustScore
}

/*
In this fuction the trust score of the user attributes is calculated

@param sysLogger: used to print debug messages
@param cpm: holds all user and device metadata

@return trust: calculated user trust 
*/
func calcUserTrust(sysLogger *logger.Logger, cpm *md.Cp_metadata) (trust int) {
	trust = 0

    if cpm.PwAuthenticated {
        trust += policies.Policies.Attributes.User.PwAuthenticated
    }

    if cpm.CertAuthenticated {
        trust += policies.Policies.Attributes.User.CertAuthenticated
    }

    sysLogger.Debugf("authorization: calcUserTrust(): for user=%s, resource=%s and action=%s the calculated user score is %d",
        cpm.User, cpm.Resource, cpm.Action, trust)

    return trust

}

/*
In this function the trust score of the device attributes is calculated

@param sysLogger: used to print debug messages
@param cpm: holds all user and device metadata

@return trust: trust score of device attributes
*/
func calcDeviceTrust(sysLogger *logger.Logger, cpm *md.Cp_metadata) (trust int) {
	trust = 0

    if deviceAccessFromTrustedLocation(cpm) {
        trust += policies.Policies.Attributes.Device.FromTrustedLocation
    }

    if !withinAllowedRequestRate(cpm) {
        trust -= policies.Policies.Attributes.Device.NotWithinAllowedRequestRatePenalty

    }

    sysLogger.Debugf("authorization: calcDeviceTrust(): for user=%s, resource=%s and action=%s the calculated device score is %d",
        cpm.User, cpm.Resource, cpm.Action, trust)

	return trust
}
