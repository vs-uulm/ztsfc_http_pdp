package trust_engine

/*
In this file, the trust score of a request is calculated. According to the trust score it is decided, if a request is
forwarded or blocked.
*/

import (
	rattr "github.com/vs-uulm/ztsfc_http_attributes"
	logger "github.com/vs-uulm/ztsfc_http_logger"
	md "github.com/vs-uulm/ztsfc_http_pdp/internal/app/metadata"
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

func ShowCaseCalcTrustScore(sysLogger *logger.Logger, cpm *md.Cp_metadata) (int, int, int) {
	userTrust := calcUserTrust(sysLogger, cpm)

	deviceTrust := calcDeviceTrust(sysLogger, cpm)

	totalTrustScore := userTrust + deviceTrust

	return totalTrustScore, userTrust, deviceTrust
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

	sysLogger.Debugf("CERT AUTHENTICATED: %v", cpm.CertAuthenticated)

	if cpm.CertAuthenticated {
		trust += policies.Policies.Attributes.Device.CertAuthenticated
	}

	if deviceAccessFromTrustedLocation(cpm) {
		trust += policies.Policies.Attributes.Device.FromTrustedLocation
	}

	if !withinAllowedRequestRate(cpm) {
	    sysLogger.Debugf("NOT WITHIN ALLOWED ACCESS RATE")
		trust -= policies.Policies.Attributes.Device.NotWithinAllowedRequestRatePenalty

	}

	sysLogger.Debugf("authorization: calcDeviceTrust(): for user=%s, resource=%s and action=%s the calculated device score is %d",
		cpm.User, cpm.Resource, cpm.Action, trust)

	return trust
}

func CalcTrustThreshold(sysLogger *logger.Logger, cpm *md.Cp_metadata, system *rattr.System) int {
	var adjustedTrustThreshold int
	adjustedTrustThreshold = policies.Policies.Resources[cpm.Resource].Actions[cpm.Action].TrustThreshold
	adjustedTrustThreshold = adjustedTrustThreshold + (system.ThreatLevel * 10)
	sysLogger.Debugf("THREAT LEVEL=%d RESULTS IN ADJUSTED TRUST TRESHOLD=%d", system.ThreatLevel, adjustedTrustThreshold)
	return adjustedTrustThreshold
}
