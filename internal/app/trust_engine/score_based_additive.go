package trust_engine

/*
In this file, the trust score of a request is calculated. According to the trust score it is decided, if a request is
forwarded or blocked.
*/

import (
	"fmt"

	rattr "github.com/vs-uulm/ztsfc_http_attributes"
	logger "github.com/vs-uulm/ztsfc_http_logger"
	md "github.com/vs-uulm/ztsfc_http_pdp/internal/app/metadata"
	"github.com/vs-uulm/ztsfc_http_pdp/internal/app/policies"
)

func PerformScoreBasedAdditive(sysLogger *logger.Logger, cpm *md.Cp_metadata, user *rattr.User, device *rattr.Device, system *rattr.System) (authDecision bool, feedback string) {
	userTrust := calcUserTrustAdditive(sysLogger, cpm, user)
	deviceTrust := calcDeviceTrustAdditive(sysLogger, cpm, device)
	ccTrust := calcCCTrustAdditive(sysLogger, cpm)
	// TODO: CCTrust

	if (userTrust + deviceTrust + ccTrust) >= 5 {
		authDecision = true
		feedback = "sussesfull"
		return
	} else {
		authDecision = false
		feedback = fmt.Sprintf("Trust score of user %s is too low", cpm.User)
		return
	}
}

/*
DEPRECATED

In this function the totalTrustScore is calculated; it comprises of user and device trust score

@param sysLogger: used to print debug messages
@param cpm: holds all user and device metadata

@return trust: calculated total trust score
*/
func CalcTrustScoreAdditive(sysLogger *logger.Logger, cpm *md.Cp_metadata, user *rattr.User, device *rattr.Device) int {
	userTrust := calcUserTrustAdditive(sysLogger, cpm, user)

	deviceTrust := calcDeviceTrustAdditive(sysLogger, cpm, device)

	totalTrustScore := userTrust + deviceTrust

	return totalTrustScore
}

func calcUserTrustAdditive(sysLogger *logger.Logger, cpm *md.Cp_metadata, user *rattr.User) (userTrustScore int) {
	userTrustScore = 0

	// Evaluates User Attribute "Password Authentication"
	if cpm.PwAuthenticated {
		userTrustScore++
	}

	// Evaluates User Attribute "Enterprise Presence"
	if user.EnterprisePresence {
		userTrustScore++
	}

	// Evaluates User Attribute "Service Usage"
	if isUsualServiceForUser(sysLogger, cpm, user) {
		userTrustScore++
	}

	// Evaluates User Attribute "Device Usage"
	if isUsualDevice(sysLogger, cpm, user) {
		userTrustScore++
	}

	// Evaluates User Attribute "Access Time"
	// TODO: Better time checking.
	if isUsualAccessTime(sysLogger, user) {
		userTrustScore++
	}

	// Evaluates User Attribute "Access Rate"
	if withinUsualAccessRate(sysLogger, user) {
		userTrustScore++
	}

	sysLogger.Debugf("trust_engine: calcUserTrust(): for user=%s, resource=%s and action=%s the calculated user score is %d",
		cpm.User, cpm.Resource, cpm.Action, userTrustScore)

	return

}

func calcDeviceTrustAdditive(sysLogger *logger.Logger, cpm *md.Cp_metadata, device *rattr.Device) (deviceTrustScore int) {
	deviceTrustScore = 0

	// Checks Device Attribute "Certificate Authentication"
	if cpm.CertAuthenticated {
		// trust += policies.Policies.Attributes.Device.CertAuthenticated
		deviceTrustScore++
	}

	// Evaluates Device Attribute "Enterprise Presence"
	if device.EnterprisePresence {
		deviceTrustScore++
	}

	// Evaluates Device Attribute "Service Usage"
	if isUsualServiceForDevice(sysLogger, cpm, device) {
		deviceTrustScore++
	}

	// Evaluates Device Attribute "User Usage"
	if isUsualUser(sysLogger, cpm, device) {
		deviceTrustScore++
	}

	// Evaluates Device Attribute "Connection Security"
	if isSecureConnection(sysLogger, cpm) {
		deviceTrustScore++
	}

	// Evaluates Device Attribute "Software Patch Level"
	if upToDateSoftwarePatchLevel(sysLogger, cpm) {
		deviceTrustScore++
	}

	// Evaluates Device Attribute "Software Patch Level"
	if upToDateSystemPatchLevel(sysLogger, cpm) {
		deviceTrustScore++
	}

	// Evaluates Device Attribute "Fingerprint"
	if correctFingerprint(sysLogger, cpm, device) {
		deviceTrustScore++
	}

	sysLogger.Debugf("trust_engine: calcDeviceTrust(): for user=%s, resource=%s and action=%s the calculated device score is %d",
		cpm.User, cpm.Resource, cpm.Action, deviceTrustScore)

	return
}

func calcCCTrustAdditive(sysLogger *logger.Logger, cpm *md.Cp_metadata) (ccTrustScore int) {
	ccTrustScore = 0

	// Evaluates CC Attribute "Authentication"
	if isSecureConnection(sysLogger, cpm) {
		ccTrustScore++
	}

	// Evaluates CC Attribute "Confidentiality"
	if isSecureConnection(sysLogger, cpm) {
		ccTrustScore++
	}

	// Evaluates CC Attribute "Integrity"
	if isSecureConnection(sysLogger, cpm) {
		ccTrustScore++
	}

	return
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
