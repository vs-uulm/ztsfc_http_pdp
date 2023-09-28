package trust_engine

import (
	"fmt"

	rattr "github.com/vs-uulm/ztsfc_http_attributes"
	logger "github.com/vs-uulm/ztsfc_http_logger"
	md "github.com/vs-uulm/ztsfc_http_pdp/internal/app/metadata"
)

func PerformCriteriaBasedBinary(sysLogger *logger.Logger, cpm *md.Cp_metadata, user *rattr.User, device *rattr.Device, system *rattr.System) (authDecision bool, feedback string) {
	authDecision, feedback = performCriteriaBasedBinaryUserAttributes(sysLogger, cpm, user)
	if !authDecision {
		return
	}
	authDecision, feedback = performCriteriaBasedBinaryDeviceAttributes(sysLogger, cpm, device)
	if !authDecision {
		return
	}

	authDecision, feedback = performCriteriaBasedBinaryCCAttributes(sysLogger, cpm)
	if !authDecision {
		return
	}

	authDecision = true
	feedback = "sussesfull"
	return
}

func performCriteriaBasedBinaryUserAttributes(sysLogger *logger.Logger, cpm *md.Cp_metadata, user *rattr.User) (authDecision bool, feedback string) {

	// Checks User Attribute "Password Authentication"
	if !allowedUserAuthentationMethod(sysLogger, cpm) {
		authDecision = false
		sysLogger.WithFields(logger.Fields{"user": cpm.User, "reason": "User trust score is too low", "explanation": "user is not sufficiently authenticated for service", "service": cpm.Resource, "outcome": "user access denied"}).Debugf("")
		//sysLogger.Debugf("Trust score for user %s is too low: user is not sufficiently authenticated!", cpm.User)
		feedback = fmt.Sprintf("User %s is not correctly authenticated for the requested service", cpm.User)
		return
	}

	// Checks User Attribute "Enterprise Presence"
	if !user.EnterprisePresence {
		authDecision = false
		feedback = fmt.Sprintf("User %s should not be present right now", cpm.User)
		return
	}

	// Checks User Attribute "Service Usage"
	if !isUsualServiceForUser(sysLogger, cpm, user) {
		authDecision = false
		feedback = fmt.Sprintf("User %s tries to access an unusual service", cpm.User)
		return
	}

	// Checks User Attribute "Device Usage"
	if !isUsualDevice(sysLogger, cpm, user) {
		authDecision = false
		feedback = fmt.Sprintf("User %s tries to access using an unusual device", cpm.User)
		return
	}

	// Checks User Attribute "Access Time"
	if !isUsualAccessTime(sysLogger, user) {
		authDecision = false
		feedback = fmt.Sprintf("User %s tries to access at an unusual time", cpm.User)
		return
	}

	// Checks User Attribute "Access Rate"
	if !withinUsualAccessRate(sysLogger, user) {
		authDecision = false
		feedback = fmt.Sprintf("User %s requests access outside of their usual access rate", cpm.User)
		return
	}

	// Check Attribute "Trust History"
	// TODO: implement

	authDecision = true
	feedback = "sussesfull"
	sysLogger.WithFields(logger.Fields{"user": cpm.User, "reason": "User trust score is high enough", "explanation": "", "outcome": "user access permitted", "service": cpm.Resource}).Debugf("")
	return
}

func performCriteriaBasedBinaryDeviceAttributes(sysLogger *logger.Logger, cpm *md.Cp_metadata, device *rattr.Device) (authDecision bool, feedback string) {

	// Checks Device Attribute "Certificate Authentication"
	if !allowedDeviceAuthentationMethod(sysLogger, cpm, device) {
		authDecision = false
		sysLogger.WithFields(logger.Fields{"device": cpm.Device, "reason": "Device trust score is too low", "explanation": "device is not sufficiently authenticated for service", "service": cpm.Resource, "outcome": "device access denied"}).Debugf("")
		//sysLogger.Debugf("Device trust score for device %s is too low: device is not sufficiently authenticated for service  %s!", cpm.Device, cpm.Resource)
		feedback = fmt.Sprintf("Device %s is not correctly authenticated for the requested service", cpm.Device)
		return
	}

	// Checks Device Attribute "Certificate Authentication"
	//if !cpm.CertAuthenticated {
	//	authDecision = false
	//	feedback = fmt.Sprintf("Device %s is not certificate authenticated", cpm.Device)
	//	return
	//}

	// Checks Device Attribute "Enterprise Presence"
	if !device.EnterprisePresence {
		authDecision = false
		feedback = fmt.Sprintf("Device %s should not be present right now", cpm.Device)
		return
	}

	// Checks Device Attribute "Service Usage"
	if !isUsualServiceForDevice(sysLogger, cpm, device) {
		authDecision = false
		feedback = fmt.Sprintf("Device %s tries to access an unusual service", cpm.Device)
		return
	}

	// Checks Device Attribute "User Usage"
	if !isUsualUser(sysLogger, cpm, device) {
		authDecision = false
		feedback = fmt.Sprintf("Device %s is used by an unusual user", cpm.Device)
		return
	}

	// JUST FOR DEMONSTRATION
	// Check Device Attribute "Connection Security"
	//if !isSecureConnection(sysLogger, cpm) {
	//	authDecision = false
	//	feedback = fmt.Sprintf("Device %s is using a insecure connection", cpm.Device)
	//	return
	//}

	// Check Device Attribute "Software Patch Level"
	if !upToDateSoftwarePatchLevel(sysLogger, cpm) {
		authDecision = false
		feedback = fmt.Sprintf("Device %s is using outdated or unsupported software for making this request", cpm.Device)
		return
	}

	// Check Device Attribute "Software Patch Level"
	if !upToDateSystemPatchLevel(sysLogger, cpm) {
		authDecision = false
		feedback = fmt.Sprintf("Device %s is using outdated or unsupported system software for making this request", cpm.Device)
		return
	}

	// Check Device Attribute "Fingerprint"
	if !correctFingerprint(sysLogger, cpm, device) {
		authDecision = false
		feedback = fmt.Sprintf("Device %s shows an unusual fingerprint", cpm.Device)
		return
	}

	// Check Device Attribute "Type"
	if !isCorrectType(sysLogger, cpm, device) {
		authDecision = false
		feedback = fmt.Sprintf("Device %s shows an unusual type", cpm.Device)
		return
	}

	authDecision = true
	feedback = "sussesfull"
	sysLogger.WithFields(logger.Fields{"device": cpm.Device, "reason": "Device trust score is high enough", "explanation": "", "outcome": "device access permitted", "service": cpm.Resource}).Debugf("")
	return
}

func performCriteriaBasedBinaryCCAttributes(sysLogger *logger.Logger, cpm *md.Cp_metadata) (authDecision bool, feedback string) {

	// JUST FOR DEMONSTRATION
	// Check CC Attributes "Authenticated, Integrity Protected and Confidential"
	//if !isSecureConnection(sysLogger, cpm) {
	//	authDecision = false
	//	feedback = fmt.Sprintf("Communication channel is not sufficiently authenticated, integrity protected or confidential")
	//	return
	//}

	authDecision = true
	feedback = "sussesfull"
	return
}
