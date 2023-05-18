package trust_engine

import (
	"crypto/tls"
	"fmt"
	"time"

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

	authDecision = true
	feedback = "sussesfull"
	return
}

func performCriteriaBasedBinaryUserAttributes(sysLogger *logger.Logger, cpm *md.Cp_metadata, user *rattr.User) (authDecision bool, feedback string) {

	// Checks Attribute "Password Authentication"
	if !cpm.PwAuthenticated {
		authDecision = false
		feedback = fmt.Sprintf("User %s is not password authenticated", cpm.User)
		return
	}

	// Checks Attribute "Enterprise Presence"
	if !user.EnterprisePresence {
		authDecision = false
		feedback = fmt.Sprintf("User %s should not be present right now", cpm.User)
		return
	}

	// Checks Attribute "Service Usage"
	if !isUsualServiceForUser(sysLogger, cpm, user) {
		authDecision = false
		feedback = fmt.Sprintf("User %s tries to access an unusual service", cpm.User)
		return
	}

	// Checks Attribute "Device Usage"
	if !isUsualDevice(sysLogger, cpm, user) {
		authDecision = false
		feedback = fmt.Sprintf("User %s tries to access using an unusual device", cpm.User)
		return
	}

	// Checks Attribute "Access Time"
	// TODO:
	requestTime := time.Now().Hour()
	if requestTime == 22 {
		requestTime = 0
	} else if requestTime == 23 {
		requestTime = 1
	} else {
		requestTime = requestTime + 2
	}
	sysLogger.Debugf("Access Time For User %s: %d", user.UserID, requestTime)
	if !(requestTime >= user.UsualTimeBegin && requestTime <= user.UsualTimeEnd) {
		authDecision = false
		feedback = fmt.Sprintf("User %s requests access outside of their usual access time", cpm.User)
		return
	}

	// Checks Attribute "Access Rate"
	if !withinUsualAccessRate(sysLogger, user) {
		authDecision = false
		feedback = fmt.Sprintf("User %s requests access outside of their usual access rate", cpm.User)
		return
	}

	// Check Attribute "Trust History"
	// TODO: implement

	authDecision = true
	feedback = "sussesfull"
	return
}

func performCriteriaBasedBinaryDeviceAttributes(sysLogger *logger.Logger, cpm *md.Cp_metadata, device *rattr.Device) (authDecision bool, feedback string) {

	// Checks Attribute "Password Authentication"
	if !cpm.CertAuthenticated {
		authDecision = false
		feedback = fmt.Sprintf("Device %s is not certificate authenticated", cpm.Device)
		return
	}

	// Checks Attribute "Enterprise Presence"
	if !device.EnterprisePresence {
		authDecision = false
		feedback = fmt.Sprintf("Device %s should not be present right now", cpm.Device)
		return
	}

	// Checks Attribute "Service Usage"
	if !isUsualServiceForDevice(sysLogger, cpm, device) {
		authDecision = false
		feedback = fmt.Sprintf("Device %s tries to access an unusual service", cpm.Device)
		return
	}

	// Checks Attribute "User Usage"
	if !isUsualUser(sysLogger, cpm, device) {
		authDecision = false
		feedback = fmt.Sprintf("Device %s is used by an unusual user", cpm.Device)
		return
	}

	// Check Attribute "Connection Security"
	if cpm.ConnectionSecurity != tls.CipherSuiteName(tls.TLS_AES_128_GCM_SHA256) &&
		cpm.ConnectionSecurity != tls.CipherSuiteName(tls.TLS_AES_256_GCM_SHA384) &&
		cpm.ConnectionSecurity != tls.CipherSuiteName(tls.TLS_CHACHA20_POLY1305_SHA256) {
		authDecision = false
		feedback = fmt.Sprintf("User %s is using a insecure connection", cpm.User)
		return
	}

	// Check Attribute "Software Patch Level"
	if !upToDateSoftwarePatchLevel(sysLogger, cpm) {
		authDecision = false
		feedback = fmt.Sprintf("User %s is using outdated or unsupported software for making this request", cpm.User)
		return
	}

	// Check Attribute "Software Patch Level"
	if !upToDateSystemPatchLevel(sysLogger, cpm) {
		authDecision = false
		feedback = fmt.Sprintf("User %s is using outdated or unsupported system software for making this request", cpm.User)
		return
	}

	authDecision = true
	feedback = "sussesfull"
	return
}
