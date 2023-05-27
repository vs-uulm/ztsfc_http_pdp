package policy_engine

import (
	rattr "github.com/vs-uulm/ztsfc_http_attributes"
	logger "github.com/vs-uulm/ztsfc_http_logger"
	md "github.com/vs-uulm/ztsfc_http_pdp/internal/app/metadata"
)

// TODO: Policy Missing. Harcoded ATM
func EvaluateACLRules(sysLogger *logger.Logger, cpm *md.Cp_metadata, user *rattr.User, device *rattr.Device, system *rattr.System) (authDecision bool, feedback string) {

	// Checks if the user is present in the User DB
	if user != nil && len(user.UserID) == 0 {
		sysLogger.Infof("authorization: PerformAuthorization(): Requested was rejected since the involved user is not present in the user DB")
		authDecision = false
		feedback = "Your request was rejected since your user is not managed by the user DB"
		return
	}

	// Checks if the user has too many failed Auth* attempts already (failed attempts > 3)
	// This is also done by the PEP to dont give away information if password was correct or not
	// For User
	if user.FailedAuthAttempts > 3 {
		sysLogger.Infof("authorization: PerformAuthorization(): Requested was rejected since user account has been suspended")
		authDecision = false
		feedback = "You user account has been suspended"
		return
	}

	// Checks if the device is present in the Device DB
	if device != nil && len(device.DeviceID) == 0 {
		sysLogger.Infof("authorization: PerformAuthorization(): Requested was rejected since the involved device is not present in the device DB")
		authDecision = false
		feedback = "Your request was rejected since your device is not managed by the device DB"
		return
	}

	// Checks if the device is revoked
	if device != nil && device.Revoked {
		sysLogger.Infof("authorization: PerformAuthorization(): Requested was rejected since the involved device '%s' is revoked", device.DeviceID)
		authDecision = false
		feedback = "Your request was rejected since your device is revoked"
		return
	}

	// Checks if the current client's request rate is withing the allowed range for the requested service
	allowedToAccessService := false
	for _, service := range user.AllowedServices {
		if cpm.Resource == service {
			allowedToAccessService = true
			continue
		}
	}
	if !allowedToAccessService {
		sysLogger.Infof("authorization: PerformAuthorization(): Requested was rejected since the involved user '%s' is not allowed to access the requested service",
			user.UserID)
		authDecision = false
		feedback = "Your request was rejected since you are not allowed to access the requested service"
		return
	}

	authDecision = true
	feedback = ""
	return
}
