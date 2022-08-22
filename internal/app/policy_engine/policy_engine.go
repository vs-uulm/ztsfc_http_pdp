package policy_engine

import (
    logger "github.com/vs-uulm/ztsfc_http_logger"
    rattr "github.com/vs-uulm/ztsfc_http_attributes"
)

// TODO: Policy Missing. Harcoded ATM
func EvaluateAttributeBasedExpressions(sysLogger *logger.Logger, device *rattr.Device, system *rattr.System) (authDecision bool, feedback string) {
	if device != nil && len(device.DeviceID) == 0 {
		sysLogger.Infof("authorization: PerformAuthorization(): Requested was rejected since the involved device is not present in the device DB")
		authDecision = false
		feedback = "Your request was rejected since your device is not managed by the device DB"
		return
	}
	if device != nil && device.Revoked {
		sysLogger.Infof("authorization: PerformAuthorization(): Requested was rejected since the involved device '%s' is revoked", device.DeviceID)
		authDecision = false
		feedback = "Your request was rejected since your device is revoked"
		return
	}

    authDecision = true
    feedback = ""
    return
}
