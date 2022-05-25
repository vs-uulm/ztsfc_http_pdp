package authorization

/*
In this file, the trust score of a request is calculated. According to the trust score it is decided, if a request is
forwarded or blocked.
*/

import (
	"fmt"
	"strings"
	"time"

	rattr "github.com/vs-uulm/ztsfc_http_attributes"
	logger "github.com/vs-uulm/ztsfc_http_logger"
	"github.com/vs-uulm/ztsfc_http_pdp/internal/app/jsonlogsender"
	md "github.com/vs-uulm/ztsfc_http_pdp/internal/app/metadata"

	"github.com/vs-uulm/ztsfc_http_pdp/internal/app/attributes"
	"github.com/vs-uulm/ztsfc_http_pdp/internal/app/policies"
	"github.com/vs-uulm/ztsfc_http_pdp/internal/app/trust_engine"
)

type AuthResponse struct {
	Allow  bool   `json:"allow"`
	Reason string `json:"reason"`
	Sfc    []Sf   `json:"sfc"`
}

type Sf struct {
	Name string `json:"name"`
	Md   string `json:"md"`
}

func (sf *Sf) toString() string {
	return fmt.Sprintf("%s(%s)", sf.Name, sf.Md)
}

/*
This function decides based on the achieved trust score and the requested service, if the request should be directly
sent to the service, sent to the DPI or be blocked.

@param sysLogger: used to print debug messages
@param req: request of the user

@return forwardSFC: List of identifiers for service functions. nil if request is not allowed at all.
@return allow: False, when the request should be blocked; True, when the request should be forwarded
*/
func PerformAuthorization(sysLogger *logger.Logger, logSender *jsonlogsender.JSONLogSender, cpm *md.Cp_metadata) (AuthResponse, error) {
	// TODO DANI/GEORG: Immer das struct AuthReponsse wenn die Funktion returned
	var authResponse AuthResponse
	var devAttributes *rattr.Device = nil

	// Step 3: request system attributes
	system := rattr.NewEmptySystem()
	err := attributes.RequestSystemAttributes(sysLogger, system)
	if err != nil {
		return authResponse, fmt.Errorf("authorization: PerformAuthorization(): error requesting system attributes from PIP: %s", err.Error())
	}

	// Step 1: request user attributes
	// TODO: implement

	// Step 2: request device attributes
	if len(cpm.Device) == 0 {
		sysLogger.Infof("authorization: PerformAuthorization(): Requested was rejected since the involved device '%s' is not authenticated", cpm.Device)
		authResponse.Allow = false
		authResponse.Reason = "Your request was rejected since your device is not authenticated"

		err = logSender.Send("ztsfc_pdp", fmt.Sprint(system.ThreatLevel), cpm.User, "0", "unknown", cpm.Location, "0", "0",
			cpm.Resource, cpm.Action, fmt.Sprint(authResponse.Allow), authResponse.Reason, "[]")
		if err != nil {
			return authResponse, fmt.Errorf("1 authorization: PerformAuthorization(): sending log to hook error: %s", err.Error())
		}
		return authResponse, nil

	} else {
		devAttributes, _ = rattr.NewEmptyDevice()
		err := attributes.RequestDeviceAttributes(sysLogger, cpm, devAttributes)
		if err != nil {
			return authResponse, fmt.Errorf("authorization: PerformAuthorization(): error requesting device attributes from PIP: %s", err.Error())
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

		err = logSender.Send("ztsfc_pdp", fmt.Sprint(system.ThreatLevel), cpm.User, "0", "unknown", cpm.Location, "0", "0",
			cpm.Resource, cpm.Action, fmt.Sprint(authResponse.Allow), authResponse.Reason, "[]")
		if err != nil {
			return authResponse, fmt.Errorf("1 authorization: PerformAuthorization(): sending log to hook error: %s", err.Error())
		}

		return authResponse, nil
	}
	// TODO DANi/GEORG: Die variable devAttributes.Revoked (boolean)
	if devAttributes != nil && devAttributes.Revoked {
		sysLogger.Infof("authorization: PerformAuthorization(): Requested was rejected since the involved device '%s' is revoked", devAttributes.DeviceID)
		authResponse.Allow = false
		authResponse.Reason = "Your request was rejected since your device is revoked"

		err = logSender.Send("ztsfc_pdp", fmt.Sprint(system.ThreatLevel), cpm.User, "0", cpm.Device, cpm.Location,
			"0", "0", cpm.Resource, cpm.Action, fmt.Sprint(authResponse.Allow),
			authResponse.Reason, sfcToString(authResponse.Sfc))
		if err != nil {
			return authResponse, fmt.Errorf("2 authorization: PerformAuthorization(): sending log to hook error: %s", err.Error())
		}

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

		err = logSender.Send("ztsfc_pdp", fmt.Sprint(system.ThreatLevel), cpm.User, fmt.Sprint(userTrustScore), cpm.Device, cpm.Location,
			fmt.Sprint(deviceTrustScore), fmt.Sprint(totalTrustScore), cpm.Resource, cpm.Action, fmt.Sprint(authResponse.Allow),
			authResponse.Reason, sfcToString(authResponse.Sfc))
		if err != nil {
			return authResponse, fmt.Errorf("2 authorization: PerformAuthorization(): sending log to hook error: %s", err.Error())
		}

		// Step Z: update device attributes
		if err := attributes.UpdateDeviceAttributes(sysLogger, cpm, devAttributes); err != nil {
			return authResponse, fmt.Errorf("authorization: PerformAuthorization(): error updating device attributes to PIP: %s", err.Error())
		}

		return authResponse, nil
	} else {

		// Add SFs to th SFC to increase the trust score
		if trustThreshold <= totalTrustScore+policies.Policies.Attributes.Sf["ips"].Basic {
			authResponse.Allow = true
			authResponse.Sfc = append(authResponse.Sfc, Sf{Name: "ips", Md: "basic"})

			err = logSender.Send("ztsfc_pdp", fmt.Sprint(system.ThreatLevel), cpm.User, fmt.Sprint(userTrustScore), cpm.Device, cpm.Location,
				fmt.Sprint(deviceTrustScore), fmt.Sprint(totalTrustScore+policies.Policies.Attributes.Sf["ips"].Basic), cpm.Resource, cpm.Action, fmt.Sprint(authResponse.Allow),
				authResponse.Reason, sfcToString(authResponse.Sfc))
			if err != nil {
				return authResponse, fmt.Errorf("3 authorization: PerformAuthorization(): sending log to hook error: %s", err.Error())
			}
			return authResponse, nil
		} else if trustThreshold <= totalTrustScore+policies.Policies.Attributes.Sf["ips"].Advanced {
			authResponse.Allow = true
			authResponse.Sfc = append(authResponse.Sfc, Sf{Name: "ips", Md: "advanced"})

			err = logSender.Send("ztsfc_pdp", fmt.Sprint(system.ThreatLevel), cpm.User, fmt.Sprint(userTrustScore), cpm.Device, cpm.Location,
				fmt.Sprint(deviceTrustScore), fmt.Sprint(totalTrustScore+policies.Policies.Attributes.Sf["ips"].Advanced), cpm.Resource, cpm.Action, fmt.Sprint(authResponse.Allow),
				authResponse.Reason, sfcToString(authResponse.Sfc))
			if err != nil {
				return authResponse, fmt.Errorf("4 authorization: PerformAuthorization(): sending log to hook error: %s", err.Error())
			}
			return authResponse, nil
		} else if trustThreshold <= totalTrustScore+policies.Policies.Attributes.Sf["ips"].Full {
			authResponse.Allow = true
			authResponse.Sfc = append(authResponse.Sfc, Sf{Name: "ips", Md: "full"})

			err = logSender.Send("ztsfc_pdp", fmt.Sprint(system.ThreatLevel), cpm.User, fmt.Sprint(userTrustScore), cpm.Device, cpm.Location,
				fmt.Sprint(deviceTrustScore), fmt.Sprint(totalTrustScore+policies.Policies.Attributes.Sf["ips"].Full), cpm.Resource, cpm.Action, fmt.Sprint(authResponse.Allow),
				authResponse.Reason, sfcToString(authResponse.Sfc))
			if err != nil {
				return authResponse, fmt.Errorf("5 authorization: PerformAuthorization(): sending log to hook error: %s", err.Error())
			}
			return authResponse, nil
		}

		authResponse.Allow = false
		authResponse.Reason = "Your request was rejected since your total trust score is too low"
		sysLogger.Infof("GUI OUTPUT: %s, %d, %s, %d, %s, %d, %d, %s, %s, %v, %s, %v",
			time.Now(), system.ThreatLevel, cpm.User, userTrustScore, cpm.Device, deviceTrustScore, totalTrustScore,
			cpm.Resource, cpm.Action, authResponse.Allow, authResponse.Reason, authResponse.Sfc)

		err = logSender.Send("ztsfc_pdp", fmt.Sprint(system.ThreatLevel), cpm.User, fmt.Sprint(userTrustScore), cpm.Device, cpm.Location,
			fmt.Sprint(deviceTrustScore), fmt.Sprint(totalTrustScore), cpm.Resource, cpm.Action, fmt.Sprint(authResponse.Allow),
			authResponse.Reason, sfcToString(authResponse.Sfc))
		if err != nil {
			return authResponse, fmt.Errorf("6 authorization: PerformAuthorization(): sending log to hook error: %s", err.Error())
		}

		return authResponse, nil

		/* Example for adding SFs to the SFC
		   authResponse.Allow = true
		   authResponse.Sfc = append(authResponse.Sfc, Sf{Name: "logger", Md: "basic"}, Sf{Name: "ips", Md: "basic"})
		   return authResponse
		*/
	}
}

func sfcToString(sfc []Sf) string {
	s := ""
	for _, sf := range sfc {
		s += sf.toString() + ","
	}
	return strings.TrimSuffix(s, ",")
}
