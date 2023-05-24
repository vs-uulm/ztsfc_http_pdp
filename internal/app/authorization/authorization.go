package authorization

/*
In this file, the trust score of a request is calculated. According to the trust score it is decided, if a request is
forwarded or blocked.
*/

import (
	"fmt"

	rattr "github.com/vs-uulm/ztsfc_http_attributes"
	logger "github.com/vs-uulm/ztsfc_http_logger"
	"github.com/vs-uulm/ztsfc_http_pdp/internal/app/attributes"
	md "github.com/vs-uulm/ztsfc_http_pdp/internal/app/metadata"
	"github.com/vs-uulm/ztsfc_http_pdp/internal/app/policies"
	"github.com/vs-uulm/ztsfc_http_pdp/internal/app/policy_engine"
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

/*
This function decides based on the achieved trust score and the requested service, if the request should be directly
sent to the service, sent to the DPI or be blocked.

@param sysLogger: used to print debug messages
@param req: request of the user

@return forwardSFC: List of identifiers for service functions. nil if request is not allowed at all.
@return allow: False, when the request should be blocked; True, when the request should be forwarded
*/
func PerformAuthorization(sysLogger *logger.Logger, cpm *md.Cp_metadata) (AuthResponse, error) {
	var authResponse AuthResponse = AuthResponse{Allow: false, Reason: "Dummy reason...", Sfc: nil}

	// Step 0: Preparation step.
	// Checks if there is a policy defined for the requested resource
	_, ok := policies.Policies.Resources[cpm.Resource]
	if !ok {
		authResponse.Reason = "There is no policy defined for the requested resource"
		//return authResponse, fmt.Errorf("authorization: PerformAuthorization(): There is no policy defined for the requested resource")
		return authResponse, nil
	}

	// Step 1: Attribute Retrieval
	var user *rattr.User
	var device *rattr.Device
	var system *rattr.System
	user, device, system, err := attributes.RetrieveAttributes(sysLogger, cpm)
	if err != nil {
		return authResponse, fmt.Errorf("authorization: PerformAuthorization(): %v", err)
	}

	// Step 2: Evaluate ACL rules
	peDecision, peFeedback := policy_engine.EvaluateACLRules(sysLogger, cpm, user, device, system)
	if !peDecision {
		authResponse.Allow = peDecision
		authResponse.Reason = peFeedback
		return authResponse, nil
	}

	// Step 3: Evaluate Trust-based Policy Rules
	switch policies.Policies.TrustAlgorithm.Variant {
	case "criteria_based_binary":
		authResponse.Allow, authResponse.Reason = trust_engine.PerformCriteriaBasedBinary(sysLogger, cpm, user, device, system)
		return authResponse, nil
	default:
		// Deprecated!
		// Step 3: Evaluate Trust Threshold Based Expressions
		trustThreshold, err := trust_engine.CalcTrustThresholdAdditive(sysLogger, cpm, system)
		if err != nil {
			authResponse.Allow = false
			authResponse.Reason = "For the requested resource the requested action is not defined."
			return authResponse, err
		}

		// Step 4: Evaluate Trust Score Based Expressions
		totalTrustScore := trust_engine.CalcTrustScoreAdditive(sysLogger, cpm, user, device)

		// Step 4b: Evaluate SL Trust Opinion; Just for Testing
		// trust_engine.CalcTrustScoreSL(sysLogger, cpm, user, device)

		sysLogger.Debugf("authorization: calcUserTrust(): for user=%s, resource=%s and action=%s the calculated total trust score is %d", cpm.User, cpm.Resource, cpm.Action, totalTrustScore)

		if totalTrustScore >= trustThreshold {
			sysLogger.Debugf("authorization: calcUserTrust(): for user=%s, resource=%s and action=%s the request has been permitted since total trust score '%d' is greater than or requals calculated threshold '%d'", cpm.User, cpm.Resource, cpm.Action, totalTrustScore, trustThreshold)
			authResponse.Allow = true
			authResponse.Reason = "trust score high enough without SFC"

			// Step X: update device attributes
			if err := attributes.UpdateDeviceAttributes(sysLogger, cpm, device); err != nil {
				return authResponse, fmt.Errorf("authorization: PerformAuthorization(): error updating device attributes to PIP: %v", err)
			}

			return authResponse, nil
		} else {
			sysLogger.Debugf("authorization: calcUserTrust(): for user=%s, resource=%s and action=%s the request has been rejected since total trust score '%d' is lower than calculated threshold '%d'", cpm.User, cpm.Resource, cpm.Action, totalTrustScore, trustThreshold)
			authResponse.Allow = false
			authResponse.Reason = "Your request was rejected since your total trust score is too low"
			return authResponse, nil

			/* Example for adding SFs to the SFC
			   authResponse.Allow = true
			   authResponse.Sfc = append(authResponse.Sfc, Sf{Name: "logger", Md: "basic"}, Sf{Name: "ips", Md: "basic"})
			   return authResponse
			*/
		}
	}
}
