package authorization

/*
In this file, the trust score of a request is calculated. According to the trust score it is decided, if a request is
forwarded or blocked.
*/

import (
    md "github.com/vs-uulm/ztsfc_http_pdp/internal/app/metadata"
    logger "github.com/vs-uulm/ztsfc_http_logger"
    "github.com/vs-uulm/ztsfc_http_pdp/internal/app/policies"
    "github.com/vs-uulm/ztsfc_http_pdp/internal/app/trust"
)

type AuthResponse struct {
    Allow bool `json:"allow"`
    Sfc []Sf `json:"sfc"`
}

type Sf struct {
    Name string `json:"name"`
    Md string `json:"md"`
}

//var (
//	trustCalc *DataSources = NewDataSources()
//)

/*
This function decides based on the achieved trust score and the requested service, if the request should be directly
sent to the service, sent to the DPI or be blocked.

@param sysLogger: used to print debug messages
@param req: request of the user

@return forwardSFC: List of identifiers for service functions. nil if request is not allowed at all.
@return allow: False, when the request should be blocked; True, when the request should be forwarded
*/
func PerformAuthorization(sysLogger *logger.Logger, cpm *md.Cp_metadata) AuthResponse {
    var authResponse AuthResponse

    totalTrustScore := trust.CalcTrustScore(sysLogger, cpm)

    sysLogger.Debugf("authorization: calcUserTrust(): for user=%s, resource=%s and action=%s the calculated total trust score is %d",
        cpm.User, cpm.Resource, cpm.Action, totalTrustScore)

    trustThreshold := policies.Policies.Resources[cpm.Resource].Actions[cpm.Action].TrustThreshold
    if totalTrustScore >= trustThreshold {
        authResponse.Allow = true
//        authResponse.Sfc = nil
        authResponse.Sfc = append(authResponse.Sfc, Sf{Name: "ips", Md: "basic"})

        return authResponse
    } else {
        authResponse.Allow = true
        authResponse.Sfc = append(authResponse.Sfc, Sf{Name: "logger", Md: "basic"}, Sf{Name: "ips", Md: "basic"})
        return authResponse

        //authResponse.Allow = false
        //return authResponse
    }
	//if aggregatedTrust >= trustThreshold {
	//	return []string{}, true
	//} else if (aggregatedTrust + trustCalc.loggerTrustIncrease) >= trustThreshold {
	//	return []string{"logger"}, true
	//} else if (aggregatedTrust + trustCalc.dpiTrustIncrease) >= trustThreshold {
	//	return []string{"dpi"}, true
	//} else if (aggregatedTrust + trustCalc.loggerTrustIncrease + trustCalc.dpiTrustIncrease) >= trustThreshold {
	//	return []string{"logger", "dpi"}, true
	//} else {
	//	return nil, false
	//}

}

/*
In this method is checked, if the user authenticated with a password or client-certificate and if the user is known to the PEP

@param req: request of the user

@return authenticated: True, when the user successfully authenticated; False, when the user didn't authenticate
*/
//func (trustCalc TrustCalculation) checkAuthentication(req *http.Request) (authenticated bool) {
//	userNamePW := ""
//	userNameCert := ""
//
//	// Check password-authentication
//	if name, err := req.Cookie("Username"); err == nil {				// Extract specified username in the cookie of the request
//		userNamePW = name.Value
//		if _, ok:= trustCalc.dataSources.UserDatabase[userNamePW]; !ok {	// Check, if specified username exists in the user database
//			trustCalc.Log("----Username " + userNamePW + "unknown -> Block\n")
//			fmt.Println("Username " + userNamePW + " unknown")
//			return false
//		}
//	}
//
//	// Check certificate-authentication
//	if certs := req.TLS.PeerCertificates; len(certs) > 0 {
//		userNameCert = certs[0].Subject.CommonName							// Extract username of the client certificate
//		if _, ok:= trustCalc.dataSources.UserDatabase[userNameCert]; !ok {	// Check, if specified username exists in the user database
//			trustCalc.Log("Username " + userNameCert + "unknown -> Block\n")
//			fmt.Println("Username " + userNameCert + " unknown")
//			return false
//		}
//	}
//
//	// Check if user authenticated with two different accounts in password and certificate
//	if userNamePW != "" && userNameCert != "" && userNamePW != userNameCert {
//		trustCalc.Log("----Username in Password" + userNamePW + "and Username in certificate " + userNamePW+" are different -> Block\n")
//		return false
//	}
//
//	trustCalc.Log("---User authenticated\n")
//	return true
//}

/*
In this method the custom headers, which are only necessary in the PEP for trust-calculation, are removed

@param req: request of the user
*/
//func (trustCalc TrustCalculation) removeHTTPHeader(req *http.Request) {
//		req.Header.Del("ip-addr-geo-area")
//		req.Header.Del("managedDevice")
//}
//
//func (trustCalc TrustCalculation) GetDataSources() *DataSources{
//	return trustCalc.dataSources
//}
//
//func (trustCalc TrustCalculation) Log(s string) {
//	trustCalc.logChannel <- []byte(s)
//}
