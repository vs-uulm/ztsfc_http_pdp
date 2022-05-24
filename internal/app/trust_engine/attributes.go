package trust_engine

/*
In this file, the trust score of a request is calculated. According to the trust score it is decided, if a request is
forwarded or blocked.
*/

import (
    "net"
    "time"

    "golang.org/x/time/rate"

    md "github.com/vs-uulm/ztsfc_http_pdp/internal/app/metadata"
    "github.com/vs-uulm/ztsfc_http_pdp/internal/app/policies"
)

func deviceAccessFromTrustedLocation(cpm *md.Cp_metadata) bool {
    resource, ok := policies.Policies.Resources[cpm.Resource]
    if !ok {
        return false
    }

    for _, trustedNetwork := range resource.TrustedIPNetworks {
        if trustedNetwork.Contains(net.ParseIP(cpm.Location)) {
            return true
        }
    }

    return false
}

func withinAllowedRequestRate(cpm *md.Cp_metadata) bool {
    maxDevicesPerUser := 5

    // TODO: Check of "policies.Policies.Resources[cpm.Resource]" exists
    user, exists := policies.Policies.Resources[cpm.Resource].ResourceAccessLimits[cpm.User]
    if !exists {
        policies.Policies.Resources[cpm.Resource].ResourceAccessLimits[cpm.User] = make(map[string]*policies.AccessLimiter)
        policies.Policies.Resources[cpm.Resource].ResourceAccessLimits[cpm.User][cpm.Device] = &policies.AccessLimiter{
            AccessLimit: rate.NewLimiter(policies.Policies.Resources[cpm.Resource].AllowedRequestsPerSecond, 2),
            PenaltyTimestamp: time.Time{},
        }
    } else if len(user) >= maxDevicesPerUser {
        for device, _ := range user {
            delete(user, device)
            break
        }
        policies.Policies.Resources[cpm.Resource].ResourceAccessLimits[cpm.User][cpm.Device] = &policies.AccessLimiter{
            AccessLimit: rate.NewLimiter(policies.Policies.Resources[cpm.Resource].AllowedRequestsPerSecond, 2),
            PenaltyTimestamp: time.Time{},
        }
    } else if policies.Policies.Resources[cpm.Resource].ResourceAccessLimits[cpm.User][cpm.Device] == nil {
        policies.Policies.Resources[cpm.Resource].ResourceAccessLimits[cpm.User][cpm.Device] = &policies.AccessLimiter{
            AccessLimit: rate.NewLimiter(policies.Policies.Resources[cpm.Resource].AllowedRequestsPerSecond, 2),
            PenaltyTimestamp: time.Time{},
        }
    }

    within := policies.Policies.Resources[cpm.Resource].ResourceAccessLimits[cpm.User][cpm.Device].PenaltyTimestamp.IsZero()
    if !within {
        applyPenaltyDirectly := policies.Policies.Resources[cpm.Resource].ResourceAccessLimits[cpm.User][cpm.Device].PenaltyTimestamp.After(time.Now())
        if applyPenaltyDirectly {
            return false
        } else {
            policies.Policies.Resources[cpm.Resource].ResourceAccessLimits[cpm.User][cpm.Device].PenaltyTimestamp = time.Time{}
        }
    }

    within = policies.Policies.Resources[cpm.Resource].ResourceAccessLimits[cpm.User][cpm.Device].AccessLimit.Allow()
    if !within {
        policies.Policies.Resources[cpm.Resource].ResourceAccessLimits[cpm.User][cpm.Device].PenaltyTimestamp = time.Now().Add(time.Second * 20)
    }

    return within
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
