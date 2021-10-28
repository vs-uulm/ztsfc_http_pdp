package trustCalculation

/*
In this file, the trust score of a request is calculated. According to the trust score it is decided, if a request is
forwarded or blocked.
*/

import (
	md "local.com/leobrada/ztsfc_http_pdp/metadata"
)

var (
	trustCalc *DataSources = NewDataSources()
)

/*
This function decides based on the achieved trust score and the requested service, if the request should be directly
sent to the service, sent to the DPI or be blocked.

@param req: request of the user

@return forwardSFC: List of identifiers for service functions. nil if request is not allowed at all.
@return allow: False, when the request should be blocked; True, when the request should be forwarded
*/
func PerformAuthorization(cpm *md.Cp_metadata) (forwardSFC []string, allow bool) {

	//fmt.Println("Start Trust Score Calculation")
	//fmt.Println("Start Calculating User Trust Score...")
	userTrust := calcUserTrust(cpm)
	//fmt.Printf("User Trust Score: %d\n", userTrust)

	//fmt.Println("Start Calculating Device Trust Score...")
	deviceTrust := calcDeviceTrust(cpm)
	//fmt.Printf("Device Trust Score: %d\n", deviceTrust)

	aggregatedTrust := userTrust + deviceTrust
	//fmt.Printf("Aggregated Trust Score: %d\n", aggregatedTrust)

	//fmt.Printf("Service Threshold: %d\n", trustCalc.thresholdValues[cpm.Resource][cpm.Action])
	if aggregatedTrust >= trustCalc.thresholdValues[cpm.Resource][cpm.Action] {
		return []string{}, true
	} else if (aggregatedTrust + trustCalc.loggerTrustIncrease) >= trustCalc.thresholdValues[cpm.Resource][cpm.Action] {
		return []string{"logger"}, true
	} else if (aggregatedTrust + trustCalc.dpiTrustIncrease) >= trustCalc.thresholdValues[cpm.Resource][cpm.Action] {
		return []string{"dpi"}, true
	} else if (aggregatedTrust + trustCalc.loggerTrustIncrease + trustCalc.dpiTrustIncrease) >= trustCalc.thresholdValues[cpm.Resource][cpm.Action] {
		return []string{"logger", "dpi"}, true
	} else {
		return nil, false
	}

	//trustCalc.Log("----User-trust: " + strconv.Itoa(userTrust) + "\n")
	//fmt.Printf("User-Trust: %d\n",userTrust)

	//    fmt.Println("Start Calculating Device Trust Score...")
	//	deviceTrust := trustCalc.calcDeviceTrust(req)
	//	trustCalc.Log("----Device-trust: " + strconv.Itoa(deviceTrust) + "\n")
	//	fmt.Printf("Device-Trust: %d\n", deviceTrust)
	//
	//	trustCalc.removeHTTPHeader(req)												// Remove custom http header, which are only necessary for trust-calculation
	//
	//	trust := userTrust + deviceTrust
	//	service := strings.Split(req.URL.Path,"/")[1]							// Derive requested service from URL
	//	trustCalc.Log("----Requested service: " + service + "\n")
	//
	//	if threshold, ok := trustCalc.dataSources.thresholdValues[service]; ok {
	//		if trust >= threshold {													// In this case the threshold was reached, without a DPI -> Send request directly to service
	//			trustCalc.Log("----Request directly send to service\n")
	//			fmt.Println("Direct to service")
	//			return false, false
	//		} else if (trust+trustCalc.dataSources.dpiTrustIncrease) >= threshold {	// In this case the threshold was only reached with the DPI -> Send request at first to the DPI
	//			trustCalc.Log("----Request send to DPI\n")
	//			fmt.Println("Request send to DPI")
	//			return true, false
	//		} else {																// In this case the threshold was not reached with the DPI because the trust-value is very low -> Request is blocked
	//			trustCalc.Log("----Trust to low. Request blocked\n")
	//			fmt.Printf("Request blocked")
	//			return false, true
	//		}
	//	} else {
	//		return false,true										// In this case an unknown service was requested -> Request is blocked
	//	}
}

/*
In this fuction the trust score of the user attributes is calculated

@param req: request of the user

@return trust: trust score of user attributes
*/
func calcUserTrust(cpm *md.Cp_metadata) (trust int) {
	trust = 0

	// Analyze authentication type
	if cpm.Pw_authenticated {
		trust = trust + trustCalc.trustIncreaseUserAttr["PW"]
	}

	if cpm.Cert_authenticated {
		trust = trust + trustCalc.trustIncreaseUserAttr["CRT"]
	}

	// Analyze geographic area
	if cpm.Location == trustCalc.mapUsergeoArea[cpm.User] {
		trust = trust + trustCalc.trustIncreaseUserAttr["UGA"]
	}

	// Analyze commonly used services
	//requestedService := strings.Split(req.URL.Path,"/")[1]						// Service is identified with first part in the requested URL
	//for _, commonService := range trustCalc.dataSources.UserDatabase[user].commonUsedService {
	//	if requestedService == commonService {										// Check, if commonly used service corresponds to the requested service
	//		trust = trust + trustCalc.dataSources.trustIncreaseUserAttr["CUS"]
	//		trustCalc.Log("----Commonly used service: " + commonService+", Trust: " +  strconv.Itoa(trust) + "\n")
	//		break
	//	}
	//}

	// Check usual amount of requests
	if cpm.RequestToday <= trustCalc.usualRequests[cpm.User] {
		trust = trust + trustCalc.trustIncreaseUserAttr["UAR"]
	}

	// Check failed attempts
	if cpm.FailedToday <= trustCalc.maxAuthAttempts {
		trust = trust + trustCalc.trustIncreaseUserAttr["AA"]
	}

	return trust
}

/*
In this function the trust score of the device attributes is calculated

@param req: request of the user

@return trust: trust score of device attributes
*/
func calcDeviceTrust(cpm *md.Cp_metadata) (trust int) {
	trust = 0

	if cpm.Device == "device1" {
		trust = trust + trustCalc.deviceDatabase["device1"]
	} else if cpm.Device == "device2" {
		trust = trust + trustCalc.deviceDatabase["device2"]
	} else if cpm.Device == "device3" {
		trust = trust + trustCalc.deviceDatabase["device3"]
	} else if cpm.Device == "device4" {
		trust = trust + trustCalc.deviceDatabase["device4"]
	} else if cpm.Device == "device5" {
		trust = trust + trustCalc.deviceDatabase["device5"]
	} else {
		trust = trust + 0
	}

	//	if device := req.Header.Get("managedDevice"); device != "" {			// Extract the used managed device form the HTTP header
	//		deviceName = device
	//		trustCalc.Log("----Managed device: " + deviceName + "\n")
	//	} else{
	//		trustCalc.Log("----No Managed device used\n")
	//		return 0		// In this case no managed device is used
	//	}
	//
	//	fmt.Println(deviceName)
	//	if device, ok := trustCalc.dataSources.deviceDatabase[deviceName]; ok {		// Check, if the specified managed device is registered in the device database
	//		if device["LPL"] {														// Check, if on the device the latest patch levels are installed
	//			trust = trust + trustCalc.dataSources.trustIncreaseDeviceAttr["LPL"]
	//			trustCalc.Log("----Current Patch level, Trust: " +  strconv.Itoa(trust) + "\n")
	//		}
	//		if device["NAVS"] {														// Check, if there are no alerts from the virus scanner
	//			trust = trust + trustCalc.dataSources.trustIncreaseDeviceAttr["NAVS"]
	//			trustCalc.Log("----No alerts from virus scanner, Trust: " +  strconv.Itoa(trust) + "\n")
	//		}
	//		if device["RI"] {														// Check, if the device was recently re-installed
	//			trust = trust + trustCalc.dataSources.trustIncreaseDeviceAttr["RI"]
	//			trustCalc.Log("----Re-Installed, Trust: " +  strconv.Itoa(trust) + "\n")
	//		}
	//	}

	return trust
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
