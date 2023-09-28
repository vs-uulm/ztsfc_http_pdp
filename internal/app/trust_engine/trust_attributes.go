package trust_engine

/*
In this file, the trust score of a request is calculated. According to the trust score it is decided, if a request is
forwarded or blocked.
*/

import (
	"crypto/tls"
	"net"
	"time"

	"golang.org/x/time/rate"

	ua "github.com/mileusna/useragent"
	rattr "github.com/vs-uulm/ztsfc_http_attributes"
	logger "github.com/vs-uulm/ztsfc_http_logger"
	attr "github.com/vs-uulm/ztsfc_http_pdp/internal/app/attributes"
	md "github.com/vs-uulm/ztsfc_http_pdp/internal/app/metadata"
	"github.com/vs-uulm/ztsfc_http_pdp/internal/app/policies"
)

func deviceAccessFromTrustedLocation(cpm *md.Cp_metadata) bool {
	for _, trustedNetwork := range policies.Policies.Resources[cpm.Resource].TrustedIPNetworks {
		if trustedNetwork.Contains(net.ParseIP(cpm.Location)) {
			return true
		}
	}

	return false
}

// TODO: remove maxDevicesPerUser
func withinAllowedRequestRate(cpm *md.Cp_metadata) bool {
	maxDevicesPerUser := 5

	// TODO: Check of "policies.Policies.Resources[cpm.Resource]" exists
	user, exists := policies.Policies.Resources[cpm.Resource].ResourceAccessLimits[cpm.User]
	if !exists {
		policies.Policies.Resources[cpm.Resource].ResourceAccessLimits[cpm.User] = make(map[string]*policies.AccessLimiter)
		policies.Policies.Resources[cpm.Resource].ResourceAccessLimits[cpm.User][cpm.Device] = &policies.AccessLimiter{
			AccessLimit:      rate.NewLimiter(policies.Policies.Resources[cpm.Resource].AllowedRequestsPerSecond, int(policies.Policies.Resources[cpm.Resource].AllowedRequestsPerSecond)),
			PenaltyTimestamp: time.Time{},
		}
	} else if len(user) >= maxDevicesPerUser {
		for device, _ := range user {
			delete(user, device)
			break
		}
		policies.Policies.Resources[cpm.Resource].ResourceAccessLimits[cpm.User][cpm.Device] = &policies.AccessLimiter{
			AccessLimit:      rate.NewLimiter(policies.Policies.Resources[cpm.Resource].AllowedRequestsPerSecond, int(policies.Policies.Resources[cpm.Resource].AllowedRequestsPerSecond)),
			PenaltyTimestamp: time.Time{},
		}
	} else if policies.Policies.Resources[cpm.Resource].ResourceAccessLimits[cpm.User][cpm.Device] == nil {
		policies.Policies.Resources[cpm.Resource].ResourceAccessLimits[cpm.User][cpm.Device] = &policies.AccessLimiter{
			AccessLimit:      rate.NewLimiter(policies.Policies.Resources[cpm.Resource].AllowedRequestsPerSecond, int(policies.Policies.Resources[cpm.Resource].AllowedRequestsPerSecond)),
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
		policies.Policies.Resources[cpm.Resource].ResourceAccessLimits[cpm.User][cpm.Device].PenaltyTimestamp = time.Now().Add(time.Minute * 5)
	}

	return within
}

func allowedUserAuthentationMethod(sysLogger *logger.Logger, cpm *md.Cp_metadata) bool {
	for _, authentication_method := range policies.Policies.Resources[cpm.Resource].AllowedUserAuthenticationMethods {
		if authentication_method == "password" && cpm.PwAuthenticated {
			return true
		}
		if authentication_method == "passkey" && cpm.PasskeyAuthenticaed {
			return true
		}
	}
	return false
}

func allowedDeviceAuthentationMethod(sysLogger *logger.Logger, cpm *md.Cp_metadata, device *rattr.Device) bool {
	for _, authentication_method := range policies.Policies.Resources[cpm.Resource].AllowedDeviceAuthenticationMethods {
		if authentication_method == "cert" && cpm.CertAuthenticated {
			return true
		}
		if authentication_method == "tpm_cert" && cpm.CertAuthenticated && device.ManagedDevice {
			return true
		}
	}
	return false
}

func isUsualAccessTime(sysLogger *logger.Logger, user *rattr.User) bool {
	// TODO: Better time checking.
	requestTime := time.Now().Hour()
	if requestTime == 22 {
		requestTime = 0
	} else if requestTime == 23 {
		requestTime = 1
	} else {
		requestTime = requestTime + 2
	}

	if !(requestTime >= user.UsualTimeBegin && requestTime <= user.UsualTimeEnd) {
		return false
	} else {
		return true
	}
}

func withinUsualAccessRate(sysLogger *logger.Logger, user *rattr.User) bool {
	limiter, exists := attr.UserLimiter[user.UserID]
	if !exists {
		sysLogger.Infof("For user %s no usual access rate limiter could be found.", user.UserID)
		return false
	}
	within := limiter.Allow()
	if !within {
		return false
	}

	return true
}

func isSecureConnection(sysLogger *logger.Logger, cpm *md.Cp_metadata) bool {
	if cpm.ConnectionSecurity == tls.CipherSuiteName(tls.TLS_AES_128_GCM_SHA256) ||
		cpm.ConnectionSecurity == tls.CipherSuiteName(tls.TLS_AES_256_GCM_SHA384) ||
		cpm.ConnectionSecurity == tls.CipherSuiteName(tls.TLS_CHACHA20_POLY1305_SHA256) {
		return true
	} else {
		return false
	}
}

func isUsualServiceForUser(sysLogger *logger.Logger, cpm *md.Cp_metadata, user *rattr.User) bool {
	for _, service := range user.UsualServices {
		if service == cpm.Resource {
			return true
		}
	}
	return false
}

func isUsualServiceForDevice(sysLogger *logger.Logger, cpm *md.Cp_metadata, device *rattr.Device) bool {
	for _, service := range device.UsualServices {
		if service == cpm.Resource {
			return true
		}
	}
	return false
}

func isUsualDevice(sysLogger *logger.Logger, cpm *md.Cp_metadata, user *rattr.User) bool {
	for _, device := range user.UsualDevices {
		if device == cpm.Device {
			return true
		}
	}
	return false
}

func isCorrectType(sysLogger *logger.Logger, cpm *md.Cp_metadata, device *rattr.Device) bool {
	agent := ua.Parse(cpm.UserAgent)

	if agent.Mobile && device.Type == "mobile" {
		sysLogger.Debugf("Is a mobile device")
		return true
	} else if agent.Tablet && device.Type == "tablet" {
		sysLogger.Debugf("Is a tablet device")
		return true
	} else if agent.Desktop && device.Type == "desktop" {
		sysLogger.Debugf("Is a desktop device")
		return true
	} else if agent.Bot && device.Type == "bot" {
		sysLogger.Debugf("Is a bot device")
		return true
	} else {
		sysLogger.Debugf("Is not recognized device")
		return false
	}

}

func isUsualUser(sysLogger *logger.Logger, cpm *md.Cp_metadata, device *rattr.Device) bool {
	for _, user := range device.UsualUser {
		if user == cpm.User {
			return true
		}
	}
	return false
}

func upToDateSoftwarePatchLevel(sysLogger *logger.Logger, cpm *md.Cp_metadata) bool {
	agent := ua.Parse(cpm.UserAgent)

	switch agent.Name {
	case ua.Safari:
		// sysLogger.Debugf("Software Patch Level For User %s: %d", cpm.User, agent.VersionNo.Major)
		if agent.VersionNo.Major < 16 {
			return false
		}
	case ua.Firefox:
		if agent.VersionNo.Major < 91 {
			return false
		}
	case ua.Chrome:
		if agent.VersionNo.Major < 113 {
			return false
		}
	case ua.Opera:
		if agent.VersionNo.Major < 98 {
			return false
		}
	case ua.Edge:
		if agent.VersionNo.Major < 113 {
			return false
		}
	default:
		return false
	}
	return true
}

func upToDateSystemPatchLevel(sysLogger *logger.Logger, cpm *md.Cp_metadata) bool {
	agent := ua.Parse(cpm.UserAgent)

	switch agent.OS {
	case ua.Windows:
		sysLogger.Debugf("Presented Window Version is:  %d", agent.OSVersionNo.Major)
		if agent.OSVersionNo.Major < 10 {
			return false
		}
	case ua.Android:
		if agent.OSVersionNo.Major < 13 {
			return false
		}
	case ua.MacOS:
		if agent.OSVersionNo.Major < 10 || agent.OSVersionNo.Minor < 15 {
			return false
		}
	case ua.IOS:
		if agent.OSVersionNo.Major < 16 {
			sysLogger.Debugf("Presented iOS Version is: %d", agent.OSVersionNo.Major)
			return false
		}
	case ua.Linux:
		if agent.OSVersionNo.Major != 0 {
			sysLogger.Debugf("Presented Linux Version is: %d", agent.OSVersionNo.Major)
			return false
		}
	default:
		return false
	}
	return true
}

func correctFingerprint(sysLogger *logger.Logger, cpm *md.Cp_metadata, device *rattr.Device) bool {
	agent := ua.Parse(cpm.UserAgent)
	fingerprint := cpm.Device + "." + agent.OS + "." + agent.Name
	sysLogger.Debugf("Device has fingerprint=%s", fingerprint)
	if device.Fingerprint == fingerprint {
		return true
	} else {
		return false
	}
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
