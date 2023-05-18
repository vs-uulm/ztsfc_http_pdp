package metadata

import (
	"net/http"
	"strconv"

	logger "github.com/vs-uulm/ztsfc_http_logger"
)

// Control Plane Metadata
type Cp_metadata struct {
	User               string
	PwAuthenticated    bool
	CertAuthenticated  bool
	Resource           string
	Action             string
	Device             string
	Location           string
	ConnectionSecurity string
	UserAgent          string
}

func (cpm *Cp_metadata) ExtractMetadata(sysLogger *logger.Logger, req *http.Request) {

	// Retreive parameters from query instead from custom headers
	cpm.User = req.URL.Query().Get("user")
	cpm.PwAuthenticated, _ = strconv.ParseBool(req.URL.Query().Get("pwAuthenticated"))
	cpm.CertAuthenticated, _ = strconv.ParseBool(req.URL.Query().Get("certAuthenticated"))
	cpm.Resource = req.URL.Query().Get("resource")
	cpm.Action = req.URL.Query().Get("action")
	cpm.Device = req.URL.Query().Get("device")
	//cpm.RequestToday, _ = strconv.Atoi(req.URL.Query().Get("requestToday"))
	//cpm.FailedToday, _ = strconv.Atoi(req.URL.Query().Get("failedToday"))
	cpm.Location = req.URL.Query().Get("location")
	cpm.ConnectionSecurity = req.URL.Query().Get("connectionSecurity")
	cpm.UserAgent = req.URL.Query().Get("userAgent")

	sysLogger.Debugf("metadata: ExtractMetadata(): User=%s, PwAuthenticated=%t, Device=%s, CertAuthenticated=%t, Resource=%s, Action=%s"+
		", Location=%s, ConnectionSecurity=%s, UserAgent=%s", cpm.User, cpm.PwAuthenticated, cpm.Device, cpm.CertAuthenticated, cpm.Resource, cpm.Action, cpm.Location, cpm.ConnectionSecurity, cpm.UserAgent)
}
