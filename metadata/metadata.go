package metadata

import (
	"net/http"
	"strconv"
)

type Cp_metadata struct {
	User               string
	Pw_authenticated   bool
	Cert_authenticated bool
	Resource           string
	Action             string
	Device             string
	RequestToday       int
	FailedToday        int
	Location           string
}

func (cpm *Cp_metadata) ExtractMetadata(req *http.Request) {

	// @author:marie
	// Retreive parameters from query instead from custom headers
	cpm.User = req.URL.Query().Get("user")
	cpm.Pw_authenticated, _ = strconv.ParseBool(req.URL.Query().Get("pwAuthenticated"))
	cpm.Cert_authenticated, _ = strconv.ParseBool(req.URL.Query().Get("certAuthenticated"))
	cpm.Resource = req.URL.Query().Get("resource")
	cpm.Action = req.URL.Query().Get("action")
	cpm.Device = req.URL.Query().Get("device")
	cpm.RequestToday, _ = strconv.Atoi(req.URL.Query().Get("requestToday"))
	cpm.FailedToday, _ = strconv.Atoi(req.URL.Query().Get("failedToday"))
	cpm.Location = req.URL.Query().Get("location")
}
