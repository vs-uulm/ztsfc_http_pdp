package router

import (
	"crypto/tls"
	"encoding/json"
	"net/http"

    autho "github.com/vs-uulm/ztsfc_http_pdp/internal/app/authorization"
    logger "github.com/vs-uulm/ztsfc_http_logger"
    "github.com/vs-uulm/ztsfc_http_pdp/internal/app/metadata"
    "github.com/vs-uulm/ztsfc_http_pdp/internal/app/config"
)

const (
	// Request URI for the API endpoint. Consists of version number and resource name.
	endpointName = "/v1/authorization"
)

type Router struct {
	frontend_tls_config *tls.Config
	frontend_server     *http.Server

    sysLogger           *logger.Logger
}

func NewRouter(sysLogger *logger.Logger) *Router {

	// Create new Router
	router := new(Router)

    router.sysLogger = sysLogger

	// Create TLS config for frontend server
	router.frontend_tls_config = &tls.Config{
		Rand:                   nil,
		Time:                   nil,
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		SessionTicketsDisabled: true,
		Certificates:           []tls.Certificate{config.Config.Pdp.X509KeyPairShownByPdpToPep},
		ClientAuth:             tls.RequireAndVerifyClientCert,
		ClientCAs:              config.Config.Pdp.CaCertPoolPdpAcceptsFromPep,
	}

	// Create MUX server
	mux := http.NewServeMux()
	mux.Handle(endpointName, router)

	// Create HTTP frontend server
	router.frontend_server = &http.Server{
		Addr:      config.Config.Pdp.ListenAddr,
		TLSConfig: router.frontend_tls_config,
		Handler:   mux,
	}

	return router
}

//type authResponse struct {
//	Allow bool     `json:"allow"`
//	Sfc   []struct {
//        Sf string `json:"sf"`
//        Md string `json:"md"`
//    } `json:"sfc"`
//}

func (router *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {

	md := new(metadata.Cp_metadata)
	md.ExtractMetadata(router.sysLogger, req)

    // Performs the Authorization; returns the determined SFC as well as the authorization decision itself.
    // TODO: return an error?
    // TODO: change order of the return values?
    // TODO: is allow only false if even with the longest sfc th trust score cant be increased sufficiently to hit the trust threshold?
	authResponse := autho.PerformAuthorization(router.sysLogger, md)

	// assemble a json response for the request and set header respectively
	w.Header().Set("Content-Type", "application/json")
	//response := authResponse{
	//	Allow: allow,
	//	Sfc:   sfc,
	//}
	json.NewEncoder(w).Encode(authResponse)
}

func (router *Router) ListenAndServeTLS() error {
	return router.frontend_server.ListenAndServeTLS("", "")
}
