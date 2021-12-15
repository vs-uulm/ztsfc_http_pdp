package router

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

    autho "github.com/vs-uulm/ztsfc_http_pdp/internal/app/authorization"
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

	router_cert_shown_to_clients tls.Certificate
	certs_that_router_accepts    *x509.CertPool

	//    md         *metadata.Cp_metadata
}

func NewRouter() (*Router, error) {

	// Create new Router
	router := new(Router)

	// Initialize Certificates
	router.router_cert_shown_to_clients, _ = tls.LoadX509KeyPair("./certs/ztsfc_pdp_prototype.crt", "./certs/ztsfc_pdp_prototype_priv.key")
	router.certs_that_router_accepts = x509.NewCertPool()
	ca_cert, err := ioutil.ReadFile("./certs/bwnet_root.pem")
	if err != nil {
		return nil, fmt.Errorf("router: NewRouter(): could not read file: %w", err)
	}
	ok := router.certs_that_router_accepts.AppendCertsFromPEM(ca_cert)
	if !ok {
		return nil, fmt.Errorf("router: NewRouter(): could not add certificate to cert pool the PDP")
	}

	// Create TLS config for frontend server
	router.frontend_tls_config = &tls.Config{
		Rand:                   nil,
		Time:                   nil,
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		SessionTicketsDisabled: true,
		Certificates:           []tls.Certificate{router.router_cert_shown_to_clients},
		ClientAuth:             tls.RequireAndVerifyClientCert,
		ClientCAs:              router.certs_that_router_accepts,
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

	//  router.md = new(metadata.Cp_metadata)

	return router, nil
}

type authResponse struct {
	Allow bool     `json:"allow"`
	Sfc   []string `json:"sfc"`
}

func (router *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {

	md := new(metadata.Cp_metadata)
	md.ExtractMetadata(req)

    // Performs the Authorization; returns the determined SFC as well as the authorization decision itself.
    // TODO: return an error?
    // TODO: change order of the return values?
    // TODO: is allow only false if even with the longest sfc th trust score cant be increased sufficiently to hit the trust threshold?
	sfc, allow := autho.PerformAuthorization(md)

	// assemble a json response for the request and set header respectively
	w.Header().Set("Content-Type", "application/json")
	response := authResponse{
		Allow: allow,
		Sfc:   sfc,
	}
	json.NewEncoder(w).Encode(response)
}

func (router *Router) ListenAndServeTLS() error {
	return router.frontend_server.ListenAndServeTLS("", "")
}
