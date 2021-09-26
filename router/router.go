package router

import (
    "crypto/tls"
    "crypto/x509"
    "fmt"
    "net/http"
    "io/ioutil"
    autho "local.com/leobrada/ztsfc_http_pdp/authorization"
    metadata "local.com/leobrada/ztsfc_http_pdp/metadata"
)

type Router struct {
    frontend_tls_config *tls.Config
    frontend_server *http.Server

    router_cert_shown_to_clients tls.Certificate
    certs_that_router_accepts *x509.CertPool

//    md         *metadata.Cp_metadata
}

func NewRouter() (*Router) {

    // Create new Router
    router := new(Router)

    // Initialize Certificates
    router.router_cert_shown_to_clients, _ = tls.LoadX509KeyPair("./certs/ztsfc_pdp_prototype.crt", "./certs/ztsfc_pdp_prototype_priv.key")
    router.certs_that_router_accepts = x509.NewCertPool()
    ca_cert, err := ioutil.ReadFile("./certs/bwnet_root.pem")
    if err != nil {
        fmt.Printf("[Router.makeCAPool]: ReadFile: ", err)
        return nil
    }
    ok := router.certs_that_router_accepts.AppendCertsFromPEM(ca_cert)
    if !ok {
        fmt.Printf("[Router.makeCAPool]: AppendCertsFromPEM: ", err)
        return nil
    }

    // Create TLS config for frontend server
    router.frontend_tls_config = &tls.Config{
        Rand:   nil,
        Time:   nil,
        MinVersion: tls.VersionTLS13,
        MaxVersion: tls.VersionTLS13,
        SessionTicketsDisabled: true,
        Certificates:   []tls.Certificate{router.router_cert_shown_to_clients},
        ClientAuth: tls.RequireAndVerifyClientCert,
        ClientCAs:  router.certs_that_router_accepts,
    }

    // Create MUX server
    mux := http.NewServeMux()
    mux.Handle("/", router)

    // Create HTTP frontend server
    router.frontend_server = &http.Server {
        Addr: "10.4.0.52:8888",
        TLSConfig: router.frontend_tls_config,
        Handler: mux,
    }

  //  router.md = new(metadata.Cp_metadata)

    return router
}

func (router *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
    //fmt.Printf("%+v\n", req.Header)
    md := new(metadata.Cp_metadata)

    md.ExtractMetadata(req)

    sfc, block := autho.PerformAuthorization(md)
    w.Header().Set("sfc", sfc)
    w.Header().Set("allow", block)
    fmt.Printf("%+v\n", md)
    fmt.Fprintf(w, "")
}

func (router *Router) ListenAndServeTLS() error {
    return router.frontend_server.ListenAndServeTLS("", "")
}
