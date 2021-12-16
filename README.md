# ztsfc_http_basicAuth

## Example Config (config/conf.yml)
    system_logger:

      system_logger_logging_level: debug

      system_logger_destination: stdout

      system_logger_format: text

    pdp:
  
      listen_addr: "127.0.0.1:443"
  
      certs_pep_accepts_when_shown_by_pep:
  
        - ./certs/some_cert.crt
  
      cert_shown_by_pdp_to_pep: ./certs/some_other_cert.crt
  
      privkey_for_certs_shown_by_pdp_to_pep: ./certs/some_priv.key
