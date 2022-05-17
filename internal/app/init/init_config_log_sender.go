package init

import (
	"fmt"
	"strings"

	"github.com/vs-uulm/ztsfc_http_pdp/internal/app/config"
)

func InitGUILoggerParams() error {
	var err error
	fields := ""

	// if (config.Config.Pdp.LoggingHook == config.LoggingHookT{}) {
	// 	return fmt.Errorf("init: InitGUILoggerParams(): in the section 'pdp' a section 'logging_hook' is missed")
	// }

	if config.Config.Pdp.LoggingHook.HookURL == "" {
		fields += "hook_url,"
	}

	if config.Config.Pdp.LoggingHook.CertShownByPdpToHook == "" {
		fields += "cert_shown_by_pdp_to_hook,"
	}

	if config.Config.Pdp.LoggingHook.PrivkeyForCertShownByPdpToHook == "" {
		fields += "privkey_for_cert_shown_by_pdp_to_hook,"
	}

	if len(config.Config.Pdp.LoggingHook.CertsPdpAcceptsWhenShownByHook) == 0 {
		fields += "certs_pdp_accepts_when_shown_by_hook,"
	}

	if fields != "" {
		return fmt.Errorf("init: InitGUILoggerParams(): in the section 'pdp.logging_hook' the following required fields are missed: '%s'", strings.TrimSuffix(fields, ","))
	}

	// Read CA certs used for signing client certs and are accepted by the logging hook
	for _, acceptedPepCert := range config.Config.Pdp.LoggingHook.CertsPdpAcceptsWhenShownByHook {
		if err = loadCACertificate(acceptedPepCert, "client", config.Config.Pdp.CaCertPoolPdpAcceptsFromHook); err != nil {
			return fmt.Errorf("init: InitGUILoggerParams(): error loading certificates PDP accepts from the logging hook: %s", err.Error())
		}
	}

	config.Config.Pdp.X509KeyPairShownByPdpToHook, err = loadX509KeyPair(config.Config.Pdp.LoggingHook.CertShownByPdpToHook,
		config.Config.Pdp.LoggingHook.PrivkeyForCertShownByPdpToHook, "Hook", "")
	if err != nil {
		return fmt.Errorf("init: InitGUILoggerParams(): error loading certificate pair PDP shows to logging hook: %s", err.Error())
	}

	return nil
}
