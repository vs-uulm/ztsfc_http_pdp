package trust_engine

import (
	logger "github.com/vs-uulm/ztsfc_http_logger"
	md "github.com/vs-uulm/ztsfc_http_pdp/internal/app/metadata"
)

func riskOfRequestProtocol(sysLogger *logger.Logger, cpm *md.Cp_metadata) (riskScore int) {
	riskScore = 0

	sysLogger.Debugf("HTTP Version is %f", cpm.RequestProtocol)
	if cpm.RequestProtocol < 2.0 {
		riskScore += 1
	}

	return
}
