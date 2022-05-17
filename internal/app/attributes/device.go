package attributes

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	rattr "github.com/vs-uulm/ztsfc_http_attributes"
	logger "github.com/vs-uulm/ztsfc_http_logger"
	"github.com/vs-uulm/ztsfc_http_pdp/internal/app/config"
	md "github.com/vs-uulm/ztsfc_http_pdp/internal/app/metadata"
)

func RequestDeviceAttributes(sysLogger *logger.Logger, cpm *md.Cp_metadata, dev *rattr.Device) error {

	devReq, err := http.NewRequest("GET", config.Config.Pip.TargetAddr+config.Config.Pip.DeviceEndpoint, nil)
	if err != nil {
		return fmt.Errorf("attributes: RequestDeviceAttributes(): unable to create device attribute request for PIP: %s", err.Error())
	}
	devReqQuery := devReq.URL.Query()
	devReqQuery.Set("device", cpm.Device)
	devReq.URL.RawQuery = devReqQuery.Encode()

	pipResp, err := config.Config.Pip.PipClient.Do(devReq)
	if err != nil {
		return fmt.Errorf("attributes: RequestDeviceAttributes(): unable to send device request to PIP: %s", err.Error())
	}

	if pipResp.StatusCode != 200 {
		return nil
	}

	err = json.NewDecoder(pipResp.Body).Decode(dev)
	if err != nil {
		return fmt.Errorf("attributes: RequestDeviceAttributes(): unable to decode the PIP response: %s", err.Error())
	}

	return nil
}

func UpdateDeviceAttributes(sysLogger *logger.Logger, cpm *md.Cp_metadata, dev *rattr.Device) error {
	dev.CurrentIP = cpm.Location

	devInJson, err := json.Marshal(dev)
	if err != nil {
		return fmt.Errorf("attributes: UpdateDeviceAttributes(): unable to create JSON representation of the device attributes for PIP: %s", err.Error())
	}

	devUpdateReq, err := http.NewRequest("POST", config.Config.Pip.TargetAddr+config.Config.Pip.UpdateDeviceEndpoint, bytes.NewBuffer(devInJson))
	if err != nil {
		return fmt.Errorf("attributes: UpdateDeviceAttributes(): unable to create device attribute update for PIP: %s", err.Error())
	}
	devUpdateReq.Header.Set("Content-Type", "application/json")

	devUpdateResp, err := config.Config.Pip.PipClient.Do(devUpdateReq)
	if err != nil {
		return fmt.Errorf("attributes: RequestDeviceAttributes(): unable to send device update request to PIP: %s", err.Error())
	}

	if devUpdateResp.StatusCode != 200 {
		return errors.New("attributes: RequestDeviceAttributes(): something went wrong. PIP responded with status: " + devUpdateResp.Status)
	}
	defer devUpdateResp.Body.Close()

	return nil
}
