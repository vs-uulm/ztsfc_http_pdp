package attributes

import (
    "encoding/json"
    "errors"
    "net/http"
    "fmt"
    "bytes"

    "github.com/vs-uulm/ztsfc_http_pdp/internal/app/config"
    md "github.com/vs-uulm/ztsfc_http_pdp/internal/app/metadata"
    rattr "github.com/vs-uulm/ztsfc_http_attributes"
    logger "github.com/vs-uulm/ztsfc_http_logger"
)

func RequestDeviceAttributes(sysLogger *logger.Logger, cpm *md.Cp_metadata, dev *rattr.Device) error {

    devReq, err := http.NewRequest("GET", config.Config.Pip.TargetAddr+config.Config.Pip.DeviceEndpoint, nil)
    if err != nil {
        return fmt.Errorf("attributes: RequestDeviceAttributes(): unable to create device attribute request for PIP: %w", err)
    }
    devReqQuery := devReq.URL.Query()
    devReqQuery.Set("device", cpm.Device)
    devReq.URL.RawQuery = devReqQuery.Encode()

    pipResp, err := config.Config.Pip.PipClient.Do(devReq)
    if err != nil {
        return fmt.Errorf("attributes: RequestDeviceAttributes(): unable to send device request to PIP: %w", err)
    }

    if pipResp.StatusCode != 200 {
        return nil
    }

    err = json.NewDecoder(pipResp.Body).Decode(dev)
    if err != nil {
        return fmt.Errorf("attributes: RequestDeviceAttributes(): unable to decode the PIP response: %w", err)
    }

    return nil
}

func UpdateDeviceAttributes(sysLogger *logger.Logger, cpm *md.Cp_metadata, dev *rattr.Device) error {
    dev.CurrentIP = cpm.Location

    devInJson, err := json.Marshal(dev)
    if err != nil {
        return fmt.Errorf("attributes: UpdateDeviceAttributes(): unable to create JSON representation of the device attributes for PIP: %w", err)
    }

    devUpdateReq, err := http.NewRequest("POST", config.Config.Pip.TargetAddr+config.Config.Pip.UpdateDeviceEndpoint, bytes.NewBuffer(devInJson))
    if err != nil {
        return fmt.Errorf("attributes: UpdateDeviceAttributes(): unable to create device attribute update for PIP: %w", err)
    }
    devUpdateReq.Header.Set("Content-Type", "application/json")

    devUpdateResp, err := config.Config.Pip.PipClient.Do(devUpdateReq)
    if err != nil {
        return fmt.Errorf("attributes: RequestDeviceAttributes(): unable to send device update request to PIP: %w", err)
    }

    if devUpdateResp.StatusCode != 200 {
        return errors.New("attributes: RequestDeviceAttributes(): something went wrong. PIP responded with status: "+ devUpdateResp.Status)
    }
    defer devUpdateResp.Body.Close()

    return nil
}
