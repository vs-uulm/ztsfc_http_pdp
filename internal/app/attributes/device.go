package attributes

import (
    "encoding/json"

    rattr "github.com/vs-uulm/ztsfc_http_attributes"
)

func RequestDeviceAttributes(cpm *md.Cp_metadata, dev *rattr.Device) error {
    devReq, err := http.NewRequest("GET", config.Config.Pip.TargetAddr+config.Config.Pip.DeviceEndpoint, nil)
    if err != nil {
        return fmt.Errorf("attributes: RequestDeviceAttributes(): unable to create device attribute request for PIP: %w", err)
    }
    devReqQuery := devReq.URL.Query()
    devReqQuery.Set("device", cpm.Device)

    pipResp, err := config.Config.Pip.PipClient.Do(devReq)
    if err != nil {
        return fmt.Errorf("attributes: RequestDeviceAttributes(): unable to send device request to PIP: %w", err)
    }

    err = json.NewDecoder(pipResp.Body).Decode(dev)
    if err != nil {
        return fmt.Errorf("attributes: RequestDeviceAttributes(): unable to decode the PIP response: %w", err)
    }

    return nil
}
