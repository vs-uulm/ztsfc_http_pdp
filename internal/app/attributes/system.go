package attributes

import (
    "encoding/json"
    "net/http"
    "fmt"

    "github.com/vs-uulm/ztsfc_http_pdp/internal/app/config"
    rattr "github.com/vs-uulm/ztsfc_http_attributes"
    logger "github.com/vs-uulm/ztsfc_http_logger"
)

func RequestSystemAttributes(sysLogger *logger.Logger, system *rattr.System) error {

    systemReq, err := http.NewRequest("GET", config.Config.Pip.TargetAddr+config.Config.Pip.SystemEndpoint, nil)
    if err != nil {
        return fmt.Errorf("attributes: RequestDeviceAttributes(): unable to create device attribute request for PIP: %w", err)
    }
    //devReqQuery := devReq.URL.Query()
    //devReqQuery.Set("system", cpm.Device)
    //devReq.URL.RawQuery = devReqQuery.Encode()

    pipResp, err := config.Config.Pip.PipClient.Do(systemReq)
    if err != nil {
        return fmt.Errorf("attributes: RequestSystemAttributes(): unable to send system request to PIP: %w", err)
    }

    err = json.NewDecoder(pipResp.Body).Decode(system)
    if err != nil {
        return fmt.Errorf("attributes: RequestSystemAttributes(): unable to decode the PIP response: %w", err)
    }

    return nil
}

//func UpdateDeviceAttributes(sysLogger *logger.Logger, cpm *md.Cp_metadata, dev *rattr.Device) error {
//    dev.CurrentIP = cpm.Location
//
//    devInJson, err := json.Marshal(dev)
//    if err != nil {
//        return fmt.Errorf("attributes: UpdateDeviceAttributes(): unable to create JSON representation of the device attributes for PIP: %w", err)
//    }
//
//    devUpdateReq, err := http.NewRequest("POST", config.Config.Pip.TargetAddr+config.Config.Pip.UpdateDeviceEndpoint, bytes.NewBuffer(devInJson))
//    if err != nil {
//        return fmt.Errorf("attributes: UpdateDeviceAttributes(): unable to create device attribute update for PIP: %w", err)
//    }
//    devUpdateReq.Header.Set("Content-Type", "application/json")
//
//    devUpdateResp, err := config.Config.Pip.PipClient.Do(devUpdateReq)
//    if err != nil {
//        return fmt.Errorf("attributes: RequestDeviceAttributes(): unable to send device update request to PIP: %w", err)
//    }
//
//    if devUpdateResp.StatusCode != 200 {
//        return errors.New("attributes: RequestDeviceAttributes(): something went wrong. PIP responded with status: "+ devUpdateResp.Status)
//    }
//    defer devUpdateResp.Body.Close()
//
//    return nil
//}
