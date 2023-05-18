package attributes

import (
	"encoding/json"
	"fmt"
	"net/http"

	"golang.org/x/time/rate"

	rattr "github.com/vs-uulm/ztsfc_http_attributes"
	logger "github.com/vs-uulm/ztsfc_http_logger"
	"github.com/vs-uulm/ztsfc_http_pdp/internal/app/config"
	md "github.com/vs-uulm/ztsfc_http_pdp/internal/app/metadata"
)

var (
	UserLimiter map[string]*rate.Limiter = make(map[string]*rate.Limiter) // Key: User, Value: Acess Rate for specified user
)

func requestUserAttributes(sysLogger *logger.Logger, cpm *md.Cp_metadata, usr *rattr.User) error {

	usrReq, err := http.NewRequest("GET", config.Config.Pip.TargetAddr+config.Config.Pip.UserEndpoint, nil)
	if err != nil {
		return fmt.Errorf("attributes: RequestUserAttributes(): unable to create device attribute request for PIP: %w", err)
	}
	usrReqQuery := usrReq.URL.Query()
	usrReqQuery.Set("user", cpm.User)
	usrReq.URL.RawQuery = usrReqQuery.Encode()

	pipResp, err := config.Config.Pip.PipClient.Do(usrReq)
	if err != nil {
		return fmt.Errorf("attributes: RequestUserAttributes(): unable to send user request to PIP: %w", err)
	}

	if pipResp.StatusCode != 200 {
		return nil
	}

	err = json.NewDecoder(pipResp.Body).Decode(usr)
	if err != nil {
		return fmt.Errorf("attributes: RequestUserAttributes(): unable to decode the PIP response: %w", err)
	}

	_, exists := UserLimiter[usr.UserID]
	if !exists {
		UserLimiter[usr.UserID] = rate.NewLimiter(usr.UsualAcessRate, int(usr.UsualAcessRate))
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
