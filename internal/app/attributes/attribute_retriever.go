package attributes

import (
    "fmt"

    md "github.com/vs-uulm/ztsfc_http_pdp/internal/app/metadata"
    logger "github.com/vs-uulm/ztsfc_http_logger"
    rattr "github.com/vs-uulm/ztsfc_http_attributes"
)

func RetrieveAttributes(sysLogger *logger.Logger, cpm *md.Cp_metadata) (*rattr.User, *rattr.Device, *rattr.System, error) {
    var user *rattr.User = nil
    var device *rattr.Device = nil
    var system *rattr.System = nil

    // Attribute Retriever
    // Step 1: request user attributes
    if len(cpm.User) == 0 {
        sysLogger.Infof("attributes: RetrieveAttributes(): unknown user provided by PEP")
    } else {
        user = rattr.NewEmptyUser()
        err := requestUserAttributes(sysLogger, cpm, user)
        if err != nil {
            return user, device, system, fmt.Errorf("attributes: RetrieveAttributes(): error requesting user attributes from PIP: %v", err)
        }
        if len(user.UserID) == 0 {
            sysLogger.Infof("attributes: RetrieveAttributes(): user '%s' uses a device PIP has no information about from '%s' for their request",
                cpm.User, cpm.Location)
        }
    }

    // Step 2: request device attributes
    if len(cpm.Device) == 0 {
        sysLogger.Infof("attributes: RetrieveAttributes(): user '%s' uses an unknown device from '%s' for their request",
            cpm.User, cpm.Location)
    } else {
        device = rattr.NewEmptyDevice()
        err := requestDeviceAttributes(sysLogger, cpm, device)
        if err != nil {
            return user, device, system, fmt.Errorf("attributes: RetrieveAttributes(): error requesting device attributes from PIP: %v", err)
        }
        if len(device.DeviceID) == 0 {
            sysLogger.Infof("attributes: RetrieveAttributes(): user '%s' uses a device PIP has no information about from '%s' for their request",
                cpm.User, cpm.Location)
        }
    }

    // Step 3: request system attributes
    system = rattr.NewEmptySystem()
    err := requestSystemAttributes(sysLogger, system)
    if err != nil {
        return user, device, system, fmt.Errorf("attributes: RetrieveAttributes(): error requesting system attributes from PIP: %v", err)
    }

    return user, device, system, nil
}
