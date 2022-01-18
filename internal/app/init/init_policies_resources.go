package init

import (
    "fmt"
    "errors"
    "strings"
    "net"

    "github.com/vs-uulm/ztsfc_http_pdp/internal/app/policies"
)

// TODO: Better structure; rework whole function
// All Policy Related Initialization Functions
func initResourcesParams() error {
    if policies.Policies.Resources == nil {
        return errors.New("init: InitResourcesParams(): no resources defined")
    }

    // Iterates over all defined (by resName) resources
    for resName, resource := range policies.Policies.Resources {
        if resource == nil {
            return errors.New("init: InitResourcesParams(): resource '" + resName + "' is empty")
        }

        if resource.Actions == nil {
            return errors.New("init: InitResourcesParams(): for resource '" + resName + "' no actions are defined")
        }

        // Iterates over all defined actions for each resource
        for action, val := range resource.Actions {
            upperAction := strings.ToUpper(action)
            if upperAction != "GET" && upperAction != "POST" {
                return errors.New("init: InitResourcesParams(): action '" + action +
                    "' defined for resource '" + resName + "' is not valid")
            }

            if val.TrustThreshold <= 0 {
                return errors.New("init: InitResourcesParams(): for resource '" + resName +
                    "' and action '" + action + "' the trust threshold makes no sense")
            }
        }

        // Iterates over all trusted locations (for each resource) and tries to extract the IPNet from it
        for _, location := range resource.TrustedLocations {
            _, ipnet, err := net.ParseCIDR(location)
            if err != nil {
                return fmt.Errorf("init: InitResourcesParams(): %s is not in valid CIDR network notation: %v", location, err)
            }
            resource.TrustedIPNetworks = append(resource.TrustedIPNetworks, ipnet)
        }

        // TODO: Checking of AllowedRequestPerSecond 
        if resource.AllowedRequestsPerSecond <= 0 {
            return errors.New("init: InitResourcesParams(): 'AllowedRequestsPerSecond' for resource '" + resName  + "' is nil or negative")
        }

        // Checking of Allowed DevicesPerUser Input
        if resource.AllowedDevicesPerUser <= 0 {
            return errors.New("init: InitResourcesParams(): 'AllowedDevicesPerUser' for resource '" + resName  + "' is nil or negative")
        }

        // Creates an empty ResourceAccessLimits map
        resource.ResourceAccessLimits = make(map[string]map[string]*policies.AccessLimiter)
    }

    return nil
}
