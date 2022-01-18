package policies

import (
    "fmt"
    "net"
    "time"

    "golang.org/x/time/rate"
)

var (
    Policies PoliciesT
)

type AttributesT struct {
    User UserT  `yaml:"user"`
    Device DeviceT  `yaml:"device"`
    Sf map[string]*SfT `yaml:"sf"`
}

type UserT struct {
    PwAuthenticated    int `yaml:"pw_authenticated"`
    CertAuthenticated   int `yaml:"cert_authenticated"`
}

type DeviceT struct {
    FromTrustedLocation int `yaml:"from_trusted_location"`
    NotWithinAllowedRequestRatePenalty int `yaml:"not_within_allowed_request_rate_penalty"`
}

type SfT struct {
    Basic int `yaml:"basic"`
    Advanced int `yaml:"advanced"`
    Full int `yaml:"full"`
}

type ActionT struct {
    TrustThreshold int `yaml:"trust_threshold"`
}

type ResourceT struct {
    Actions map[string]*ActionT `yaml:"actions"`
    TrustedLocations   []string `yaml:"trusted_locations"`
    AllowedRequestsPerSecond rate.Limit `yaml:"allowed_requests_per_second"`
    AllowedDevicesPerUser int `yaml:"allowed_devices_per_user"`

    TrustedIPNetworks []*net.IPNet
    ResourceAccessLimits map[string]map[string]*AccessLimiter
}

type AccessLimiter struct {
    AccessLimit *rate.Limiter
    PenaltyTimestamp time.Time
}

type PoliciesT struct {
    Attributes AttributesT  `yaml:"attributes"`
    Resources map[string]*ResourceT  `yaml:"resources"`
}

func PrintAllowedRequestsPerSecond(p *PoliciesT) {
    for key, val := range p.Resources {
        fmt.Printf("Allowed requests per second for %s: %f\n", key, val.AllowedRequestsPerSecond)
    }
}

func PrintTrustedLocations(p *PoliciesT) {
    for key, val := range p.Resources {
        fmt.Printf("Trusted locations for %s: %v", key, val.TrustedLocations)
    }
}
