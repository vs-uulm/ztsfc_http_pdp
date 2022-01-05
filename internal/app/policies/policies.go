package policies

import (
    "fmt"
    "net"
)

var (
    Policies PoliciesT
)

type AttributesT struct {
    User UserT  `yaml:"user"`
    Device DeviceT  `yaml:"device"`
}

type UserT struct {
    PwAuthenticated    int `yaml:"pw_authenticated"`
    CertAuthenticated   int `yaml:"cert_authenticated"`
}

type DeviceT struct {
    FromTrustedLocation int `yaml:"from_trusted_location"`
}

type ActionT struct {
    TrustThreshold int `yaml:"trust_threshold"`
}

type ResourceT struct {
    Actions map[string]*ActionT `yaml:"actions"`
    TrustedLocations   []string `yaml:"trusted_locations"`

    TrustedIPNetworks []*net.IPNet
}

type PoliciesT struct {
    Attributes AttributesT  `yaml:"attributes"`
    Resources map[string]*ResourceT  `yaml:"resources"`
}

func PrintTrustedLocations(p *PoliciesT) {
    for key, val := range p.Resources {
        fmt.Printf("Trusted locations for %s: %v", key, val.TrustedLocations)
    }

    //tt1 := p.Resources["service1.testbed.informatik.uni-ulm.de"].Actions["get"].TrustThreshold
    //tt2 := p.Resources["service1.testbed.informatik.uni-ulm.de"].Actions["post"].TrustThreshold

    //fmt.Printf("GET TT=%d\n", tt1)
    //fmt.Printf("POST TT=%d\n", tt2)
}
