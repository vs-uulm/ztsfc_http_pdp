package policies

import "fmt"

var (
    Policies PoliciesT
)

type AttributesT struct {
    User UserT  `yaml:"user"`
}

type UserT struct {
    PwAuthenticated    int `yaml:"pw_authenticated"`
    CertAuthenticated   int `yaml:"cert_authenticated"`
}

type ActionT struct {
    TrustThreshold int `yaml:"trust_threshold"`
}

type ResourceT struct {
    Actions map[string]*ActionT `yaml:"actions"`
}

type PoliciesT struct {
    Attributes AttributesT  `yaml:"attributes"`
    Resources map[string]*ResourceT  `yaml:"resources"`
}

func PrintS(p *PoliciesT) {
    tt1 := p.Resources["service1.testbed.informatik.uni-ulm.de"].Actions["get"].TrustThreshold
    tt2 := p.Resources["service1.testbed.informatik.uni-ulm.de"].Actions["post"].TrustThreshold

    fmt.Printf("GET TT=%d\n", tt1)
    fmt.Printf("POST TT=%d\n", tt2)
}
