package init

import (
    "fmt"
)

func InitPolicies() error {
    if err := initResourcesParams(); err != nil {
        return fmt.Errorf("init: InitPolicies(): %v", err)
    }

    if err := initAttributesParams(); err != nil {
        return fmt.Errorf("init: InitPolicies(): %v", err)
    }
    return nil
}
