package init

import (
	"fmt"
)

func InitPolicies() error {
	if err := initResourcesParams(); err != nil {
		return fmt.Errorf("init: InitPolicies(): %s", err.Error())
	}

	if err := initAttributesParams(); err != nil {
		return fmt.Errorf("init: InitPolicies(): %s", err.Error())
	}
	return nil
}
