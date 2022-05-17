package init

import (
	"fmt"
)

func InitConfig() error {
	if err := initPdpParams(); err != nil {
		return fmt.Errorf("init: InitConfig(): %s", err.Error())
	}

	if err := initPipParams(); err != nil {
		return fmt.Errorf("init: InitConfig(): %s", err.Error())
	}

	return nil
}
