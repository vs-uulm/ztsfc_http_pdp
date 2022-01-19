package init

import (
    "fmt"
)

func InitConfig() error {
    if err := initPdpParams(); err != nil {
        return fmt.Errorf("init: InitConfig(): %v", err)
    }

    return nil
}
