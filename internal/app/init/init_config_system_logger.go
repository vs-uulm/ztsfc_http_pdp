package init

import (
    "github.com/vs-uulm/ztsfc_http_pdp/internal/app/config"
)

func InitSysLoggerParams() {
    if config.Config.SysLogger.LogLevel == "" {
            config.Config.SysLogger.LogLevel = "error"
    }

    if config.Config.SysLogger.LogFilePath == "" {
            config.Config.SysLogger.LogFilePath = "stdout"
    }

    if config.Config.SysLogger.IfTextFormatter == "" {
            config.Config.SysLogger.IfTextFormatter = "json"
    }
}
