package logging

import (
	"time"
)

type Config struct {
	LogFilename  string        `json:"logFilename"`
	LogLevel     string        `json:"logLevel"`
	RotationTime time.Duration `json:"rotationTime"`
}
