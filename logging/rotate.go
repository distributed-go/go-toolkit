package logging

import (
	"log"
	"time"

	rotatelogs "github.com/lestrrat-go/file-rotatelogs"
)

const (
	logFile      = "./log/app_%Y-%m-%d.log"
	rotationTime = 24 * time.Hour
	purgeTime    = 7 * 24 * time.Hour
)

// See https://github.com/lestrrat-go/file-rotatelogs
func newRotateLogs() *rotatelogs.RotateLogs {
	res, err := rotatelogs.New(
		logFile,
		rotatelogs.WithRotationTime(rotationTime),
		rotatelogs.WithMaxAge(purgeTime),
	)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("log file path: %v", logFile)
	return res
}
