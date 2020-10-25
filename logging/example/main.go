package main

import (
	"github.com/golang-microservices/go-microservice-toolkit/logging"
	"go.uber.org/zap"
)

func main() {
	logging.InitLogger()
	defer logging.Sync()   // flush log buffer
	logging.SyncWhenStop() // flush log buffer. when interrupt or terminated.

	// time.Sleep(60*time.Second)
	logging.Info("USER_INFO", zap.String("name", "Alice"), zap.Int("age", 20))
}
