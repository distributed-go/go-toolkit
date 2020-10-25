package logging

import (
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	once      sync.Once
	zapLogger *zap.Logger
)

// Initialize the Logger.
// Outputs short logs to the console and Write structured and detailed json logs to the log file.
func InitLogger() *zap.Logger {
	once.Do(func() {
		log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
		initZapLogger()
		Info("INIT_LOGGER")
	})
	return zapLogger
}

// See https://pkg.go.dev/go.uber.org/zap
func initZapLogger() {
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "ts",
		LevelKey:       "level",
		NameKey:        "name",
		CallerKey:      "caller",
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		FunctionKey:    "function",
		EncodeLevel:    zapcore.CapitalLevelEncoder,
		EncodeTime:     zapcore.RFC3339NanoTimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}
	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderConfig),
		zapcore.NewMultiWriteSyncer(zapcore.AddSync(newRotateLogs())),
		zap.DebugLevel,
	)
	zapLogger = zap.New(core, zap.AddCaller(), zap.AddStacktrace(zap.ErrorLevel)).With(
		zap.String("version", *getVersion(Revision)),
		zap.String("hostname", *getHost()),
	)
}

type VersionType int

const (
	_ VersionType = iota
	Revision
	Tag
)

// You can use the git revision or tag as a version.
// When using tag, recommend semantic versioning.
// See https://semver.org/
func getVersion(versionType VersionType) *string {
	var out []byte
	var err error

	switch versionType {
	case Revision:
		out, err = exec.Command("git", "rev-parse", "--short", "HEAD").Output()
	case Tag:
		out, err = exec.Command("git", "tag").Output()
	}
	if err != nil {
		log.Print(err)
		return nil
	}

	ret := strings.TrimRight(string(out), "\n")
	return &ret
}

func getHost() *string {
	ret, err := os.Hostname()
	if err != nil {
		log.Print(err)
		return nil
	}
	return &ret
}
