package perf

import (
	"go.uber.org/zap"
	"runtime"
	"strconv"
	"time"
)

// TODO: module-level structured logging
var log = zap.Must(zap.NewDevelopment()).Sugar()

func Perf(label string) func() {
	caller := "<unknown>"

	_, file, line, ok := runtime.Caller(1)
	if ok {
		caller = file + ":" + strconv.Itoa(line)
	}

	log.Debugf("[%s] starting label: %s", caller, label)
	start := time.Now()
	return func() {
		log.Debugf("[%s] %s took %s", caller, time.Since(start).String(), label)
	}
}
