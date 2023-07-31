package perf

import (
	"go.uber.org/zap"
	"runtime"
	"strconv"
	"time"
)

func Perf(label string) func() {
	caller := "<unknown>"

	_, file, line, ok := runtime.Caller(1)
	if ok {
		caller = file + ":" + strconv.Itoa(line)
	}

	zap.S().Debugf("[%s] starting label: %s", caller, label)
	start := time.Now()
	return func() {
		zap.S().Debugf("[%s] %s took %s", caller, time.Since(start).String(), label)
	}
}
