// Copyright 2025 cosmiclentil89. Licensed under the Apache License, Version 2.0.

package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/sirupsen/logrus"
)

var Log = logrus.New()

func Start(logFilePath string, debug bool) *os.File {

	// Open the log file
	logFile, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0666)
	if err != nil {
		fmt.Println("ERROR opening log file:", err.Error())
	} else {
		Log.SetOutput(logFile)
	}

	// Configure logging
	// Set log level based on debug flag
	if debug {
		Log.SetLevel(logrus.DebugLevel)
	} else {
		Log.SetLevel(logrus.InfoLevel)
	}
	Log.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:			true,
		TimestampFormat:		"2006-01-02 15:04:05.000",
		ForceColors:			true,
		DisableColors:			false,
		DisableLevelTruncation:	false,
		PadLevelText:			true,
		QuoteEmptyFields:		true,
		CallerPrettyfier:		func(f *runtime.Frame) (string, string) {
									return "", fmt.Sprintf("%s:%d", filepath.Base(f.File), f.Line)
								},
		
	})

	// Optional: Enable to show file and line number in logs
	// Log.SetReportCaller(true)

	return logFile
}