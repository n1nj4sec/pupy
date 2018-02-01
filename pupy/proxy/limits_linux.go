// +build linux

package main

import (
	log "github.com/sirupsen/logrus"
	"syscall"
)

func init() {
	log.Warning("Set rlimits")
	limits := &syscall.Rlimit{}
	err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, limits)
	if err != nil {
		log.Fatalln("Couldn't get rlimit value: ", err)
	}

	limits.Cur = limits.Max
	syscall.Setrlimit(syscall.RLIMIT_NOFILE, limits)
}
