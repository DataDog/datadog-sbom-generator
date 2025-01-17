package output

import (
	"log"
	"os"
)

// mustGetWorkingDirectory panics if it can't get the working directory
func mustGetWorkingDirectory() string {
	dir, err := os.Getwd()
	if err != nil {
		log.Panicf("can't get working dir: %v", err)
	}

	return dir
}
