package main

import (
	"os"

	"github.com/elastic/beats/v7/packetbeat/cmd"

	// import supported protocol modules
	_ "github.com/aagardezi/packetbeatnativegwproto/protos/nativegw"
)

var Name = "nativegw"

// Setups and Runs Packetbeat
func main() {
	if err := cmd.RootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
