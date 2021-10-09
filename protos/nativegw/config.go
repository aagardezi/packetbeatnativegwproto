package nativegw

import (
	"github.com/elastic/beats/v7/packetbeat/config"
	"github.com/elastic/beats/v7/packetbeat/protos"
)

type nativegwConfig struct {
	config.ProtocolCommon `config:",inline"`
}

var (
	defaultConfig = nativegwConfig{
		ProtocolCommon: config.ProtocolCommon{
			TransactionTimeout: protos.DefaultTransactionExpiration,
		},
	}
)

func (c *nativegwConfig) Validate() error {
	return nil
}
