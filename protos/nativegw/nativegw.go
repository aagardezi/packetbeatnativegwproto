package nativegw

import (
	"time"

	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/elastic/beats/v7/libbeat/logp"

	"github.com/elastic/beats/v7/packetbeat/procs"
	"github.com/elastic/beats/v7/packetbeat/protos"
	"github.com/elastic/beats/v7/packetbeat/protos/tcp"
)

// nativegwPlugin application level protocol analyzer plugin
type nativegwPlugin struct {
	ports        protos.PortsConfig
	parserConfig parserConfig
	transConfig  transactionConfig
	watcher      procs.ProcessesWatcher
	pub          transPub
}

// Application Layer tcp stream data to be stored on tcp connection context.
type connection struct {
	streams [2]*stream
	trans   transactions
}

// Uni-directional tcp stream state for parsing messages.
type stream struct {
	parser parser
}

var (
	debugf = logp.MakeDebug("nativegw")

	// use isDebug/isDetailed to guard debugf/detailedf to minimize allocations
	// (garbage collection) when debug log is disabled.
	isDebug = false
)

func init() {
	protos.Register("nativegw", New)
}

// New create and initializes a new nativegw protocol analyzer instance.
func New(
	testMode bool,
	results protos.Reporter,
	watcher procs.ProcessesWatcher,
	cfg *common.Config,
) (protos.Plugin, error) {
	p := &nativegwPlugin{}
	config := defaultConfig
	if !testMode {
		if err := cfg.Unpack(&config); err != nil {
			return nil, err
		}
	}

	if err := p.init(results, watcher, &config); err != nil {
		return nil, err
	}
	return p, nil
}

func (np *nativegwPlugin) init(results protos.Reporter, watcher procs.ProcessesWatcher, config *nativegwConfig) error {
	if err := np.setFromConfig(config); err != nil {
		return err
	}
	np.pub.results = results
	np.watcher = watcher

	isDebug = logp.IsDebug("http")
	return nil
}

func (np *nativegwPlugin) setFromConfig(config *nativegwConfig) error {

	// set module configuration
	if err := np.ports.Set(config.Ports); err != nil {
		return err
	}

	// set parser configuration
	parser := &np.parserConfig
	parser.maxBytes = tcp.TCPMaxDataInStream

	// set transaction correlator configuration
	trans := &np.transConfig
	trans.transactionTimeout = config.TransactionTimeout

	// set transaction publisher configuration
	pub := &np.pub
	pub.sendRequest = config.SendRequest
	pub.sendResponse = config.SendResponse

	return nil
}

// ConnectionTimeout returns the per stream connection timeout.
// Return <=0 to set default tcp module transaction timeout.
func (np *nativegwPlugin) ConnectionTimeout() time.Duration {
	return np.transConfig.transactionTimeout
}

// GetPorts returns the ports numbers packets shall be processed for.
func (np *nativegwPlugin) GetPorts() []int {
	return np.ports.Ports
}

// Parse processes a TCP packet. Return nil if connection
// state shall be dropped (e.g. parser not in sync with tcp stream)
func (np *nativegwPlugin) Parse(
	pkt *protos.Packet,
	tcptuple *common.TCPTuple, dir uint8,
	private protos.ProtocolData,
) protos.ProtocolData {
	defer logp.Recover("Parse nativegwPlugin exception")

	conn := np.ensureConnection(private)
	st := conn.streams[dir]
	if st == nil {
		st = &stream{}
		st.parser.init(&np.parserConfig, func(msg *message) error {
			return conn.trans.onMessage(tcptuple.IPPort(), dir, msg)
		})
		conn.streams[dir] = st
	}

	if err := st.parser.feed(pkt.Ts, pkt.Payload); err != nil {
		debugf("%v, dropping TCP stream for error in direction %v.", err, dir)
		np.onDropConnection(conn)
		return nil
	}
	return conn
}

// ReceivedFin handles TCP-FIN packet.
func (np *nativegwPlugin) ReceivedFin(
	tcptuple *common.TCPTuple, dir uint8,
	private protos.ProtocolData,
) protos.ProtocolData {
	return private
}

// GapInStream handles lost packets in tcp-stream.
func (np *nativegwPlugin) GapInStream(tcptuple *common.TCPTuple, dir uint8,
	nbytes int,
	private protos.ProtocolData,
) (protos.ProtocolData, bool) {
	conn := getConnection(private)
	if conn != nil {
		np.onDropConnection(conn)
	}

	return nil, true
}

// onDropConnection processes and optionally sends incomplete
// transaction in case of connection being dropped due to error
func (np *nativegwPlugin) onDropConnection(conn *connection) {
}

func (np *nativegwPlugin) ensureConnection(private protos.ProtocolData) *connection {
	conn := getConnection(private)
	if conn == nil {
		conn = &connection{}
		conn.trans.init(&np.transConfig, np.watcher, np.pub.onTransaction)
	}
	return conn
}

func (conn *connection) dropStreams() {
	conn.streams[0] = nil
	conn.streams[1] = nil
}

func getConnection(private protos.ProtocolData) *connection {
	if private == nil {
		return nil
	}

	priv, ok := private.(*connection)
	if !ok {
		logp.Warn("nativegw connection type error")
		return nil
	}
	if priv == nil {
		logp.Warn("Unexpected: nativegw connection data not set")
		return nil
	}
	return priv
}
