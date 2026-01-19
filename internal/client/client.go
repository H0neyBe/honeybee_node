package client

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/honeybee/node/internal/auth"
	"github.com/honeybee/node/internal/config"
	"github.com/honeybee/node/internal/constants"
	"github.com/honeybee/node/internal/honeypot"
	"github.com/honeybee/node/internal/logger"
	"github.com/honeybee/node/internal/protocol"
)

// NodeClient manages the connection to the honeybee_core manager
type NodeClient struct {
	cfg         *config.Config
	nodeID      uint64
	totpMgr     *auth.TOTPManager
	tlsConfig   *tls.Config
	conn        net.Conn
	writer      *bufio.Writer
	reader      *bufio.Reader
	mu          sync.Mutex
	stopChan    chan struct{}
	doneChan    chan struct{}
	registered  bool
	honeypotMgr *honeypot.HoneypotManager
}

// NewNodeClient creates a new node client
func NewNodeClient(cfg *config.Config) (*NodeClient, error) {
	// Generate random node ID
	nodeID, err := generateNodeID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate node ID: %w", err)
	}

	// Initialize TOTP manager if enabled
	var totpMgr *auth.TOTPManager
	if cfg.Auth.TOTPEnabled {
		totpMgr, err = auth.NewTOTPManager(cfg.Auth.TOTPSecretDir)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize TOTP manager: %w", err)
		}
	}

	// Initialize TLS config if enabled
	var tlsConfig *tls.Config
	if cfg.TLS.Enabled {
		tlsCfg := &auth.TLSConfig{
			CertFile:           cfg.TLS.CertFile,
			KeyFile:            cfg.TLS.KeyFile,
			CAFile:             cfg.TLS.CAFile,
			InsecureSkipVerify: cfg.TLS.InsecureSkipVerify,
			ServerName:         cfg.TLS.ServerName,
		}
		tlsConfig, err = auth.LoadTLSConfig(tlsCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS config: %w", err)
		}
	}

	// Initialize honeypot manager if enabled
	var honeypotMgr *honeypot.HoneypotManager
	if cfg.Honeypot.Enabled {
		honeypotMgr, err = honeypot.NewHoneypotManager(cfg.Honeypot.BaseDir, nodeID)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize honeypot manager: %w", err)
		}
	}

	return &NodeClient{
		cfg:         cfg,
		nodeID:      nodeID,
		totpMgr:     totpMgr,
		tlsConfig:   tlsConfig,
		stopChan:    make(chan struct{}),
		doneChan:    make(chan struct{}),
		honeypotMgr: honeypotMgr,
	}, nil
}

// Run starts the node client main loop
func (nc *NodeClient) Run() error {
	defer close(nc.doneChan)

	logger.WithFields(map[string]interface{}{
		"node_id":   nc.nodeID,
		"node_name": nc.cfg.Node.Name,
		"node_type": nc.cfg.Node.Type,
	}).Info("Starting node client")

	// Start honeypot manager if enabled
	if nc.honeypotMgr != nil {
		if err := nc.honeypotMgr.Start(); err != nil {
			logger.Errorf("Failed to start honeypot manager: %v", err)
		} else {
			logger.Info("Honeypot manager started")
		}
	}

	for {
		select {
		case <-nc.stopChan:
			logger.Info("Node client shutting down")
			if nc.honeypotMgr != nil {
				nc.honeypotMgr.Stop()
			}
			return nil
		default:
		}

		// Connect to server
		if err := nc.connect(); err != nil {
			logger.Errorf("Connection failed: %v", err)
			nc.waitReconnect()
			continue
		}

		// Register with server
		if err := nc.register(); err != nil {
			logger.Errorf("Registration failed: %v", err)
			nc.closeConnection()
			nc.waitReconnect()
			continue
		}

		// Send initial status
		if err := nc.sendStatusUpdate(protocol.NodeStatusRunning); err != nil {
			logger.Errorf("Failed to send initial status: %v", err)
			nc.closeConnection()
			nc.waitReconnect()
			continue
		}

		// Run main event loop
		if err := nc.eventLoop(); err != nil {
			logger.Errorf("Event loop error: %v", err)
		}

		nc.closeConnection()
		nc.waitReconnect()
	}
}

// connect establishes connection to the server
func (nc *NodeClient) connect() error {
	timeout := time.Duration(nc.cfg.Server.ConnectionTimeout) * time.Second
	logger.Infof("Connecting to server at %s (TLS: %v)", nc.cfg.Server.Address, nc.cfg.TLS.Enabled)

	var conn net.Conn
	var err error

	if nc.cfg.TLS.Enabled {
		dialer := &net.Dialer{Timeout: timeout}
		conn, err = tls.DialWithDialer(dialer, "tcp", nc.cfg.Server.Address, nc.tlsConfig)
		if err != nil {
			return fmt.Errorf("TLS connection failed: %w", err)
		}

		// Verify TLS connection
		tlsConn := conn.(*tls.Conn)
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return fmt.Errorf("TLS handshake failed: %w", err)
		}

		state := tlsConn.ConnectionState()
		logger.Debugf("TLS connection established: version=%s, cipher=%s",
			tlsVersionString(state.Version),
			tls.CipherSuiteName(state.CipherSuite))
	} else {
		conn, err = net.DialTimeout("tcp", nc.cfg.Server.Address, timeout)
		if err != nil {
			return fmt.Errorf("TCP connection failed: %w", err)
		}
		logger.Warn("Connected without TLS encryption (not recommended for production)")
	}

	nc.conn = conn
	nc.writer = bufio.NewWriter(conn)
	nc.reader = bufio.NewReader(conn)

	logger.Info("Connected to server successfully")
	return nil
}

// register sends registration message to the server
func (nc *NodeClient) register() error {
	logger.Info("Sending registration")

	registration := protocol.NodeRegistration{
		NodeID:   nc.nodeID,
		NodeName: nc.cfg.Node.Name,
		Address:  nc.cfg.Node.Address,
		Port:     nc.cfg.Node.Port,
		NodeType: protocol.NodeType(nc.cfg.Node.Type),
	}

	// Add TOTP code if enabled
	if nc.cfg.Auth.TOTPEnabled && nc.totpMgr != nil {
		// Load or generate TOTP secret
		_, isNew, err := nc.totpMgr.LoadOrGenerateSecret()
		if err != nil {
			return fmt.Errorf("failed to load TOTP secret: %w", err)
		}

		if isNew {
			logger.Info("Generated new TOTP secret (first-time registration)")
		} else {
			logger.Debug("Using existing TOTP secret")
		}

		// Generate TOTP code
		code, err := nc.totpMgr.GenerateCode()
		if err != nil {
			return fmt.Errorf("failed to generate TOTP code: %w", err)
		}

		registration.TOTPCode = code
		logger.Debugf("TOTP code generated: %s", code)
	}

	envelope := protocol.MessageEnvelope{
		Version: constants.ProtocolVersion,
		Message: protocol.MessageType{
			NodeRegistration: &registration,
		},
	}

	if err := nc.sendMessage(envelope); err != nil {
		return fmt.Errorf("failed to send registration: %w", err)
	}

	// Wait for registration acknowledgment
	ack, err := nc.waitForRegistrationAck()
	if err != nil {
		return fmt.Errorf("registration acknowledgment failed: %w", err)
	}

	if !ack.Accepted {
		msg := "unknown reason"
		if ack.Message != nil {
			msg = *ack.Message
		}
		return fmt.Errorf("registration rejected: %s", msg)
	}

	logger.Info("Registration accepted")
	if ack.Message != nil {
		logger.Infof("Server message: %s", *ack.Message)
	}

	// If server provides TOTP key (first registration), save it
	if ack.TOTPKey != "" && nc.totpMgr != nil {
		logger.Info("Received TOTP key from server, saving...")
		if err := nc.totpMgr.SetSecret(ack.TOTPKey); err != nil {
			logger.Errorf("Failed to save TOTP key: %v", err)
		}
	}

	nc.registered = true
	return nil
}

// waitForRegistrationAck waits for registration acknowledgment
func (nc *NodeClient) waitForRegistrationAck() (*protocol.RegistrationAck, error) {
	// Set read deadline
	nc.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer nc.conn.SetReadDeadline(time.Time{})

	line, err := nc.reader.ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read acknowledgment: %w", err)
	}

	var envelope protocol.MessageEnvelope
	if err := json.Unmarshal(line, &envelope); err != nil {
		return nil, fmt.Errorf("failed to parse acknowledgment: %w", err)
	}

	// Validate protocol version
	if envelope.Version != constants.ProtocolVersion {
		logger.Warnf("Protocol version mismatch: got %d, expected %d",
			envelope.Version, constants.ProtocolVersion)
	}

	if envelope.Message.RegistrationAck == nil {
		return nil, fmt.Errorf("expected RegistrationAck, got different message")
	}

	return envelope.Message.RegistrationAck, nil
}

// eventLoop runs the main event loop
func (nc *NodeClient) eventLoop() error {
	heartbeatTicker := time.NewTicker(time.Duration(nc.cfg.Server.HeartbeatInterval) * time.Second)
	defer heartbeatTicker.Stop()

	errorChan := make(chan error, 2)

	// Start message reader
	go nc.readMessages(errorChan)

	// Get pot (honeypot) event channel if available
	var potEvents <-chan *protocol.PotEvent
	if nc.honeypotMgr != nil {
		potEvents = nc.honeypotMgr.EventChannel()
	}

	// Main loop
	for {
		select {
		case <-nc.stopChan:
			nc.sendNodeDrop()
			return nil

		case <-heartbeatTicker.C:
			if err := nc.sendStatusUpdate(protocol.NodeStatusRunning); err != nil {
				return fmt.Errorf("heartbeat failed: %w", err)
			}
			logger.Debug("Heartbeat sent")

		case event, ok := <-potEvents:
			if ok && event != nil {
				if err := nc.sendPotEvent(event); err != nil {
					logger.Errorf("Failed to send pot event: %v", err)
				}
			}

		case err := <-errorChan:
			return err
		}
	}
}

// readMessages reads messages from the server
func (nc *NodeClient) readMessages(errorChan chan<- error) {
	for {
		line, err := nc.reader.ReadBytes('\n')
		if err != nil {
			errorChan <- fmt.Errorf("read error: %w", err)
			return
		}

		logger.Infof("📥 Raw message: %s", string(line))

		var envelope protocol.MessageEnvelope
		if err := json.Unmarshal(line, &envelope); err != nil {
			logger.Warnf("Failed to parse message: %v", err)
			logger.Warnf("Raw bytes: %v", line)
			continue
		}

		if err := nc.handleMessage(&envelope); err != nil {
			logger.Errorf("Failed to handle message: %v", err)
		}
	}
}

// handleMessage processes incoming messages from the server
func (nc *NodeClient) handleMessage(envelope *protocol.MessageEnvelope) error {
	// Validate protocol version
	if envelope.Version != constants.ProtocolVersion {
		logger.Warnf("Protocol version mismatch: got %d, expected %d",
			envelope.Version, constants.ProtocolVersion)
	}

	// Handle NodeCommand with NodeCommandType
	if cmd := envelope.Message.NodeCommand; cmd != nil {
		cmdJSON, _ := json.Marshal(cmd)
		logger.Infof("📦 NodeCommand parsed: %s", string(cmdJSON))
		nc.handleNodeCommand(cmd)
	}

	return nil
}

// handleNodeCommand handles all node commands from the server
func (nc *NodeClient) handleNodeCommand(cmd *protocol.NodeCommand) {
	cmdType := &cmd.Command
	cmdName := cmdType.GetCommandName()
	logger.Infof("Received command: %s", cmdName)

	switch {
	case cmdType.Restart != nil:
		logger.Info("Restart command received")
		nc.sendStatusUpdate(protocol.NodeStatusStopped)
		time.Sleep(500 * time.Millisecond)
		nc.sendStatusUpdate(protocol.NodeStatusRunning)
		nc.sendEvent(protocol.NewStartedEvent())

	case cmdType.UpdateConfig != nil:
		logger.Info("UpdateConfig command received")
		nc.sendEvent(protocol.NewErrorEvent("UpdateConfig not yet implemented"))

	case cmdType.InstallPot != nil:
		logger.Infof("InstallPot command: %s (type: %s)", cmdType.InstallPot.PotID, cmdType.InstallPot.HoneypotType)
		nc.handleInstallPot(cmdType.InstallPot)

	case cmdType.DeployPot != nil:
		potID := *cmdType.DeployPot
		logger.Infof("DeployPot command: %s", potID)
		nc.handleStartPot(potID)

	case cmdType.GetPotStatus != nil:
		potID := *cmdType.GetPotStatus
		logger.Infof("GetPotStatus command: %s", potID)
		nc.handleGetPotStatus(potID)

	case cmdType.RestartPot != nil:
		potID := *cmdType.RestartPot
		logger.Infof("RestartPot command: %s", potID)
		nc.handleRestartPot(potID)

	case cmdType.StopPot != nil:
		potID := *cmdType.StopPot
		logger.Infof("StopPot command: %s", potID)
		nc.handleStopPot(potID)

	case cmdType.GetPotLogs != nil:
		potID := *cmdType.GetPotLogs
		logger.Infof("GetPotLogs command: %s", potID)
		nc.sendEvent(protocol.NewErrorEvent("GetPotLogs not yet implemented"))

	case cmdType.GetPotMetrics != nil:
		potID := *cmdType.GetPotMetrics
		logger.Infof("GetPotMetrics command: %s", potID)
		nc.sendEvent(protocol.NewErrorEvent("GetPotMetrics not yet implemented"))

	case cmdType.GetPotInfo != nil:
		potID := *cmdType.GetPotInfo
		logger.Infof("GetPotInfo command: %s", potID)
		nc.handleGetPotStatus(potID) // Same as GetPotStatus for now

	case cmdType.GetInstalledPots != nil:
		logger.Info("GetInstalledPots command")
		nc.handleGetInstalledPots()

	default:
		logger.Warnf("Unknown command type: %s", cmdName)
		nc.sendEvent(protocol.NewErrorEvent(fmt.Sprintf("Unknown command: %s", cmdName)))
	}
}

// handleInstallPot handles the InstallPot command
func (nc *NodeClient) handleInstallPot(cmd *protocol.InstallPot) {
	if nc.honeypotMgr == nil {
		logger.Error("Honeypot manager not enabled")
		nc.sendEvent(protocol.NewErrorEvent("Honeypot manager not enabled"))
		return
	}

	// Add default ports to config if not specified
	if cmd.Config == nil {
		cmd.Config = make(map[string]string)
	}
	if _, ok := cmd.Config["ssh_port"]; !ok {
		cmd.Config["ssh_port"] = fmt.Sprintf("%d", nc.cfg.Honeypot.DefaultSSH)
	}
	if _, ok := cmd.Config["telnet_port"]; !ok {
		cmd.Config["telnet_port"] = fmt.Sprintf("%d", nc.cfg.Honeypot.DefaultTel)
	}

	if err := nc.honeypotMgr.InstallPot(cmd); err != nil {
		logger.Errorf("Failed to install pot: %v", err)
		nc.sendEvent(protocol.NewErrorEvent(fmt.Sprintf("Failed to install pot: %v", err)))
		return
	}

	// Send success event
	message := fmt.Sprintf("Honeypot %s (%s) installed successfully", cmd.PotID, cmd.HoneypotType)
	if cmd.AutoStart {
		message += " and will start automatically"
	}
	nc.sendEvent(protocol.NewAlarmEvent(message))
}

// handleStartPot handles starting a pot (honeypot)
func (nc *NodeClient) handleStartPot(potID string) {
	if nc.honeypotMgr == nil {
		logger.Error("Honeypot manager not enabled")
		nc.sendEvent(protocol.NewErrorEvent("Honeypot manager not enabled"))
		return
	}

	if err := nc.honeypotMgr.StartHoneypot(potID); err != nil {
		logger.Errorf("Failed to start pot: %v", err)
		nc.sendEvent(protocol.NewErrorEvent(fmt.Sprintf("Failed to start pot: %v", err)))
		return
	}

	// Send success event
	nc.sendEvent(protocol.NewAlarmEvent(fmt.Sprintf("Honeypot %s started successfully", potID)))
}

// handleStopPot handles stopping a pot (honeypot)
func (nc *NodeClient) handleStopPot(potID string) {
	if nc.honeypotMgr == nil {
		logger.Error("Honeypot manager not enabled")
		nc.sendEvent(protocol.NewErrorEvent("Honeypot manager not enabled"))
		return
	}

	if err := nc.honeypotMgr.StopHoneypot(potID); err != nil {
		logger.Errorf("Failed to stop pot: %v", err)
		nc.sendEvent(protocol.NewErrorEvent(fmt.Sprintf("Failed to stop pot: %v", err)))
		return
	}

	// Send success event
	nc.sendEvent(protocol.NewAlarmEvent(fmt.Sprintf("Honeypot %s stopped successfully", potID)))
}

// handleRestartPot handles restarting a pot (honeypot)
func (nc *NodeClient) handleRestartPot(potID string) {
	if nc.honeypotMgr == nil {
		logger.Error("Honeypot manager not enabled")
		nc.sendEvent(protocol.NewErrorEvent("Honeypot manager not enabled"))
		return
	}

	// Stop then start
	if err := nc.honeypotMgr.StopHoneypot(potID); err != nil {
		logger.Warnf("Error stopping pot for restart: %v", err)
	}
	time.Sleep(500 * time.Millisecond)
	if err := nc.honeypotMgr.StartHoneypot(potID); err != nil {
		logger.Errorf("Failed to restart pot: %v", err)
		nc.sendEvent(protocol.NewErrorEvent(fmt.Sprintf("Failed to restart pot: %v", err)))
		return
	}

	// Send success event
	nc.sendEvent(protocol.NewAlarmEvent(fmt.Sprintf("Honeypot %s restarted successfully", potID)))
}

// handleGetPotStatus handles getting the status of a pot
func (nc *NodeClient) handleGetPotStatus(potID string) {
	if nc.honeypotMgr == nil {
		logger.Error("Honeypot manager not enabled")
		nc.sendEvent(protocol.NewErrorEvent("Honeypot manager not enabled"))
		return
	}

	status, err := nc.honeypotMgr.GetStatus(potID)
	if err != nil {
		logger.Errorf("Failed to get pot status: %v", err)
		nc.sendEvent(protocol.NewErrorEvent(fmt.Sprintf("Failed to get pot status: %v", err)))
		return
	}

	nc.sendPotStatusUpdate(status)
}

// handleGetInstalledPots handles getting the list of installed pots
func (nc *NodeClient) handleGetInstalledPots() {
	if nc.honeypotMgr == nil {
		logger.Error("Honeypot manager not enabled")
		nc.sendEvent(protocol.NewErrorEvent("Honeypot manager not enabled"))
		return
	}

	pots := nc.honeypotMgr.ListPots()
	logger.Infof("Found %d installed honeypots: %v", len(pots), func() []string {
		ids := make([]string, len(pots))
		for i, p := range pots {
			ids[i] = p.PotID
		}
		return ids
	}())

	// Send each pot status
	for _, pot := range pots {
		nc.sendPotStatusUpdate(pot)
	}

	// Send summary event
	potList := make([]string, len(pots))
	for i, pot := range pots {
		potList[i] = fmt.Sprintf("%s (%s - %s)", pot.PotID, pot.PotType, pot.Status)
	}
	message := fmt.Sprintf("Found %d installed honeypot(s): %s", len(pots), potList)
	nc.sendEvent(protocol.NewAlarmEvent(message))
}

// sendPotEvent sends a pot (honeypot) event to the server as a PotLog
func (nc *NodeClient) sendPotEvent(event *protocol.PotEvent) error {
	// Get the honeypot type from the manager
	var potType string
	if nc.honeypotMgr != nil {
		if status, err := nc.honeypotMgr.GetStatus(event.PotID); err == nil {
			potType = status.PotType
		}
	}

	// If pot type is still unknown, try to get it from metadata
	if potType == "" {
		if pt, ok := event.Metadata["pot_type"]; ok {
			potType = pt
		} else {
			potType = "unknown"
		}
	}

	// Convert PotEvent to PotLog for MongoDB storage
	potLog := protocol.PotEventToPotLog(event, potType)

	envelope := protocol.MessageEnvelope{
		Version: constants.ProtocolVersion,
		Message: protocol.MessageType{
			PotLog: potLog,
		},
	}

	return nc.sendMessage(envelope)
}

// sendPotStatusUpdate sends a pot status update to the server
func (nc *NodeClient) sendPotStatusUpdate(status *protocol.PotStatusUpdate) error {
	envelope := protocol.MessageEnvelope{
		Version: constants.ProtocolVersion,
		Message: protocol.MessageType{
			PotStatusUpdate: status,
		},
	}

	return nc.sendMessage(envelope)
}

// sendMessage sends a message to the server
func (nc *NodeClient) sendMessage(envelope protocol.MessageEnvelope) error {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	data, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	// Write message with newline
	if _, err := nc.writer.Write(data); err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}

	if err := nc.writer.WriteByte('\n'); err != nil {
		return fmt.Errorf("failed to write newline: %w", err)
	}

	if err := nc.writer.Flush(); err != nil {
		return fmt.Errorf("failed to flush: %w", err)
	}

	return nil
}

// sendStatusUpdate sends a status update to the server
func (nc *NodeClient) sendStatusUpdate(status protocol.NodeStatus) error {
	envelope := protocol.MessageEnvelope{
		Version: constants.ProtocolVersion,
		Message: protocol.MessageType{
			NodeStatusUpdate: &protocol.NodeStatusUpdate{
				NodeID: nc.nodeID,
				Status: status,
			},
		},
	}

	return nc.sendMessage(envelope)
}

// sendEvent sends an event to the server
func (nc *NodeClient) sendEvent(event *protocol.NodeEvent) error {
	envelope := protocol.MessageEnvelope{
		Version: constants.ProtocolVersion,
		Message: protocol.MessageType{
			NodeEvent: event,
		},
	}

	return nc.sendMessage(envelope)
}

// sendNodeDrop sends a node drop message
func (nc *NodeClient) sendNodeDrop() error {
	logger.Info("Sending NodeDrop")

	envelope := protocol.MessageEnvelope{
		Version: constants.ProtocolVersion,
		Message: protocol.MessageType{
			NodeDrop: &struct{}{},
		},
	}

	return nc.sendMessage(envelope)
}

// closeConnection closes the connection
func (nc *NodeClient) closeConnection() {
	if nc.conn != nil {
		nc.conn.Close()
		nc.conn = nil
	}
	nc.registered = false
}

// waitReconnect waits before reconnecting
func (nc *NodeClient) waitReconnect() {
	delay := time.Duration(nc.cfg.Server.ReconnectDelay) * time.Second
	logger.Infof("Reconnecting in %v...", delay)

	select {
	case <-nc.stopChan:
	case <-time.After(delay):
	}
}

// Stop stops the node client
func (nc *NodeClient) Stop() {
	close(nc.stopChan)
	<-nc.doneChan
}

// generateNodeID generates a random node ID
func generateNodeID() (uint64, error) {
	var id uint64
	err := binary.Read(rand.Reader, binary.BigEndian, &id)
	if err != nil {
		return 0, err
	}
	return id, nil
}

// tlsVersionString returns a string representation of TLS version
func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", version)
	}
}
