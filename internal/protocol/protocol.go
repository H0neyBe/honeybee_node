// Package protocol defines the communication protocol between HoneyBee nodes
// and the HoneyBee Core manager. It provides message types, envelopes, and
// serialization formats for all inter-component communication.
//
// The protocol uses JSON encoding wrapped in versioned envelopes to support
// backwards compatibility and protocol evolution.
package protocol

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/honeybee/node/internal/constants"
	"github.com/honeybee/node/internal/errors"
)

// NodeType classifies the capability level of a node
type NodeType string

const (
	NodeTypeFull  NodeType = "Full"
	NodeTypeAgent NodeType = "Agent"
)

// NodeStatus represents the lifecycle state of a node
// Matches honeybee_core/bee_message/src/common.rs
type NodeStatus string

const (
	NodeStatusConnected NodeStatus = "Connected"
	NodeStatusDeploying NodeStatus = "Deploying"
	NodeStatusRunning   NodeStatus = "Running"
	NodeStatusStopped   NodeStatus = "Stopped"
	NodeStatusFailed    NodeStatus = "Failed"
	NodeStatusUnknown   NodeStatus = "Unknown"
)

// PotStatus represents the lifecycle state of a honeypot (pot)
// Matches honeybee_core/bee_message/src/node/node_to_manager.rs
type PotStatus string

const (
	PotStatusInstalling PotStatus = "Installing"
	PotStatusRunning    PotStatus = "Running"
	PotStatusStopped    PotStatus = "Stopped"
	PotStatusFailed     PotStatus = "Failed"
)

// MessageEnvelope wraps all protocol messages with versioning
type MessageEnvelope struct {
	Version uint64      `json:"version"`
	Message MessageType `json:"message"`
}

// MessageType represents the union of all message types
// This structure matches the Rust enum serialization format from honeybee_core
type MessageType struct {
	// Node to Manager messages (NodeToManagerMessage enum variants)
	NodeRegistration *NodeRegistration `json:"NodeRegistration,omitempty"`
	NodeStatusUpdate *NodeStatusUpdate `json:"NodeStatusUpdate,omitempty"`
	NodeEvent        *NodeEvent        `json:"NodeEvent,omitempty"`
	NodeDrop         *struct{}         `json:"NodeDrop,omitempty"` // Unit variant

	// Pot messages (Node → Manager)
	PotStatusUpdate *PotStatusUpdate `json:"PotStatusUpdate,omitempty"`
	PotLog          *PotLog          `json:"PotLog,omitempty"`

	// Manager to Node messages (ManagerToNodeMessage enum variants)
	NodeCommand     *NodeCommand     `json:"NodeCommand,omitempty"`
	RegistrationAck *RegistrationAck `json:"RegistrationAck,omitempty"`
}

// NodeRegistration is sent during initial connection handshake
type NodeRegistration struct {
	NodeID   uint64   `json:"node_id"`
	NodeName string   `json:"node_name"`
	Address  string   `json:"address"`
	Port     uint16   `json:"port"`
	NodeType NodeType `json:"node_type"`
	TOTPCode string   `json:"totp_code,omitempty"` // TOTP for authentication
}

// NodeStatusUpdate publishes the current operating state
type NodeStatusUpdate struct {
	NodeID uint64     `json:"node_id"`
	Status NodeStatus `json:"status"`
}

// NodeEvent represents noteworthy events
// Matches the Rust enum serialization: NodeEvent { Started | Stopped | Alarm | Error }
type NodeEvent struct {
	// Only ONE of these fields should be set to match Rust enum serialization
	Started *struct{}   `json:"Started,omitempty"` // Unit variant
	Stopped *struct{}   `json:"Stopped,omitempty"` // Unit variant
	Alarm   *AlarmEvent `json:"Alarm,omitempty"`   // Struct variant
	Error   *ErrorEvent `json:"Error,omitempty"`   // Struct variant
}

// AlarmEvent represents the Alarm variant payload
type AlarmEvent struct {
	Description string `json:"description"`
}

// ErrorEvent represents the Error variant payload
type ErrorEvent struct {
	Message string `json:"message"`
}

// NodeCommand instructs a node to perform an action
// Matches honeybee_core/bee_message/src/node/manager_to_node.rs
type NodeCommand struct {
	NodeID  uint64          `json:"node_id"`
	Command NodeCommandType `json:"command"`
}

// NodeCommandType represents the type of command to execute
// Matches the Rust enum NodeCommandType
type NodeCommandType struct {
	Restart          *struct{}   `json:"Restart,omitempty"`
	UpdateConfig     *struct{}   `json:"UpdateConfig,omitempty"`
	InstallPot       *InstallPot `json:"InstallPot,omitempty"`
	DeployPot        *string     `json:"DeployPot,omitempty"`     // PotId
	GetPotStatus     *string     `json:"GetPotStatus,omitempty"`  // PotId
	RestartPot       *string     `json:"RestartPot,omitempty"`    // PotId
	StopPot          *string     `json:"StopPot,omitempty"`       // PotId
	GetPotLogs       *string     `json:"GetPotLogs,omitempty"`    // PotId
	GetPotMetrics    *string     `json:"GetPotMetrics,omitempty"` // PotId
	GetPotInfo       *string     `json:"GetPotInfo,omitempty"`    // PotId
	GetInstalledPots *struct{}   `json:"GetInstalledPots,omitempty"`
}

// UnmarshalJSON implements custom unmarshaling to handle null values from Rust's Unit type
func (ct *NodeCommandType) UnmarshalJSON(data []byte) error {
	// Use a temporary type to avoid recursion
	type Alias NodeCommandType
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(ct),
	}

	// First, unmarshal normally
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	// Now check for null values and convert them to non-nil pointers
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	// For each field that might have null value, set it to a non-nil pointer
	if _, exists := raw["Restart"]; exists && ct.Restart == nil {
		ct.Restart = &struct{}{}
	}
	if _, exists := raw["UpdateConfig"]; exists && ct.UpdateConfig == nil {
		ct.UpdateConfig = &struct{}{}
	}
	if _, exists := raw["GetInstalledPots"]; exists && ct.GetInstalledPots == nil {
		ct.GetInstalledPots = &struct{}{}
	}

	return nil
}

// InstallPot contains details for installing a honeypot
// Matches honeybee_core/bee_message/src/node/manager_to_node.rs
type InstallPot struct {
	PotID        string            `json:"pot_id"`
	HoneypotType string            `json:"honeypot_type"`
	GitURL       *string           `json:"git_url,omitempty"`
	GitBranch    *string           `json:"git_branch,omitempty"`
	Config       map[string]string `json:"config,omitempty"`
	AutoStart    bool              `json:"auto_start"`
}

// RegistrationAck confirms whether registration succeeded
type RegistrationAck struct {
	NodeID   uint64  `json:"node_id"`
	Accepted bool    `json:"accepted"`
	Message  *string `json:"message,omitempty"`
	TOTPKey  string  `json:"totp_key,omitempty"` // Sent on first registration
}

// =============================================================================
// Pot (Honeypot) Protocol Messages
// Matches honeybee_core/bee_message/src/node/node_to_manager.rs
// =============================================================================

// PotStatusUpdate reports the current state of a pot (honeypot)
// Matches honeybee_core/bee_message/src/node/node_to_manager.rs
type PotStatusUpdate struct {
	NodeID  uint64    `json:"node_id"`
	PotID   string    `json:"pot_id"`
	PotType string    `json:"pot_type"`
	Status  PotStatus `json:"status"`
	Message *string   `json:"message,omitempty"`
}

// PotEvent represents events captured by the honeypot
// Matches honeybee_core/bee_message/src/node/node_to_manager.rs
type PotEvent struct {
	NodeID    uint64            `json:"node_id"`
	PotID     string            `json:"pot_id"`
	Event     string            `json:"event"`
	Message   *string           `json:"message,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	Timestamp uint64            `json:"timestamp"`
}

// PotLog represents logs/events captured by the honeypot for storage
// Matches honeybee_core/bee_message/src/node/node_to_manager.rs
type PotLog struct {
	NodeID    uint64                 `json:"node_id"`
	PotID     string                 `json:"pot_id"`
	PotType   string                 `json:"pot_type"`
	LogType   string                 `json:"log_type"`
	Data      map[string]interface{} `json:"data"`
	Timestamp string                 `json:"timestamp"`
}

// =============================================================================
// Validation Methods
// =============================================================================

// Validate checks if a NodeRegistration is valid
func (nr *NodeRegistration) Validate() error {
	if nr.NodeID == 0 {
		return errors.Wrap(nil, errors.ErrCategoryProtocol, "INVALID_NODE_ID", "Node ID cannot be zero")
	}
	if nr.NodeName == "" {
		return errors.Wrap(nil, errors.ErrCategoryProtocol, "INVALID_NODE_NAME", "Node name cannot be empty")
	}
	if nr.NodeType != NodeTypeFull && nr.NodeType != NodeTypeAgent {
		return errors.Wrap(nil, errors.ErrCategoryProtocol, "INVALID_NODE_TYPE", "Invalid node type")
	}
	return nil
}

// Validate checks if an InstallPot command is valid
func (cmd *InstallPot) Validate() error {
	if cmd.PotID == "" {
		return errors.Wrap(nil, errors.ErrCategoryProtocol, "INVALID_POT_ID", "Pot ID cannot be empty")
	}
	if cmd.HoneypotType == "" {
		return errors.Wrap(nil, errors.ErrCategoryProtocol, "INVALID_HONEYPOT_TYPE", "Honeypot type cannot be empty")
	}
	// Validate honeypot type is supported
	supported := false
	for _, t := range constants.SupportedHoneypotTypes {
		if cmd.HoneypotType == t {
			supported = true
			break
		}
	}
	if !supported {
		return errors.Wrap(nil, errors.ErrCategoryProtocol, "UNSUPPORTED_HONEYPOT",
			fmt.Sprintf("Honeypot type '%s' is not supported", cmd.HoneypotType))
	}
	return nil
}

// Validate checks if a NodeCommand is valid
func (cmd *NodeCommand) Validate() error {
	if cmd.NodeID == 0 {
		return errors.Wrap(nil, errors.ErrCategoryProtocol, "INVALID_NODE_ID", "Node ID cannot be zero")
	}
	// Validate the command type has exactly one field set
	if cmd.Command.InstallPot != nil {
		return cmd.Command.InstallPot.Validate()
	}
	return nil
}

// GetCommandName returns a string representation of the command type
func (ct *NodeCommandType) GetCommandName() string {
	switch {
	case ct.Restart != nil:
		return "Restart"
	case ct.UpdateConfig != nil:
		return "UpdateConfig"
	case ct.InstallPot != nil:
		return "InstallPot"
	case ct.DeployPot != nil:
		return "DeployPot"
	case ct.GetPotStatus != nil:
		return "GetPotStatus"
	case ct.RestartPot != nil:
		return "RestartPot"
	case ct.StopPot != nil:
		return "StopPot"
	case ct.GetPotLogs != nil:
		return "GetPotLogs"
	case ct.GetPotMetrics != nil:
		return "GetPotMetrics"
	case ct.GetPotInfo != nil:
		return "GetPotInfo"
	case ct.GetInstalledPots != nil:
		return "GetInstalledPots"
	default:
		return "Unknown"
	}
}

// Validate checks if a MessageEnvelope is valid
func (env *MessageEnvelope) Validate() error {
	if env.Version != constants.ProtocolVersion {
		return errors.Wrap(nil, errors.ErrCategoryProtocol, "VERSION_MISMATCH",
			fmt.Sprintf("Protocol version mismatch: expected %d, got %d",
				constants.ProtocolVersion, env.Version))
	}
	return nil
}

// =============================================================================
// Encoding/Decoding Methods
// =============================================================================

// MarshalEnvelope wraps a message in an envelope and marshals to JSON
func MarshalEnvelope(msg *MessageType) ([]byte, error) {
	envelope := &MessageEnvelope{
		Version: constants.ProtocolVersion,
		Message: *msg,
	}

	data, err := json.Marshal(envelope)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCategoryProtocol, "MARSHAL_FAILED", "Failed to marshal message")
	}

	if len(data) > constants.MaxMessageSize {
		return nil, errors.Wrap(nil, errors.ErrCategoryProtocol, "MESSAGE_TOO_LARGE",
			fmt.Sprintf("Message size %d exceeds maximum %d", len(data), constants.MaxMessageSize))
	}

	return data, nil
}

// UnmarshalEnvelope unmarshals JSON data into a MessageEnvelope
func UnmarshalEnvelope(data []byte) (*MessageEnvelope, error) {
	if len(data) > constants.MaxMessageSize {
		return nil, errors.Wrap(nil, errors.ErrCategoryProtocol, "MESSAGE_TOO_LARGE",
			fmt.Sprintf("Message size %d exceeds maximum %d", len(data), constants.MaxMessageSize))
	}

	var envelope MessageEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, errors.Wrap(err, errors.ErrCategoryProtocol, "UNMARSHAL_FAILED", "Failed to unmarshal message")
	}

	if err := envelope.Validate(); err != nil {
		return nil, err
	}

	return &envelope, nil
}

// =============================================================================
// Helper Constructors
// =============================================================================

// NewStartedEvent creates a new "Started" node event
func NewStartedEvent() *NodeEvent {
	return &NodeEvent{Started: &struct{}{}}
}

// NewStoppedEvent creates a new "Stopped" node event
func NewStoppedEvent() *NodeEvent {
	return &NodeEvent{Stopped: &struct{}{}}
}

// NewAlarmEvent creates a new "Alarm" node event with a description
func NewAlarmEvent(description string) *NodeEvent {
	return &NodeEvent{
		Alarm: &AlarmEvent{
			Description: description,
		},
	}
}

// NewErrorEvent creates a new "Error" node event with a message
func NewErrorEvent(message string) *NodeEvent {
	return &NodeEvent{
		Error: &ErrorEvent{
			Message: message,
		},
	}
}

// NewPotStatusUpdate creates a new pot status update message
func NewPotStatusUpdate(nodeID uint64, potID, potType string, status PotStatus, message string) *PotStatusUpdate {
	var msg *string
	if message != "" {
		msg = &message
	}
	return &PotStatusUpdate{
		NodeID:  nodeID,
		PotID:   potID,
		PotType: potType,
		Status:  status,
		Message: msg,
	}
}

// NewPotEvent creates a new pot event from raw honeypot event data
func NewPotEvent(nodeID uint64, potID string, rawEvent map[string]interface{}) *PotEvent {
	event := &PotEvent{
		NodeID:    nodeID,
		PotID:     potID,
		Timestamp: uint64(time.Now().Unix()),
		Metadata:  make(map[string]string),
	}

	// Extract event ID
	if eventID, ok := rawEvent["eventid"].(string); ok {
		event.Event = eventID
	}

	// Extract message
	if message, ok := rawEvent["message"].(string); ok {
		event.Message = &message
	}

	// Convert other fields to metadata
	for key, value := range rawEvent {
		if key == "eventid" || key == "message" {
			continue
		}
		switch v := value.(type) {
		case string:
			event.Metadata[key] = v
		case float64:
			event.Metadata[key] = fmt.Sprintf("%v", v)
		case bool:
			event.Metadata[key] = fmt.Sprintf("%v", v)
		}
	}

	return event
}

// PotEventToPotLog converts a PotEvent to a PotLog for storage
func PotEventToPotLog(event *PotEvent, potType string) *PotLog {
	// Convert metadata strings to interface{} map for Data field
	data := make(map[string]interface{})
	for k, v := range event.Metadata {
		data[k] = v
	}

	// Add event ID to data
	if event.Event != "" {
		data["event"] = event.Event
	}

	// Add message to data if present
	if event.Message != nil {
		data["message"] = *event.Message
	}

	return &PotLog{
		NodeID:    event.NodeID,
		PotID:     event.PotID,
		PotType:   potType,
		LogType:   event.Event, // Use event type as log type
		Data:      data,
		Timestamp: time.Unix(int64(event.Timestamp), 0).Format(time.RFC3339),
	}
}
