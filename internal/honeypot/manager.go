package honeypot

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/honeybee/node/internal/logger"
	"github.com/honeybee/node/internal/protocol"
)

// HoneypotManager manages honeypot installations and lifecycle
type HoneypotManager struct {
	baseDir       string
	honeypots     map[string]*HoneypotInstance
	mu            sync.RWMutex
	eventChan     chan *protocol.PotEvent
	nodeID        uint64
	eventListener net.Listener
	listenerPort  int
	ctx           context.Context
	cancel        context.CancelFunc
}

// HoneypotInstance represents a single honeypot installation
type HoneypotInstance struct {
	ID          string
	Type        string
	GitURL      string
	InstallPath string
	Status      protocol.PotStatus
	SSHPort     uint16
	TelnetPort  uint16
	Process     *exec.Cmd
	cancelFunc  context.CancelFunc
	mu          sync.Mutex
}

// NewHoneypotManager creates a new honeypot manager
func NewHoneypotManager(baseDir string, nodeID uint64) (*HoneypotManager, error) {
	// Create base directory if it doesn't exist
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create honeypot base directory: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &HoneypotManager{
		baseDir:   baseDir,
		honeypots: make(map[string]*HoneypotInstance),
		eventChan: make(chan *protocol.PotEvent, 1000),
		nodeID:    nodeID,
		ctx:       ctx,
		cancel:    cancel,
	}, nil
}

// Start starts the honeypot manager and event listener
func (hm *HoneypotManager) Start() error {
	// Start the event listener for receiving honeypot events via socket
	if err := hm.startEventListener(); err != nil {
		return fmt.Errorf("failed to start event listener: %w", err)
	}

	logger.Infof("HoneypotManager started, event listener on port %d", hm.listenerPort)
	return nil
}

// Stop stops all honeypots and the manager
func (hm *HoneypotManager) Stop() {
	hm.cancel()

	// Stop all honeypots
	hm.mu.RLock()
	for _, hp := range hm.honeypots {
		hm.stopHoneypot(hp)
	}
	hm.mu.RUnlock()

	// Close event listener
	if hm.eventListener != nil {
		hm.eventListener.Close()
	}

	close(hm.eventChan)
	logger.Info("HoneypotManager stopped")
}

// EventChannel returns the channel for pot (honeypot) events
func (hm *HoneypotManager) EventChannel() <-chan *protocol.PotEvent {
	return hm.eventChan
}

// InstallPot installs a honeypot (pot) from a Git repository
// Matches honeybee_core protocol - accepts InstallPot command
func (hm *HoneypotManager) InstallPot(cmd *protocol.InstallPot) error {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	// Check if honeypot already exists
	if _, exists := hm.honeypots[cmd.PotID]; exists {
		return fmt.Errorf("pot %s already exists", cmd.PotID)
	}

	installPath := filepath.Join(hm.baseDir, cmd.PotID)

	// Get git URL
	gitURL := ""
	if cmd.GitURL != nil {
		gitURL = *cmd.GitURL
	}

	instance := &HoneypotInstance{
		ID:          cmd.PotID,
		Type:        cmd.HoneypotType,
		GitURL:      gitURL,
		InstallPath: installPath,
		Status:      protocol.PotStatusInstalling,
		SSHPort:     2222, // Default SSH port
		TelnetPort:  2223, // Default Telnet port
	}

	// Override ports from config if provided
	if cmd.Config != nil {
		if sshPort, ok := cmd.Config["ssh_port"]; ok {
			if p, err := parsePort(sshPort); err == nil {
				instance.SSHPort = p
			}
		}
		if telnetPort, ok := cmd.Config["telnet_port"]; ok {
			if p, err := parsePort(telnetPort); err == nil {
				instance.TelnetPort = p
			}
		}
	}

	hm.honeypots[cmd.PotID] = instance

	// Install honeypot in background
	go hm.installPotAsync(instance, cmd)

	return nil
}

// PotStoreURL is the official HoneyBee PotStore repository
const PotStoreURL = "https://github.com/H0neyBe/honeybee_potstore.git"

// installPotAsync performs the actual installation asynchronously
func (hm *HoneypotManager) installPotAsync(instance *HoneypotInstance, cmd *protocol.InstallPot) {
	logger.Infof("Installing pot %s (type: %s)", instance.ID, instance.Type)

	// Send installing status
	hm.sendStatusUpdate(instance, "Installing from HoneyBee PotStore...")

	// Determine source: use custom git_url if provided, otherwise use PotStore
	gitURL := ""
	if cmd.GitURL != nil && *cmd.GitURL != "" {
		gitURL = *cmd.GitURL
	} else {
		gitURL = PotStoreURL
	}

	branch := "main"
	if cmd.GitBranch != nil && *cmd.GitBranch != "" {
		branch = *cmd.GitBranch
	}

	// Clone the repository
	tempPath := instance.InstallPath
	if gitURL == PotStoreURL {
		// Clone potstore to temp location, then move honeypot subdirectory
		tempPath = filepath.Join(hm.baseDir, ".potstore-temp")
	}

	gitArgs := []string{"clone", "--depth", "1", "--branch", branch, gitURL, tempPath}
	gitCmd := exec.CommandContext(hm.ctx, "git", gitArgs...)
	gitCmd.Stdout = os.Stdout
	gitCmd.Stderr = os.Stderr

	if err := gitCmd.Run(); err != nil {
		logger.Errorf("Failed to clone repository: %v", err)
		instance.Status = protocol.PotStatusFailed
		hm.sendStatusUpdate(instance, fmt.Sprintf("Git clone failed: %v", err))
		return
	}

	// If using PotStore, move the specific honeypot directory
	if gitURL == PotStoreURL {
		honeypotSrcPath := filepath.Join(tempPath, instance.Type)
		if _, err := os.Stat(honeypotSrcPath); os.IsNotExist(err) {
			// Try with version suffix (e.g., cowrie-2.9.0)
			entries, _ := filepath.Glob(filepath.Join(tempPath, instance.Type+"*"))
			if len(entries) > 0 {
				honeypotSrcPath = entries[0]
			} else {
				logger.Errorf("Honeypot %s not found in PotStore", instance.Type)
				instance.Status = protocol.PotStatusFailed
				hm.sendStatusUpdate(instance, fmt.Sprintf("Honeypot %s not found in PotStore", instance.Type))
				os.RemoveAll(tempPath)
				return
			}
		}

		// Move honeypot to final location
		if err := os.Rename(honeypotSrcPath, instance.InstallPath); err != nil {
			// If rename fails (cross-device), try copy
			logger.Infof("Rename failed, copying directory: %v", err)
			if err := copyDir(honeypotSrcPath, instance.InstallPath); err != nil {
				logger.Errorf("Failed to copy honeypot: %v", err)
				instance.Status = protocol.PotStatusFailed
				hm.sendStatusUpdate(instance, fmt.Sprintf("Failed to copy honeypot: %v", err))
				os.RemoveAll(tempPath)
				return
			}
		}

		// Cleanup temp potstore
		os.RemoveAll(tempPath)
	}

	logger.Infof("Installed honeypot to %s", instance.InstallPath)

	// Run honeypot-specific setup
	if err := hm.setupHoneypot(instance, cmd.Config); err != nil {
		logger.Errorf("Failed to setup honeypot: %v", err)
		instance.Status = protocol.PotStatusFailed
		hm.sendStatusUpdate(instance, fmt.Sprintf("Setup failed: %v", err))
		return
	}

	instance.Status = protocol.PotStatusStopped
	hm.sendStatusUpdate(instance, "Installation complete")

	logger.Infof("Honeypot %s installed successfully", instance.ID)

	// Auto-start if requested
	if cmd.AutoStart {
		if err := hm.StartHoneypot(cmd.PotID); err != nil {
			logger.Errorf("Failed to auto-start honeypot: %v", err)
		}
	}
}

// setupHoneypot performs honeypot-specific setup (virtualenv, config, etc.)
func (hm *HoneypotManager) setupHoneypot(instance *HoneypotInstance, config map[string]string) error {
	switch instance.Type {
	case "cowrie":
		return hm.setupCowrie(instance, config)
	case "honnypotter":
		return hm.setupHonnyPotter(instance, config)
	case "dionaea":
		return hm.setupDionaea(instance, config)
	case "heralding":
		return hm.setupHeralding(instance, config)
	case "elasticpot":
		return hm.setupElasticpot(instance, config)
	case "mailoney":
		return hm.setupMailoney(instance, config)
	default:
		// Try generic Python honeypot setup
		return hm.setupGenericPython(instance, config)
	}
}

// setupCowrie sets up Cowrie honeypot
func (hm *HoneypotManager) setupCowrie(instance *HoneypotInstance, config map[string]string) error {
	logger.Info("Setting up Cowrie honeypot...")

	// Determine Python command
	pythonCmd := "python3"
	if runtime.GOOS == "windows" {
		pythonCmd = "python"
	}

	// Create virtual environment
	venvPath := filepath.Join(instance.InstallPath, "cowrie-env")
	venvCmd := exec.CommandContext(hm.ctx, pythonCmd, "-m", "venv", venvPath)
	venvCmd.Dir = instance.InstallPath
	if err := venvCmd.Run(); err != nil {
		return fmt.Errorf("failed to create virtualenv: %w", err)
	}

	// Determine pip path
	var pipPath string
	if runtime.GOOS == "windows" {
		pipPath = filepath.Join(venvPath, "Scripts", "pip")
	} else {
		pipPath = filepath.Join(venvPath, "bin", "pip")
	}

	// Upgrade pip
	pipUpgradeCmd := exec.CommandContext(hm.ctx, pipPath, "install", "--upgrade", "pip")
	pipUpgradeCmd.Dir = instance.InstallPath
	if err := pipUpgradeCmd.Run(); err != nil {
		logger.Warnf("Failed to upgrade pip: %v", err)
	}

	// Install requirements
	reqPath := filepath.Join(instance.InstallPath, "requirements.txt")
	if _, err := os.Stat(reqPath); err == nil {
		pipInstallCmd := exec.CommandContext(hm.ctx, pipPath, "install", "-r", reqPath)
		pipInstallCmd.Dir = instance.InstallPath
		pipInstallCmd.Stdout = os.Stdout
		pipInstallCmd.Stderr = os.Stderr
		if err := pipInstallCmd.Run(); err != nil {
			return fmt.Errorf("failed to install requirements: %w", err)
		}
	}

	// Note: We don't need `pip install -e .` because we set PYTHONPATH
	// when running Cowrie. This avoids issues with setuptools_scm and
	// git shallow clones.
	logger.Info("Cowrie dependencies installed, skipping editable install (using PYTHONPATH)")

	// Create configuration
	if err := hm.createCowrieConfig(instance, config); err != nil {
		return fmt.Errorf("failed to create cowrie config: %w", err)
	}

	// Create necessary directories
	dirs := []string{
		filepath.Join(instance.InstallPath, "var", "log", "cowrie"),
		filepath.Join(instance.InstallPath, "var", "lib", "cowrie", "tty"),
		filepath.Join(instance.InstallPath, "var", "lib", "cowrie", "downloads"),
		filepath.Join(instance.InstallPath, "var", "run", "cowrie"),
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return nil
}

// createCowrieConfig creates the Cowrie configuration file
func (hm *HoneypotManager) createCowrieConfig(instance *HoneypotInstance, config map[string]string) error {
	configPath := filepath.Join(instance.InstallPath, "etc", "cowrie.cfg")

	// Ensure etc directory exists
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		return err
	}

	// Create config content with HoneyBee integration
	configContent := fmt.Sprintf(`# HoneyBee-managed Cowrie Configuration
# Honeypot ID: %s

[honeypot]
hostname = honeybee-%s
log_path = var/log/cowrie
download_path = var/lib/cowrie/downloads
state_path = var/lib/cowrie
data_path = src/cowrie/data
contents_path = honeyfs
backend = shell
logtype = plain
timezone = UTC

[ssh]
enabled = true
listen_endpoints = tcp:%d:interface=0.0.0.0

[telnet]
enabled = true
listen_endpoints = tcp:%d:interface=0.0.0.0

# JSON logging for local storage
[output_jsonlog]
enabled = true
logfile = var/log/cowrie/cowrie.json

# Socket output to HoneyBee Node
[output_socketlog]
enabled = true
address = 127.0.0.1:%d
timeout = 5
`, instance.ID, instance.ID, instance.SSHPort, instance.TelnetPort, hm.listenerPort)

	// Apply custom config overrides
	for key, value := range config {
		configContent += fmt.Sprintf("\n%s = %s", key, value)
	}

	return os.WriteFile(configPath, []byte(configContent), 0644)
}

// setupDionaea sets up Dionaea honeypot
func (hm *HoneypotManager) setupDionaea(instance *HoneypotInstance, config map[string]string) error {
	logger.Info("Setting up Dionaea honeypot...")
	// Dionaea typically requires compilation, this is a simplified setup
	return hm.setupGenericPython(instance, config)
}

// setupHeralding sets up Heralding honeypot
func (hm *HoneypotManager) setupHeralding(instance *HoneypotInstance, config map[string]string) error {
	logger.Info("Setting up Heralding honeypot...")
	return hm.setupGenericPython(instance, config)
}

// setupElasticpot sets up Elasticpot honeypot
func (hm *HoneypotManager) setupElasticpot(instance *HoneypotInstance, config map[string]string) error {
	logger.Info("Setting up Elasticpot honeypot...")
	return hm.setupGenericPython(instance, config)
}

// setupMailoney sets up Mailoney honeypot
func (hm *HoneypotManager) setupMailoney(instance *HoneypotInstance, config map[string]string) error {
	logger.Info("Setting up Mailoney honeypot...")
	return hm.setupGenericPython(instance, config)
}

// setupHonnyPotter sets up HonnyPotter WordPress honeypot
func (hm *HoneypotManager) setupHonnyPotter(instance *HoneypotInstance, config map[string]string) error {
	logger.Info("Setting up HonnyPotter honeypot...")

	// Get pot ID from config or use instance ID
	potID := instance.ID
	if id, ok := config["pot_id"]; ok && id != "" {
		potID = id
	}

	// Create logs directory
	logDir := filepath.Join(instance.InstallPath, "logs")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("failed to create logs directory: %w", err)
	}

	// Verify PHP is available
	phpCmd := "php"
	if runtime.GOOS == "windows" {
		phpCmd = "php.exe"
	}

	// Check if PHP is installed
	phpCheckCmd := exec.CommandContext(hm.ctx, phpCmd, "-v")
	if err := phpCheckCmd.Run(); err != nil {
		logger.Warnf("PHP not found in PATH, HonnyPotter may require manual PHP setup")
	}

	// Verify required PHP extensions
	extensions := []string{"json", "sockets"}
	for _, ext := range extensions {
		extCheckCmd := exec.CommandContext(hm.ctx, phpCmd, "-m")
		output, _ := extCheckCmd.Output()
		if !strings.Contains(strings.ToLower(string(output)), strings.ToLower(ext)) {
			logger.Warnf("PHP extension '%s' may not be available", ext)
		}
	}

	// Set default HTTP port if not specified
	httpPort := uint16(8080) // Default to 8080 for HonnyPotter
	if portStr, ok := config["http_port"]; ok && portStr != "" {
		if port, err := parsePort(portStr); err == nil {
			httpPort = port
		}
	}

	// Store HTTP port in SSHPort field for HonnyPotter (since it doesn't use SSH)
	instance.SSHPort = httpPort

	logger.Infof("HonnyPotter setup complete. Pot ID: %s, HTTP Port: %d", potID, httpPort)
	return nil
}

// parsePort parses a port string to uint16
func parsePort(portStr string) (uint16, error) {
	var port uint16
	_, err := fmt.Sscanf(portStr, "%d", &port)
	if err != nil {
		return 0, fmt.Errorf("invalid port: %w", err)
	}
	if port == 0 {
		return 0, fmt.Errorf("port cannot be 0")
	}
	return port, nil
}

// setupGenericPython sets up a generic Python-based honeypot
func (hm *HoneypotManager) setupGenericPython(instance *HoneypotInstance, config map[string]string) error {
	logger.Infof("Setting up generic Python honeypot: %s", instance.Type)

	// Determine Python command
	pythonCmd := "python3"
	if runtime.GOOS == "windows" {
		pythonCmd = "python"
	}

	// Create virtual environment
	venvPath := filepath.Join(instance.InstallPath, "venv")
	venvCmd := exec.CommandContext(hm.ctx, pythonCmd, "-m", "venv", venvPath)
	venvCmd.Dir = instance.InstallPath
	if err := venvCmd.Run(); err != nil {
		return fmt.Errorf("failed to create virtualenv: %w", err)
	}

	// Determine pip path
	var pipPath string
	if runtime.GOOS == "windows" {
		pipPath = filepath.Join(venvPath, "Scripts", "pip")
	} else {
		pipPath = filepath.Join(venvPath, "bin", "pip")
	}

	// Upgrade pip
	pipUpgradeCmd := exec.CommandContext(hm.ctx, pipPath, "install", "--upgrade", "pip")
	pipUpgradeCmd.Dir = instance.InstallPath
	pipUpgradeCmd.Run() // Ignore errors

	// Install requirements if exists
	reqPath := filepath.Join(instance.InstallPath, "requirements.txt")
	if _, err := os.Stat(reqPath); err == nil {
		pipInstallCmd := exec.CommandContext(hm.ctx, pipPath, "install", "-r", reqPath)
		pipInstallCmd.Dir = instance.InstallPath
		pipInstallCmd.Stdout = os.Stdout
		pipInstallCmd.Stderr = os.Stderr
		if err := pipInstallCmd.Run(); err != nil {
			return fmt.Errorf("failed to install requirements: %w", err)
		}
	}

	// Create log directory
	logDir := filepath.Join(instance.InstallPath, "logs")
	os.MkdirAll(logDir, 0755)

	return nil
}

// StartHoneypot starts a honeypot instance
func (hm *HoneypotManager) StartHoneypot(honeypotID string) error {
	hm.mu.Lock()
	instance, exists := hm.honeypots[honeypotID]
	hm.mu.Unlock()

	if !exists {
		return fmt.Errorf("honeypot %s not found", honeypotID)
	}

	instance.mu.Lock()
	defer instance.mu.Unlock()

	if instance.Status == protocol.PotStatusRunning {
		return fmt.Errorf("honeypot %s is already running", honeypotID)
	}

	switch instance.Type {
	case "cowrie":
		return hm.startCowrie(instance)
	case "honnypotter":
		return hm.startHonnyPotter(instance)
	default:
		// Try generic Python start
		return hm.startGenericPython(instance)
	}
}

// startGenericPython starts a generic Python-based honeypot
func (hm *HoneypotManager) startGenericPython(instance *HoneypotInstance) error {
	logger.Infof("Starting %s honeypot %s", instance.Type, instance.ID)

	// Determine Python path
	var pythonPath string
	if runtime.GOOS == "windows" {
		pythonPath = filepath.Join(instance.InstallPath, "venv", "Scripts", "python")
	} else {
		pythonPath = filepath.Join(instance.InstallPath, "venv", "bin", "python")
	}

	// Create context for the process
	ctx, cancel := context.WithCancel(hm.ctx)
	instance.cancelFunc = cancel

	// Look for common entry points
	entryPoints := []string{"main.py", "run.py", "server.py", "honeypot.py"}
	var entryPoint string
	for _, ep := range entryPoints {
		epPath := filepath.Join(instance.InstallPath, ep)
		if _, err := os.Stat(epPath); err == nil {
			entryPoint = ep
			break
		}
	}

	if entryPoint == "" {
		cancel()
		return fmt.Errorf("no entry point found for %s", instance.Type)
	}

	cmd := exec.CommandContext(ctx, pythonPath, entryPoint)
	cmd.Dir = instance.InstallPath
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		cancel()
		return fmt.Errorf("failed to start %s: %w", instance.Type, err)
	}

	instance.Process = cmd
	instance.Status = protocol.PotStatusRunning
	hm.sendStatusUpdate(instance, fmt.Sprintf("%s honeypot started", instance.Type))

	// Monitor process
	go func() {
		err := cmd.Wait()
		instance.mu.Lock()
		if instance.Status == protocol.PotStatusRunning {
			if err != nil {
				logger.Errorf("%s process exited with error: %v", instance.Type, err)
				instance.Status = protocol.PotStatusFailed
				hm.sendStatusUpdate(instance, fmt.Sprintf("Process exited: %v", err))
			} else {
				instance.Status = protocol.PotStatusStopped
				hm.sendStatusUpdate(instance, "Process exited normally")
			}
		}
		instance.mu.Unlock()
	}()

	return nil
}

// startCowrie starts the Cowrie honeypot
func (hm *HoneypotManager) startCowrie(instance *HoneypotInstance) error {
	logger.Infof("Starting Cowrie honeypot %s", instance.ID)

	// Determine paths based on OS
	var twistdPath string
	if runtime.GOOS == "windows" {
		twistdPath = filepath.Join(instance.InstallPath, "cowrie-env", "Scripts", "twistd.exe")
	} else {
		twistdPath = filepath.Join(instance.InstallPath, "cowrie-env", "bin", "twistd")
	}

	// Create context for the process
	ctx, cancel := context.WithCancel(hm.ctx)
	instance.cancelFunc = cancel

	// Source path for PYTHONPATH
	srcPath := filepath.Join(instance.InstallPath, "src")

	// Run twistd directly with cowrie plugin
	// Arguments: twistd -n -l - cowrie
	// -n = nodaemon (foreground)
	// -l - = log to stdout
	cmd := exec.CommandContext(ctx, twistdPath, "-n", "-l", "-", "cowrie")
	cmd.Dir = instance.InstallPath
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("PYTHONPATH=%s", srcPath),
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		cancel()
		return fmt.Errorf("failed to start cowrie: %w", err)
	}

	instance.Process = cmd
	instance.Status = protocol.PotStatusRunning
	hm.sendStatusUpdate(instance, "Honeypot started")

	// Monitor process in background
	go func() {
		err := cmd.Wait()
		instance.mu.Lock()
		if instance.Status == protocol.PotStatusRunning {
			if err != nil {
				logger.Errorf("Cowrie process exited with error: %v", err)
				instance.Status = protocol.PotStatusFailed
				hm.sendStatusUpdate(instance, fmt.Sprintf("Process exited: %v", err))
			} else {
				instance.Status = protocol.PotStatusStopped
				hm.sendStatusUpdate(instance, "Process exited normally")
			}
		}
		instance.mu.Unlock()
	}()

	logger.Infof("Cowrie honeypot %s started on SSH:%d, Telnet:%d",
		instance.ID, instance.SSHPort, instance.TelnetPort)

	return nil
}

// startHonnyPotter starts the HonnyPotter WordPress honeypot
func (hm *HoneypotManager) startHonnyPotter(instance *HoneypotInstance) error {
	logger.Infof("Starting HonnyPotter honeypot %s", instance.ID)

	// Determine PHP command
	phpCmd := "php"
	if runtime.GOOS == "windows" {
		phpCmd = "php.exe"
	}

	// Get HTTP port from instance (stored during setup)
	httpPort := uint16(8080) // Default
	if instance.SSHPort != 0 {
		// For HonnyPotter, SSHPort field stores the HTTP port
		httpPort = instance.SSHPort
	}

	// Get pot ID from instance
	potID := instance.ID

	// Entry point - prefer standalone.php, fallback to wp-login.php
	entryPoint := filepath.Join(instance.InstallPath, "standalone.php")
	if _, err := os.Stat(entryPoint); os.IsNotExist(err) {
		entryPoint = filepath.Join(instance.InstallPath, "wp-login.php")
		if _, err := os.Stat(entryPoint); os.IsNotExist(err) {
			return fmt.Errorf("no entry point found for HonnyPotter (checked standalone.php and wp-login.php)")
		}
	}

	// Create context for the process
	ctx, cancel := context.WithCancel(hm.ctx)
	instance.cancelFunc = cancel

	// Set environment variables for HoneyBee integration
	env := os.Environ()
	env = append(env, fmt.Sprintf("HONEYBEE_POT_ID=%s", potID))
	env = append(env, fmt.Sprintf("HONEYBEE_EVENT_PORT=%d", hm.listenerPort))
	env = append(env, fmt.Sprintf("HONEYBEE_HONEYPOT_ID=%s", instance.ID))
	env = append(env, fmt.Sprintf("HONEYBEE_HONEYPOT_TYPE=%s", instance.Type))
	env = append(env, "HONEYBEE_ENABLE=true")
	env = append(env, "HONEYBEE_ENABLE_FILE_LOG=true")
	env = append(env, fmt.Sprintf("HONEYBEE_LOG_FILE=%s", filepath.Join(instance.InstallPath, "logs", "honnypotter.log")))

	// Start PHP built-in server
	// php -S 0.0.0.0:8080 standalone.php
	cmd := exec.CommandContext(ctx, phpCmd, "-S", fmt.Sprintf("0.0.0.0:%d", httpPort), entryPoint)
	cmd.Dir = instance.InstallPath
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		cancel()
		return fmt.Errorf("failed to start HonnyPotter: %w", err)
	}

	instance.Process = cmd
	instance.Status = protocol.PotStatusRunning
	hm.sendStatusUpdate(instance, fmt.Sprintf("HonnyPotter started on port %d", httpPort))

	// Monitor process in background
	go func() {
		err := cmd.Wait()
		instance.mu.Lock()
		if instance.Status == protocol.PotStatusRunning {
			if err != nil {
				logger.Errorf("HonnyPotter process exited with error: %v", err)
				instance.Status = protocol.PotStatusFailed
				hm.sendStatusUpdate(instance, fmt.Sprintf("Process exited: %v", err))
			} else {
				instance.Status = protocol.PotStatusStopped
				hm.sendStatusUpdate(instance, "Process exited normally")
			}
		}
		instance.mu.Unlock()
	}()

	logger.Infof("HonnyPotter honeypot %s started on HTTP:%d", instance.ID, httpPort)
	return nil
}

// StopHoneypot stops a honeypot instance
func (hm *HoneypotManager) StopHoneypot(honeypotID string) error {
	hm.mu.RLock()
	instance, exists := hm.honeypots[honeypotID]
	hm.mu.RUnlock()

	if !exists {
		return fmt.Errorf("honeypot %s not found", honeypotID)
	}

	return hm.stopHoneypot(instance)
}

// stopHoneypot stops a specific honeypot instance
func (hm *HoneypotManager) stopHoneypot(instance *HoneypotInstance) error {
	instance.mu.Lock()
	defer instance.mu.Unlock()

	if instance.Status != protocol.PotStatusRunning {
		return nil
	}

	logger.Infof("Stopping honeypot %s", instance.ID)

	if instance.cancelFunc != nil {
		instance.cancelFunc()
	}

	if instance.Process != nil && instance.Process.Process != nil {
		instance.Process.Process.Kill()
	}

	instance.Status = protocol.PotStatusStopped
	hm.sendStatusUpdate(instance, "Honeypot stopped")

	return nil
}

// GetStatus returns the status of a pot (honeypot)
func (hm *HoneypotManager) GetStatus(potID string) (*protocol.PotStatusUpdate, error) {
	hm.mu.RLock()
	instance, exists := hm.honeypots[potID]
	hm.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("pot %s not found", potID)
	}

	return protocol.NewPotStatusUpdate(hm.nodeID, instance.ID, instance.Type, instance.Status, ""), nil
}

// ListPots returns all pot (honeypot) instances
func (hm *HoneypotManager) ListPots() []*protocol.PotStatusUpdate {
	hm.mu.RLock()
	defer hm.mu.RUnlock()

	var result []*protocol.PotStatusUpdate
	for _, instance := range hm.honeypots {
		result = append(result, protocol.NewPotStatusUpdate(
			hm.nodeID, instance.ID, instance.Type, instance.Status, ""))
	}
	return result
}

// sendStatusUpdate sends a pot status update to the event channel
func (hm *HoneypotManager) sendStatusUpdate(instance *HoneypotInstance, message string) {
	// Create a PotEvent to carry the status update
	msg := fmt.Sprintf("Status: %s - %s", instance.Status, message)
	event := &protocol.PotEvent{
		NodeID:    hm.nodeID,
		PotID:     instance.ID,
		Event:     "honeybee.pot.status",
		Message:   &msg,
		Timestamp: uint64(time.Now().Unix()),
		Metadata: map[string]string{
			"pot_type":    instance.Type,
			"status":      string(instance.Status),
			"ssh_port":    fmt.Sprintf("%d", instance.SSHPort),
			"telnet_port": fmt.Sprintf("%d", instance.TelnetPort),
		},
	}

	select {
	case hm.eventChan <- event:
	default:
		logger.Warn("Event channel full, dropping status update")
	}
}

// startEventListener starts a TCP listener for receiving honeypot events
func (hm *HoneypotManager) startEventListener() error {
	// Find an available port starting from 9100
	var listener net.Listener
	var err error
	for port := 9100; port < 9200; port++ {
		listener, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			hm.listenerPort = port
			break
		}
	}
	if listener == nil {
		return fmt.Errorf("failed to find available port for event listener: %w", err)
	}

	hm.eventListener = listener

	// Start accepting connections
	go hm.acceptConnections()

	return nil
}

// acceptConnections accepts incoming connections from honeypots
func (hm *HoneypotManager) acceptConnections() {
	for {
		conn, err := hm.eventListener.Accept()
		if err != nil {
			select {
			case <-hm.ctx.Done():
				return
			default:
				logger.Errorf("Failed to accept connection: %v", err)
				continue
			}
		}
		go hm.handleConnection(conn)
	}
}

// handleConnection handles a single honeypot connection
func (hm *HoneypotManager) handleConnection(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	for {
		select {
		case <-hm.ctx.Done():
			return
		default:
		}

		line, err := reader.ReadBytes('\n')
		if err != nil {
			return
		}

		// Parse the JSON event from Cowrie
		var rawEvent map[string]interface{}
		if err := json.Unmarshal(line, &rawEvent); err != nil {
			logger.Warnf("Failed to parse honeypot event: %v", err)
			continue
		}

		// Find the pot (honeypot) instance this event belongs to
		potID := hm.findHoneypotForEvent(rawEvent)

		// Create PotEvent
		event := protocol.NewPotEvent(hm.nodeID, potID, rawEvent)

		// Send to event channel
		select {
		case hm.eventChan <- event:
		default:
			logger.Warn("Event channel full, dropping pot event")
		}
	}
}

// findHoneypotForEvent tries to determine which honeypot an event belongs to
func (hm *HoneypotManager) findHoneypotForEvent(event map[string]interface{}) string {
	// Try to get sensor name from event
	if sensor, ok := event["sensor"].(string); ok {
		return sensor
	}

	// Default to first honeypot if only one exists
	hm.mu.RLock()
	defer hm.mu.RUnlock()

	for id := range hm.honeypots {
		return id
	}

	return "unknown"
}

// copyDir recursively copies a directory from src to dst
func copyDir(src, dst string) error {
	// Get source info
	srcInfo, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("failed to stat source: %w", err)
	}

	// Create destination directory
	if err := os.MkdirAll(dst, srcInfo.Mode()); err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}

	// Read directory contents
	entries, err := os.ReadDir(src)
	if err != nil {
		return fmt.Errorf("failed to read source directory: %w", err)
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.IsDir() {
			// Recursively copy subdirectory
			if err := copyDir(srcPath, dstPath); err != nil {
				return err
			}
		} else {
			// Copy file
			if err := copyFile(srcPath, dstPath); err != nil {
				return err
			}
		}
	}

	return nil
}

// copyFile copies a single file from src to dst
func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer srcFile.Close()

	srcInfo, err := srcFile.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat source file: %w", err)
	}

	dstFile, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, srcInfo.Mode())
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer dstFile.Close()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return fmt.Errorf("failed to copy file contents: %w", err)
	}

	return nil
}
