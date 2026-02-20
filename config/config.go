package config

import (
	"encoding/json"
	"io/ioutil"

	log "github.com/gophish/gophish/logger"
)

// AdminServer represents the Admin server configuration details
type AdminServer struct {
	ListenURL            string   `json:"listen_url"`
	UseTLS               bool     `json:"use_tls"`
	CertPath             string   `json:"cert_path"`
	KeyPath              string   `json:"key_path"`
	CSRFKey              string   `json:"csrf_key"`
	AllowedInternalHosts []string `json:"allowed_internal_hosts"`
	TrustedOrigins       []string `json:"trusted_origins"`
}

// PhishServer represents the Phish server configuration details
type PhishServer struct {
	ListenURL   string            `json:"listen_url"`
	UseTLS      bool              `json:"use_tls"`
	CertPath    string            `json:"cert_path"`
	KeyPath     string            `json:"key_path"`
	IPBlacklist []BlacklistEntry  `json:"ip_blacklist"`
	// Evasion settings
	ServerName           string `json:"server_name,omitempty"`
	XMailer              string `json:"x_mailer,omitempty"`
	EnableContactHeader  bool   `json:"enable_contact_header,omitempty"`
	EnableServerHeader   bool   `json:"enable_server_header,omitempty"`
}

// BlacklistEntry represents a single IP blacklist entry
type BlacklistEntry struct {
	IPRange     string `json:"ip_range"`
	Action      string `json:"action"`
	RedirectURL string `json:"redirect_url,omitempty"`
	FakePage    string `json:"fake_page,omitempty"`
}

// Config represents the configuration information.
type Config struct {
	AdminConf      AdminServer `json:"admin_server"`
	PhishConf      PhishServer `json:"phish_server"`
	DBName         string      `json:"db_name"`
	DBPath         string      `json:"db_path"`
	DBSSLCaPath    string      `json:"db_sslca_path"`
	MigrationsPath string      `json:"migrations_prefix"`
	TestFlag       bool        `json:"test_flag"`
	ContactAddress string      `json:"contact_address"`
	Logging        *log.Config `json:"logging"`
}

// Version contains the current gophish version
var Version = ""

// DefaultServerName is the default server identifier used when not configured
const DefaultServerName = "nginx"

// DefaultXMailer is the default X-Mailer header value
const DefaultXMailer = "Mozilla/5.0"

// LoadConfig loads the configuration from the specified filepath
func LoadConfig(filepath string) (*Config, error) {
	// Get the config file
	configFile, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	config := &Config{}
	err = json.Unmarshal(configFile, config)
	if err != nil {
		return nil, err
	}
	if config.Logging == nil {
		config.Logging = &log.Config{}
	}
	// Set evasion defaults if not configured
	if config.PhishConf.ServerName == "" {
		config.PhishConf.ServerName = DefaultServerName
	}
	if config.PhishConf.XMailer == "" {
		config.PhishConf.XMailer = DefaultXMailer
	}
	// Choosing the migrations directory based on the database used.
	config.MigrationsPath = config.MigrationsPath + config.DBName
	// Explicitly set the TestFlag to false to prevent config.json overrides
	config.TestFlag = false
	return config, nil
}
