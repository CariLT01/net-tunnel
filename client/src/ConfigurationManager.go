package main

import (
	"encoding/json"
	"log"
	"os"
)

type ClientConfig struct {
	VpnServer       string `json:"vpnServer"`
	HttpScheme      string `json:"httpScheme"`
	WebsocketScheme string `json:"websocketScheme"`
}

type ConfigurationManager struct {
	config *ClientConfig
}

var CONFIG_PATH = "clientConfig.json"

func NewConfig() *ClientConfig {
	return &ClientConfig{
		VpnServer:       "net-tunnel.onrender.com",
		HttpScheme:      "https",
		WebsocketScheme: "wss",
	}
}

func NewConfigManager() *ConfigurationManager {
	return &ConfigurationManager{
		config: NewConfig(),
	}
}

func (manager *ConfigurationManager) SaveConfig() {
	data, err := json.MarshalIndent(manager.config, "", "  ")
	if err != nil {
		log.Print("error: failed to save config: failed to serialize to json: ", err)
		return
	}
	err = os.WriteFile(CONFIG_PATH, data, 0644)
	if err != nil {
		log.Print("error: failed to save config: failed to write file: ", err)
	}
}

func (manager *ConfigurationManager) LoadConfig() {
	var cfg ClientConfig = *NewConfig()

	data, err := os.ReadFile(CONFIG_PATH)
	if err != nil {
		log.Print("error: failed to load config: failed to open file: ", err)
		return
	}

	err = json.Unmarshal(data, &cfg)
	if err != nil {
		log.Print("error: failed to load config: failed to decode json: ", err)
		return
	}

	log.Print("loaded config")
	manager.config = &cfg
}
