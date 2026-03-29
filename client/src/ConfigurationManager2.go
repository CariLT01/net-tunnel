package main

import (
	"encoding/json"
	"log"
	"os"
)

type ClientConfigJson struct {
	VpnServer       *string `json:"vpnServer"`
	HttpScheme      *string `json:"httpScheme"`
	WebsocketScheme *string `json:"websocketScheme"`
}

type ClientConfig struct {
	VpnServer       string
	HttpScheme      string
	WebsocketScheme string
}

type ConfigurationManager struct {
	config *ClientConfig
}

var CONFIG_PATH = "clientConfig.json"

func NewConfig() *ClientConfig {
	return &ClientConfig{
		VpnServer:       "data-router-329.onrender.com",
		HttpScheme:      "https",
		WebsocketScheme: "wss",
	}
}

func NewConfigJson() *ClientConfigJson {
	return &ClientConfigJson{
		VpnServer:       nil,
		HttpScheme:      nil,
		WebsocketScheme: nil,
	}
}

func NewConfigManager() *ConfigurationManager {
	return &ConfigurationManager{
		config: NewConfig(),
	}
}

func (manager *ConfigurationManager) SaveConfig() {
	log.Print("not saving anything")
}

func (manager *ConfigurationManager) LoadConfig() {
	var defaults ClientConfig = *NewConfig()
	var cfg ClientConfigJson = *NewConfigJson()

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

	if cfg.HttpScheme == nil {
		cfg.HttpScheme = &defaults.HttpScheme
	}
	if cfg.VpnServer == nil {
		cfg.VpnServer = &defaults.VpnServer
	}
	if cfg.WebsocketScheme == nil {
		cfg.WebsocketScheme = &defaults.WebsocketScheme
	}

	config := ClientConfig{
		WebsocketScheme: *cfg.WebsocketScheme,
		HttpScheme:      *cfg.HttpScheme,
		VpnServer:       *cfg.VpnServer,
	}

	log.Print("loaded config")
	manager.config = &config
}
