package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
)

type Config struct {
	Root     string      `json:"folder"`
	Port     int64       `json:"port"`
	Password string      `json:"password"`
	Peers    []PeerEntry `json:"peers"`
}

type PeerEntry struct {
	IP       string `json:"IP"`
	Port     int64  `json:"Port"`
	Password string `json:"password"`
}

func main() {
	cname := ""
	if len(os.Args) < 2 {
		cname = "config.json"
	} else if len(os.Args) == 2 && (os.Args[1] == "help" || os.Args[1] == "--help" || os.Args[1] == "-h") {
		fmt.Printf("Usage: %s <configuration file>\n", os.Args[0])
		os.Exit(0)
	} else {
		cname = os.Args[1]
	}

	// Load config
	config, err := loadConfig(cname)
	if err != nil {
		log.Fatal(err)
	}

	// Validate config file
	// Test root folder for existence
	info, err := os.Stat(config.Root)
	if os.IsNotExist(err) {
		log.Fatalf("The specified folder %s does not exist.", config.Root)
	} else if !info.IsDir() {
		log.Fatalf("The specified folder %s is not a folder.", config.Root)
	}

	// Check IPs
	for i, p := range config.Peers {
		if net.ParseIP(p.IP) == nil {
			log.Fatalf("Invalid IP for peer %d: %s", i, p.IP)
		}
	}

	// Create File Manager
	log.Printf("Folder to synchronize: %s", config.Root)

	// Create Tunnels
	done := make(chan bool)
	for _, p := range config.Peers {
		log.Printf("Found peer config for %s", p.IP)

		t := &Tunnel{
			IP:       p.IP,
			Port:     p.Port,
			Password: p.Password,
			Root:     config.Root,
		}

		if err := t.Setup(); err != nil {
			log.Printf("[%s:%s] Error setting up peer: %s", p.IP, p.Port, err)
			continue
		}

		go t.Start()
	}

	if config.Password != "" {
		server := &Server{
			Port:     config.Port,
			Password: config.Password,
			Root:     config.Root,
		}
		server.Start()
	}

	<-done
}

func loadConfig(path string) (*Config, error) {
	configFile, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer configFile.Close()

	fileContents, err := ioutil.ReadAll(configFile)
	if err != nil {
		return nil, err
	}

	config := &Config{}
	err = json.Unmarshal(fileContents, config)
	if err != nil {
		return nil, err
	}

	return config, nil
}
