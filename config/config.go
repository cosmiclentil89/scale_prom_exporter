package config

import (
	"log"
	"os"
	"fmt"
	"flag"
)

type Config struct {
	BindIP			string
	BindPort		string
	ScrapeInterval	string
	ClusterIP		string
	Username		string
	Password		string

	// Logging
	LogPath 	string // e.g., "/var/log/core-db-api.log"
	Debug		bool // e.g., true
}

var VERSION = "1.0.0"

func printUsage() {
	fmt.Fprintf(flag.CommandLine.Output(), `
Scale Exporter - Usage

Flags:
  -lp,	--logpath			string	Path for log output				(ENV: LOG_PATH, default: "/var/log/scale-exporter.log")
  -ip,	--bindIp			string	IP address to bind exporter to	(ENV: BIND_IP, default: "localhost")
  -p,	--bindPort			string	Port to bind exporter to		(ENV: BIND_PORT, default: "8066")
  -c,	--clusterIp			string	Scale Cluster IP				(ENV: CLUSTER, default: "")
  -u	--clusterUsername	string	local cluster username			(ENV: USERNAME, default: "")
  -pw	--clusterpassword	string	local cluster password			(ENV: PASSWORD, default: "")
  -si	--scrapeInterval	int		seconds to wait before each 	(ENV: SCRAPEINTERVAL, default: 15)
  									scrape, minimum of 10s
  -d, --debug				bool	prints debug messages			(ENV: DEBUG, default: "FALSE")
  -v								Print version and exit
  -h, --help						Show this help message


Examples:
  Run with flags:
    scale_exporter --logpath=./scale-exporter.log

  Run with environment variables:
    export LOG_PATH="./scale-exporter.log

    scale_exporter
`)
}


func getFlagOrEnv(flagVal, envKey, fallback string) string {
	if flagVal != "" {
		return flagVal
	}
	if val, ok := os.LookupEnv(envKey); ok {
		return val
	}
	return fallback
}

func getBoolFlagOrEnv(flagVal bool, envKey string, fallback bool) bool {
	if flagVal {
		return true
	}
	if val, ok := os.LookupEnv(envKey); ok {
		return val == "true" || val == "1" || val == "TRUE"
	}
	return fallback
}

func LoadConfig() *Config {

	var version = flag.Bool("v", false, "Prints out the IPsec-Restarter version")
	var logPath = flag.String("lp", "", "log path for output")
	var bindIp = flag.String("ip", "", "IP address to bind exporter to")
	var bindPort = flag.String("p", "", "port to bind exporter to")
	var clusterIp = flag.String("c", "", "IP Address of Scale Cluster")
	var clusterUsername = flag.String("u", "", "Username for Scale Cluster")
	var clusterPassword = flag.String("pw", "", "Password for Scale Cluster")
	var scrapeInterval = flag.String("si","","Scrape interval in seconds")
	var debug = flag.Bool("d",false,"Debug output")


	flag.Usage = printUsage

	flag.Parse()

	if *version {
		fmt.Print("Package Version: ", VERSION)
		os.Exit(0)
	}

	cfg := &Config{
		BindIP:		getFlagOrEnv(*bindIp, "BIND_IP", "localhost"),
		BindPort:	getFlagOrEnv(*bindPort, "BIND_PORT", "8066"),
		LogPath:	getFlagOrEnv(*logPath, "LOG_PATH", "/var/log/scale-exporter.log"),
		ClusterIP: 	getFlagOrEnv(*clusterIp, "CLUSTER", ""),
		Username: 	getFlagOrEnv(*clusterUsername, "USERNAME", ""),
		Password: 	getFlagOrEnv(*clusterPassword, "PASSWORD", ""),
		ScrapeInterval: getFlagOrEnv(*scrapeInterval, "SCRAPEINTERVAL", "15"),
		Debug:		getBoolFlagOrEnv(*debug, "DEBUG", false),	
	}

	if cfg.LogPath =="" {
		log.Fatalln("No Log file set.")
	}

	if cfg.ClusterIP == "" {
		printUsage()
		log.Fatalln("No cluster IP Set. Please set one to start.")	
	}

	if cfg.Username == "" {
		printUsage()
		log.Fatalln("No Cluster username set. Please set one to start.")	
	}

	if cfg.Password == "" {
		printUsage()
		log.Fatalln("No Cluster password set. Please set one to start.")	
	}

	return cfg
}