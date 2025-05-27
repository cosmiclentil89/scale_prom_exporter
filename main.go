package main

import (
	"crypto/tls"
	"encoding/json"
	"log"
	"net/http"
	"time"
	"encoding/base64"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/cosmiclentil89/scale_prom_exporter/config"
	"github.com/cosmiclentil89/scale_prom_exporter/utils/logger"

)

type Node struct {
	UUID                string  `json:"uuid"`
	LanIP               string  `json:"lanIP"`
	Capacity            int64   `json:"capacity"`
	MemUsagePercentage  float64 `json:"memUsagePercentage"`
	TotalMemUsageBytes  int64   `json:"totalMemUsageBytes"`
	SystemMemUsageBytes int64   `json:"systemMemUsageBytes"`
	CPUUsage            float64 `json:"cpuUsage"`
	NumCPUs             int     `json:"numCPUs"`
	CPUhz               int64   `json:"CPUhz"`
	NumCores            int     `json:"numCores"`
	NumThreads          int     `json:"numThreads"`
	NetworkStatus       string  `json:"networkStatus"`
	VirtualizationOnline bool   `json:"virtualizationOnline"`
	AllowRunningVMs     bool    `json:"allowRunningVMs"`
}

// Prometheus metrics
var (
	cpuUsage = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "scale_node_cpu_usage_percent", Help: "CPU usage %"}, []string{"node"},
	)
	memUsage = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "scale_node_mem_usage_percent", Help: "Memory usage %"}, []string{"node"},
	)
	totalMem = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "scale_node_total_mem_usage_bytes", Help: "Total memory usage in bytes"}, []string{"node"},
	)
	systemMem = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "scale_node_system_mem_usage_bytes", Help: "System memory usage in bytes"}, []string{"node"},
	)
	capacity = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "scale_node_capacity_bytes", Help: "Storage capacity in bytes"}, []string{"node"},
	)
	virtualization = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "scale_node_virtualization_online", Help: "Virtualization ready (1=true)"}, []string{"node"},
	)
	allowVMs = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "scale_node_allow_running_vms", Help: "Allow VMs (1=true)"}, []string{"node"},
	)
	netStatus = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "scale_node_network_status", Help: "Network status (ONLINE=1, OFFLINE=0, UNKNOWN=-1)"}, []string{"node"},
	)
)

func networkStatusToValue(status string) float64 {
	switch status {
	case "ONLINE":
		return 1
	case "OFFLINE":
		return 0
	default:
		return -1
	}
}

func boolToFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func fetchAndExportMetrics(apiURL string, username string,password string, allowInsecure bool) {

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			// Disable TLS verification for self-signed certs
			TLSClientConfig: &tls.Config{InsecureSkipVerify: allowInsecure},
		},
	}

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		logger.Log.Errorln("Request error:", err)
		return
	}

	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	req.Header.Add("Authorization", "Basic "+auth)
	req.Header.Add("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		logger.Log.Errorln("Request failed:", err)
		return
	}
	defer resp.Body.Close()

	var nodes []Node
	if err := json.NewDecoder(resp.Body).Decode(&nodes); err != nil {
		logger.Log.Errorln("Decode error:", err)
		return
	}

	for _, node := range nodes {
		labels := prometheus.Labels{"node": node.LanIP}
		cpuUsage.With(labels).Set(node.CPUUsage)
		memUsage.With(labels).Set(node.MemUsagePercentage)
		totalMem.With(labels).Set(float64(node.TotalMemUsageBytes))
		systemMem.With(labels).Set(float64(node.SystemMemUsageBytes))
		capacity.With(labels).Set(float64(node.Capacity))
		virtualization.With(labels).Set(boolToFloat(node.VirtualizationOnline))
		allowVMs.With(labels).Set(boolToFloat(node.AllowRunningVMs))
		netStatus.With(labels).Set(networkStatusToValue(node.NetworkStatus))
	}
}

func main() {

	// Load Config
	cfg := config.LoadConfig()

	// Start Logging
	logFile :=logger.Start(cfg.LogPath,cfg.Debug)

	defer logFile.Close()

	logger.Log.Infoln("Starting Scale Exporter.")

	logger.Log.Debugln("Loaded Config: ", cfg)

	// Register metrics
	prometheus.MustRegister(cpuUsage, memUsage, totalMem, systemMem, capacity, virtualization, allowVMs, netStatus)

	apiURL := "https://"+cfg.ClusterIP + "/rest/v1/Node"
	allowInsecure := true

	go func() {
		for {
			fetchAndExportMetrics(apiURL,cfg.Username,cfg.Password, allowInsecure)
			time.Sleep(15 * time.Second)
		}
	}()
	
	bindStr := cfg.BindIP+":"+cfg.BindPort

	http.Handle("/metrics", promhttp.Handler())
	logger.Log.Infoln("Exporter running on: " + bindStr)
	log.Fatal(http.ListenAndServe(bindStr, nil))
}
