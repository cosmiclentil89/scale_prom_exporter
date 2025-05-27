# Scale Computing Prometheus Exporter

A Prometheus exporter that scrapes node metrics from a [Scale Computing](https://www.scalecomputing.com/) cluster and exposes them for Prometheus to collect.

## 📦 Features

- Gathers node-level metrics such as CPU usage, memory usage, capacity, and virtualization state.
- Supports scraping from clusters with self-signed SSL certificates.
- Configurable via **flags** or **environment variables**.
- Built-in `/metrics` endpoint for Prometheus scraping.
- Optional debug logging.

---

## 🚀 Getting Started

### Prerequisites

- Go 1.22.2+
- Access to a Scale Computing cluster with API enabled
- Prometheus for scraping

---

## 🔧 Configuration

You can configure the exporter via **command-line flags** or **environment variables**.

### Environment Variables

| Variable         | Description                          | Default                      |
|------------------|--------------------------------------|------------------------------|
| `LOG_PATH`       | Path to log file                     | `/var/log/scale-exporter.log` |
| `BIND_IP`        | IP address to bind the exporter      | `localhost`                  |
| `BIND_PORT`      | Port to bind the exporter            | `8066`                       |
| `CLUSTER`        | IP address of the Scale Cluster      | *(required)*                 |
| `USERNAME`       | Username for cluster authentication  | *(required)*                 |
| `PASSWORD`       | Password for cluster authentication  | *(required)*                 |
| `SCRAPEINTERVAL` | Interval in seconds between scrapes  | `15`                         |
| `DEBUG`          | Enable debug logging (`true/false`)  | `false`                      |

### Flags

```text
  -lp, --logpath             string   Log file path
  -ip, --bindIp              string   Exporter bind IP
  -p,  --bindPort            string   Exporter bind port
  -c,  --clusterIp           string   Scale Cluster IP
  -u,  --clusterUsername     string   Cluster username
  -pw, --clusterpassword     string   Cluster password
  -si, --scrapeInterval      int      Scrape interval in seconds (min 10)
  -d,  --debug                        Enable debug logging
  -v                                Print version and exit
  -h, --help                        Show help message
