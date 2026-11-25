# Telemetry collector

Receives the anonymous reports of `xdp-loader` (see
[Telemetry](../README.md#telemetry) and `loader/telemetry.rs`) and publishes
the totals. Go, standard library only.

```bash
go test ./...
go build -o collector .
./collector -listen 127.0.0.1:8099 -state /var/lib/xdp-collector/state.json
```

| Endpoint | |
|---|---|
| `POST /v1/report` | one report, JSON, at most 4 KiB; unknown fields and implausible values are rejected, one report per id and minute |
| `GET /v1/summary` | servers seen within the last 65 minutes, their players, packets dropped today and in total, versions, protections, XDP modes, architectures, kernels |
| `GET /v1/badge/servers`, `/v1/badge/players` | [shields.io endpoint](https://shields.io/badges/endpoint-badge) badges |

What it keeps: the latest report of each installation id (forgotten after 30
days of silence) and the packet totals per day (for a year). It never stores
or logs the address a report came from. It speaks plain HTTP and is meant to
run behind a reverse proxy that terminates TLS.
