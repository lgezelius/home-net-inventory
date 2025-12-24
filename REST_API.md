# REST API

The **home-net-inventory** REST API provides programmatic access to discovered network devices and scan operations/status.
It is intended for local or trusted-network use.

All responses are JSON unless otherwise noted.

---

## Base URL

```text
http://<host>:<port>
```

Example:

```text
http://localhost:8000
```

---

## Authentication

Currently, the API does **not** implement authentication.
Access should be restricted at the network or reverse-proxy level.

---

## Common Response Codes

| Status | Meaning |
|------|--------|
| 200 | Success |
| 400 | Bad request |
| 404 | Resource not found |
| 500 | Server error |

---

## Devices

### List Devices

Returns all known devices in the inventory.

Endpoint:

```http
GET /devices
```

Example request:

```http
GET /devices
```

Response:

```json
[
  {
    "id": 1,
    "hostname": "macbook-pro",
    "ip_address": "192.168.1.20",
    "mac_address": "AA:BB:CC:DD:EE:FF",
    "vendor": "Apple",
    "device_type": "computer",
    "first_seen": "2025-12-20T18:22:11Z",
    "last_seen": "2025-12-23T21:10:03Z"
  }
]
```

---

### Get Device by ID

Returns details for a single device.

Endpoint:

```http
GET /devices/{device_id}
```

Example request:

```http
GET /devices/1
```

Response:

```json
{
  "id": 54,
  "mac": "34:98:B5:AA:BB:CC",
  "vendor": "Netgear",
  "display_name": null,
  "first_seen": "2025-12-24 05:53:50",
  "last_seen": "2025-12-24 05:53:50",
  "observations": [
    {
      "seen_at": "2025-12-24 06:30:56",
      "ip": "192.168.1.249",
      "hostname": "RBS750P-B1CC.lan"
    },
    {
      "seen_at": "2025-12-24 05:53:50",
      "ip": "192.168.1.249",
      "hostname": "RBS750P-B1CC.lan"
    }
  ]
}
```

---

## Scan

### Start Scan

Initiates a new network scan.

Endpoint:

```http
GET /scan
```

Example request:

```http
GET /scan
```

Response:

```json
{
  "status": "started"
}
```

---

### Scan Status

Returns the current status of the network scan.

Endpoint:

```http
GET /scan/status
```

Example request:

```http
GET /scan/status
```

Response:

```json
{
  "status": "idle"
}
```

*Note: Exact fields may vary; consult `/openapi.json` for the canonical schema.*

---

## Notes

- Endpoint paths and fields may evolve as the project matures.
- The API is optimized for automation and integration with Home Assistant, Prometheus exporters, or custom dashboards.
