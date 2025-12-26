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
| 409 | Conflict (e.g., scan already running) |
| 500 | Server error |

---

## Devices

### List Devices

Returns recent devices (sorted by `last_seen` desc). Use the optional `limit` query param (default 200).

- `device_name`: model-like identity (often from mDNS TXT `md` or derived best name)
- `friendly_name`: user-facing name (often from mDNS TXT `fn`)

Endpoint:

```http
GET /devices?limit=200
```

Response:

```json
[
  {
    "id": 42,
    "mac": "AA:BB:CC:DD:EE:FF",
    "vendor": "Apple",
    "device_name": "Apple TV 4K",
    "friendly_name": "Living Room Apple TV",
    "display_name": "Living Room Apple TV",
    "mdns_name": "Apple TV",
    "mdns_service_types": ["_airplay._tcp.local."],
    "mdns_instances": ["Apple-TV-1234._airplay._tcp.local."],
    "mdns_txt": {"model": "AppleTV6,2"},
    "first_seen": "2025-12-23T21:10:03+00:00",
    "last_seen": "2025-12-24T05:53:50+00:00",
    "last_ip": "192.168.1.20",
    "last_hostname": "apple-tv.lan"
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
GET /devices/42
```

Response:

```json
{
  "id": 42,
  "mac": "AA:BB:CC:DD:EE:FF",
  "vendor": "Apple",
  "device_name": "Apple TV 4K",
  "friendly_name": "Living Room Apple TV",
  "display_name": "Living Room Apple TV",
  "mdns_name": "Apple TV",
  "mdns_service_types": ["_airplay._tcp.local."],
  "mdns_instances": ["Apple-TV-1234._airplay._tcp.local."],
  "mdns_txt": {"model": "AppleTV6,2"},
  "first_seen": "2025-12-23T21:10:03+00:00",
  "last_seen": "2025-12-24T05:53:50+00:00",
  "observations": [
    {
      "seen_at": "2025-12-24T06:30:56+00:00",
      "ip": "192.168.1.20",
      "hostname": "apple-tv.lan"
    },
    {
      "seen_at": "2025-12-24T05:53:50+00:00",
      "ip": "192.168.1.20",
      "hostname": "apple-tv.lan"
    }
  ]
}
```

---

## Scan

### Start Scan

Initiates a new network scan. In normal operation the background scanner runs on an interval; use this endpoint for ad‑hoc runs.

Endpoint:

```http
POST /scan
```

Query parameters:

- `sync` (bool, default `false`): when `true`, run in the request thread. Disallowed if the background scanner is enabled.

Responses:

- `200` `{ "ok": true, "mode": "async" }` (or `"sync"` when `sync=1`)
- `409` `{ "detail": "Scan already running" }` if a scan is in progress

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
  "running": false,
  "last_started": "2025-12-24T05:53:50+00:00",
  "last_finished": "2025-12-24T05:54:02+00:00",
  "last_error": null,
  "macless_hosts": [
    {
      "ip": "192.168.1.50",
      "hostname": "nomac.lan",
      "vendor": "Acme",
      "mdns_name": null
    }
  ]
}
```

---

## Notes

- Endpoint paths and fields may evolve as the project matures.
- The API is optimized for automation and integration with Home Assistant, Prometheus exporters, or custom dashboards.
