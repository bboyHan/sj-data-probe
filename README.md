# DataProbe (神机数探)

Universal Data Collector Engine — 万能数据采集引擎。

## Overview

DataProbe is a kernel-level data interception and extraction engine. It captures network traffic at multiple protocol layers, decrypts TLS where configured, and extracts structured data using hot-reloadable JSON rules.

### Architecture

```
┌──────────────────────────────────────────────────────┐
│  DataProbe Engine (.NET 8 Console / Windows Service)   │
│                                                        │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐    │
│  │ WinDivert│  │DnsSpoof  │  │ TlsProxy          │    │
│  │ Channel  │  │Channel   │  │ (SChannel MITM)   │    │
│  └────┬─────┘  └────┬─────┘  └────────┬─────────┘    │
│       │             │                  │               │
│       └─────────────┴──────────────────┘               │
│                        │                               │
│                 ┌──────▼──────┐                        │
│                 │  RuleEngine  │   (JSON rules)        │
│                 └──────┬──────┘                        │
│                        │                               │
│                 ┌──────▼──────┐                        │
│                 │ Credential  │                        │
│                 │ Queue       │──→ HTTP Backend        │
│                 └─────────────┘                        │
│                                                        │
│  REST API :18801  │  Swagger UI: /api/docs             │
└────────────────────────────────────────────────────────┘
```

### Components

| Project | Description |
|---------|-------------|
| **DataProbe.Core** | Shared types: config, credential model, channel interface, queue, traffic buffer |
| **DataProbe.Capture** | Capture channels: WinDivert kernel driver, DNS spoofing, packet filtering |
| **DataProbe.Tls** | TLS proxy: SChannel-based MITM with dynamic certificate generation |
| **DataProbe.Http** | HTTP/1.1 and HTTP/2 protocol parsers |
| **DataProbe.Extractor** | Rule engine: pattern matching and data extraction from parsed traffic |
| **DataProbe.Api** | ASP.NET host: REST API, Swagger docs, web dashboard, Windows Service |

### Quick Start

```bash
# Build
dotnet build

# Run (development)
dotnet run --project src/DataProbe.Api

# Run with target domains
dotnet run --project src/DataProbe.Api -- --target-domains "example.com,api.example.com"

# API
curl http://localhost:18801/status
curl http://localhost:18801/api/docs    # Swagger UI
```

### Capture Channels

Each channel implements `ICaptureChannel` and can be independently registered:

- **WinDivertChannel**: Kernel-level TCP SYN interception. Diverts outbound TCP/443 traffic to the TLS proxy.
- **DnsSpoofChannel**: DNS response spoofing. Redirects target domain DNS responses to localhost.
- **TlsProxyChannel**: TLS man-in-the-middle. Decrypts, extracts, and forwards selectively.

### Extraction Rules

Rules are JSON files in the `platforms/` directory, loaded at startup and hot-reloaded on change:

```json
{
  "name": "example_rule",
  "priority": 100,
  "matchers": [
    {"field": "domain", "operator": "contains", "value": "example.com"},
    {"field": "path", "operator": "regex", "value": "/api/data"}
  ],
  "extractors": [
    {"name": "target_value", "source": "response_body",
     "pattern": "\"key\":\"([^\"]+)\"", "output_field": "value", "data_type": "url"}
  ]
}
```

### License

MIT
