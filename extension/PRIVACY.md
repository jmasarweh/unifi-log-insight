# Privacy Policy — UniFi Insights Plus Browser Extension

**Last updated:** 2026-03-12

## Overview

UniFi Insights Plus is a browser extension that enriches your UniFi Network Controller with threat intelligence, GeoIP data, and an embedded Log Insight dashboard. It is a companion to the self-hosted [UniFi Log Insight](https://github.com/jmasarweh/unifi-log-insight) server.

## Data Collection

**This extension does not collect, transmit, or store any personal data.** There is no analytics, telemetry, tracking, or third-party data sharing of any kind.

## Data Flow

All communication is strictly between your browser and two user-specified servers:

1. **Your UniFi Controller** — The extension injects enrichment badges and an embedded dashboard tab into your UniFi Network Controller pages. It reads IP addresses displayed on-screen to look up threat data. No data is sent to any external service.

2. **Your Log Insight Server** — The extension communicates with your self-hosted Log Insight instance (which you configure during setup) to fetch threat intelligence, GeoIP, and log data. This server runs on your own infrastructure.

The extension never contacts any server other than the two URLs you explicitly configure.

## Permissions

| Permission | Purpose |
|---|---|
| `storage` | Save your settings (Log Insight server URL, UniFi controller URL, feature toggles) locally in your browser. Settings sync across your devices via your browser's built-in sync. |
| `scripting` | Inject content scripts into your UniFi Controller pages to display threat badges, enrichment panels, and the embedded Log Insight tab. |
| `optional host access` | Declared as `*://*/*` in the manifest to support any UniFi controller address (IP, hostname, or domain). **Access is never granted automatically.** You are prompted to grant access to your specific controller URL only — the extension never accesses any other site. |

## Local Storage

The extension stores the following data locally in your browser:

- Log Insight server URL
- UniFi controller URL
- Feature toggle states (tab injection, flow enrichment)
- Cached UI theme preference
- Cached health check data (server version, log count)

No credentials, passwords, API keys, or authentication tokens are stored by the extension.

## Third-Party Services

This extension does not communicate with any third-party service. All threat intelligence, GeoIP lookups, and log queries are handled by your self-hosted Log Insight server.

## Open Source

The extension source code is publicly available at [github.com/jmasarweh/unifi-log-insight](https://github.com/jmasarweh/unifi-log-insight) under the Business Source License 1.1.

## Full Privacy Policy

For the complete and up-to-date privacy policy, visit [insightsplus.dev/privacy](https://insightsplus.dev/privacy).

## Changes

If this privacy policy is updated, the changes will be reflected on our website and this document's "Last updated" date.

## Contact

For questions about this privacy policy, email [hello@insightsplus.dev](mailto:hello@insightsplus.dev), open an issue at [github.com/jmasarweh/unifi-log-insight/issues](https://github.com/jmasarweh/unifi-log-insight/issues), or visit [insightsplus.dev](https://insightsplus.dev).
