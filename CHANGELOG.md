# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-25

First version confirmed working against a hardware device.

### Added
- LLDP switch impersonation: on the first LLDP PDU from the target, send a
  derived LLDP packet to trigger an IS-IS Hello (Auto-sense).
- Single-sniffer state machine capturing both LLDP and IS-IS in one thread,
  avoiding the race between sending the LLDP and catching the reply.
- IS-IS authentication key brute-force over a dictionary, using the RFC 5310
  HMAC-SHA256 construction (key preparation + both SHA-256 passes via the
  stdlib `hmac` module).
- Simple CLI: `auto-sense-abuse <network interface> <dictionary>`.
- Packet derivation helpers for MAC, IP, Fabric Attach payload and system-id.

### Known limitations
- SHA-256 authentication only; MD5 and no-auth are not yet handled.
- Forming the IS-IS adjacency from a virtual VOSS switch is out of scope.

[0.1.0]: https://github.com/yjosier/Auto-sense-abuse/releases/tag/v0.1.0
