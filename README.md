
<div align="center">

# τensorprox SN91 | Bittensor


[![License: CC BY-NC 4.0](https://img.shields.io/badge/License-CC%20BY--NC%204.0-orange.svg)](https://creativecommons.org/licenses/by-nc/4.0/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Bittensor](https://img.shields.io/badge/Bittensor-Subnet%2091-green.svg)](https://bittensor.com)

<br/>

## The Incentivized DDoS Scrubbing Center <!-- omit in toc -->

[Discord](https://discord.gg/kaUT68P336) • [Taostats](https://taostats.io/subnets/91) • [Linkedin](https://www.linkedin.com/company/shugo-io/) • [Twitter](https://x.com/shugoio)


τensorprox is a Bittensor subnet (netuid=91) that provides decentralized DDoS protection through a network of incentivized scrubbers. Miners deploy eBPF/XDP-based traffic filtering infrastructure, while validators continuously audit their performance and set on-chain weights to distribute ALPHA rewards.

<br/>

## How to start ?

**[Run A Validator Node](./assets/validator.md)** · **[Run A Miner Node](./assets/miner.md)**

</div>

<br/>

## Table of Contents

- [Overview](#overview)
- [Product Architecture](#product-architecture)
- [Traffic Flow](#traffic-flow)
- [Assignment Strategy](#assignment-strategy)
- [Audit System](#audit-system)
- [Reward Mechanism](#reward-mechanism)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

### What is τensorprox?

τensorprox creates a decentralized marketplace for DDoS protection services. The network consists of:

| Actor | Role | Incentive |
|-------|------|-----------|
| **Miners** | Deploy and operate scrubber infrastructure | Earn ALPHA based on audit performance |
| **Validators** | Audit miner performance and set weights | Earn ALPHA through validation rewards |
| **Origins** | Protected servers receiving clean traffic | Pay for protection through the marketplace |

### Key Features

- **8-Layer XDP Defense**: Kernel-level packet filtering with sub-microsecond latency
- **High Availability**: Active + standby scrubber model with automatic failover
- **Real Traffic Validation**: Validators verify actual packet filtering, not self-reported metrics
- **Audit-Based Rewards**: Miners earn exclusively from audit EMA scores, ensuring validator consensus
- **Cloud Infrastructure**: Deploy scrubbers on AWS (additional providers planned)
- **Region-Aware Assignment**: Origins are assigned to geographically proximate miners

---

## Product Architecture

τensorprox operates as a complete DDoS protection platform with decentralized infrastructure.

```
       ┌─────────────────────────────────────────────────────────────────────────────┐
       │                           TENSORPROX WEB APPLICATION                        │
       │                                                                             │
       │  • Origin onboarding and management                                         │
       │  • Real-time traffic dashboard                                              │
       │  • Billing and bandwidth tracking                                           │
       │  • Attack analytics and reporting                                           │
       └────────────────────────────────┬────────────────────────────────────────────┘
                                        │
                           Stack-Based Load Balancing
                           (Heartbeat-driven TPM selection)
                                        │
                ┌───────────────────────┼───────────────────────┐
                │                       │                       │
                ▼                       ▼                       ▼
       ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
       │   TPM-Lite 1    │    │   TPM-Lite 2    │    │   TPM-Lite N    │
       │  (Validator 1)  │    │  (Validator 2)  │    │  (Validator N)  │
       │                 │    │                 │    │                 │
       │ • Assignment    │    │ • Assignment    │    │ • Assignment    │
       │   Engine        │    │   Engine        │    │   Engine        │
       │ • Exit Hub Mgmt │    │ • Exit Hub Mgmt │    │ • Exit Hub Mgmt │
       │ • Audit System  │    │ • Audit System  │    │ • Audit System  │
       └────────┬────────┘    └────────┬────────┘    └────────┬────────┘
                │                      │                      │
                └──────────────────────┼──────────────────────┘
                                       │
                         ┌─────────────┼─────────────┐
                         │             │             │
                         ▼             ▼             ▼
                  ┌───────────┐ ┌───────────┐ ┌───────────┐
                  │  Miner 1  │ │  Miner 2  │ │  Miner N  │
                  │ (Shard)   │ │ (Shard)   │ │ (Shard)   │
                  │           │ │           │ │           │
                  │ Scrubber  │ │ Scrubber  │ │ Scrubber  │
                  │ (Active)  │ │ (Active)  │ │ (Active)  │
                  │ Scrubber  │ │ Scrubber  │ │ Scrubber  │
                  │ (Standby) │ │ (Standby) │ │ (Standby) │
                  └─────┬─────┘ └─────┬─────┘ └─────┬─────┘
                        │             │             │
                        └─────────────┼─────────────┘
                                      │
                           [WireGuard Tunnels]
                                      │
                                      ▼
                           ┌───────────────────┐
                           │     Exit Hubs     │
                           │ (Reverse Proxies) │
                           └─────────┬─────────┘
                                     │
                                     ▼
                           ┌───────────────────┐
                           │ Protected Origins │
                           └───────────────────┘
```

### Components

#### TensorProx Web Application

The web application serves as the customer-facing interface:

- **Origin Management**: Onboard new origins, configure protection settings
- **Real-time Dashboard**: Live traffic metrics, attack detection alerts
- **Billing Integration**: Usage-based billing tied to bandwidth consumption
- **Stack-Based Load Balancing**: Distributes API requests across available TPM instances

#### TPM-Lite (τensorprox Manager)

Each validator runs an embedded TPM-Lite instance that:

- **Assignment Engine**: Matches origins to miners based on EMA scores and region proximity
- **Exit Hub Lifecycle**: Deploys, monitors, and recycles exit hub instances
- **Audit Coordination**: Manages continuous audit cycles across all miners
- **Metrics Aggregation**: Collects bandwidth and volume data from scrubbers
- **Web App Sync**: Pushes state updates via heartbeats, receives SSE notifications

#### Miner Shards

Each miner operates a "shard" consisting of:

- **Active Scrubber**: Handles live traffic with XDP-based filtering
- **Standby Scrubber**: Hot standby for automatic failover
- **Miner Control Plane**: 90+ REST API endpoints for infrastructure management
- **WireGuard Tunnels**: Encrypted connections to exit hubs and validators

#### Scrubber XDP Program

8-layer defense at the NIC level:

| Layer | Function |
|-------|----------|
| 1 | Global blacklist/whitelist |
| 2 | Per-origin reputation control |
| 3 | Bogon and invalid IP filtering |
| 4 | Rate limiting (PPS, CPS, BPS) |
| 5 | SYN cookies and quarantine |
| 6 | TCP flag anomaly detection |
| 7 | Application layer protection |
| 8 | Challenge-based verification |

#### Exit Hubs

Exit hubs act as reverse proxies between scrubbers and protected origins:

- Deployed by validators on AWS
- Terminate WireGuard tunnels from scrubbers
- Forward clean traffic to origin servers
- Report bandwidth usage for billing

---

## Traffic Flow

### Production Traffic Path

```
Internet Traffic → Scrubber (XDP Filter) → WireGuard Tunnel → Exit Hub → Origin Server
```

1. **Incoming Traffic**: All traffic destined for a protected origin is routed to the assigned scrubber
2. **XDP Filtering**: The eBPF/XDP program inspects packets at line rate, dropping malicious traffic
3. **Clean Traffic**: Legitimate packets traverse the WireGuard tunnel to the exit hub
4. **Origin Delivery**: Exit hub forwards clean traffic to the protected origin server

### Audit Traffic Path

```
Validator → WireGuard Tunnel → Scrubber → XDP Stats → Validator
```

1. **Test Generation**: Validator creates synthetic attack and benign packets
2. **Tunnel Delivery**: Packets sent through dedicated audit WireGuard tunnel
3. **XDP Processing**: Scrubber processes packets, updating counters
4. **Stats Query**: Validator retrieves XDP counter deltas via miner API
5. **Score Calculation**: Validator computes accuracy from expected vs actual blocking

---

## Assignment Strategy

The assignment engine determines which miners protect which origins.

### Eligibility Requirements

| Criteria | Threshold | Purpose |
|----------|-----------|---------|
| EMA Score | ≥ 0.8 | Minimum audit performance to receive origins |
| Shard Status | Ready | Active scrubber must be healthy |
| Capacity | Available | Shard must have room for additional origins |

### Assignment Process

1. **Candidate Ranking**: Eligible miners ranked by EMA score (highest first)
2. **Region Matching**: Origins matched to miners within 1000km when possible
3. **Load Balancing**: Origins distributed across miners to balance load
4. **Exit Hub Deployment**: Validator deploys exit hub for the origin-miner pairing
5. **Tunnel Setup**: WireGuard tunnels established between scrubber and exit hub

### EMA Score Calculation

```
new_ema = 0.2 × latest_audit_score + 0.8 × previous_ema
```

- **Alpha = 0.2**: Recent audits weighted 20%, history weighted 80%
- **Effective Window**: ~9 audits of historical influence
- **Smoothing Effect**: Single bad audit doesn't destroy ranking; sustained poor performance does

---

## Audit System

### Continuous Auditing

Validators run audits continuously with a 30-second cooldown between cycles:

1. **Packet Generation**: Attack + benign packets per audit (dynamic ratio between 3:1 and 10:1, randomized each round)
2. **Miner Notification**: Audit start signal sent to miner
3. **Multi-Wave Traffic Injection**: Traffic spread over ~60 seconds through WireGuard tunnel. Burst waves (3-5 per audit, randomized) trigger rate limiters at max speed, interleaved with paced regular traffic to test sustained filtering and rate limiter recovery
4. **Stats Collection**: XDP counter deltas queried from miner
5. **Score Computation**: Accuracy calculated from expected vs reported blocking

### Attack Categories Tested

#### Layer 3 (IP) Attacks
| Attack Type | Detection Method |
|-------------|------------------|
| Bogon Source IPs | RFC 1918 private, loopback, link-local, multicast |
| Blacklisted IPs | LPM trie lookup against known malicious prefixes |
| Land Attack | Source IP == Destination IP |
| Malformed IP | IHL < 5, version != 4, TTL == 0 |
| Fragmentation | Tiny fragments, overlapping offsets |

#### Layer 4 (TCP) Attacks
| Attack Type | Detection Method |
|-------------|------------------|
| TCP XMAS | All flags set (FIN+PSH+URG) |
| TCP NULL | No flags set |
| TCP SYN+FIN | Invalid flag combination |
| SYN Flood | Global rate limit on SYN packets |

#### Layer 4 (UDP) Attacks
| Attack Type | Detection Method |
|-------------|------------------|
| DNS Amplification | Port 53 source/dest |
| NTP Amplification | Port 123 source/dest |
| Memcached Amplification | Port 11211 source/dest |
| UDP Flood | Global rate limit on UDP |

#### Layer 7 (Application) Attacks
| Attack Type | Detection Method |
|-------------|------------------|
| Slowloris | SYN flood targeting HTTP ports |
| HTTP Flood | PSH+ACK flood targeting HTTP ports |

### Audit Score Components

The audit score is computed from three factors:

| Factor | Weight | Description |
|--------|--------|-------------|
| **Attack Coverage** | 55% | Per-category mitigation effectiveness |
| **False Positive Prevention** | 25% | Protecting legitimate traffic (critical for UX) |
| **Latency** | 20% | RTT measurements, response time performance |

```
audit_score = 0.55 × attack_coverage + 0.25 × fp_score + 0.20 × latency_score
```

**Attack Coverage**: Weighted sum of per-category blocking rates (signature-based and rate-limit categories).

**False Positive Score**: Exponential penalty for blocking benign traffic - `(1 - fp_rate)²`.

**Latency Score**: Distance-normalized RTT comparison. Miners aren't penalized for geographic distance; scoring compares actual RTT to expected RTT based on physical distance.

### Anti-Gaming Measures

| Gaming Vector | Prevention |
|---------------|------------|
| Fake stats | Validator sends REAL packets, XDP counters must reflect reality |
| Reset XDP program | Counter reset detection catches negative deltas |
| Block all traffic | False positive check penalizes blocking benign packets |
| Pass all traffic | Attack blocking check penalizes missing attacks |

### Production Audit (Origin Monitoring)

In addition to synthetic audits, validators monitor miners' real production traffic through exit hub XDP metrics. Production audits are used for **origin monitoring and enforcement only** — they do not affect Bittensor weights.

```
Exit Hub → XDP Metrics → TPM → Production Score → EMA → Flagging/Reassignment
```

**How It Works:**

1. **Exit Hubs Report XDP Metrics**: Each exit hub (controlled by validators, not miners) reports SYN/SYN-ACK ratios, packet counts, and drop stats every 60 seconds
2. **TPM Aggregates Data**: Metrics are aggregated per miner across all assigned origins
3. **Production Score**: Binary scoring — healthy (1.0) or severe failure (0.3) based on unmitigated SYN floods or blocking all legitimate traffic
4. **Production EMA**: Smoothed with alpha=0.2, same as audit EMA
5. **Flagging**: If production EMA drops below 0.50, the miner is flagged and origins are reassigned
6. **Benign Traffic Tests**: Validators send benign packets through the production path to verify legitimate traffic passes through

**Why production audits don't affect weights:** Each validator only has production data for miners it owns (its own exit hubs). Using this in weight calculation would cause validators to disagree, breaking consensus. Audit EMA is the same across all validators.

---

## Reward Mechanism

### Bittensor Weight Formula

```
weight = steepened(ema_audit_score)
```

Rewards are currently based exclusively on **audit EMA** — the exponential moving average of synthetic audit scores.
Audit EMA scores are steepened to amplify top-end differences (e.g., 0.93 vs 0.96 becomes much more impactful), preventing clustering at high scores.

> **Roadmap: Volume-Weighted Rewards**
>
> In future releases, the weight formula will incorporate **production traffic volume** to reward miners proportionally to the amount of traffic they scrub for clients. This is essential for a healthy marketplace — miners handling more real-world traffic should earn more.
>
> Volume is excluded from the current formula because each validator only has visibility into traffic flowing through its own exit hubs. Without inter-validator communication, including volume in weights would cause validators to disagree, breaking Bittensor consensus. A **gossip-based consensus protocol** is planned for upcoming releases, enabling validators to share and agree on production metrics across the network. Once deployed, the formula will evolve to:
>
> ```
> weight = steepened(α × ema_audit_score + β × volume_score)
> ```

---

## Project Structure

```
tensorprox/
├── neurons/                  # Entry points
│   ├── miner.py             # Miner neuron
│   └── validator.py         # Validator neuron
├── τensorprox/              # Core library
│   ├── base/                # Base classes (neuron, miner, validator)
│   ├── core/                # Production implementations
│   ├── services/            # Operational services
│   ├── rewards/             # Scoring and leaderboard
│   ├── config/              # Configuration structures
│   └── tpm/                 # TPM-Lite (decentralized management)
├── miner_control_plane/     # Miner API and services
│   ├── api/                 # REST endpoints
│   └── services/            # Business logic
├── shared/                  # Shared utilities
│   ├── providers/           # Cloud provider abstraction
│   ├── utils/               # SSH, WireGuard, network helpers
│   └── database.py          # Connection pooling
├── configs/                 # Infrastructure bootstrap scripts
│   └── assets/              # Scrubber, exit hub, attacker configs
├── database/                # Schema and setup scripts
├── .env.miner.example       # Miner configuration template
└── .env.validator.example   # Validator configuration template
```

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

---

## License

This work is licensed under a [Creative Commons Attribution-NonCommercial 4.0 International License](https://creativecommons.org/licenses/by-nc/4.0/).

---

## Links

- **Product Platform**: https://tensorprox.io
- **Shugo**: https://shugo.io
- **Documentation**: https://github.com/shugo-labs/tensorprox
- **Issues**: https://github.com/shugo-labs/tensorprox/issues
- **Bittensor**: https://bittensor.com
- **W&B Dashboard**: https://wandb.ai/shugo-labs/tensorprox
