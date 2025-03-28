<div align="center">

# **Tensorprox: SN234** <!-- omit in toc -->
[![Discord Chat](https://img.shields.io/discord/308323056592486420.svg)](https://discord.gg/bittensor)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

### The Incentivized DDoS Scrubbing Center <!-- omit in toc -->

[Discord](https://discord.gg/bittensor) • [Taostats](https://taostats.io/) •

</div>

---

This repository is the **official codebase for Bittensor Subnet 234 (SN234) v0.1.0+**. To learn more about the Bittensor project and the underlying mechanics, [read here.](https://docs.bittensor.com/)

# Introduction

Tensorprox defines an innovative incentive mechanism for creating a distributed Scrubber Center to protect miners and server instances from DDoS attacks. The validation process employs **synthetic traffic generation by alternating between normal traffic and complex DDoS attack simulations, aiming to reproduce the natural behavior of both normal and malicious traffic**.

## Core Concept

The subnet operates on a unique distributed network architecture where:
- **Validators** challenge miners by simulating real-world DDoS scenarios
- **Miners** provide DDoS protection services using custom routing firewall systems
- **Performance** is evaluated through comprehensive traffic analysis

## Network Architecture

### Components
- **Validator Nodes**: Responsible for challenge generation and performance evaluation
- **Miner Nodes**: Provide DDoS mitigation services
- **Test Machines**:
  * Attacker Machine: Generates malicious traffic
  * Benign Machine: Generates normal traffic
  * King Machine: Target receiver machine

### Workflow
1. SSH access established via PingSynapse protocol
2. Validator locks machine access
3. Synthetic traffic scenarios generated
4. Miner's protection model evaluated
5. Performance metrics calculated

# Reward Mechanism

## Overview

The reward mechanism is a sophisticated scoring system that evaluates miners' performance in DDoS protection based on multiple critical metrics.

### Reward Calculation Components

The reward function is composed of four key metrics:

1. **Attack Detection Accuracy (ADA)** - 30% Weight
   - Measures the ability to detect and block malicious traffic
   - Calculated as: `(Total Attack Packets - Attacks Reaching King) / Total Attack Packets`

2. **False Positive Rate (FPR)** - 30% Weight
   - Evaluates precision in distinguishing between benign and malicious traffic
   - Calculated as: `1 - (Total Benign Packets - Benign Packets Reaching King) / Total Benign Packets`

3. **Throughput Efficiency** - 20% Weight
   - Measures capacity to handle network traffic
   - Normalized total packets sent relative to maximum packets processed

4. **Latency Factor** - 20% Weight
   - Assesses response time and network performance
   - Calculated using normalized Round-Trip Time (RTT)

### Scoring Method

The final reward is calculated using a weighted sum:

```
Reward = (0.3 * Attack Detection Accuracy) + 
         (0.3 * False Positive Rate) + 
         (0.2 * Normalized Packets Sent) + 
         (0.2 * Normalized RTT)
```

<div align="center">

**[Validator Documentation](./assets/validator.md)** · **[Miner Documentation](./assets/miner.md)**

</div>

# Technical Overview

## Protocol Communication
Built using Bittensor SDK, enabling secure and efficient node interactions through PingSynapse communication protocol.

## Key Technologies
- Bittensor SDK
- Custom Routing Firewall
- SSH Access Management
- Synthetic Traffic Generation

# Contribution

We welcome contributions! Detailed guidelines will be published soon.

# License

The only authorized commercial use of this software is for mining or validating within the TensorProx subnet.
For any other commercial licensing requests, please contact Shugo LTD.

See the full license terms here: https://creativecommons.org/licenses/by-nc/4.0/

# Contact

Join our [Discord](https://discord.gg/bittensor) for community support and discussions.

---

**Disclaimer**: Tensorprox is an experimental DDoS mitigation network. Always conduct thorough testing in controlled environments.