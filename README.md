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

<div align="center">

**[Validator Documentation](./assets/validator.md)** · **[Miner Documentation](./assets/miner.md)**

</div>

# Technical Overview

## Protocol Communication
Built using Bittensor SDK, enabling secure and efficient node interactions through PingSynapse communication protocol.

## Reward Mechanism
Miners compete and are rewarded based on:
- Traffic filtering accuracy
- Attack mitigation effectiveness
- Response time
- Model sophistication

## Key Technologies
- Bittensor SDK
- Custom Routing Firewall
- SSH Access Management
- Synthetic Traffic Generation

# Installation

Detailed installation instructions coming soon. Preliminary setup will require:
- Python 3.8+
- Bittensor SDK
- SSH-compatible infrastructure

# Contribution

We welcome contributions! Detailed guidelines will be published soon.

# License

Licensed under the MIT License.

# Contact

Join our [Discord](https://discord.gg/bittensor) for community support and discussions.

---

**Disclaimer**: Tensorprox is an experimental DDoS mitigation network. Always conduct thorough testing in controlled environments.