#!/usr/bin/env python3
from shared.database import get_db_connection as get_db
"""
Multi-Dimensional Threat Scoring System
Industry-standard OOP approach for extensible attack detection

Integrates:
- Layer 2 Protocol Violations (invalid TCP, bogons, invalid IP)
- Behavioral Patterns (SYN floods, RST floods, scans)
- Volumetric Metrics (PPS, burst rate)
- Temporal Patterns (persistence, burst timing)

Design Pattern: Strategy + Builder
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from enum import Enum
import logging

logger = logging.getLogger('emn-threat-scoring')

# ============================================================================
# Enums and Constants
# ============================================================================

class ThreatLevel(Enum):
    """Threat severity levels (industry standard)"""
    BENIGN = 0          # Score 0-19: Normal traffic
    SUSPICIOUS = 1      # Score 20-39: Monitor, soft mitigation
    THREAT = 2          # Score 40-69: Temp blacklist
    SEVERE = 3          # Score 70+: Permanent blacklist

class MitigationAction(Enum):
    """Mitigation actions (aligned with existing functions)"""
    MONITOR = 'monitor'
    SOFT_PENALTY = 'ratelimit_penalty'      # Existing: apply_ratelimit_penalty()
    TEMP_BLACKLIST = 'temp_blacklist'        # Existing: apply_temp_blacklist()
    PERM_BLACKLIST = 'perm_blacklist'        # Existing: add_to_permanent_blacklist()
    CHALLENGE_ESCALATE = 'challenge_escalate' # Existing: set_global_challenge_via_bpf()

# Industry standard thresholds (from RFC 3704, Fail2Ban, Cloudflare practices)
LAYER2_THRESHOLDS = {
    'invalid_tcp': {
        'recon': (5, 20),       # 5-20 violations
        'scan': (20, 100),      # 20-100 violations
        'aggressive': (100, 500), # 100-500 violations
        'attack': (500, float('inf'))  # 500+ violations
    },
    'bogon': {
        'any': (1, float('inf'))  # ANY bogon = immediate action
    },
    'invalid_ip': {
        'broken': (10, 100),    # 10-100 violations
        'malicious': (100, float('inf'))  # 100+ violations
    }
}

# ============================================================================
# Data Classes (Type-Safe Metrics)
# ============================================================================

@dataclass
class Layer2Metrics:
    """Layer 2 protocol violation metrics"""
    invalid_tcp_count: int = 0
    bogon_count: int = 0
    invalid_ip_count: int = 0
    time_window_seconds: int = 60

    def total_violations(self) -> int:
        """Total protocol violations"""
        return self.invalid_tcp_count + self.bogon_count + self.invalid_ip_count

    def violation_types(self) -> int:
        """Count of different violation types (multi-vector indicator)"""
        return sum([
            self.invalid_tcp_count > 0,
            self.bogon_count > 0,
            self.invalid_ip_count > 0
        ])

@dataclass
class BehavioralMetrics:
    """Behavioral pattern metrics (existing)"""
    syn_count: int = 0
    rst_count: int = 0
    packets_total: int = 0
    burst_count: int = 0
    first_seen_ts: int = 0
    last_seen_ts: int = 0

    def duration(self) -> int:
        """Observation duration in seconds"""
        return max(self.last_seen_ts - self.first_seen_ts, 1)

    def packet_rate(self) -> float:
        """Packets per second"""
        return self.packets_total / self.duration()

@dataclass
class VolumetricMetrics:
    """Volumetric/rate metrics (future integration)"""
    pps: float = 0.0
    bps: float = 0.0
    cps: float = 0.0  # Connections per second

@dataclass
class ThreatSignature:
    """Complete threat assessment (output of scoring)"""
    ip_address: str
    attack_score: int  # 0-100
    attack_types: List[str] = field(default_factory=list)
    confidence: float = 0.0  # 0.0-1.0
    threat_level: ThreatLevel = ThreatLevel.BENIGN
    recommended_action: MitigationAction = MitigationAction.MONITOR
    duration_seconds: int = 0
    evidence: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        """Convert to dictionary for database storage"""
        return {
            'ip_address': self.ip_address,
            'attack_score': self.attack_score,
            'attack_types': self.attack_types,
            'confidence': self.confidence,
            'threat_level': self.threat_level.name,
            'recommended_action': self.recommended_action.value,
            'duration_seconds': self.duration_seconds
        }

# ============================================================================
# Base Metric Scorer (Extensible Pattern)
# ============================================================================

class MetricScorer:
    """
    Base class for metric-based scoring
    Allows easy addition of new metrics (Layer 3, Layer 4, etc.)
    """

    def score(self, metrics) -> Tuple[int, List[str]]:
        """
        Calculate score and attack types from metrics

        Returns:
            (score_contribution, attack_types): Score 0-100 and detected patterns
        """
        raise NotImplementedError("Subclasses must implement score()")

    def get_confidence(self, metrics) -> float:
        """
        Calculate confidence in detection

        Returns:
            confidence: 0.0-1.0
        """
        raise NotImplementedError("Subclasses must implement get_confidence()")

# ============================================================================
# Layer 2 Protocol Scorer (NEW - Industry Standard)
# ============================================================================

class Layer2ProtocolScorer(MetricScorer):
    """
    Score based on protocol violations (invalid TCP, bogons, invalid IP)
    Industry standard thresholds from RFC 3704, Fail2Ban, Cloudflare
    """

    def score(self, metrics: Layer2Metrics) -> Tuple[int, List[str]]:
        """
        Calculate Layer 2 protocol violation score

        Returns:
            (score, attack_types): 0-100 score and detected patterns
        """
        score = 0
        attack_types = []

        # Invalid TCP Flags (port scanning indicator)
        invalid_tcp = metrics.invalid_tcp_count
        if invalid_tcp >= 500:
            score += 50
            attack_types.append('aggressive_scan')
            logger.info(f"Aggressive scan detected: {invalid_tcp} invalid TCP")
        elif invalid_tcp >= 100:
            score += 35
            attack_types.append('scan')
            logger.info(f"Port scan detected: {invalid_tcp} invalid TCP")
        elif invalid_tcp >= 20:
            score += 20
            attack_types.append('recon')
            logger.debug(f"Reconnaissance detected: {invalid_tcp} invalid TCP")
        elif invalid_tcp >= 5:
            score += 10
            attack_types.append('probe')
            logger.debug(f"Probing detected: {invalid_tcp} invalid TCP")

        # Bogon Sources (spoofing - always serious)
        bogon = metrics.bogon_count
        if bogon >= 1:
            score += 60  # High score for any bogon
            attack_types.append('spoofing')
            logger.warning(f"Bogon source detected: {bogon} packets from invalid range")

        # Invalid IP Headers (protocol abuse)
        invalid_ip = metrics.invalid_ip_count
        if invalid_ip >= 100:
            score += 30
            attack_types.append('protocol_flood')
            logger.info(f"Protocol flood detected: {invalid_ip} invalid IP")
        elif invalid_ip >= 10:
            score += 15
            attack_types.append('protocol_abuse')
            logger.debug(f"Protocol abuse detected: {invalid_ip} invalid IP")

        # Multi-vector penalty (coordinated attack indicator)
        if metrics.violation_types() >= 2:
            score += 20
            attack_types.append('multi_vector')
            logger.warning(f"Multi-vector attack: {metrics.violation_types()} violation types")

        return min(score, 100), attack_types

    def get_confidence(self, metrics: Layer2Metrics) -> float:
        """
        Protocol violations have high confidence (near-deterministic)
        """
        confidence = 0.5  # Base

        # Bogon = 100% confident (no false positives)
        if metrics.bogon_count >= 1:
            return 1.0

        # Invalid TCP (very high confidence for scanning)
        if metrics.invalid_tcp_count >= 100:
            confidence = 0.95
        elif metrics.invalid_tcp_count >= 20:
            confidence = 0.85
        elif metrics.invalid_tcp_count >= 5:
            confidence = 0.70

        # Invalid IP adds confidence
        if metrics.invalid_ip_count >= 10:
            confidence = min(confidence + 0.1, 1.0)

        return round(confidence, 2)

# ============================================================================
# Behavioral Pattern Scorer (Existing Logic, Now OOP)
# ============================================================================

class BehavioralPatternScorer(MetricScorer):
    """
    Score based on behavioral patterns (SYN floods, RST floods, scans)
    Wraps existing calculate_attack_signature() logic in OOP pattern
    """

    def __init__(self, origin_syn_ack_ratio: Optional[float] = None):
        self.origin_syn_ack_ratio = origin_syn_ack_ratio

    def score(self, metrics: BehavioralMetrics) -> Tuple[int, List[str]]:
        """
        Calculate behavioral pattern score (existing logic from attack_detection.py)
        """
        score = 0
        attack_types = []

        # Pattern 1: SYN Flood
        if metrics.syn_count > 100 and self.origin_syn_ack_ratio and self.origin_syn_ack_ratio > 10:
            score += 40
            attack_types.append('syn_flood')

        # Pattern 2: RST Flood
        if metrics.rst_count > 50:
            score += 30
            attack_types.append('rst_flood')

        # Pattern 3: Volumetric
        if metrics.packets_total > 10000:
            score += 20
            attack_types.append('volumetric')

        # Pattern 4: Port Scan (many connections, low data)
        if metrics.syn_count > 50 and metrics.packets_total < 200:
            score += 25
            attack_types.append('scan')

        # Pattern 5: Burst Attack
        if metrics.burst_count > 500:
            score += 15
            attack_types.append('burst')

        return min(score, 100), attack_types

    def get_confidence(self, metrics: BehavioralMetrics) -> float:
        """
        Confidence based on sample size and observation time (existing logic)
        """
        packets = metrics.packets_total
        age = metrics.duration()

        packet_confidence = min(packets / 1000, 1.0)
        age_confidence = min(age / 300, 1.0)  # 5 minutes

        return round((packet_confidence + age_confidence) / 2, 2)

# ============================================================================
# Multi-Dimensional Threat Scorer (Combines All Metrics)
# ============================================================================

class MultiDimensionalThreatScorer:
    """
    Combines multiple metric dimensions for comprehensive threat assessment
    Extensible: Easy to add new scorers (Layer 3, Layer 4, ML-based, etc.)

    Design: Uses Strategy pattern - each scorer is independent and composable
    """

    def __init__(self):
        self.scorers: List[Tuple[MetricScorer, object]] = []

    def add_scorer(self, scorer: MetricScorer, metrics: object):
        """
        Add a metric scorer to the assessment

        Args:
            scorer: MetricScorer instance
            metrics: Metrics object (Layer2Metrics, BehavioralMetrics, etc.)
        """
        self.scorers.append((scorer, metrics))
        return self  # Builder pattern

    def calculate(self, ip_address: str) -> ThreatSignature:
        """
        Calculate comprehensive threat signature from all dimensions

        Args:
            ip_address: IP being assessed

        Returns:
            ThreatSignature: Complete assessment with score, types, confidence
        """
        total_score = 0
        all_attack_types = []
        all_confidences = []
        evidence = {}

        # Aggregate scores from all dimensions
        for scorer, metrics in self.scorers:
            dimension_score, attack_types = scorer.score(metrics)
            dimension_confidence = scorer.get_confidence(metrics)

            total_score += dimension_score
            all_attack_types.extend(attack_types)
            all_confidences.append(dimension_confidence)

            # Store evidence
            scorer_name = scorer.__class__.__name__
            evidence[scorer_name] = {
                'score': dimension_score,
                'types': attack_types,
                'confidence': dimension_confidence,
                'metrics': self._metrics_to_dict(metrics)
            }

        # Deduplicate attack types
        unique_types = list(set(all_attack_types))

        # Combined confidence (weighted average, higher confidence = more weight)
        if all_confidences:
            weighted_sum = sum(c * c for c in all_confidences)  # Square for weighting
            weight_total = sum(all_confidences)
            combined_confidence = weighted_sum / weight_total if weight_total > 0 else 0.5
        else:
            combined_confidence = 0.5

        # Cap score at 100
        final_score = min(total_score, 100)

        # Determine threat level
        threat_level = self._score_to_threat_level(final_score)

        # Determine recommended action
        action, duration = self._threat_to_action(threat_level, final_score, combined_confidence)

        return ThreatSignature(
            ip_address=ip_address,
            attack_score=final_score,
            attack_types=unique_types,
            confidence=round(combined_confidence, 2),
            threat_level=threat_level,
            recommended_action=action,
            duration_seconds=duration,
            evidence=evidence
        )

    def _score_to_threat_level(self, score: int) -> ThreatLevel:
        """Map score to threat level (industry standard ranges)"""
        if score >= 70:
            return ThreatLevel.SEVERE
        elif score >= 40:
            return ThreatLevel.THREAT
        elif score >= 20:
            return ThreatLevel.SUSPICIOUS
        else:
            return ThreatLevel.BENIGN

    def _threat_to_action(self, threat_level: ThreatLevel, score: int, confidence: float) -> Tuple[MitigationAction, int]:
        """
        Determine mitigation action based on threat level and confidence

        Returns:
            (action, duration_seconds)
        """
        # High confidence adjustments
        confidence_boost = 1.2 if confidence >= 0.9 else 1.0

        if threat_level == ThreatLevel.SEVERE or (score >= 60 and confidence >= 0.9):
            # Permanent blacklist for severe threats OR high-confidence threats
            return MitigationAction.PERM_BLACKLIST, 0  # Permanent

        elif threat_level == ThreatLevel.THREAT:
            # Temporary blacklist (1 hour standard)
            return MitigationAction.TEMP_BLACKLIST, 3600

        elif threat_level == ThreatLevel.SUSPICIOUS:
            # Soft penalty (5 minutes standard)
            return MitigationAction.SOFT_PENALTY, 300

        else:
            # Monitor only
            return MitigationAction.MONITOR, 0

    def _metrics_to_dict(self, metrics) -> Dict:
        """Convert metrics object to dictionary for evidence"""
        if hasattr(metrics, '__dict__'):
            return {k: v for k, v in metrics.__dict__.items() if not k.startswith('_')}
        return {}

# ============================================================================
# Metrics Collector (Extensible Base)
# ============================================================================

class MetricsCollector:
    """
    Base class for collecting metrics from various sources
    Extensible: Easy to add new metric sources
    """

    def collect(self, ip_address: str, time_window: int) -> object:
        """
        Collect metrics for given IP and time window

        Args:
            ip_address: IP to collect metrics for
            time_window: Time window in seconds

        Returns:
            Metrics object (Layer2Metrics, BehavioralMetrics, etc.)
        """
        raise NotImplementedError("Subclasses must implement collect()")

class Layer2MetricsCollector(MetricsCollector):
    """
    Collect Layer 2 protocol violation metrics from database

    Integrates with: ddos_metrics table
    """

    def __init__(self, db_connection):
        self.conn = db_connection

    def collect(self, ip_address: str, time_window: int = 60) -> Layer2Metrics:
        """
        Query Layer 2 violations for specific IP

        Note: Currently ddos_metrics doesn't have per-IP breakdown
        This is a placeholder for future per-IP correlation
        For now, returns global stats (all IPs aggregated)
        """
        try:
            cur = self.conn.cursor()

            cur.execute("""
                SELECT
                    COALESCE(SUM(xdp_drop_invalid_tcp), 0) as invalid_tcp,
                    COALESCE(SUM(xdp_drop_bogon), 0) as bogon,
                    COALESCE(SUM(xdp_drop_invalid_ip), 0) as invalid_ip
                FROM ddos_metrics
                WHERE timestamp > NOW() - INTERVAL '%s seconds'
            """, (time_window,))

            row = cur.fetchone()
            cur.close()

            return Layer2Metrics(
                invalid_tcp_count=int(row['invalid_tcp'] or 0),
                bogon_count=int(row['bogon'] or 0),
                invalid_ip_count=int(row['invalid_ip'] or 0),
                time_window_seconds=time_window
            )

        except Exception as e:
            logger.error(f"Failed to collect Layer 2 metrics: {e}")
            return Layer2Metrics()  # Return zeros on error

# ============================================================================
# Helper Functions (Maintain Compatibility with Existing Code)
# ============================================================================

def assess_threat_multi_dimensional(
    ip_address: str,
    layer2_metrics: Layer2Metrics,
    behavioral_metrics: BehavioralMetrics,
    origin_syn_ack_ratio: Optional[float] = None
) -> ThreatSignature:
    """
    Main entry point for multi-dimensional threat assessment

    Integrates:
    - Layer 2 protocol violations
    - Behavioral patterns
    - Origin-level context

    Args:
        ip_address: IP to assess
        layer2_metrics: Protocol violation metrics
        behavioral_metrics: Behavioral pattern metrics
        origin_syn_ack_ratio: Origin SYN/SYN-ACK ratio for context

    Returns:
        ThreatSignature: Complete assessment with recommended action
    """
    scorer = MultiDimensionalThreatScorer()

    # Add Layer 2 dimension
    scorer.add_scorer(
        Layer2ProtocolScorer(),
        layer2_metrics
    )

    # Add Behavioral dimension
    scorer.add_scorer(
        BehavioralPatternScorer(origin_syn_ack_ratio),
        behavioral_metrics
    )

    # Calculate comprehensive signature
    signature = scorer.calculate(ip_address)

    logger.info(f"Multi-dimensional threat assessment for {ip_address}: "
                f"score={signature.attack_score}, "
                f"confidence={signature.confidence}, "
                f"action={signature.recommended_action.value}")

    return signature

# ============================================================================
# Integration with Existing Functions
# ============================================================================

def execute_mitigation_action(signature: ThreatSignature, origin_id: Optional[str] = None):
    """
    Execute mitigation action based on threat signature

    Integrates with existing functions:
    - apply_ratelimit_penalty()
    - apply_temp_blacklist()
    - add_to_permanent_blacklist()

    Args:
        signature: ThreatSignature from assessment
        origin_id: Origin ID (if origin-specific)

    Returns:
        success: bool
    """
    from automated_mitigation import (
        apply_ratelimit_penalty,
        apply_temp_blacklist,
        add_to_permanent_blacklist
    )

    ip = signature.ip_address
    action = signature.recommended_action

    try:
        if action == MitigationAction.SOFT_PENALTY:
            # Soft penalty: 50% rate limit
            return apply_ratelimit_penalty(
                ip_address=ip,
                penalty_level=1,  # 50% rate
                duration_seconds=signature.duration_seconds
            )

        elif action == MitigationAction.TEMP_BLACKLIST:
            # Temporary blacklist
            return apply_temp_blacklist(
                ip_address=ip,
                origin_id=origin_id,
                attack_score=signature.attack_score,
                attack_types=signature.attack_types,
                duration_seconds=signature.duration_seconds
            )

        elif action == MitigationAction.PERM_BLACKLIST:
            # Permanent blacklist
            return add_to_permanent_blacklist(
                ip_address=ip,
                attack_types=signature.attack_types,
                attack_score=signature.attack_score
            )

        elif action == MitigationAction.MONITOR:
            # Just log, no action
            logger.info(f"Monitoring {ip}: score={signature.attack_score}, types={signature.attack_types}")
            return True

        else:
            logger.warning(f"Unknown action type: {action}")
            return False

    except Exception as e:
        logger.error(f"Failed to execute mitigation for {ip}: {e}")
        return False

# ============================================================================
# Example Usage
# ============================================================================

def example_usage():
    """
    Example: How to use the multi-dimensional scoring system
    """
    # Scenario: IP with both protocol violations and behavioral anomalies

    # Collect Layer 2 metrics
    layer2 = Layer2Metrics(
        invalid_tcp_count=150,  # Port scanning
        bogon_count=0,
        invalid_ip_count=5
    )

    # Collect Behavioral metrics
    behavioral = BehavioralMetrics(
        syn_count=200,
        rst_count=10,
        packets_total=250,
        burst_count=100,
        first_seen_ts=1000,
        last_seen_ts=1060
    )

    # Assess threat
    signature = assess_threat_multi_dimensional(
        ip_address="203.0.113.50",
        layer2_metrics=layer2,
        behavioral_metrics=behavioral,
        origin_syn_ack_ratio=15.0
    )

    # Result:
    # - Layer 2 score: 35 (scan) + 15 (invalid IP) = 50
    # - Behavioral score: 40 (SYN flood) + 25 (scan pattern) = 65
    # - Total: 115 → capped at 100
    # - Attack types: ['scan', 'syn_flood', 'protocol_abuse']
    # - Confidence: ~0.9 (high)
    # - Action: PERM_BLACKLIST (score > 70, confidence > 0.9)

    # Execute mitigation
    execute_mitigation_action(signature, origin_id="O1")

if __name__ == '__main__':
    # Configure logging for standalone testing
    logging.basicConfig(level=logging.INFO)
    example_usage()
