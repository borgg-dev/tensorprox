"""
EIP Availability Service.

Tracks Elastic IP (EIP) availability per region to enable fail-fast
deployment decisions. This prevents the scenario where deployments
fail at the end due to AWS EIP quota exhaustion.

Key Features:
- Queries AWS DescribeAddresses API to count used EIPs
- Cache with configurable TTL (default: 60 seconds)
- Configurable quota via settings (default: 5 per region)
- Graceful degradation if AWS query fails (optimistic behavior)
"""

import logging
import time
from typing import Optional

from miner_control_plane.utils.aws import aws_operations
from shared.config import get_settings

logger = logging.getLogger(__name__)

# Cache TTL in seconds (balance between freshness and API calls)
DEFAULT_CACHE_TTL = 60


class EIPAvailabilityService:
    """
    Service to track EIP availability per region.

    Provides cached queries to AWS to determine how many EIPs are
    available before attempting allocation, enabling fail-fast behavior.
    """

    def __init__(self, cache_ttl: int = DEFAULT_CACHE_TTL):
        """
        Initialize the EIP availability service.

        Args:
            cache_ttl: Time-to-live for cached EIP counts in seconds
        """
        self.settings = get_settings()
        self.cache_ttl = cache_ttl
        # Cache structure: {region: (eip_count, timestamp)}
        self._cache: dict[str, tuple[int, float]] = {}

    def _get_quota(self) -> int:
        """
        Get configured EIP quota per region.

        Returns:
            Configured quota or default of 5
        """
        return getattr(self.settings, 'aws_eip_quota_per_region', 5)

    def _query_eip_count(self, region: str) -> Optional[int]:
        """
        Query AWS for current EIP count in a region.

        Args:
            region: AWS region to query

        Returns:
            Number of EIPs in use, or None if query fails
        """
        try:
            addresses = aws_operations.describe_addresses(region=region)
            count = len(addresses) if addresses else 0
            logger.debug(f"Queried EIP count for {region}: {count}")
            return count
        except Exception as e:
            logger.warning(
                f"Failed to query EIP count for {region}: {e}. "
                f"Will use optimistic behavior."
            )
            return None

    def get_eip_usage(self, region: str) -> tuple[int, int, int]:
        """
        Get EIP usage stats for a region (cached).

        Args:
            region: AWS region to check

        Returns:
            Tuple of (quota, used, available)
            If query fails, returns (quota, 0, quota) for optimistic behavior
        """
        quota = self._get_quota()
        now = time.time()

        # Check cache
        if region in self._cache:
            cached_count, cached_time = self._cache[region]
            if (now - cached_time) < self.cache_ttl:
                available = max(0, quota - cached_count)
                logger.debug(
                    f"EIP cache hit for {region}: {cached_count}/{quota} used, "
                    f"{available} available"
                )
                return quota, cached_count, available

        # Query AWS
        eip_count = self._query_eip_count(region)

        if eip_count is None:
            # Graceful degradation: optimistic behavior
            logger.warning(
                f"EIP query failed for {region}, assuming full availability "
                f"({quota} EIPs)"
            )
            return quota, 0, quota

        # Update cache
        self._cache[region] = (eip_count, now)
        available = max(0, quota - eip_count)

        logger.info(
            f"EIP availability for {region}: {eip_count}/{quota} used, "
            f"{available} available"
        )

        return quota, eip_count, available

    def has_eip_available(self, region: str) -> bool:
        """
        Check if at least one EIP is available in a region.

        Args:
            region: AWS region to check

        Returns:
            True if at least one EIP slot is available, False otherwise
        """
        quota, used, available = self.get_eip_usage(region)
        return available >= 1

    def clear_cache(self, region: Optional[str] = None) -> None:
        """
        Clear EIP cache after allocation or release.

        Should be called after successful EIP allocation or release
        to ensure fresh data on next query.

        Args:
            region: Specific region to clear, or None to clear all
        """
        if region:
            if region in self._cache:
                del self._cache[region]
                logger.debug(f"Cleared EIP cache for {region}")
        else:
            self._cache.clear()
            logger.debug("Cleared all EIP cache")


# Module-level singleton for easy access
eip_availability = EIPAvailabilityService()
