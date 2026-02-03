"""
GeoIP service for IP geolocation and distance calculation.

Uses free IP geolocation APIs to determine coordinates of IP addresses,
enabling distance-based latency normalization in the reward model.
"""

import math
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple
from loguru import logger

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


@dataclass
class GeoLocation:
    """Geographic location data for an IP address."""
    ip: str
    latitude: float
    longitude: float
    city: Optional[str] = None
    region: Optional[str] = None
    country: Optional[str] = None
    isp: Optional[str] = None
    timestamp: float = 0.0

    def is_valid(self) -> bool:
        """Check if location data is valid."""
        return (
            -90 <= self.latitude <= 90 and
            -180 <= self.longitude <= 180 and
            not (self.latitude == 0 and self.longitude == 0)  # Reject null island
        )


class GeoIPService:
    """
    Service for IP geolocation and distance calculation.

    Features:
    - Caches lookups to avoid repeated API calls
    - Falls back to multiple providers if primary fails
    - Calculates haversine distance between coordinates
    - Computes expected RTT based on distance

    Expected RTT formula:
    - Speed of light in fiber: ~200,000 km/s = 200 km/ms
    - Real-world factor (routing overhead, processing): ~100 km/ms
    - So 1000 km distance ≈ 10ms minimum RTT (one-way)
    - Round-trip = 2x, so 1000 km ≈ 20ms RTT baseline

    We use a more conservative estimate:
    - expected_rtt_ms = distance_km * 0.02 + 5ms base overhead
    """

    # Cache TTL in seconds (1 hour)
    CACHE_TTL = 3600

    # RTT estimation constants
    # Conservative estimate: ~50 km per ms of round-trip time
    # This accounts for routing inefficiencies and processing delays
    KM_PER_MS_RTT = 50.0
    BASE_OVERHEAD_MS = 5.0  # Minimum RTT even for very close servers

    def __init__(self):
        """Initialize the GeoIP service."""
        self._cache: Dict[str, GeoLocation] = {}
        self._last_request_time: float = 0
        self._min_request_interval = 0.1  # 100ms between requests (rate limiting)

    def get_location(self, ip: str) -> Optional[GeoLocation]:
        """
        Get geographic location for an IP address.

        Args:
            ip: IP address to geolocate

        Returns:
            GeoLocation if successful, None if lookup failed
        """
        # Check cache first
        cached = self._get_cached(ip)
        if cached:
            return cached

        # Try primary provider (ip-api.com - free, no key required)
        location = self._lookup_ip_api(ip)

        # Try fallback if primary failed
        if not location:
            location = self._lookup_ipinfo(ip)

        # Cache successful lookup
        if location and location.is_valid():
            self._cache[ip] = location
            return location

        return None

    def _get_cached(self, ip: str) -> Optional[GeoLocation]:
        """Get cached location if still valid."""
        if ip in self._cache:
            cached = self._cache[ip]
            if time.time() - cached.timestamp < self.CACHE_TTL:
                return cached
            else:
                del self._cache[ip]
        return None

    def _rate_limit(self):
        """Enforce rate limiting between API requests."""
        now = time.time()
        elapsed = now - self._last_request_time
        if elapsed < self._min_request_interval:
            time.sleep(self._min_request_interval - elapsed)
        self._last_request_time = time.time()

    def _lookup_ip_api(self, ip: str) -> Optional[GeoLocation]:
        """
        Lookup IP using ip-api.com (free, no auth required).

        Rate limit: 45 requests per minute for free tier.
        """
        if not REQUESTS_AVAILABLE:
            return None

        self._rate_limit()

        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,lat,lon,city,regionName,country,isp"

            response = requests.get(url, timeout=5.0)

            if response.status_code != 200:
                logger.warning(f"ip-api.com returned {response.status_code}")
                return None

            data = response.json()

            if data.get("status") != "success":
                logger.debug(f"ip-api.com lookup failed: {data.get('message', 'unknown')}")
                return None

            return GeoLocation(
                ip=ip,
                latitude=data.get("lat", 0),
                longitude=data.get("lon", 0),
                city=data.get("city"),
                region=data.get("regionName"),
                country=data.get("country"),
                isp=data.get("isp"),
                timestamp=time.time()
            )

        except Exception as e:
            logger.debug(f"ip-api.com lookup error: {e}")
            return None

    def _lookup_ipinfo(self, ip: str) -> Optional[GeoLocation]:
        """
        Fallback lookup using ipinfo.io (free tier, limited).
        """
        if not REQUESTS_AVAILABLE:
            return None

        self._rate_limit()

        try:
            url = f"https://ipinfo.io/{ip}/json"

            response = requests.get(url, timeout=5.0)

            if response.status_code != 200:
                return None

            data = response.json()

            # ipinfo returns "lat,lon" as a single "loc" field
            loc = data.get("loc", "")
            if not loc or "," not in loc:
                return None

            lat, lon = loc.split(",")

            return GeoLocation(
                ip=ip,
                latitude=float(lat),
                longitude=float(lon),
                city=data.get("city"),
                region=data.get("region"),
                country=data.get("country"),
                isp=data.get("org"),
                timestamp=time.time()
            )

        except Exception as e:
            logger.debug(f"ipinfo.io lookup error: {e}")
            return None

    def calculate_distance_km(
        self,
        lat1: float,
        lon1: float,
        lat2: float,
        lon2: float
    ) -> float:
        """
        Calculate distance between two coordinates using Haversine formula.

        Args:
            lat1, lon1: First location coordinates
            lat2, lon2: Second location coordinates

        Returns:
            Distance in kilometers
        """
        # Earth radius in km
        R = 6371.0

        # Convert to radians
        lat1_rad = math.radians(lat1)
        lat2_rad = math.radians(lat2)
        dlat = math.radians(lat2 - lat1)
        dlon = math.radians(lon2 - lon1)

        # Haversine formula
        a = (
            math.sin(dlat / 2) ** 2 +
            math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon / 2) ** 2
        )
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

        return R * c

    def get_distance_between_ips(
        self,
        ip1: str,
        ip2: str
    ) -> Optional[float]:
        """
        Calculate distance between two IP addresses.

        Args:
            ip1: First IP address
            ip2: Second IP address

        Returns:
            Distance in kilometers, or None if lookup failed
        """
        loc1 = self.get_location(ip1)
        loc2 = self.get_location(ip2)

        if not loc1 or not loc2:
            logger.debug(f"Could not geolocate one or both IPs")
            return None

        distance = self.calculate_distance_km(
            loc1.latitude, loc1.longitude,
            loc2.latitude, loc2.longitude
        )

        logger.debug(
            f"Distance: ({loc1.city}, {loc1.country}) <-> "
            f"({loc2.city}, {loc2.country}) = {distance:.0f} km"
        )

        return distance

    def calculate_expected_rtt_ms(self, distance_km: float) -> float:
        """
        Calculate expected RTT based on geographic distance.

        Formula: expected_rtt = (distance_km / KM_PER_MS) + BASE_OVERHEAD

        Args:
            distance_km: Distance between endpoints in kilometers

        Returns:
            Expected RTT in milliseconds
        """
        return (distance_km / self.KM_PER_MS_RTT) + self.BASE_OVERHEAD_MS

    def get_expected_rtt_between_ips(
        self,
        ip1: str,
        ip2: str
    ) -> Tuple[Optional[float], Optional[float]]:
        """
        Calculate expected RTT between two IP addresses.

        Args:
            ip1: First IP address (e.g., validator)
            ip2: Second IP address (e.g., scrubber)

        Returns:
            Tuple of (distance_km, expected_rtt_ms), or (None, None) if lookup failed
        """
        distance = self.get_distance_between_ips(ip1, ip2)

        if distance is None:
            return None, None

        expected_rtt = self.calculate_expected_rtt_ms(distance)

        logger.debug(
            f"Expected RTT calculation: "
            f"distance={distance:.0f}km, expected_rtt={expected_rtt:.1f}ms"
        )

        return distance, expected_rtt


# Singleton instance for reuse
_geoip_service: Optional[GeoIPService] = None


def get_geoip_service() -> GeoIPService:
    """Get the singleton GeoIP service instance."""
    global _geoip_service
    if _geoip_service is None:
        _geoip_service = GeoIPService()
    return _geoip_service
