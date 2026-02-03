"""Geolocation Service - Single Source of Truth for Geographic Data.

PURPOSE:
    This module consolidates ALL geographic concerns for TPM:
    - Cloud provider region coordinates (AWS, Linode, OVH, GCP, etc.)
    - IP address geolocation via MaxMind GeoLite2
    - Distance calculations (Haversine formula)
    - Region matching and proximity sorting

USAGE:
    from tensorprox.tpm.services.geolocation import (
        get_location,
        find_best_region,
        get_regions_by_proximity,
    )

    # Geolocate an IP address
    location = get_location("173.255.234.157")
    # → {"lat": 51.5, "lon": -0.12, "country": "GB", "city": "London"}

    # Find best region from available pool
    best = find_best_region(location["lat"], location["lon"], ["us-east-1", "eu-west-2"])
    # → "eu-west-2"

    # Get all regions sorted by proximity
    regions = get_regions_by_proximity("eu-central-1", provider="aws")
    # → ["eu-central-1", "eu-central-2", "eu-west-3", ...]

MAXMIND SETUP:
    1. Register at https://www.maxmind.com/en/geolite2/signup
    2. Download GeoLite2-City.mmdb
    3. Set TPM_GEOLITE2_DB_PATH in tp_m.env (or place in default location)

ADDING NEW PROVIDERS:
    Add region coordinates to REGION_COORDINATES dict:
    REGION_COORDINATES["gcp"] = {
        "us-central1": (41.2619, -95.8608),
        ...
    }
"""
from __future__ import annotations

import gzip
import io
import os
import tarfile
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from math import atan2, cos, radians, sin, sqrt
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

from shared.utils.logging import get_logger
from tensorprox.tpm.repositories import SystemErrorRepository

logger = get_logger(__name__)

# Module-level repository for system error logging
_system_error_repo = SystemErrorRepository()

# MaxMind download URL template
MAXMIND_DOWNLOAD_URL = (
    "https://download.maxmind.com/app/geoip_download"
    "?edition_id=GeoLite2-City&license_key={license_key}&suffix=tar.gz"
)

# Database refresh interval (MaxMind updates weekly, we check daily)
DATABASE_MAX_AGE_DAYS = 7

# =============================================================================
# Region Coordinates - All Cloud Providers
# =============================================================================

REGION_COORDINATES: Dict[str, Dict[str, tuple[float, float]]] = {
    "aws": {
        # United States
        "us-east-1": (37.4316, -78.6569),       # N. Virginia
        "us-east-2": (39.9612, -82.9988),       # Ohio
        "us-west-1": (37.7749, -122.4194),      # N. California
        "us-west-2": (45.5152, -122.6784),      # Oregon
        # Asia Pacific
        "ap-south-1": (19.0760, 72.8777),       # Mumbai
        "ap-northeast-3": (34.6937, 135.5023),  # Osaka
        "ap-northeast-2": (37.5665, 126.9780),  # Seoul
        "ap-southeast-1": (1.3521, 103.8198),   # Singapore
        "ap-southeast-2": (-33.8688, 151.2093), # Sydney
        "ap-northeast-1": (35.6762, 139.6503),  # Tokyo
        # Canada
        "ca-central-1": (45.5017, -73.5673),    # Central (Montreal)
        # Europe
        "eu-central-1": (50.1109, 8.6821),      # Frankfurt
        "eu-west-1": (53.3498, -6.2603),        # Ireland
        "eu-west-2": (51.5074, -0.1278),        # London
        "eu-south-1": (45.4642, 9.1900),        # Milan
        "eu-west-3": (48.8566, 2.3522),         # Paris
        "eu-south-2": (40.4168, -3.7038),       # Spain (Madrid)
        "eu-north-1": (59.3293, 18.0686),       # Stockholm
        "eu-central-2": (47.3769, 8.5417),      # Zurich
        # Middle East
        "me-central-1": (25.2048, 55.2708),     # UAE (Dubai)
        # South America
        "sa-east-1": (-23.5505, -46.6333),      # Sao Paulo
    },
    "linode": {
        # Linode region IDs and their coordinates
        "us-east": (39.0438, -77.4874),         # Washington, DC
        "us-central": (32.7767, -96.7970),      # Dallas, TX
        "us-west": (33.8121, -117.9190),        # Fremont, CA
        "us-southeast": (33.7490, -84.3880),    # Atlanta, GA
        "us-iad": (38.9519, -77.4480),          # Ashburn, VA
        "us-ord": (41.8781, -87.6298),          # Chicago, IL
        "us-lax": (33.9416, -118.4085),         # Los Angeles, CA
        "us-mia": (25.7617, -80.1918),          # Miami, FL
        "us-sea": (47.6062, -122.3321),         # Seattle, WA
        "eu-west": (51.5074, -0.1278),          # London, UK
        "eu-central": (50.1109, 8.6821),        # Frankfurt, DE
        "ap-south": (1.3521, 103.8198),         # Singapore
        "ap-northeast": (35.6762, 139.6503),    # Tokyo, JP
        "ap-west": (19.0760, 72.8777),          # Mumbai, IN
        "ap-southeast": (1.2855, 103.8565),     # Singapore (legacy)
        "ca-central": (43.6532, -79.3832),      # Toronto, CA
        "br-gru": (-23.5505, -46.6333),         # Sao Paulo, BR
        "fr-par": (48.8566, 2.3522),            # Paris, FR
        "nl-ams": (52.3676, 4.9041),            # Amsterdam, NL
        "se-sto": (59.3293, 18.0686),           # Stockholm, SE
        "in-maa": (13.0827, 80.2707),           # Chennai, IN
        "jp-osa": (34.6937, 135.5023),          # Osaka, JP
        "it-mil": (45.4642, 9.1900),            # Milan, IT
        "id-cgk": (-6.2088, 106.8456),          # Jakarta, ID
    },
    # Future providers can be added here:
    # "gcp": { ... },
    # "ovh": { ... },
}


# =============================================================================
# MaxMind GeoIP2 Integration
# =============================================================================

@dataclass
class GeoLocation:
    """Result of IP geolocation lookup."""

    lat: float
    lon: float
    country: Optional[str] = None
    city: Optional[str] = None
    accuracy_radius: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "lat": self.lat,
            "lon": self.lon,
            "country": self.country,
            "city": self.city,
            "accuracy_radius": self.accuracy_radius,
        }


class GeoLocationError(Exception):
    """Base exception for geolocation errors."""


class DatabaseNotFoundError(GeoLocationError):
    """MaxMind database file not found."""


class IPNotFoundError(GeoLocationError):
    """IP address not found in database."""


# =============================================================================
# Database Download & Initialization
# =============================================================================

def _get_db_path() -> Path:
    """Get configured database path."""
    try:
        from shared.config import get_tp_management_settings
        settings = get_tp_management_settings()
        return Path(settings.tpm_geolite2_db_path)
    except Exception:
        return Path("/var/lib/GeoIP/GeoLite2-City.mmdb")


def _get_license_key() -> Optional[str]:
    """Get MaxMind license key from config."""
    try:
        from shared.config import get_tp_management_settings
        settings = get_tp_management_settings()
        return settings.tpm_maxmind_license_key
    except Exception:
        return None


def _is_database_fresh(db_path: Path) -> bool:
    """Check if database exists and is not too old."""
    if not db_path.exists():
        return False

    mtime = datetime.fromtimestamp(db_path.stat().st_mtime, tz=timezone.utc)
    age = datetime.now(timezone.utc) - mtime

    if age > timedelta(days=DATABASE_MAX_AGE_DAYS):
        logger.info(
            "GeoLite2 database is %d days old, needs refresh",
            age.days,
        )
        return False

    return True


def download_geolite2_database(force: bool = False) -> bool:
    """Download GeoLite2-City database from MaxMind.

    Args:
        force: If True, download even if database is fresh

    Returns:
        True if database is ready (downloaded or already exists), False on failure
    """
    db_path = _get_db_path()
    license_key = _get_license_key()

    # Check if we need to download
    if not force and _is_database_fresh(db_path):
        logger.debug("GeoLite2 database is fresh, skipping download")
        return True

    if not license_key:
        if db_path.exists():
            logger.warning(
                "TPM_MAXMIND_LICENSE_KEY not set, using existing database (may be stale)"
            )
            return True
        logger.warning(
            "TPM_MAXMIND_LICENSE_KEY not set and no existing database. "
            "IP geolocation will be disabled. "
            "Get a free license key at https://www.maxmind.com/en/geolite2/signup"
        )
        return False

    logger.info("Downloading GeoLite2-City database from MaxMind...")

    url = MAXMIND_DOWNLOAD_URL.format(license_key=license_key)

    try:
        response = requests.get(url, timeout=60, stream=True)
        response.raise_for_status()

        # Create parent directory if needed
        db_path.parent.mkdir(parents=True, exist_ok=True)

        # Extract .mmdb from tar.gz
        with tarfile.open(fileobj=io.BytesIO(response.content), mode="r:gz") as tar:
            for member in tar.getmembers():
                if member.name.endswith(".mmdb"):
                    # Extract just the .mmdb file
                    mmdb_file = tar.extractfile(member)
                    if mmdb_file:
                        with open(db_path, "wb") as f:
                            f.write(mmdb_file.read())
                        logger.info(
                            "GeoLite2-City database downloaded successfully: %s (%.1f MB)",
                            db_path,
                            db_path.stat().st_size / (1024 * 1024),
                        )
                        return True

        logger.error("No .mmdb file found in MaxMind archive")
        try:
            _system_error_repo.log_error(
                error_source="geolocation",
                error_code="download_failed",
                error_message="No .mmdb file found in MaxMind archive",
                context={"db_path": str(db_path)},
            )
        except Exception:
            pass  # Don't break main flow
        return False

    except requests.exceptions.HTTPError as exc:
        http_status = exc.response.status_code
        if http_status == 401:
            logger.error(
                "MaxMind authentication failed. Check TPM_MAXMIND_LICENSE_KEY is valid."
            )
            error_message = "MaxMind authentication failed"
        else:
            logger.error("MaxMind download failed: HTTP %d", http_status)
            error_message = f"MaxMind download failed: HTTP {http_status}"
        try:
            _system_error_repo.log_error(
                error_source="geolocation",
                error_code="download_failed",
                error_message=error_message,
                context={"db_path": str(db_path), "http_status": http_status},
            )
        except Exception:
            pass  # Don't break main flow
        return False
    except Exception as exc:
        logger.error("Failed to download GeoLite2 database: %s", exc, exc_info=True)
        try:
            _system_error_repo.log_error(
                error_source="geolocation",
                error_code="download_failed",
                error_message=f"Failed to download GeoLite2 database: {exc}",
                context={"db_path": str(db_path)},
            )
        except Exception:
            pass  # Don't break main flow
        return False


def initialize_geolocation() -> bool:
    """Initialize geolocation service on TPM startup.

    Downloads database if needed, then initializes the reader.

    Returns:
        True if geolocation is available, False otherwise
    """
    logger.info("Initializing geolocation service...")

    # Download/update database
    if not download_geolite2_database():
        logger.warning("Geolocation service unavailable (no database)")
        return False

    # Initialize reader
    reader = _get_geoip_reader()
    if reader is None:
        logger.warning("Geolocation service unavailable (reader init failed)")
        return False

    logger.info("Geolocation service initialized successfully")
    return True


# Module-level reader (lazy initialization)
_geoip_reader = None
_geoip_init_attempted = False


def _get_geoip_reader():
    """Get or initialize the MaxMind database reader."""
    global _geoip_reader, _geoip_init_attempted

    if _geoip_reader is not None:
        return _geoip_reader

    if _geoip_init_attempted:
        return None

    _geoip_init_attempted = True

    try:
        import geoip2.database
    except ImportError:
        logger.warning("geoip2 package not installed, geolocation disabled")
        return None

    # Use configured path (set by _get_db_path())
    db_path = _get_db_path()

    if not db_path.exists():
        logger.warning(
            "MaxMind GeoLite2-City.mmdb not found at %s. "
            "Run initialize_geolocation() on startup to auto-download.",
            db_path,
        )
        return None

    try:
        _geoip_reader = geoip2.database.Reader(str(db_path))
        logger.info("Loaded MaxMind GeoLite2 database from %s", db_path)
        return _geoip_reader
    except Exception as exc:
        logger.error("Failed to load GeoLite2 from %s: %s", db_path, exc)
        try:
            _system_error_repo.log_error(
                error_source="geolocation",
                error_code="db_load_failed",
                error_message=f"Failed to load GeoLite2 database: {exc}",
                context={"db_path": str(db_path)},
            )
        except Exception:
            pass  # Don't break main flow
        return None


def get_location(ip: str) -> Optional[GeoLocation]:
    """Geolocate an IP address using MaxMind GeoLite2.

    Args:
        ip: IPv4 or IPv6 address string

    Returns:
        GeoLocation with lat/lon/country/city, or None if lookup fails

    Example:
        >>> loc = get_location("8.8.8.8")
        >>> loc.country
        'US'
        >>> loc.lat, loc.lon
        (37.751, -97.822)
    """
    reader = _get_geoip_reader()
    if reader is None:
        logger.debug("GeoIP reader not available, cannot geolocate %s", ip)
        return None

    try:
        import geoip2.errors
        response = reader.city(ip)

        location = GeoLocation(
            lat=response.location.latitude or 0.0,
            lon=response.location.longitude or 0.0,
            country=response.country.iso_code,
            city=response.city.name,
            accuracy_radius=response.location.accuracy_radius,
        )

        logger.debug(
            "Geolocated %s: lat=%.4f, lon=%.4f, country=%s, city=%s",
            ip,
            location.lat,
            location.lon,
            location.country,
            location.city,
        )

        return location

    except geoip2.errors.AddressNotFoundError:
        logger.debug("IP %s not found in GeoLite2 database", ip)
        return None
    except Exception as exc:
        logger.warning("Geolocation failed for %s: %s", ip, exc)
        try:
            _system_error_repo.log_error(
                error_source="geolocation",
                error_code="lookup_failed",
                error_message=f"Geolocation failed for IP: {exc}",
                context={"ip": ip},
            )
        except Exception:
            pass  # Don't break main flow
        return None


# =============================================================================
# Distance Calculations
# =============================================================================

def haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate great-circle distance between two points in km.

    Uses the Haversine formula to account for Earth's curvature.

    Args:
        lat1: Latitude of point 1 in degrees
        lon1: Longitude of point 1 in degrees
        lat2: Latitude of point 2 in degrees
        lon2: Longitude of point 2 in degrees

    Returns:
        Distance in kilometers
    """
    R = 6371  # Earth radius in km

    lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
    dlat = lat2 - lat1
    dlon = lon2 - lon1

    a = sin(dlat / 2) ** 2 + cos(lat1) * cos(lat2) * sin(dlon / 2) ** 2
    c = 2 * atan2(sqrt(a), sqrt(1 - a))

    return R * c


# =============================================================================
# Region Matching
# =============================================================================

def get_region_coordinates(region: str, provider: str = "aws") -> Optional[tuple[float, float]]:
    """Get coordinates for a specific region.

    Args:
        region: Region identifier (e.g., "us-east-1", "eu-west")
        provider: Cloud provider ("aws", "linode", etc.)

    Returns:
        Tuple of (latitude, longitude) or None if unknown
    """
    provider_regions = REGION_COORDINATES.get(provider.lower(), {})
    return provider_regions.get(region)


def get_all_regions(provider: str = "aws") -> List[str]:
    """Get all known regions for a provider.

    Args:
        provider: Cloud provider ("aws", "linode", etc.)

    Returns:
        List of region identifiers
    """
    return list(REGION_COORDINATES.get(provider.lower(), {}).keys())


def infer_provider_from_region(region: str) -> str:
    """Infer cloud provider from region naming convention.

    Detection rules:
    - AWS regions have numbers at the end (e.g., us-east-1, eu-central-1)
    - Linode regions are simpler (e.g., us-east, eu-central) or use airport codes (us-iad)

    Also checks if region exists in known region coordinates for each provider.

    Args:
        region: Region identifier to analyze

    Returns:
        Provider name ("aws", "linode") - defaults to "aws" if ambiguous
    """
    if not region:
        return "aws"

    region_lower = region.lower()

    # First, check if region exists in any provider's known regions
    for provider, regions in REGION_COORDINATES.items():
        if region_lower in regions:
            return provider

    # Fallback: infer from naming pattern
    # AWS regions end with -N (number), e.g., us-east-1, ap-southeast-2
    import re
    if re.search(r'-\d+$', region_lower):
        return "aws"

    # Linode uses simpler names or 3-letter codes
    # e.g., us-east, eu-west, us-iad, us-ord
    return "linode"


# Default regions per provider (used as fallback when no region specified)
DEFAULT_REGIONS = {
    "aws": "us-west-2",
    "linode": "us-west",
}


def get_default_region_for_provider(provider: str) -> str:
    """Get the default region for a cloud provider.

    Args:
        provider: Cloud provider name (aws, linode)

    Returns:
        Default region string for that provider
    """
    return DEFAULT_REGIONS.get(provider.lower(), "us-west-2")


def get_regions_by_proximity(
    origin_region: str,
    provider: str = "aws",
    available_regions: Optional[List[str]] = None,
) -> List[str]:
    """Return regions sorted by distance from origin_region.

    Args:
        origin_region: Starting region for distance calculation
        provider: Cloud provider ("aws", "linode", etc.)
        available_regions: Optional filter - only include these regions

    Returns:
        List of region names, closest first. Origin region is always first.
    """
    provider_coords = REGION_COORDINATES.get(provider.lower(), {})

    if origin_region not in provider_coords:
        logger.warning(
            "Unknown region %s for provider %s, returning default order",
            origin_region,
            provider,
        )
        regions = list(provider_coords.keys())
        if available_regions:
            regions = [r for r in regions if r in available_regions]
        return regions

    origin_lat, origin_lon = provider_coords[origin_region]

    # Calculate distances
    distances: List[tuple[str, float]] = []
    for region, (lat, lon) in provider_coords.items():
        if available_regions and region not in available_regions:
            continue
        dist = haversine_distance(origin_lat, origin_lon, lat, lon)
        distances.append((region, dist))

    distances.sort(key=lambda x: x[1])
    sorted_regions = [region for region, _ in distances]

    logger.debug(
        "Regions by proximity from %s: %s",
        origin_region,
        sorted_regions[:5],
    )

    return sorted_regions


def find_best_region(
    lat: float,
    lon: float,
    available_regions: List[str],
    provider: str = "aws",
) -> Optional[str]:
    """Find the closest region to given coordinates from available pool.

    Args:
        lat: Latitude in degrees
        lon: Longitude in degrees
        available_regions: List of region identifiers to choose from
        provider: Cloud provider ("aws", "linode", etc.)

    Returns:
        Closest region identifier, or None if no valid regions

    Example:
        >>> find_best_region(51.5, -0.12, ["us-east-1", "eu-west-2"])
        'eu-west-2'
    """
    if not available_regions:
        logger.warning("find_best_region called with empty available_regions")
        return None

    provider_coords = REGION_COORDINATES.get(provider.lower(), {})

    distances: List[tuple[str, float]] = []
    for region in available_regions:
        coords = provider_coords.get(region)
        if coords is None:
            logger.debug("Region %s not in %s coordinates, skipping", region, provider)
            continue
        region_lat, region_lon = coords
        dist = haversine_distance(lat, lon, region_lat, region_lon)
        distances.append((region, dist))

    if not distances:
        logger.warning(
            "No valid regions found for coordinates (%.4f, %.4f) in provider %s",
            lat,
            lon,
            provider,
        )
        return available_regions[0] if available_regions else None

    distances.sort(key=lambda x: x[1])
    best_region, best_distance = distances[0]

    logger.info(
        "Best region for (%.4f, %.4f): %s (%.0f km)",
        lat,
        lon,
        best_region,
        best_distance,
    )

    return best_region


def find_best_region_for_ip(
    ip: str,
    available_regions: List[str],
    provider: str = "aws",
    fallback_region: Optional[str] = None,
) -> Optional[str]:
    """Find the closest region to an IP address from available pool.

    Convenience function that combines get_location() and find_best_region().

    Args:
        ip: IP address to geolocate
        available_regions: List of region identifiers to choose from
        provider: Cloud provider ("aws", "linode", etc.)
        fallback_region: Region to use if geolocation fails

    Returns:
        Closest region identifier, or fallback_region if geolocation fails

    Example:
        >>> find_best_region_for_ip("8.8.8.8", ["us-east-1", "eu-west-2"])
        'us-east-1'
    """
    location = get_location(ip)

    if location is None:
        logger.warning(
            "Could not geolocate IP %s, using fallback region: %s",
            ip,
            fallback_region,
        )
        return fallback_region

    best = find_best_region(
        location.lat,
        location.lon,
        available_regions,
        provider=provider,
    )

    if best is None:
        logger.warning(
            "No matching region for IP %s (%.4f, %.4f), using fallback: %s",
            ip,
            location.lat,
            location.lon,
            fallback_region,
        )
        return fallback_region

    return best


def get_fallback_regions(
    failed_region: str,
    provider: str = "aws",
    max_fallbacks: int = 3,
    excluded_regions: Optional[List[str]] = None,
) -> List[str]:
    """
    Get ordered list of fallback regions when a region has capacity issues.

    Regions are sorted by distance from the failed region, so the nearest
    alternative is tried first.

    Args:
        failed_region: The region that failed due to capacity
        provider: Cloud provider (aws, linode)
        max_fallbacks: Maximum number of fallback regions to return
        excluded_regions: Regions to skip (already tried or known issues)

    Returns:
        List of region identifiers sorted by proximity to failed_region
    """
    if excluded_regions is None:
        excluded_regions = set()
    else:
        excluded_regions = set(excluded_regions)

    # Always exclude the failed region
    excluded_regions.add(failed_region)

    provider_coords = REGION_COORDINATES.get(provider.lower(), {})
    if not provider_coords:
        logger.warning("No regions defined for provider: %s", provider)
        return []

    # Get coordinates of failed region
    if failed_region not in provider_coords:
        logger.warning("Failed region %s not found in coordinates", failed_region)
        # Return all non-excluded regions in arbitrary order
        return [r for r in provider_coords.keys() if r not in excluded_regions][:max_fallbacks]

    failed_lat, failed_lon = provider_coords[failed_region]

    # Calculate distance to all other regions
    distances = []
    for region, (lat, lon) in provider_coords.items():
        if region in excluded_regions:
            continue
        distance = haversine_distance(failed_lat, failed_lon, lat, lon)
        distances.append((distance, region))

    # Sort by distance and return top N
    distances.sort(key=lambda x: x[0])
    fallback_regions = [region for _, region in distances[:max_fallbacks]]

    logger.info(
        "Fallback regions for %s (provider=%s): %s",
        failed_region,
        provider,
        fallback_regions,
    )

    return fallback_regions
