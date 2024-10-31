import geoip2.database
from requests import get
from math import radians, sin, cos, sqrt, atan2

def haversine_distance(lat1, lon1, lat2, lon2):
    # Radius of the Earth in kilometers
    R = 6371.0
    # Convert latitude and longitude from degrees to radians
    dlat = radians(lat2 - lat1)
    dlon = radians(lon2 - lon1)
    a = sin(dlat / 2)**2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon / 2)**2
    c = 2 * atan2(sqrt(a), sqrt(1 - a))
    distance = R * c
    return distance

def get_my_public_ip():
    """Retrieve the local IP address."""
    try:
        return get('https://api.ipify.org').text.strip()

    except Exception as e:
        print(f"Error getting my public IP: {e}")
        return "0.0.0.0"  # Fallback IP if there's an error
        
def get_location_from_maxmind(ip_address, db_path="tensorprox/rewards/GeoLite2-City.mmdb"):
    with geoip2.database.Reader(db_path) as reader:
        try:
            response = reader.city(ip_address)
            return {
                "city": response.city.name,
                "country": response.country.name,
                "latitude": response.location.latitude,
                "longitude": response.location.longitude,
                "region": response.subdivisions.most_specific.name
            }
        except geoip2.errors.AddressNotFoundError:
            return {}