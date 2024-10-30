import numpy as np
from typing import ClassVar
from pydantic import BaseModel, ConfigDict
from tensorprox.base.dendrite import DendriteResponseEvent
from tensorprox.tasks.base_task import DDoSDetectionTask
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


class DDoSDetectionRewardEvent(BaseModel):
    task: DDoSDetectionTask
    rewards: list[float]
    timings: list[float]
    uids: list[int]

    model_config = ConfigDict(arbitrary_types_allowed=True)

    def asdict(self) -> dict:
        return {
            "rewards": self.rewards,
            "timings": self.timings,
            "uids": self.uids,
            "task": self.task,
        }

class BatchRewardOutput(BaseModel):
    rewards: np.ndarray
    timings: np.ndarray
    model_config = ConfigDict(arbitrary_types_allowed=True)


class DDoSDetectionRewardModel(BaseModel):

    alpha: float = 5.0  # Decay rate parameter for exponential decrease
    avg_distance: float = 3500
    latency_speed: float = 200000 #5ms latency per 1000km : this is an estimation assuming machines have the same capabilities

    def reward(self, reference: str, response_event: DendriteResponseEvent) -> BatchRewardOutput:

        # Compute base scores (1 for match, 0 otherwise)
        scores = np.array([1 if prediction == reference else 0 for prediction in response_event.predictions])
        timings = np.array(response_event.timings)

        miners_locations = [get_location_from_maxmind(ip) for ip in response_event.ips]
        local_ip = get_my_public_ip()
        local_location = get_location_from_maxmind(local_ip)

        if local_location :
            local_lat, local_lon = local_location['latitude'], local_location['longitude']

            # Calculate distances
            distances = [
                haversine_distance(local_lat, local_lon, loc['latitude'], loc['longitude']) 
                if loc else self.avg_distance for loc in miners_locations
            ]
        else :
            distances = [self.avg_distance]*len(miners_locations)

        #adjust timing based on the distance to validator machine
        adjusted_timings = np.array([t - d/self.latency_speed for t, d in zip(timings, distances)])


        # Apply exponential decay based on combined decay factors, limiting the minimum to 0
        decayed_scores = np.maximum(0, scores * np.exp(-self.alpha * adjusted_timings))


        # Return BatchRewardOutput with decayed scores
        return BatchRewardOutput(
            rewards=decayed_scores,
            timings=timings
        )

class BaseRewardConfig(BaseModel):

    reward_model: ClassVar[DDoSDetectionRewardModel] = DDoSDetectionRewardModel()

    @classmethod
    def apply(
        cls,
        response_event: DendriteResponseEvent,
        reference: str,
        task: DDoSDetectionTask,
    ) -> DDoSDetectionRewardEvent:
        
        # Get the reward output
        batch_rewards_output = cls.reward_model.reward(reference, response_event)

        # Return the DDoSDetectionRewardEvent using the BatchRewardOutput
        return DDoSDetectionRewardEvent(
            task=task,
            rewards=batch_rewards_output.rewards.tolist(),
            timings=batch_rewards_output.timings.tolist(),
            uids=response_event.uids,
        )
