import redis

# Connect to Redis
redis_client = redis.StrictRedis(host='localhost', port=6379, db=0)

# Check if a key exists in Redis
key = "validators_completion"
if redis_client.exists(key):
    print(f"Key '{key}' exists in Redis.")
else:
    print(f"Key '{key}' does not exist in Redis.")
