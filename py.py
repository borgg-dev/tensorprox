from requests import get

def get_public_ip():
    return get('https://api.ipify.org').text.strip()

print(get_public_ip())

