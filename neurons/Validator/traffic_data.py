import websockets
import json
import asyncio

class TrafficData:
    def __init__(self, uri, feature_queue):
        self.uri = uri
        self.feature_queue = feature_queue

    async def listen(self):
        while True:
            try:
                async with websockets.connect(self.uri) as websocket:
                    print("Listening on WebSocket : pulling features...")
                    while True:
                        message = await websocket.recv()
                        await self.handle_message(message)
            except Exception as e:
                print(f"An error occurred: {e}")
                await asyncio.sleep(1)  # Wait before attempting to reconnect

    async def handle_message(self, message):
        try:
            features = json.loads(message)
            features['label'] = '0'
            # print(f"Received features: {features}")
            await self.feature_queue.put(features)  # Put features in the queue
        except json.JSONDecodeError:
            print(f"Received non-JSON message: {message}")

    async def start(self):
        await self.listen()

