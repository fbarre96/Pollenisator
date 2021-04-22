
class NotificationService:

    clients = set()
    def start(self):
        start_server = websockets.serve(self.ws_handler, '0.0.0.0', 8577)
        loop = asyncio.get_event_loop()
        loop.run_until_complete(start_server)
        loop.run_forever()

    async def register(self, ws):
        self.clients.add(ws)
    
    async def unregister(self, ws):
        self.clients.remove(ws)
    
    async def send_to_clients(self, message):
        if self.clients:
            await asyncio.wait([client.send(message) for client in self.clients])
    
    async def ws_handler(self, ws, uri):
        await self.register(ws)
        try:
            await self.distribute(ws)
        finally:
            await self.unregister(ws)
    
    async def distribute(self, ws):
        async for message in ws:
            await self.send_to_clients(message)



