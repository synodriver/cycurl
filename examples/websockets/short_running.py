import asyncio

import cycurl

URL = "ws://echo.websocket.events"


ws = cycurl.WebSocket().connect(URL)
ws.send(b"Foo")
reply = ws.recv()
print(reply)


async def async_examples():
    async with cycurl.AsyncSession() as s, s.ws_connect(URL) as ws:
        await ws.send(b"Bar")
        reply = await ws.recv()
        print(reply)


asyncio.run(async_examples())
