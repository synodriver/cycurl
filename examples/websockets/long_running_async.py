import asyncio
asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
from cycurl import requests


async def main():
    async with requests.AsyncSession() as s:
        ws = await s.ws_connect("wss://api.gemini.com/v1/marketdata/BTCUSD")
        print(
            "For websockets, you need to set $wss_proxy environment variable!\n"
            "$https_proxy will not work!"
        )
        print(">>> Websocket open!")

        async for message in ws:
            print(message)

        print("<<< Websocket closed!")


asyncio.run(main())
