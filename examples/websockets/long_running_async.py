#!/usr/bin/env python3
import asyncio

import cycurl


async def main() -> None:
    """Long running WSS example"""
    async with cycurl.AsyncSession() as session:
        async with session.ws_connect(
            "wss://api.gemini.com/v1/marketdata/BTCUSD",
        ) as ws:
            print(
                "For websockets, you need to set $wss_proxy environment variable!\n"
                "$https_proxy will not work!"
            )
            print(">>> Websocket open!")

            try:
                async for message in ws:
                    print(message)
            except (KeyboardInterrupt, asyncio.CancelledError):
                pass

        print("<<< Websocket closed!")


asyncio.run(main())
