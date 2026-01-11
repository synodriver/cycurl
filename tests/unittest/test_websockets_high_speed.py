"""Test high-speed WebSocket message handling.

This test ensures that the WebSocket client doesn't crash when receiving
messages at very high speed, which is especially important for free-threading
Python (cp313t) where there's no GIL.
"""

import asyncio
import threading
import time
import pytest

try:
    import websockets
    HAS_WEBSOCKETS = True
except ImportError:
    HAS_WEBSOCKETS = False


@pytest.fixture
def high_speed_ws_server():
    """Create a WebSocket server that sends messages at high speed."""
    if not HAS_WEBSOCKETS:
        pytest.skip("websockets library not installed")
    
    server_started = threading.Event()
    server = None
    
    async def handler(websocket, path):
        """Send messages as fast as possible."""
        for i in range(200):
            await websocket.send(f"Message {i}")
            # No sleep - send as fast as possible
    
    async def run_server():
        nonlocal server
        server = await websockets.serve(handler, "127.0.0.1", 0)
        server_started.set()
        await asyncio.Future()  # Run forever
    
    def server_thread():
        asyncio.run(run_server())
    
    thread = threading.Thread(target=server_thread, daemon=True)
    thread.start()
    server_started.wait(timeout=5)
    
    if not server_started.is_set():
        pytest.fail("Server failed to start")
    
    # Get the actual port
    port = list(server.sockets)[0].getsockname()[1]
    
    class ServerInfo:
        url = f"ws://127.0.0.1:{port}"
    
    yield ServerInfo
    
    # Cleanup
    if server:
        server.close()


def test_high_speed_messages(high_speed_ws_server):
    """Test that WebSocket doesn't crash with high-speed messages."""
    from cycurl import WebSocket
    
    msg_count = 0
    start_time = time.time()
    
    def on_message(ws: WebSocket, message):
        nonlocal msg_count
        msg_count += 1
        if msg_count >= 100:
            ws.close()
    
    def on_error(ws: WebSocket, error: Exception):
        pytest.fail(f"WebSocket error: {error}")
    
    def on_open(ws: WebSocket):
        pass
    
    def on_close(ws: WebSocket, code: int, reason: str):
        pass
    
    ws = WebSocket(
        on_open=on_open,
        on_close=on_close,
        on_message=on_message,
        on_error=on_error,
    )
    
    # This should not crash even with very fast messages
    ws.run_forever(high_speed_ws_server.url)
    
    elapsed = time.time() - start_time
    
    # Verify we received at least 100 messages
    assert msg_count >= 100, f"Expected at least 100 messages, got {msg_count}"
    
    # Verify it completed in reasonable time (should be fast)
    assert elapsed < 10, f"Took too long: {elapsed}s"
    
    print(f"Successfully received {msg_count} messages in {elapsed:.3f}s ({msg_count/elapsed:.1f} msg/s)")


def test_continuous_high_speed_messages(high_speed_ws_server):
    """Test sustained high-speed message reception without crashes."""
    from cycurl import WebSocket
    
    msg_count = 0
    error_occurred = False
    
    def on_message(ws: WebSocket, message):
        nonlocal msg_count
        msg_count += 1
        # Process all 200 messages
        if msg_count >= 200:
            ws.close()
    
    def on_error(ws: WebSocket, error: Exception):
        nonlocal error_occurred
        error_occurred = True
        pytest.fail(f"WebSocket error: {error}")
    
    ws = WebSocket(
        on_message=on_message,
        on_error=on_error,
    )
    
    # This should handle all 200 messages without crashing
    ws.run_forever(high_speed_ws_server.url)
    
    assert not error_occurred, "Error occurred during processing"
    assert msg_count >= 200, f"Expected at least 200 messages, got {msg_count}"


def test_yielding_occurs():
    """Verify that the yielding mechanism is in place.
    
    This is a code inspection test to ensure the fix is present.
    """
    from cycurl.requests.websockets import WebSocket
    import inspect
    
    # Get the source code of run_forever
    source = inspect.getsource(WebSocket.run_forever)
    
    # Verify the yielding code is present
    assert "time.sleep(0)" in source, "Yielding mechanism not found in run_forever"
    assert "YIELD_INTERVAL" in source, "YIELD_INTERVAL constant not found"
    assert "YIELD_MESSAGE_COUNT" in source, "YIELD_MESSAGE_COUNT constant not found"
    assert "message_count" in source, "message_count tracking not found"
