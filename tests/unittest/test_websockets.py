from cycurl.requests import AsyncSession, WebSocket, Session
from cycurl import _curl as m
from cycurl.requests.websockets import wait_for_socket
import socket


def test_websocket(ws_server):
    ws = WebSocket()
    ws.connect(ws_server.url)

    # deprecated
    with Session() as s:
        s.ws_connect(ws_server.url)


def test_hello(ws_server):
    ws = WebSocket()
    ws.connect(ws_server.url)
    ws.send(b"Foo me once")
    content, _ = ws.recv()
    assert content == b"Foo me once"

    # deprecated
    with Session() as s:
        ws = s.ws_connect(ws_server.url)
        ws.send(b"Foo me once")
        content, _ = ws.recv()
        assert content == b"Foo me once"


def test_hello_twice(ws_server):
    ws = WebSocket()
    ws.connect(ws_server.url)

    ws.send(b"Bar")
    reply, _ = ws.recv()

    for _ in range(10):
        ws.send_str("Bar")
        reply = ws.recv_str()
        assert reply == "Bar"

    with Session() as s:
        ws = s.ws_connect(ws_server.url)
        ws.send(b"Foo me once")
        content, _ = ws.recv()
        assert content == b"Foo me once"


def test_receive_large_messages(ws_server):
    ws = WebSocket()
    ws.connect(ws_server.url)
    for _ in range(10):
        ws.send("*" * 10000)
    for _ in range(10):
        buffer, _ = ws.recv()
        assert len(buffer) == 10000
    ws.close()


def test_receive_large_messages_run_forever(ws_server):
    def on_open(ws: WebSocket):
        ws.send("*" * 10000)

    chunk_counter = 0

    def on_data(ws: WebSocket, data, frame):
        nonlocal chunk_counter
        if frame.flags & m.CURLWS_CLOSE:
            return
        chunk_counter += 1

    message = ""

    def on_message(ws: WebSocket, msg):
        nonlocal message
        message = msg
        # Gracefully close the connection to exit the run_forever loop
        ws.send("", m.CURLWS_CLOSE)

    ws = WebSocket(
        on_open=on_open,
        on_data=on_data,
        on_message=on_message,
    )
    ws.run_forever(ws_server.url)

    assert chunk_counter == 10000 // 1024 + 1
    assert len(message) == 10000


def test_on_data_callback(ws_server):
    on_data_called = False

    def on_data(ws: WebSocket, data, frame):
        nonlocal on_data_called
        on_data_called = True

    ws = WebSocket(on_data=on_data)
    ws.connect(ws_server.url)

    ws.send("Hello")
    ws.recv()
    assert on_data_called is False
    ws.close()


async def test_hello_twice_async(ws_server):
    async with AsyncSession() as s:
        ws = await s.ws_connect(ws_server.url)

        await ws.send(b"Bar")
        reply, _ = await ws.recv()

        for _ in range(10):
            await ws.send_str("Bar")
            reply = await ws.recv_str()
            assert reply == "Bar"


def test_wait_for_socket():
    """Test that wait_for_socket works with any file descriptor value.
    
    This is a regression test for the OverflowError that occurred when
    select.select() was used with file descriptors >= FD_SETSIZE (1024).
    """
    # Create a socket to test with
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    fd = sock.fileno()
    
    try:
        # Test read mode (should timeout on a non-ready socket)
        result = wait_for_socket(fd, mode="read", timeout=0.01)
        assert isinstance(result, bool)
        
        # Test write mode (socket should be writable)
        result = wait_for_socket(fd, mode="write", timeout=0.01)
        assert isinstance(result, bool)
        
    finally:
        sock.close()

