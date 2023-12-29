import cycurl as m
from cycurl import AsyncCurl, Curl


async def test_init(server):
    ac = AsyncCurl()


async def test_add_handle(server):
    ac = AsyncCurl()
    c = Curl()
    c.setopt(m.CURLOPT_URL, "http://example.com")
    c.setopt(m.CURLOPT_WRITEFUNCTION, lambda x: len(x))
    fut = ac.add_handle(c)
    await fut


async def test_socket_action(server):
    ac = AsyncCurl()
    running = ac.socket_action(-1, 0)
    # assert running == 0
    c = Curl()
    c.setopt(m.CURLOPT_URL, "http://example.com")
    c.setopt(m.CURLOPT_WRITEFUNCTION, lambda x: len(x))
    fut = ac.add_handle(c)
    await fut
    running = ac.socket_action(-1, 0)
    # assert running == 1


async def test_process_data(server):
    ...
