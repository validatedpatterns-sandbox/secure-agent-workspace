"""Shared UI transport recovery without resending application requests."""
import asyncio
import types

import pytest


def transport(ab):
    module = types.ModuleType("saw_ui_limit")
    exec(compile(ab.SANDBOX_UI_LIMIT_PY, "saw_ui_limit.py", "exec"), module.__dict__)
    return module


@pytest.mark.parametrize("method", [b"GET", b"POST"])
def test_connect_only_queues_during_cli_listener_restart(ab, method):
    module = transport(ab)

    async def scenario():
        seen = []

        async def upstream(reader, writer):
            seen.append(await reader.readuntil(b"\r\n\r\n"))
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            await writer.drain()
            writer.close()

        reservation = await asyncio.start_server(upstream, "127.0.0.1", 0)
        port = reservation.sockets[0].getsockname()[1]
        reservation.close()
        await reservation.wait_closed()
        front = await asyncio.start_server(module.handler(port, module.Slots(16), retry_sent=False), "127.0.0.1", 0)

        async def restart():
            # Reproduce a token-expiry CLI restart: no listener for two seconds.
            await asyncio.sleep(2.1)
            return await asyncio.start_server(upstream, "127.0.0.1", port)

        restarting = asyncio.create_task(restart())
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", front.sockets[0].getsockname()[1])
            request = method + b" / HTTP/1.1\r\nHost: fixture\r\nContent-Length: 0\r\n\r\n"
            writer.write(request)
            await writer.drain()
            response = await asyncio.wait_for(reader.read(), 8)
            writer.close()
            assert response.startswith(b"HTTP/1.1 200")
            assert seen == [request]
        finally:
            up = await restarting
            up.close()
            front.close()
            await up.wait_closed()
            await front.wait_closed()

    asyncio.run(scenario())


@pytest.mark.parametrize("method", [b"GET", b"POST"])
def test_connect_only_never_replays_after_any_request_was_sent(ab, method):
    module = transport(ab)

    async def scenario():
        seen = []

        async def upstream(reader, writer):
            seen.append(await reader.readuntil(b"\r\n\r\n"))
            writer.close()  # An upstream may have processed it: never replay.

        up = await asyncio.start_server(upstream, "127.0.0.1", 0)
        front = await asyncio.start_server(module.handler(up.sockets[0].getsockname()[1], module.Slots(16), retry_sent=False), "127.0.0.1", 0)
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", front.sockets[0].getsockname()[1])
            writer.write(method + b" / HTTP/1.1\r\nHost: fixture\r\n\r\n")
            await writer.drain()
            assert await asyncio.wait_for(reader.read(), 3) == b""
            writer.close()
            assert len(seen) == 1
        finally:
            up.close()
            front.close()
            await up.wait_closed()
            await front.wait_closed()

    asyncio.run(scenario())


def test_expired_websocket_is_closed_and_client_can_reconnect(ab):
    module = transport(ab)

    async def scenario():
        seen = []
        expired = asyncio.Event()

        async def upstream(reader, writer):
            seen.append(await reader.readuntil(b"\r\n\r\n"))
            writer.write(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n")
            await writer.drain()
            if len(seen) == 1:
                await expired.wait()
            writer.close()

        up = await asyncio.start_server(upstream, "127.0.0.1", 0)
        front = await asyncio.start_server(module.handler(up.sockets[0].getsockname()[1], module.Slots(16), retry_sent=False), "127.0.0.1", 0)
        try:
            for attempt in range(2):
                reader, writer = await asyncio.open_connection("127.0.0.1", front.sockets[0].getsockname()[1])
                writer.write(b"GET /ws HTTP/1.1\r\nHost: fixture\r\nUpgrade: websocket\r\n\r\n")
                await writer.drain()
                assert b"101" in await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 3)
                if attempt == 0:
                    expired.set()
                assert await asyncio.wait_for(reader.read(), 3) == b""
                writer.close()
                assert len(seen) == attempt + 1
        finally:
            up.close()
            front.close()
            await up.wait_closed()
            await front.wait_closed()

    asyncio.run(scenario())
