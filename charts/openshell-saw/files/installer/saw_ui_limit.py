"""Caps the connections to `openshell forward service` (SAW sandbox UI).

OpenShell allows 20 concurrent forward connections per sandbox and closes
the rest (RESOURCE_EXHAUSTED, "sandbox SSH connection limit reached",
NVIDIA/OpenShell#3494). A browser loading the OpenClaw control UI through
the route opens more than that at once, and the requests that lost came
back as 502/504 after 30 s. This TCP relay sits between oauth2-proxy and the
forward:

- at most MAX connections reach the forward; the others wait for a free one;
- while some wait, an HTTP keep-alive connection that has been idle for
  IDLE_PREEMPT seconds after an answer is closed to make room (an HTTP
  client opens a new one); WebSocket connections are never closed;
- a connection the forward closes or resets before answering is retried;
- a GET that gets no answer at all within ANSWER_WAIT is sent again on new
  connections, and the first answer wins.

  python3 saw_ui_limit.py LISTEN_PORT UPSTREAM_PORT [MAX] [--connect-only]

The container relay uses --connect-only: reconnect only before sending bytes,
never replay an HTTP request or WebSocket frame. The stable listener absorbs
brief stock-CLI restarts. Established WebSockets still close when upstream
authentication expires; clients must reconnect normally.
"""
import asyncio
import sys
import time


def log(message):
    print(message, file=sys.stderr, flush=True)

RETRIES = 8
BUFFER_LIMIT = 1 << 20
ANSWER_WAIT = 2.0       # seconds to wait for a first answer byte before giving up retries
IDLE_PREEMPT = 2.0      # seconds an answered keep-alive connection may hold a slot others wait for
HEDGES = 2              # extra connections for a repeatable request that gets no answer
HEDGE_TOTAL = 25.0      # seconds before giving up on such a request (the router allows 30)
# For a request that is not safe to send again and lost its answer.
_AMBIGUOUS_BODY = b"The sandbox closed the connection; the request may have been processed.\n"
AMBIGUOUS_ANSWER = (b"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\n"
                    b"Content-Length: %d\r\nConnection: close\r\n\r\n" % len(_AMBIGUOUS_BODY)) + _AMBIGUOUS_BODY


class Conn:
    """One client connection holding (or waiting for) a slot."""

    def __init__(self, websocket):
        self.websocket = websocket
        self.last = time.monotonic()
        self.answered = False       # the forward spoke last: no request in flight
        self.writers = []

    def touch(self, answered):
        self.last = time.monotonic()
        self.answered = answered

    def idle_for(self):
        return time.monotonic() - self.last

    def close(self):
        for w in self.writers:
            try:
                w.transport.abort()
            except Exception:
                pass


class Slots:
    """MAX upstream connections at a time; idle keep-alive ones give way.

    A client connection holds one slot for its upstream connection. A hedge
    (an extra connection for a repeatable request that got no answer) takes
    a slot of its own, only when one is free, and gives it back as soon as
    it is closed or becomes the connection that answered."""

    def __init__(self, limit):
        self.limit = limit
        self.active = set()
        self.extra = 0          # hedge connections open now
        self.cond = asyncio.Condition()

    def in_use(self):
        return len(self.active) + self.extra

    def try_extra(self):
        """Take a slot for a hedge connection if one is free; never waits.
        (No await: atomic within the event loop.)"""
        if self.in_use() >= self.limit:
            return False
        self.extra += 1
        return True

    async def release_extra(self, count=1):
        if count <= 0:
            return
        async with self.cond:
            self.extra = max(0, self.extra - count)
            self.cond.notify(count)

    def victim(self):
        idle = [c for c in self.active
                if not c.websocket and c.answered and c.idle_for() >= IDLE_PREEMPT]
        return min(idle, key=lambda c: c.last) if idle else None

    def describe(self):
        ws = sum(1 for c in self.active if c.websocket)
        busy = sum(1 for c in self.active if not c.websocket and not c.answered)
        idle = sorted(round(c.idle_for(), 1) for c in self.active if not c.websocket and c.answered)
        return (f"{self.in_use()}/{self.limit} in use: {ws} websocket, {busy} awaiting an answer, "
                f"{len(idle)} answered (idle s: {idle}), {self.extra} hedge")

    async def acquire(self, conn):
        start = time.monotonic()
        logged = 0.0
        async with self.cond:
            while self.in_use() >= self.limit:
                v = self.victim()
                if v is not None:
                    log(f"closing a keep-alive connection idle {v.idle_for():.1f}s to make room")
                    self.active.discard(v)
                    v.close()
                    break
                waited = time.monotonic() - start
                if waited - logged >= 5:
                    logged = waited
                    log(f"waiting {waited:.0f}s for a slot; {self.describe()}")
                try:
                    await asyncio.wait_for(self.cond.wait(), 0.25)
                except asyncio.TimeoutError:
                    pass
            self.active.add(conn)
        if time.monotonic() - start >= 1:
            log(f"got a slot after {time.monotonic() - start:.1f}s; {self.describe()}")

    async def release(self, conn):
        async with self.cond:
            if conn in self.active:
                self.active.discard(conn)
                self.cond.notify()


async def relay(reader, writer, conn, answered):
    """Copy until EOF, then half-close the other side."""
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            conn.touch(answered)
            writer.write(data)
            await writer.drain()
        if writer.can_write_eof():
            writer.write_eof()
    except (ConnectionError, OSError):
        pass


class Ambiguous(Exception):
    """The request reached the forward, but no answer came back: it may or
    may not have been processed, so it is not sent again."""


async def open_answering(upstream, sent, slots, retry_sent=True):
    """Connect to the forward and send the client's first bytes.

    Retries when nothing was sent (the connection failed), and, for a
    request that is safe to send again (replayable), when the forward
    closes or resets the connection without answering: that is how it
    refuses a connection past its limit. Any other request may already
    have been processed by then, so it is not sent again: Ambiguous."""
    for attempt in range(RETRIES + 1):
        try:
            ureader, uwriter = await asyncio.open_connection("127.0.0.1", upstream)
        except OSError:
            await asyncio.sleep(min(1.0, 0.2 * (attempt + 1)))
            continue
        if not retry_sent:
            try:
                uwriter.write(sent)
                await uwriter.drain()
            except (ConnectionError, OSError):
                uwriter.close()
                raise Ambiguous()
            # Once the connection exists, relay exactly once. Even a GET that
            # loses its response must not be replayed in connect-only mode.
            return ureader, uwriter, b""
        try:
            uwriter.write(sent)
            await uwriter.drain()
            # A refused forward connection closes (or resets) at once. A
            # request still being sent (a large body) gets no answer yet:
            # relay it.
            first = await asyncio.wait_for(ureader.read(65536), ANSWER_WAIT)
        except asyncio.TimeoutError:
            if not hedgeable(sent):
                log(f"no answer within {ANSWER_WAIT:.0f}s ({sent[:60]!r}); relaying without retries")
                return ureader, uwriter, b""
            return await hedge(upstream, sent, ureader, uwriter, slots)
        except (ConnectionError, OSError):
            first = b""
        if first:
            return ureader, uwriter, first
        uwriter.close()
        if not replayable(sent):
            raise Ambiguous()
        await asyncio.sleep(min(1.0, 0.2 * (attempt + 1)))
    return None, None, b""


def replayable(sent):
    """A complete GET/HEAD/OPTIONS request without a body (a WebSocket
    upgrade included: no answer means no upgrade): sending it again cannot
    repeat a change."""
    head = sent.split(b"\r\n\r\n", 1)
    return len(head) == 2 and not head[1] and sent.split(b" ", 1)[0] in (b"GET", b"HEAD", b"OPTIONS")


def hedgeable(sent):
    """A replayable request that is not a WebSocket upgrade: safe to send
    again on another connection while the first is still open."""
    return replayable(sent) and b"upgrade: websocket" not in sent.lower()


async def hedge(upstream, sent, ureader, uwriter, slots):
    """Found live: a request through the forward sometimes got no answer at
    all (no error, nothing in the forward's log) and the browser saw a 504.
    For a request that is safe to repeat, send it again on new connections
    and keep whichever answers first. Each extra connection needs a free
    slot (Slots.try_extra); without one, the request just keeps waiting on
    the connections it has."""
    pending = {asyncio.ensure_future(ureader.read(65536)): (ureader, uwriter)}
    extras = 0
    deadline = time.monotonic() + HEDGE_TOTAL
    try:
        for extra in range(HEDGES + 1):
            if extra < HEDGES:
                if slots.try_extra():
                    extras += 1
                    log(f"no answer within {ANSWER_WAIT:.0f}s ({sent[:60]!r}); "
                        f"sending it again ({extra + 1})")
                    try:
                        r, w = await asyncio.open_connection("127.0.0.1", upstream)
                        w.write(sent)
                        await w.drain()
                        pending[asyncio.ensure_future(r.read(65536))] = (r, w)
                    except (ConnectionError, OSError):
                        pass
                else:
                    log(f"no answer within {ANSWER_WAIT:.0f}s ({sent[:60]!r}); "
                        "no free slot to send it again")
            wait = ANSWER_WAIT * 2 if extra < HEDGES else max(0.0, deadline - time.monotonic())
            done, _ = await asyncio.wait(pending, timeout=wait, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                r, w = pending.pop(task)
                try:
                    data = task.result()
                except (ConnectionError, OSError):
                    data = b""
                if data:
                    for other, (_, ow) in pending.items():
                        other.cancel()
                        ow.close()
                    pending.clear()
                    return r, w, data
                w.close()
            if not pending:
                break
        for other, (_, ow) in pending.items():
            other.cancel()
            ow.close()
        log(f"no answer on {extras + 1} connections ({sent[:60]!r})")
        return None, None, b""
    finally:
        # The connection that answered (if any) runs on the client's own
        # slot; every extra one taken here is closed by now.
        await slots.release_extra(extras)


def handler(upstream, slots, retry_sent=True):
    async def handle(creader, cwriter):
        conn = None
        try:
            # The first bytes tell an HTTP request from a WebSocket upgrade,
            # and are what a retry resends.
            sent = await creader.read(65536)
            if not sent:
                return
            conn = Conn(b"upgrade: websocket" in sent.lower())
            conn.writers.append(cwriter)
            await slots.acquire(conn)
            try:
                ureader, uwriter, first = await open_answering(upstream, sent, slots, retry_sent)
            except Ambiguous:
                log("the forward closed without an answer; "
                    "not sending it again, it may have been processed")
                cwriter.write(AMBIGUOUS_ANSWER)
                await cwriter.drain()
                return
            if ureader is None:
                log("the forward refused the connection on every retry")
                return
            conn.writers.append(uwriter)
            conn.touch(bool(first))
            if first:
                cwriter.write(first)
                await cwriter.drain()
            await asyncio.gather(relay(creader, uwriter, conn, False),
                                 relay(ureader, cwriter, conn, True))
            uwriter.close()
        except (ConnectionError, OSError):
            pass
        finally:
            if conn is not None:
                await slots.release(conn)
            cwriter.close()
    return handle


async def main(listen, upstream, limit, retry_sent=True):
    server = await asyncio.start_server(handler(upstream, Slots(limit), retry_sent), "127.0.0.1", listen,
                                        limit=BUFFER_LIMIT)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    listen_port, upstream_port = int(sys.argv[1]), int(sys.argv[2])
    max_conns = int(sys.argv[3]) if len(sys.argv) > 3 else 10
    if len(sys.argv) > 5 or (len(sys.argv) == 5 and sys.argv[4] != "--connect-only"):
        raise SystemExit("expected LISTEN_PORT UPSTREAM_PORT [MAX] [--connect-only]")
    asyncio.run(main(listen_port, upstream_port, max_conns, retry_sent=len(sys.argv) < 5))
