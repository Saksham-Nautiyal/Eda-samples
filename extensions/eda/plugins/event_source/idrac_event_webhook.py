import asyncio
import json
import logging
import ssl
from typing import Any

from aiohttp import web

logger = logging.getLogger(__name__)
routes = web.RouteTableDef()


@routes.post(r"/{endpoint:.*}")
async def webhook(request: web.Request) -> web.Response:
    """Return response to webhook request."""
    try:
        payload = await request.json()
    except json.JSONDecodeError as exc:
        logger.warning("Wrong body request: failed to decode JSON payload: %s", exc)
        raise web.HTTPBadRequest(text="Invalid JSON payload") from None
    
    # Include headers in the payload
    headers = dict(request.headers)
    headers.pop("Authorization", None)
    
    # Flatten the 'Events' list
    if 'Events' in payload:
        events = payload.pop('Events')
        for event in events:
            for key, value in event.items():
                payload[key] = value
    
    # Flatten the 'Oem' dictionary
    if 'Oem' in payload:
        oem = payload.pop('Oem')
        for oem_key, oem_value in oem.items():
            for oem_subkey, oem_subvalue in oem_value.items():
                payload[oem_subkey] = oem_subvalue
    
    # Add headers to the payload
    payload['headers'] = headers
    
    # Get the client IP address
    idrac_ip = request.remote
    request.app["idrac_ip"] = idrac_ip
    payload['idrac_ip'] = idrac_ip
    
    # Optionally, put the payload into the queue
    await request.app["queue"].put(payload)
    
    async def response_body():
        # Yield the JSON response
        yield json.dumps(payload).encode('utf-8')
        
    return web.Response(body=response_body(), content_type='application/json')


async def main(queue: asyncio.Queue, args: dict[str, Any]) -> None:
    """Receive events via webhook."""
    if "port" not in args:
        msg = "Missing required argument: port"
        raise ValueError(msg)

    app = web.Application()
    app["queue"] = queue

    app.add_routes(routes)

    if args.get("verify_certs", True):
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        if args.get("certfile") and args.get("keyfile"):
            ssl_context.load_cert_chain(args["certfile"], args["keyfile"])
    else:
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE


    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(
        runner,
        args.get("host", "0.0.0.0"),  # noqa: S104
        args.get("port"),
        ssl_context=ssl_context if args.get("verify_certs", True) else None
    )
    await site.start()

    try:
        await asyncio.Future()
    except asyncio.CancelledError:
        logger.info("Webhook Plugin Task Cancelled")
    finally:
        await runner.cleanup()


class MockQueue:
    """A fake queue."""

    def __init__(self):
        self.queue = asyncio.Queue()

    async def put(self, event: dict) -> None:
        """Put event in the queue."""
        self.queue.put_nowait(event)


if __name__ == "__main__":
    asyncio.run(
        main(
            MockQueue().queue,
            {
                "host": "0.0.0.0",
                "port": 5000,
                "verify_certs": False,  # Set to False to disable SSL certificate verification
                "certfile": "cert.pem",  # Optional: Path to SSL certificate file
                "keyfile": "server.key",    # Optional: Path to SSL private key file
            },
        ),
    )
