# tensorprox/core/fetch_nonce_key.py
from aiohttp import web
import subprocess
import tempfile
import os
import asyncio

async def verify_quote(quote_bytes):
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(quote_bytes)
        quote_path = f.name
    result = await asyncio.create_subprocess_exec(
        "gramine-verify-quote", "--quote", quote_path,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    await result.wait()
    os.unlink(quote_path)
    return result.returncode == 0

async def attest(request):
    data = await request.post()
    quote = data['quote'].file.read()
    if await verify_quote(quote):
        return web.Response(text=os.environ.get("ROUND_NONCE", ""))
    else:
        raise web.HTTPForbidden()

def create_app():
    app = web.Application()
    app.router.add_post('/attest', attest)
    return app

async def start_nonce_server():
    app = create_app()
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', 8443)
    await site.start()
    print("Nonce server started on port 8443")
    # Keep running forever
    while True:
        await asyncio.sleep(3600)