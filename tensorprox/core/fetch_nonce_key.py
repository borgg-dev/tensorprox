# tensorprox/core/fetch_nonce_key.py
from aiohttp import web
import subprocess
import tempfile
import os
import asyncio

EXPECTED_MRENCLAVE = os.environ.get("EXPECTED_MRENCLAVE")  # Set this in your environment

async def verify_quote(quote_bytes):
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(quote_bytes)
        quote_path = f.name
    proc = await asyncio.create_subprocess_exec(
        "gramine-verify-quote", "--quote", quote_path,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()
    os.unlink(quote_path)
    if proc.returncode != 0:
        return False
    # Parse MRENCLAVE from stdout
    for line in stdout.decode().splitlines():
        if "MRENCLAVE" in line:
            mrenclave = line.split(":")[1].strip().replace("0x", "")
            return mrenclave == EXPECTED_MRENCLAVE
    return False

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

if __name__ == "__main__":
    asyncio.run(start_nonce_server())