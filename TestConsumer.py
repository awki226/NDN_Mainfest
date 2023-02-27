#Purpose:Consumes the intrest packets
import asyncio
import os

from ndn.app import NDNApp
from ndn.types import InterestNack, InterestTimeout
from ndn.encoding import Name
from ndn.security import KeychainDigest

from manifest import Manifest


async def on_data(interest_name, data):
    print(f'Received data for interest: {interest_name}')

    # Verify manifest
    manifest_name = interest_name + [Name.from_str('/manifest')]

    try:
        manifest_data = await app.get_data(manifest_name, must_be_fresh=True, can_be_prefix=False)
        manifest = Manifest.from_bytes(manifest_data.content)
        manifest.verify(data)
    except Exception as e:
        print(f'Manifest verification failed: {e}')
        return

    # Print data
    print(f'Received data: {data.content}')


async def on_timeout(interest_name):
    print(f'Timeout for interest: {interest_name}')


async def on_nack(interest_name, reason, **_kwargs):
    print(f'Nacked interest {interest_name} with reason: {reason}')


async def express_interest(name: Name):
    try:
        app.express_interest(name, on_data=on_data, on_timeout=on_timeout, on_nack=on_nack)
    except (ValueError, InterestNack, InterestTimeout) as e:
        print(f'Failed to express interest {name}: {e}')


if __name__ == '__main__':
    app = NDNApp()

    # Set up keychain
    keychain = KeychainDigest()
    keychain.import_key('./key.pub')
    keychain.import_cert('./cert.pem')

    # Express interest in data
    name = Name.from_str('/example/test/data')
    manifest_name = name + [Name.from_str('/manifest')]

    asyncio.run(express_interest(manifest_name))
    asyncio.run(express_interest(name))

    app.run_forever()
