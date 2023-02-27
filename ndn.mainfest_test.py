import asyncio
import os
from ndn.app import NDNApp
from ndn.encoding import Name, Component
from ndn.types import InterestNack, InterestTimeout, Interest
from manifest import Manifest

async def publish_data(app: NDNApp):
    # Open file and read data
    filename = "Plaintext4000bytes.txt"
    with open(filename, "rb") as f:
        data = f.read()

    # Create data name and content object
    name = Name.from_str("/example/test/data")
    content = bytes(data)

    # Create manifest
    manifest = Manifest(name)
    manifest.add_digest(sha256digest(content))

    # Set the file digest
    file_digest = sha256digest(content)
    manifest.set_file_digest((len(content), file_digest))

    # Create data packet with manifest metadata
    data_name = name + [Component.from_version(0)]
    data_obj = Data(name=data_name, content=content, metainfo=MetaInfo())
    data_obj.metainfo.content_type = ContentType.BLOB
    data_obj.metainfo.final_block_id = Component.from_version(0)
    data_obj.manifest = manifest

    # Register prefix and publish data packet
    def on_interest(int_name: Name, _int_param: InterestParam, app_param: Any):
        app.put_data(data_obj)
        print("Data published: ", data_name)
    
    app.route(data_name, on_interest)
    app.run_forever()
