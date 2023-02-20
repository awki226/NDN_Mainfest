#Purpose:Sends out the interest packet
import sys
import subprocess
import hashlib
from typing import Optional
from ndn.app import NDNApp
from ndn.encoding import Name, InterestParam, BinaryStr, FormalName, MetaInfo
import logging


logging.basicConfig(format='[{asctime}]{levelname}:{message}',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.INFO,
                    style='{')


app = NDNApp()

userFile = sys.argv[1]
with open( userFile,'rb') as file:
    packetData = file.read()
#print(packetData)
hash = hashlib.md5(packetData)
filename = hash.hexdigest()
consumer = subprocess.Popen(['sudo','python3.9', 'consumer2.py', filename])
@app.route('/testBytes')
def on_interest(name: FormalName, param: InterestParam, _app_param: Optional[BinaryStr]):
    print(f'>> I: {Name.to_str(name)}, {param}')
    content = packetData
    app.send_intrest(name, content=content, freshness_period=10000)
    print(f'<< D: {Name.to_str(name)}')
    app.parse_data(name, content=content, feshness_period=10000)
    print(MetaInfo(freshness_period=10000))
    print(f'Content: (size: {len(content)})')
    print('')
if __name__ == '__main__':
    app.run_forever()
