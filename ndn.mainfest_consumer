#Gets interest from producer via a tcp-stream
import logging 
import ndn.utils 
import hashlib 
import subprocess 
from multiprocessing import Process 
import os 
from pathlib import Path 
import glob 
from contextlib import redirect_stdout 
from ndn.app import NDNApp 
from ndn.types import InterestNack, InterestTimeout, InterestCanceled, ValidationFailure 
from ndn.encoding import Name, Component, InterestParam, BinaryStr, FormalName, MetaInfo 
 
logging.basicConfig(format='[{asctime}]{levelname}:{message}', 
                    datefmt='%Y-%m-%d %H:%M:%S', 
                    level=logging.INFO, 
                    style='{') 
 
 
app = NDNApp() 

        print(f'Received Data Name: {Name.to_str(data_name)}')
        print(meta_info)
        print(bytes(content) if content else None)
        for (i=0; i < len(content); i++)
            hash = hashlib.sha256(content)
            filename = hash.hexdigest() + ".txt"
            print('Writing to file name ', filename)
            sxfile = open(filename, 'wb')
            sxfile.write(content)
            sxfile.close()
   except InterestNack as e:
        print(f'Nacked with reason={e.reason}')
    except InterestTimeout:
        print(f'Timeout')
    except InterestCanceled:
        print(f'Canceled')
    except ValidationFailure:
        print(f'Data failed to validate')



if __name__ == '__main__':
    app.run_forever(after_start=main())
                                                              50,0-1        Bot
