import json
import pickle
import re
import threading
import time
import uuid
from socket import *
import os

import ipfshttpclient

from dataframe import *
from queue import PriorityQueue, Empty
from update import Update_Method
from fair_lock import RWLock
def get_self_IP():
    '''

    :return: ip
    '''
    try:
        s = socket(AF_INET, SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        return ip
    except Exception as e:
        print(e)
    finally:
        s.close()
IP=get_self_IP()
print(IP)



#client=ipfshttpclient.connect("/ip4/127.0.0.1/tcp/5001")
#result=client.bootstrap.add(["/ip4/10.134.145.47/tcp/4001/ipfs/Qmc7QPThKSZ6UuaPEZ8afPWW5FTQR6eq8aLVNZfYkB4RLy"])
#re=client.bootstrap.rm(client.bootstrap.list()["Peers"])
#print(result)




