#数据信息帧
class info_packet:
    def __init__(self, capsule=None, pub_key1=None, pub_key2=None, verify_key=None, kfrag=None,
                 cfrag=None, CID=None, IP=None, selfport=None, check=None, leval=None, ttl=None, version=None):
        self.info = {"capsule": capsule,
                     "pub_key1": pub_key1,
                     "pub_key2": pub_key2,
                     "verify_key": verify_key,
                     "kfrag": kfrag,
                     "cfrag": cfrag,
                     "CID": CID,
                     "IP": IP,
                     "selfport": selfport,
                     "check": check,
                     "leval": leval,
                     "ttl": ttl,
                     "version": version,
                     }


#节点状态帧
class stat_packet:

    def __init__(self, id, To, Tu, state,IP=None):
        self.info = {"id": id, "To": To, "Tu": Tu, "state": state,"IP":IP}  # record the neighbors state
        # state:0:free 1:normal 2:overload