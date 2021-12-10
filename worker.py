import threading
from dataframe import *
from umbral import keys, pre, signing, config, params, kfrags, cfrags
from queue import Empty

class Worker(threading.Thread):
    def __init__(self,mywindow):
        super().__init__()

        self.MyWindow=mywindow

    def run(self) -> None:
        while True:
            if not self.MyWindow.ev1.wait(0): break
            self.MyWindow.lock.acquire_write()
            try:
                obj=self.MyWindow.task_queue.get(block=True,timeout=0.5)
            except Empty:
                print("当前为空")
                self.MyWindow.lock.release()
                continue
            if (self.MyWindow.task_queue.qsize() == self.MyWindow.state.info["To"] - 5):
                self.MyWindow.state.info["state"] = 1

                ip_id = self.MyWindow.IP_FIND()
                for ip, id in ip_id.items():
                    packet = stat_packet(id=self.MyWindow.state.info["id"], To=self.MyWindow.state.info["To"], Tu=self.MyWindow.state.info["Tu"],
                                         state=1)
                    self.MyWindow.send(packet, ip)
            elif (self.MyWindow.task_queue.qsize() == self.MyWindow.state.info["Tu"] - 5):

                self.MyWindow.state.info['state'] = 0

                ip_id = self.MyWindow.IP_FIND()
                for ip, id in ip_id.items():
                    packet = stat_packet(id=self.MyWindow.state.info["id"], To=self.MyWindow.state.info["To"],
                                         Tu=self.MyWindow.state.info["Tu"], state=0)
                    self.MyWindow.send(packet, ip)
            self.MyWindow.lock.release()

            obj = obj[2]
            kfrag = obj.info["kfrag"]
            kfrag = kfrags.KFrag.from_bytes(kfrag)

            capsule = obj.info["capsule"]
            param = params.UmbralParameters(self.MyWindow.curve)
            capsule = pre.Capsule.from_bytes(capsule, param)

            pub_key1 = obj.info["pub_key1"]
            pub_key1 = keys.UmbralPublicKey.from_bytes(pub_key1)
            pub_key2 = obj.info["pub_key2"]
            pub_key2 = keys.UmbralPublicKey.from_bytes(pub_key2)
            verify_key = obj.info["verify_key"]
            verify_key = keys.UmbralPublicKey.from_bytes(verify_key)

            capsule.set_correctness_keys(pub_key2, pub_key1, verify_key)
            print(capsule)
            cfrag = pre.reencrypt(kfrag, capsule)
            print("CFrag finish", cfrag)

            cfrag = cfrag.to_bytes()

            cfrag_packet = info_packet(cfrag=cfrag, CID=obj.info["CID"], version=obj.info["version"])
            self.MyWindow.send(packet=cfrag_packet, des_IP=obj.info["IP"])
        print("退出")





