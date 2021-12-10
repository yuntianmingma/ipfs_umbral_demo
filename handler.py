from collections import deque

from umbral import keys, pre, signing, config, params, kfrags, cfrags
from dataframe import *
from parameter import *
import uuid
from random import shuffle, random

class Handler:

    def __init__(self,mywindow):
        self.MyWindow=mywindow


    def handler_info(self,obj):
        if(obj.info['check']==0):#确认CID正确，返回capsule(测试重点：IP和capsule是否存在)
            print("接收到check为0")
            capsule = self.MyWindow.record[obj.info["CID"]]
            capsule = capsule.to_bytes()
            pub_key2 = self.MyWindow.pub_key.to_bytes()
            verify_key = self.MyWindow.verifying_key.to_bytes()
            IP=self.MyWindow.get_self_IP()
            responce = info_packet(capsule=capsule, CID=obj.info["CID"], check=1, IP=IP,
                                   pub_key2=pub_key2, verify_key=verify_key)

            self.MyWindow.send(packet=responce, des_IP=obj.info["IP"])


        elif(obj.info['check']==1):#保存capsule,发出正式请求消息
            print("接收到check为1")
            capsule = obj.info["capsule"]
            param = params.UmbralParameters(self.MyWindow.curve)
            capsule = pre.Capsule.from_bytes(capsule, param)

            pub_key2 = obj.info["pub_key2"]
            pub_key2 = keys.UmbralPublicKey.from_bytes(pub_key2)
            verify_key = obj.info["verify_key"]
            verify_key = keys.UmbralPublicKey.from_bytes(verify_key)
            capsule.set_correctness_keys(pub_key2, self.MyWindow.pub_key, verify_key)
            if obj.info["CID"] in self.MyWindow.record:#作用，记录record？
                self.MyWindow.record[obj.info["CID"]].append(capsule)
            else:
                self.MyWindow.record[obj.info["CID"]] = [capsule]
            pub_key = self.MyWindow.pub_key.to_bytes()
            IP = self.MyWindow.get_self_IP()
            responce = info_packet(CID=obj.info["CID"], IP=IP, pub_key1=pub_key, check=2, ttl=0, leval=LEVEL)
            self.MyWindow.send(packet=responce, des_IP=obj.info["IP"])


        elif(obj.info['check']==2):#接收正式请求并生成frag
            print("接收到check为2")
            capsule = self.MyWindow.record[obj.info["CID"]]
            pub_key1 = keys.UmbralPublicKey.from_bytes(obj.info["pub_key1"])
            kfrags_ = pre.generate_kfrags(self.MyWindow.pri_key, pub_key1, THRESHOLD, SPLIT_NUMBER, self.MyWindow.signer)
            capsule = capsule.to_bytes()
            pub_key1 = pub_key1.to_bytes()
            pub_key2 = self.MyWindow.pub_key.to_bytes()
            verify_key = self.MyWindow.verifying_key.to_bytes()
            IP_ID = self.MyWindow.IP_FIND()#查找临近节点
            version = uuid.uuid1()


            visited_id = deque(maxlen=len(IP_ID))
            for kfrag in kfrags_:
                kfrag = kfrag.to_bytes()
                flag = 0

                for ip, id in IP_ID.items():
                    if id not in visited_id:

                        if (self.MyWindow.neighbor_state[id][2] == 0 and ip != obj.info["IP"]):
                            packet = info_packet(capsule=capsule, kfrag=kfrag, CID=obj.info["CID"],
                                                 IP=obj.info["IP"], pub_key1=pub_key1, pub_key2=pub_key2,
                                                 verify_key=verify_key, check=3, ttl=0, leval=obj.info["leval"],
                                                 version=version)
                            self.MyWindow.send(packet, ip)
                            visited_id.append(id)
                            if (len(visited_id) == len(IP_ID)):
                                visited_id.clear()
                            flag = 1
                            break
                if (flag == 0):
                    for ip, id in IP_ID.items():
                        if id not in visited_id:

                            if (self.MyWindow.neighbor_state[id][2] == 1 and ip != obj.info["IP"]):
                                packet = info_packet(capsule=capsule, kfrag=kfrag, CID=obj.info["CID"],
                                                     IP=obj.info["IP"], pub_key1=pub_key1, pub_key2=pub_key2,
                                                     verify_key=verify_key, check=3, ttl=0, leval=obj.info["leval"],
                                                     version=version)
                                self.MyWindow.send(packet, ip)
                                visited_id.append(id)
                                if (len(visited_id) == len(IP_ID)):
                                    visited_id.clear()
                                flag = 1
                                break
                if (flag == 0):
                    for ip, id in IP_ID.items():
                        if id not in visited_id:

                            if (self.MyWindow.neighbor_state[id][2] == 2 and ip != obj.info["IP"]):
                                packet = info_packet(capsule=capsule, kfrag=kfrag, CID=obj.info["CID"],
                                                     IP=obj.info["IP"], pub_key1=pub_key1, pub_key2=pub_key2,
                                                     verify_key=verify_key, check=3, ttl=0, leval=obj.info["leval"],
                                                     version=version)
                                self.MyWindow.send(packet, ip)
                                visited_id.append(id)
                                if (len(visited_id) == len(IP_ID)):
                                    visited_id.clear()
                                flag = 1
                                break

        elif(obj.info['check']==3):#接收frag生成cfrag(当前状态的锁定问题)
            print("接收到check为3")
            self.MyWindow.lock3.acquire()

            if (self.MyWindow.state.info['state'] == 2):
                ip_id = self.MyWindow.IP_FIND()
                flag = 0
                random_node = list(ip_id.items())
                shuffle(random_node)
                for ip, id in random_node:
                    if (self.MyWindow.neighbor_state[id][2] == 0 and ip != obj.info["IP"]):
                        # add ttl
                        obj.info["ttl"] += 1
                        self.MyWindow.send(obj, ip)
                        flag = 1
                        break

                if (flag == 0):
                    for ip, id in random_node:
                        if (self.MyWindow.neighbor_state[id][2] == 1 and ip != obj.info["IP"]):
                            # add ttl
                            obj.info["ttl"] += 1
                            self.MyWindow.send(obj, ip)
                            flag = 1
                            break

                if (flag == 0):
                    for ip, id in random_node:
                        if (self.MyWindow.neighbor_state[id][2] == 2 and ip != obj.info["IP"]):
                            # add ttl
                            obj.info["ttl"] += 1
                            self.MyWindow.send(obj, ip)

                            break




            else:

                self.MyWindow.lock.acquire_write()
                # old_va=self.task_queue.qsize()
                temp_list = []
                for i in range(self.MyWindow.task_queue.qsize()):
                    a = self.MyWindow.task_queue.get()
                    temp_list.append(a)

                for i in range(len(temp_list)):
                    temp_list[i][0] -= 1
                    self.MyWindow.task_queue.put(temp_list[i])

                prior_value = obj.info["ttl"] + 0 + obj.info["leval"]
                obj = [-prior_value, self.MyWindow.index, obj]
                self.MyWindow.task_queue.put(obj)
                self.MyWindow.index += 1
                #print("current task number:", self.MyWindow.task_queue.qsize())

                if (self.MyWindow.task_queue.qsize() == self.MyWindow.state.info["To"] + 5):

                    self.MyWindow.state.info["state"] = 2
                    # self.lock.release()
                    ip_id = self.MyWindow.IP_FIND()
                    for ip, id in ip_id.items():
                        packet = stat_packet(id=self.MyWindow.state.info["id"], To=self.MyWindow.state.info["To"],
                                             Tu=self.MyWindow.state.info["Tu"], state=2)
                        self.MyWindow.send(packet, ip)
                elif (self.MyWindow.task_queue.qsize() == self.MyWindow.state.info["Tu"] + 5):

                    self.MyWindow.state.info['state'] = 1
                    # self.lock.release()
                    ip_id = self.MyWindow.IP_FIND()
                    for ip, id in ip_id.items():
                        packet = stat_packet(id=self.MyWindow.state.info["id"], To=self.MyWindow.state.info["To"],
                                             Tu=self.MyWindow.state.info["Tu"], state=1)
                        self.MyWindow.send(packet, ip)

                self.MyWindow.lock.release()
            self.MyWindow.lock3.release()

        else:#接收cfrag
            self.MyWindow.lock2.acquire()
            print("接收到cfrag")
            if obj.info["version"] in self.MyWindow.old_version:
                self.MyWindow.lock2.release()
                return
            if obj.info["CID"] not in self.MyWindow.tempo_cfrags:
                # cfrag handle
                print("accumulating cfrag.............")
                temp = obj.info["cfrag"]
                version = obj.info["version"]
                temp = cfrags.CapsuleFrag.from_bytes(temp)
                self.MyWindow.tempo_cfrags[obj.info["CID"]] = {version: [temp]}




            else:

                temp = obj.info["cfrag"]
                version = obj.info["version"]
                temp = cfrags.CapsuleFrag.from_bytes(temp)
                if version in self.MyWindow.tempo_cfrags[obj.info["CID"]]:
                    self.MyWindow.tempo_cfrags[obj.info["CID"]][version].append(temp)

                else:
                    self.MyWindow.tempo_cfrags[obj.info["CID"]][version] = [temp]

                if len(self.MyWindow.tempo_cfrags[obj.info["CID"]][version]) >= THRESHOLD:

                    # print(self.tempo_cfrags[obj.info["CID"]])
                    capsule = self.MyWindow.record[obj.info["CID"]].pop()
                    # print(capsule)
                    for cfrag in self.MyWindow.tempo_cfrags[obj.info["CID"]][version]:
                        capsule.attach_cfrag(cfrag)
                    print("begin decrypting")
                    self.MyWindow.download_and_decrypt(obj.info["CID"], capsule)
                    self.MyWindow.tempo_cfrags[obj.info["CID"]].pop(version)
                    self.MyWindow.old_version.add(version)
            self.MyWindow.lock2.release()


    def handler_stat(self,obj):
        print("接收临近节点状态信息:", obj.info["id"], "\n")
        self.MyWindow.neighbor_state[obj.info["id"]] = [obj.info["To"], obj.info["Tu"], obj.info["state"]]
        #如果是初始化状态信息，回复
        if(obj.info["IP"]!=None):
            packet=stat_packet(id=self.MyWindow.state.info["id"], To=self.MyWindow.state.info["To"],
                                         Tu=self.MyWindow.state.info["Tu"], state=self.MyWindow.state.info["state"])
            self.MyWindow.send(packet,obj.info["IP"])
