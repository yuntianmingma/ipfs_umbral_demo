import pickle
import os
import threading
from select import select
from socket import *
class tracer:
    def __init__(self,id):
        self.id=id
        if os.path.exists("tracer.pkl"):
            with open("tracer.pkl","rb") as f:
                self.tracer=pickle.load(f)
        else:
            self.tracer={}
        print(self.tracer)


    def receive(self):
        '''
        {CID:IP}接收
        :return:
        '''
        IP=self.get_IP()
        PORT=7002
        self.sk = socket(AF_INET, SOCK_STREAM, 0)
        self.sk.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self.sk.setblocking(False)
        self.sk.bind((IP, PORT))
        self.sk.listen(10)
        # print("测试点到达")

        rlist = [self.sk]
        wlist = []
        xlist = []
        #msg_dict = {}
        msg_writer={}
        # 多路IO接收
        threading.Timer(10,self.save).start()
        while True:
            #print(rlist,wlist)
            rs, ws, xs = select(rlist, wlist, xlist,5)  # 阻塞调用（终止）
            #print(len(ws),len(rs))
            for r in rs:
                if r is self.sk:
                    c, addr = r.accept()
                    c.setblocking(False)
                    rlist.append(c)
                    #msg_dict[c] = []
                else:

                    data = r.recv(1024)

                    if data:
                        #print(data)

                        obj = pickle.loads(data)
                        print(obj)
                        # 处理
                        key_list=list(obj.keys())
                        if obj[key_list[0]]=='':
                            if r not in wlist:
                                wlist.append(r)
                            #查询IP
                            try:
                                print("返回过程")
                                target_IP=self.tracer[key_list[0]]
                                response=pickle.dumps({key_list[0]:target_IP})
                                msg_writer[r]=response
                            except :
                                msg_writer[r]=pickle.dumps({key_list[0]:''})

                        else:
                            self.tracer[key_list[0]]=obj[key_list[0]]


                            print("接收成功")
                            print(self.tracer)

                        continue

                    else:

                        print("关闭连接")

                        if r in wlist:
                            wlist.remove(r)
                        if r in ws:

                            ws.remove(r)
                        rlist.remove(r)
                        r.close()



            for w in ws:
                #print(w)
                try:
                    w.sendall(msg_writer[w])
                    print("返回数据")
                    msg_writer.pop(w)
                except:
                    wlist.remove(w)


            for e in xs:
                if e in rlist:
                    #print(e)
                    rlist.remove(e)
                    e.close()
                if e in wlist:
                    wlist.remove(e)
                    e.close()
    def save(self):
        with open("tracer.pkl","wb") as f:
            pickle.dump(self.tracer,f)
            print("保存成功")
        threading.Timer(10,self.save).start()








    def get_IP(self):
        try:
            s = socket(AF_INET, SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            return ip
        except Exception as e:
            print(e)
        finally:
            s.close()

if __name__=="__main__":
    tr=tracer(1)
    tr.receive()



