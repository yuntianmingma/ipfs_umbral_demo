import re
import sys
import threading
from collections import defaultdict
from queue import PriorityQueue

from PyQt5.QtWidgets import QApplication, QMainWindow, QDialog, QFileDialog, QMessageBox
from test import *
from setting import *
from dataframe import *
import ipfshttpclient
from umbral import keys, pre, signing, config, params, kfrags, cfrags
from datetime import datetime
from subprocess import Popen, PIPE
import platform
import time
import os
import pickle
from cryptography import fernet
import json
from socket import *
from parameter import *
from select import select
from handler import Handler
from worker import Worker
from update import Update_Method
from fair_lock import RWLock

config.set_default_curve()


class DlgWindow(QDialog, Ui_Dialog):
    def __init__(self, parent_window, parent=None):
        super(DlgWindow, self).__init__(parent)
        self.setupUi(self)
        self.parent_window = parent_window
        # print(self.parent_window.overload_state.text)

        self.overload.setText(self.parent_window.overload_state.text())
        self.underload.setText(self.parent_window.underload_state_.text())
        # print(self.parent_window.overload_state.text())

        self.setWindowTitle("参数设置")
        self.confirm.clicked.connect(self.confirm_clicked)
        self.cancel.clicked.connect(self.cancel_clicked)

    def confirm_clicked(self):
        overload_threshold = self.overload.text()
        underload_threshold = self.underload.text()
        seed = str(self.seed.toPlainText()).split("\n")  # 新增种子节点
        # print(seed)
        # 字符检测
        if not (self.is_allowed_number(underload_threshold) and self.is_allowed_number(overload_threshold) and int(
                overload_threshold) > int(underload_threshold)):
            return
        if not (self.is_ipfs_id(seed)):
            return
        if not os.path.exists("conf"):
            setting = {"overload": overload_threshold, "underload": underload_threshold, "seed": seed}
            with open("conf", "w") as f:
                json.dump(setting, f)
            self.close()
        else:
            with open("conf", "r") as f:
                conf = json.load(f)
                if (seed[0] == ''):
                    seed = conf["seed"]
                else:
                    seed.extend(conf["seed"])

            setting = {"overload": overload_threshold, "underload": underload_threshold, "seed": seed}
            with open("conf", "w") as f:
                json.dump(setting, f)
            self.close()
        # self.parent_window.overload_state.setText(overload_threshold)
        # self.parent_window.underload_state_.setText(underload_threshold)
        # 更新种子节点，重启后生效
        QMessageBox.information(self, "配置变更", "重启后生效", QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)

    def cancel_clicked(self):
        self.close()

    def is_allowed_number(self, number):
        '''

        :param number:
        :return:
        '''
        try:

            number = float(number)

            if (number.is_integer() and 20 <= number <= 80):
                return True
            else:
                QMessageBox.critical(self, "参数错误", "阈值应为20到80的整数", QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
                return False

        except Exception as e:
            print(e)
            QMessageBox.critical(self, "参数错误", "阈值应为20到80的整数", QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
            return False

    def is_ipfs_id(self, id_list: list) -> bool:
        '''
        需补充长度限制,正则匹配
        示例：/ip4/10.134.145.47/tcp/4001/ipfs/Qmc7QPThKSZ6UuaPEZ8afPWW5FTQR6eq8aLVNZfYkB4RLy
        :param id_list:
        :return:
        '''
        pattern = r"^/ip4/(?:[0-9]{1,3}\.){3}[0-9]{1,3}/tcp/([0-9]+)/ipfs/([0-9a-zA-Z]{46})$"
        if id_list[0] == '':
            return True
        for id in id_list:

            if not (re.match(pattern, id)):
                QMessageBox.critical(self, "节点ID错误", "请输入正确节点ID", QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
                return False
        return True


'''
主窗口
'''


class MyWindow(QMainWindow, Ui_MainWindow):
    curve = params.Curve(714)

    def __init__(self, parent=None):
        super(MyWindow, self).__init__(parent)
        self.setupUi(self)
        self.startbutton.clicked.connect(self.startbutton_click)
        self.end_button.clicked.connect(self.endbutton_click)

        self.upload.clicked.connect(self.uploadbutton_click)
        self.download.clicked.connect(self.downloadbutton_click)
        self.file_search.clicked.connect(self.file_searchbutton_click)
        self.init_button.clicked.connect(self.init)
        self.parameter_setting_button.clicked.connect(self.settingbutton_click)

        # 加载基础默认配置
        with open("conf", "r") as f:
            conf = json.load(f)
            self.overload_state.setText(conf["overload"])
            self.underload_state_.setText(conf["underload"])
            self.overload_state.setReadOnly(True)
            self.underload_state_.setReadOnly(True)
        # 加载密钥
        with open("key_pair.pkl", "rb") as f:
            key_pair = pickle.load(f)
            pub_key = keys.UmbralPublicKey.from_bytes(key_pair["pub_key"])
            verifying_key = keys.UmbralPublicKey.from_bytes(key_pair["verifying_key"])
            pri_key = keys.UmbralPrivateKey.from_bytes(key_pair["pri_key"])
            signing_key = keys.UmbralPrivateKey.from_bytes(key_pair["signing_key"])
            self.pri_key = pri_key
            self.pub_key = pub_key
            self.signing_key = signing_key
            self.verifying_key = verifying_key
            self.signer = signing.Signer(self.signing_key)

        self.log.append("本机公钥:" + self.pub_key.hex() + "\n")
        QApplication.processEvents()

        # 加载上传记录
        self.record = {}
        if os.path.exists("data.pkl") and os.path.getsize("data.pkl") > 0:
            param = params.UmbralParameters(self.curve)
            with open("data.pkl", "rb") as f:
                records = pickle.load(f)
                for record in records:

                    for key in record.keys():
                        capsule = pre.Capsule.from_bytes(record[key], param)
                        record[key] = capsule
                        self.record.update(record)

        self.log.append("上传记录加载完毕\n")
        QApplication.processEvents()

        self.set_dialog = DlgWindow(self)  # 参数设置对话框
        self.handler = Handler(self)  # 处理函数
        self.neighbor_state = defaultdict(list)
        self.lock = RWLock()  # 优先队列输入和输出的互斥锁,采用公平锁
        self.lock2 = threading.Lock()  # cfrag处理锁
        self.lock3 = threading.Lock()  # frag处理锁
        self.task_queue = PriorityQueue()  # 优先队列

        self.worker = Worker(self)  # 工作线程
        self.updator = Update_Method(self)

        self.tempo_cfrags = {}  # cfrag临时存储字典

        self.index = 0  # 任务索引号
        self.old_version = set()  # 老版本集合
        self.task_completed = 0  # 任务完成数量

        # 启动IPFS功能
        self.log.append("IPFS服务准备启动\n")
        # 检测系统
        self.log.append("当前操作系统：" + platform.system() + "\n")
        QApplication.processEvents()
        try:
            self.result1 = Popen(["taskkill", "/f", "/im", "ipfs.exe"], stderr=PIPE)
            self.result1.wait(0.5)
            self.result2 = Popen(["ipfs", "daemon"], stdout=PIPE)
            self.log.append("正在启动IPFS......\n")
            QApplication.processEvents()
            time.sleep(5)
            self.log.append("IPFS服务启动成功\n")
            QApplication.processEvents()

            self.client = ipfshttpclient.connect("/ip4/127.0.0.1/tcp/5001")
            node_info = self.client.id()

            # 状态初始化
            self.state = stat_packet(id=node_info["ID"], To=int(self.overload_state.text()),
                                     Tu=int(self.underload_state_.text()), state=0)
            if (self.task_queue.qsize() >= self.state.info["To"]):
                self.state.info["state"] = 2
            elif (self.task_queue.qsize() <= self.state.info["Tu"]):
                self.state.info["state"] = 0
            else:
                self.state.info["state"] = 1

            self.log.append("本机IPFS ID:" + node_info["ID"] + "\n")
            QApplication.processEvents()
            # 种子节点初始化
            self.seed_setting()
            self.ev1 = threading.Event()
            self.ev1.set()
            # 进度展示
            self.finished.setReadOnly(True)
            self.waiting.setReadOnly(True)
            self.node_state.setReadOnly(True)
            threading.Thread(target=self.interface_show).start()

        except Exception as e:
            print(e)
            self.log.append("连接IPFS失败\n")
            self.result1 = Popen(["taskkill", "/f", "/im", "ipfs.exe"], stderr=PIPE)
            self.ev1.clear()
            QApplication.processEvents()

    def startbutton_click(self):

        # 邻近节点扫描
        '''try:
                self.neighbor_scanner()
            except:
                self.log.append("无法连接邻近节点\n")
                QApplication.processEvents()
                return'''

        # 启动节点功能，提供重加密服务,设置监听套接字
        self.log.append("开始监听任务\n")
        self.monitor()
        self.worker.start()
        self.updator.start()

    def endbutton_click(self):
        # 日志打包后清除
        try:

            # 关闭IPFS服务
            self.client.close()
            self.log.append("终止IPFS服务\n")
            Popen(["taskkill", "/f", "/im", "ipfs.exe"], stdout=PIPE)
            self.log.append("终止监听\n")
            self.ev1.clear()
            QApplication.processEvents()
            curDatetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            if not os.path.exists(os.getcwd() + "\logs"):
                os.mkdir(os.getcwd() + "\\logs")
            with open(".\logs" + "\log_" + curDatetime + ".log", "w", encoding='utf-8') as file:
                file.write(str(self.log.toPlainText()))

        except Exception as e:

            print(e)

    def settingbutton_click(self):

        self.set_dialog.show()

    def uploadbutton_click(self):
        # 选择文件路径
        file_path = self.filename.text()
        curDatetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log.append("上传： " + file_path.split("/")[-1] + " " + curDatetime + "\n")
        QApplication.processEvents()
        with open(file_path, "rb") as file:
            # 文件加密
            symmetric_key = fernet.Fernet.generate_key()
            upload_data_bytes = file.read()
            encrpted_file = fernet.Fernet(symmetric_key).encrypt(upload_data_bytes)
            encrypted_key, capsule = pre.encrypt(self.pub_key, symmetric_key)
            upload = encrpted_file + b"   " + encrypted_key
            # 上传记录文件
            res = self.client.add_bytes(upload)
            # 上传CID:IP关联
            sk = socket()
            IP = self.get_self_IP()
            sk.connect((TRACER_IP, 7002))
            packet = pickle.dumps({res: IP})
            sk.sendall(packet)
            sk.close()
            # 保存上传数据
            curDatetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.log.append("上传文件返回CID:" + res + " " + curDatetime + "\n")
            QApplication.processEvents()
            self.record.update({res: capsule})
            capsule = capsule.to_bytes()
            upload_record = {res: capsule}
            try:
                if not os.path.exists("data.pkl"):
                    list = []
                    with open("data.pkl", "wb") as f:
                        list.append(upload_record)
                        pickle.dump(list, f)
                else:
                    fr = open("data.pkl", "rb")
                    old_pickle = pickle.load(fr)
                    fr.close()
                    old_pickle.append(upload_record)
                    with open("data.pkl", "wb") as f:
                        pickle.dump(old_pickle, f)
                self.log.append("文件上传记录已保存")
                QApplication.processEvents()
            except Exception as e:
                print(e)

    def downloadbutton_click(self):
        '''
        实际上存在IP与文件绑定的问题，需要先向tracer请求,之后发出请求命令
        :return:
        '''

        CID = self.CID.text()
        IP = self.get_self_IP()
        torrent = pickle.dumps({CID: ""})
        try:
            sk = socket()
            sk.connect((TRACER_IP, 7002))
            sk.sendall(torrent)
            data = sk.recv(1024)
            res = pickle.loads(data)
            print(res)
            sk.close()
        except:
            QMessageBox.critical(self, "Tracer连接错误", "无法获得目的IP", QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
            return
        # 判断返回值的可靠性
        if list(res.values())[0] == '':
            QMessageBox.critical(self, "CID错误", "文件CID不存在", QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
            return
        # 发送初始请求
        request = info_packet(CID=CID, IP=IP, check=0)
        self.send(request, list(res.values())[0])

    def download_and_decrypt(self, CID, capsule):
        encrypt_data = self.client.cat(CID).split(b"   ")
        file_data = encrypt_data[0]
        key_data = encrypt_data[1]
        key_clear_data = pre.decrypt(key_data, capsule, self.pri_key)
        decrypt_res = fernet.Fernet(key_clear_data).decrypt(file_data)
        file = decrypt_res.decode("utf-8")
        print(file)
        QApplication.processEvents()

    def file_searchbutton_click(self):
        # 进入文件筛选页面
        # get_dir_path=QFileDialog.getExistingDirectory(self,"选取文件夹","C:/")
        # self.filename.setText(str(get_dir_path))
        get_filename_path, ok = QFileDialog.getOpenFileName(self,
                                                            "选择文件",
                                                            "C:/",
                                                            "All Files (*);;Text Files (*.txt)")
        if ok:
            self.filename.setText(str(get_filename_path))

    def init(self):
        # 确认初始化弹窗，警告密钥丢失风险
        answer = QMessageBox.question(self, "确认", "生成新的Umbral公私钥对吗？", QMessageBox.Yes | QMessageBox.No)
        if answer == QMessageBox.Yes:
            self.log.append("生成新的Umbral公私钥对\n")
            QApplication.processEvents()
            key_pair = {}
            # create asymmetrical key for the node,this is unique for each node
            self.pri_key = keys.UmbralPrivateKey.gen_key()
            self.pub_key = self.pri_key.get_pubkey()
            # create the key for digital signature
            self.signing_key = keys.UmbralPrivateKey.gen_key()
            self.verifying_key = self.signing_key.get_pubkey()
            self.signer = signing.Signer(self.signing_key)
            # save the keys as binary file
            key_pair["pri_key"] = self.pri_key.to_bytes()
            key_pair["pub_key"] = self.pub_key.to_bytes()
            key_pair["signing_key"] = self.signing_key.to_bytes()
            key_pair["verifying_key"] = self.verifying_key.to_bytes()
            with open("key_pair.pkl", "wb") as f:
                pickle.dump(key_pair, f)
            curDatetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.log.append("密钥对生成成功 " + curDatetime + "\n")
            QApplication.processEvents()

    def monitor(self):
        '''
        准备优先队列，IP与文件的绑定问题
        完成IO多路复用设计
        :return:
        '''

        t_monitor = threading.Thread(target=self.monitor_impl, name="monitor")
        t_monitor.setDaemon(True)
        t_monitor.start()
        # print(t_monitor.name)

    def connection_handler(self, object):
        '''
        根据object类型进行处理
        :param objet:
        :return:
        '''
        if isinstance(object, info_packet):
            threading.Thread(target=self.handler.handler_info, args=(object,)).start()
        if isinstance(object, stat_packet):
            threading.Thread(target=self.handler.handler_stat, args=(object,)).start()

    def send(self, packet, des_IP):
        '''

        :param IP:
        :return:
        '''
        packet = pickle.dumps(packet)
        sk = socket(AF_INET, SOCK_STREAM, 0)
        sk.connect((des_IP, 7001))
        sk.sendall(packet)
        sk.close()

    def IP_FIND(self):
        '''
        查找当前连接节点IP，IPV6过滤
        :return:
        '''
        try:
            IP_ID = {}
            peers_info = self.client.swarm.peers()['Peers']
            for peer in peers_info:
                ip = peer['Addr'].split("/")[2]
                id = peer['Peer']
                ip_id = {ip: id}
                IP_ID.update(ip_id)
            return IP_ID
        except:
            QMessageBox.critical(self, "节点错误", "当前无连接节点", QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
            return

    def get_self_IP(self):
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

    def monitor_impl(self):
        IP = self.get_self_IP()
        # print("测试点到达")
        self.log.append("本机IP：%s,通讯端口：%s\n" % (IP, PORT))
        QApplication.processEvents()

        self.sk = socket(AF_INET, SOCK_STREAM, 0)
        self.sk.setblocking(False)
        self.sk.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self.sk.bind((IP, PORT))
        self.sk.listen(10)
        # print("测试点到达")

        rlist = [self.sk]
        wlist = []
        xlist = []
        # msg_dict = {}
        # 多路IO接收
        while (True):
            if not self.ev1.wait(0): break
            rs, ws, xs = select(rlist, wlist, xlist, 5)  # 阻塞调用（终止）
            for r in rs:
                if r is self.sk:
                    c, addr = r.accept()
                    self.log.append("收到连接请求，来自：" + addr[0] + "：" + str(addr[1]))
                    QApplication.processEvents()
                    c.setblocking(False)
                    rlist.append(c)
                    # msg_dict[c] = []
                else:

                    data = r.recv(1024)

                    if data:

                        obj = pickle.loads(data)
                        # 处理线程
                        self.connection_handler(obj)

                        continue
                    else:
                        rlist.remove(r)
                        r.close()

        self.sk.close()
        self.log.append("成功终止监听\n")

    def neighbor_scanner(self):
        '''
        节点状态交换
        :return:
        '''
        ip_id = self.IP_FIND()
        print(ip_id)
        IP = self.get_self_IP()
        packet = stat_packet(id=self.state.info["id"], To=self.state.info["To"], Tu=self.state.info["Tu"],
                             state=self.state.info["state"], IP=IP)
        for ip, id in ip_id.items():
            if id not in self.neighbor_state:
                self.send(packet, ip)

    def seed_setting(self):
        '''
        更新IPFS bootstrap list
        :return:
        '''
        with open("conf", "r") as f:
            try:
                conf = json.load(f)
                # print(conf["seed"])
                self.client.bootstrap.rm(self.client.bootstrap.list()["Peers"])
                self.client.bootstrap.add(conf["seed"])
            except Exception as e:
                print(e)
                QMessageBox.critical(self, "种子节点设置", "种子节点设置错误", QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)

    def closeEvent(self, a0: QtGui.QCloseEvent) -> None:
        # print("关闭窗口")
        try:

            # 关闭IPFS服务
            self.client.close()
            self.log.append("终止IPFS服务\n")
            Popen(["taskkill", "/f", "/im", "ipfs.exe"], stdout=PIPE)
            #self.log.append("终止监听\n")
            self.ev1.clear()
            QApplication.processEvents()
            curDatetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            if not os.path.exists(os.getcwd() + "\logs"):
                os.mkdir(os.getcwd() + "\\logs")
            with open(".\logs" + "\log_" + curDatetime + ".log", "w", encoding='utf-8') as file:
                file.write(str(self.log.toPlainText()))

        except Exception as e:

            print(e)

    def interface_show(self):
        '''
        单一线程循环监控显示
        :return:
        '''
        while True:
            if not self.ev1.wait(0):
                print("退出")
                break

            self.waiting.setText(str(self.task_queue.qsize()))
            self.finished.setText(str(self.task_completed))
            if():
            palatte=self.node_state.palette()
            palatte.setColor(QtGui.QPalette.Text,QtGui.QColor.fromRgb(0,255,0))
            self.node_state.setPalette(palatte)
            self.node_state.setText(str(self.state.info["state"]))


if __name__ == '__main__':
    app = QApplication(sys.argv)
    myWin = MyWindow()
    myWin.show()

    sys.exit(app.exec_())
