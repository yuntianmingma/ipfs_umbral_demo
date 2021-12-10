import copy
import math
import threading

from dataframe import stat_packet


class Update_Method(threading.Thread):
    def __init__(self,mywindow):
        super().__init__()
        self.MyWindow=mywindow
    def run(self) -> None:
        '''
        主要涉及定时阈值更新算法以及终止判断
        :return:
        '''

        #计时启动
        self.timer=threading.Timer(30,self.update)
        self.timer.start()
        #print(self.timer)
        threading.Thread(target=self.flag_monitor).start()
        print("计时开始")



    def update(self):

            print("开始阈值更新")

            self.MyWindow.lock.acquire_write()
            sum_To = 0
            sum_Tu = 0
            neighbor_state = copy.deepcopy(self.MyWindow.neighbor_state)
            for key, value in neighbor_state.items():
                sum_To += value[0]
                sum_Tu += value[1]
            avg_To = sum_To / len(neighbor_state)  # 取整
            avg_Tu = sum_Tu / len(neighbor_state)

            old_To = self.MyWindow.state.info["To"]
            old_Tu = self.MyWindow.state.info["Tu"]
            # 更新跳过判断
            if (abs(old_To - avg_To) <= 1 or abs(old_Tu - avg_To) <= 1):#调整
                self.MyWindow.lock.release()
                self.timer=threading.Timer(30,self.update)
                self.timer.start()
                return

            self.MyWindow.state.info["To"] += (avg_To - old_To) * 0.5
            self.MyWindow.state.info["Tu"] += (avg_Tu - old_Tu) * 0.5
            self.MyWindow.state.info["Tu"] = math.ceil(self.MyWindow.state.info["Tu"])
            self.MyWindow.state.info["To"] = math.ceil(self.MyWindow.state.info["To"])

            if (self.MyWindow.task_queue.qsize() >= self.MyWindow.state.info["To"]):
                self.MyWindow.state.info["state"] = 2
            elif (self.MyWindow.task_queue.qsize() <= self.MyWindow.state.info["Tu"]):
                self.MyWindow.state.info["state"] = 0
            else:
                self.MyWindow.state.info["state"] = 1
            # self.lock.release()
            ip_id = self.MyWindow.IP_FIND()
            for ip, id in ip_id.items():
                packet = stat_packet(id=self.MyWindow.state.info["id"], To=self.MyWindow.state.info["To"],
                                     Tu=self.MyWindow.state.info["Tu"], state=self.MyWindow.state.info["state"])
                self.MyWindow.send(packet, ip)
            self.MyWindow.lock.release()

            self.timer=threading.Timer(30,self.update)
            self.timer.start()

    def flag_monitor(self):
        while True:
            if not self.MyWindow.ev1.wait(0):
                self.timer.cancel()
                print("结束阈值更新")
                break

