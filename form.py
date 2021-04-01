from ui_form import *
from iforest import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from datetime import *
from scapy.all import *
from sklearn import metrics
from sklearn.metrics import f1_score, recall_score, precision_score
import matplotlib.pyplot as plt
from matplotlib.pyplot import legend
import numpy as np
import sys

class Form(Ui_Form, QMainWindow):
    def __init__(self):
        super(self.__class__, self).__init__()
        self.setupUi(self)
        self.setFixedSize(self.size())
        self.action_PCAP.triggered.connect(self.openPCAP)
        self.action_Text.triggered.connect(self.openText)
        self.actionFind.triggered.connect(self.find)
        self.actionSave.triggered.connect(self.save)
        self.actionROC.triggered.connect(self.ROC)
        self.tableWidget.setColumnCount(6)
        self.tableWidget.setRowCount(8)
        self.tableWidget.setHorizontalHeaderLabels(
            ["Время", "Время (обычный вид)", "Размер", "Тип пакета",
             "Адрес отправителя", "Адрес получателя"])
        self.tableWidget_2.setColumnCount(7)
        self.tableWidget_2.setRowCount(8)
        self.tableWidget_2.setHorizontalHeaderLabels(
            ["Время", "Время (обычный вид)", "Количество", "Общий размер", "Оценка аномалии", "Аномалия", "Реально"])
        self.y = []
        self.scores = []

    def ticks(self, dt, c=False):
        if c:
            return int(math.ceil((dt - datetime(1, 1, 1)).total_seconds()) * 10000000)
        else:
            return int((dt - datetime(1, 1, 1)).total_seconds() * 10000000)

    def openPCAP(self):
        fname = QFileDialog.getOpenFileName(self, 'Открыть файл', '', 'PCAP files(*.pcap)')[0]
        if fname != '':
            scapy_cap = rdpcap(fname)
            self.tableWidget.setRowCount(len(scapy_cap))
            i = 0
            pckgCount = {}
            pckgSize = {}
            pckgTicks = {}
            minData = datetime.now()
            maxData = datetime(1, 1, 1)
            for packet in scapy_cap:
                self.tableWidget.setItem(i, 0,
                    QTableWidgetItem(str(self.ticks(datetime.fromtimestamp(packet.time)))))
                ft = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S.%f')
                self.tableWidget.setItem(i, 1, QTableWidgetItem(ft))
                t = datetime.strptime(str.split(ft, '.')[0], '%Y-%m-%d %H:%M:%S')
                if minData > t:
                    minData = t
                if maxData < t:
                    maxData = t
                if t in pckgCount:                
                    pckgCount[t] += 1
                    pckgSize[t] += len(packet)
                else:
                    pckgCount[t] = 1
                    pckgSize[t] = len(packet)
                    pckgTicks[t] = str(self.ticks(t, True))
                self.tableWidget.setItem(i, 2, QTableWidgetItem(str(len(packet))))
                if 'IP' in packet:
                    self.tableWidget.setItem(i, 3, QTableWidgetItem('IPv4'))
                    self.tableWidget.setItem(i, 4,
                        QTableWidgetItem(packet.getlayer(IP).src))
                    self.tableWidget.setItem(i, 5,
                        QTableWidgetItem(packet.getlayer(IP).dst))
                elif 'ARP' in packet:
                    self.tableWidget.setItem(i, 3, QTableWidgetItem('ARP'))
                    self.tableWidget.setItem(i, 4,
                        QTableWidgetItem(packet.psrc))
                    self.tableWidget.setItem(i, 5,
                        QTableWidgetItem(packet.pdst))
                i += 1

            
            self.tableWidget.resizeColumnsToContents()
            d = minData
            while d < maxData:
                d += timedelta(seconds=1)
                if not(d in pckgCount):
                    pckgCount[d] = 0
                    pckgSize[d] = 0
                    pckgTicks[d] = str(self.ticks(d, True))
                    
            i = 0
            self.tableWidget_2.setRowCount(len(pckgCount))
            self.test = []
            pckgCount = dict(sorted(pckgCount.items()))
            pckgSize = dict(sorted(pckgSize.items()))
            for key in pckgCount:
                self.tableWidget_2.setItem(i, 0,
                    QTableWidgetItem(pckgTicks[key]))
                self.tableWidget_2.setItem(i, 1,
                    QTableWidgetItem(str(key)))
                self.tableWidget_2.setItem(i, 2,
                    QTableWidgetItem(str(pckgCount[key])))
                self.tableWidget_2.setItem(i, 3,
                    QTableWidgetItem(str(pckgSize[key])))
                self.test.append([pckgCount[key], pckgSize[key]])
                i += 1
            self.tableWidget_2.resizeColumnsToContents()

    def openText(self):
        fname = QFileDialog.getOpenFileName(self, 'Открыть файл', '', 'Text files(*.txt)')[0]
        if fname != '':
            self.tableWidget.setRowCount(sum(1 for line in open(fname)))
            pckgCount = {}
            pckgSize = {}
            pckgTicks = {}
            i = 0
            minData = datetime.now()
            maxData = datetime(1, 1, 1)
            with open(fname, 'r') as f:
                for line in f.readlines():
                    spl = str.split(line, ';')
                    for j in range(len(spl)):
                        self.tableWidget.setItem(i, j, QTableWidgetItem(spl[j]))
                    t = datetime.strptime(str.split(spl[1], '.')[0], '%Y-%m-%d %H:%M:%S')
                    if minData > t:
                        minData = t
                    if maxData < t:
                        maxData = t
                    if t in pckgCount:                
                        pckgCount[t] += 1
                        pckgSize[t] += int(spl[2])
                    else:
                        pckgCount[t] = 1
                        pckgSize[t] = int(spl[2])
                        pckgTicks[t] = str(self.ticks(t, True))
                    i += 1
                    
            self.tableWidget.resizeColumnsToContents()
            d = minData
            while d < maxData:
                d += timedelta(seconds=1)
                if not(d in pckgCount):
                    pckgCount[d] = 0
                    pckgSize[d] = 0
                    pckgTicks[d] = str(self.ticks(d, True))
            i = 0
            self.tableWidget_2.setRowCount(len(pckgCount))
            self.test = []

            pckgCount = dict(sorted(pckgCount.items()))
            pckgSize = dict(sorted(pckgSize.items()))
            for key in pckgCount:
                self.tableWidget_2.setItem(i, 0,
                    QTableWidgetItem(pckgTicks[key]))
                self.tableWidget_2.setItem(i, 1,
                    QTableWidgetItem(str(key)))
                self.tableWidget_2.setItem(i, 2,
                    QTableWidgetItem(str(pckgCount[key])))
                self.tableWidget_2.setItem(i, 3,
                    QTableWidgetItem(str(pckgSize[key])))
                self.test.append([pckgCount[key], pckgSize[key]])
                i += 1
            self.tableWidget_2.resizeColumnsToContents()

    def find(self):
        forest = iforest(self.test[(len(self.test) // 20):(len(self.test) // 10)], 100, len(self.test) // 20)
        c = (2 * math.log(len(self.test) - 1) + 0.5772156649) - 2 * (len(self.test) - 1) / len(self.test)
        self.y = []
        self.scores = []
        for i in range(len(self.test)):
            h = 0
            for t in forest:
                h += path(self.test[i], t, 0)
            e = h / len(forest)
            rank = math.pow(2, -e / c)
            self.tableWidget_2.setItem(i, 4, QTableWidgetItem(str(rank)))
            self.y.append(rank)
            self.tableWidget_2.setItem(i, 5, QTableWidgetItem('1' if rank > 0.5 else '0'))
            self.tableWidget_2.setItem(i, 6, QTableWidgetItem(
                '1' if int(self.tableWidget_2.item(i, 3).text()) / (int(self.tableWidget_2.item(i, 2).text()) + 1) > 100 else '0'))
            self.scores.append(int(self.tableWidget_2.item(i, 6).text()))
            item = self.tableWidget_2.item(i, 5)
            if item.text() == '1':
                item.setBackground(Qt.red)

    def save(self):
        fname = QFileDialog.getSaveFileName(self, 'Сохранить файл')[0]
        if fname != '':
            with open(fname, 'w') as f:
                for i in range(self.tableWidget.rowCount()):
                    for j in range(self.tableWidget.columnCount() - 1):
                        f.write(self.tableWidget.item(i, j).text())
                        f.write(';')
                    f.write(self.tableWidget.item(i, self.tableWidget.columnCount() - 1).text())
                    f.write('\n')

    def ROC(self):
        if (len(self.y) > 0) and (len(self.y) > 0):
            r = 0.25
            y1 = []
            g = []
            while (r < 0.65):
                for y in self.y:
                    y1.append(1 if y > r else 0)
                fpr, tpr, thresholds = metrics.roc_curve(np.array(y1), np.array(self.scores))    
                g.append(plt.plot(fpr, tpr))
                self.textEdit.append('Параметр r: ' + str(r))
                self.textEdit.append('Precision: ' + str(precision_score(y1, self.scores, average='macro')))
                self.textEdit.append('Recall: ' + str(recall_score(y1, self.scores, average='macro')))
                self.textEdit.append('F-мера: ' + str(f1_score(y1, self.scores, average='macro')))
                self.textEdit.append('')
                y1 = []
                r += 0.05
            
            plt.show()

