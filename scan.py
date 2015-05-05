#!/usr/bin/env python 
'''
Author: Abishek
Mail : ashek70@gmail.com

'''
import sys
from PyQt4 import QtCore, QtGui, uic
from PyQt4.QtGui import *
from PyQt4.QtCore import *
import os
import signal
import re
import datetime
import subprocess as sp
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *



global interface,stopmon
stopmon = 0
unique = [] 
aps = {} # dictionary to store unique
global p_row,p_no
p_no = 0


def Exit():
    #os.system('airmon-ng stop mon0')
    exit(0)


def Initial_mon():
    global interface
    #interface = 'mon0'

    a = subprocess.call(['airmon-ng','start','wlan1'])
    if a >= 0:
        interface = 'mon0'
    else:
        print "could start monitoring mode"
        Exit()




#Start Gui---------------------------------------------------------------#
qtCreatorFile = "scan.ui" # Enter file here.

Ui_MainWindow, QtBaseClass = uic.loadUiType(qtCreatorFile)

class MyApp(QtGui.QMainWindow, Ui_MainWindow):
    def __init__(self):
        QtGui.QMainWindow.__init__(self)
        Ui_MainWindow.__init__(self)
        self.setupUi(self)
        self.setWindowTitle('IDPS')
        self.mon_start_button.clicked.connect(self.Mon)
        self.mon_stop_button.clicked.connect(self.stop_mon)
        self.wt = workerThread()
        self.connect(self.wt,SIGNAL("mon_success"),self.threadDone,Qt.DirectConnection)
        self.ids_start_button.clicked.connect(self.start_ids)
    def Mon(self):
        self.wt.start()

    def stop_mon(self):
        global stopmon
        stopmon = 1
    #start ids module
    def start_ids(self):
        e = sp.Popen(['python', 'ids.py'])
        if e >= 0:
            window.hide()

    def threadDone(self):
        global p_no,p_row,p_col
        global bssid,ssid,channel,enc,ssid
        p_no += 1
        p_col = 0
        no = QtGui.QTableWidgetItem("%d" %p_no )
        self.mon_table.setItem(p_row, p_col , no)
        p_col = p_col + 1
        bs = QtGui.QTableWidgetItem("%s" %bssid )
        self.mon_table.setItem(p_row, p_col , bs)
        p_col = p_col + 1
        ch = QtGui.QTableWidgetItem("%d" %int(channel))
        self.mon_table.setItem(p_row, p_col , ch)
        p_col = p_col + 1
        en = QtGui.QTableWidgetItem("%s" %enc )
        self.mon_table.setItem(p_row, p_col , en)
        p_col = p_col + 1
        ss = QtGui.QTableWidgetItem("%s" %ssid )
        self.mon_table.setItem(p_row, p_col , ss)
        self.mon_table.show()
        #self.mon_table.reset()
        self.p_num = p_no
        self.mon_lcd.display(self.p_num)
        p_row += 1


class workerThread(QThread):
    def __int__(self, parent=None):
        super(workerThread,self).__init__(parent)

    def run(self):
        global stopmon
        def sniffAP(p):
            global p_row,p_no,p_col
            global bssid,ssid,channel,enc,ssid
            if ( (p.haslayer(Dot11Beacon) or p.haslayer(Dot11ProbeResp)) and not aps.has_key(p[Dot11].addr3)):
                ssid       = p[Dot11Elt].info
                bssid      = p[Dot11].addr3
                channel    = int( ord(p[Dot11Elt:3].info))
                capability = p.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}\
                        {Dot11ProbeResp:%Dot11ProbeResp.cap%}")

                # Check for encryption
                if re.search("privacy", capability): enc = 'Y'
                else: enc  = 'N'

                # Save discovered AP
                aps[p[Dot11].addr3] = enc

                self.emit(SIGNAL("mon_success"))
        while (stopmon != 1):
            sniff(iface=interface,prn=sniffAP)
        stopmon = 0

if __name__ == "__main__":
    global p_row
    p_row = 0
    Initial_mon()
    app = QtGui.QApplication(sys.argv)
    window = MyApp()
    window.show()
    sys.exit(app.exec_())