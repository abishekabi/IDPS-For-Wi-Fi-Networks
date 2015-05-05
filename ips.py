#!/usr/bin/env python
import sys
from PyQt4 import QtCore, QtGui, uic
from PyQt4.QtCore import *
from PyQt4.QtGui import *
import os
import subprocess as sp
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

global fkMAC, fktext,source,baseMAC,stop_fkvar,stop_unvar
stop_fkvar = 0
stop_unvar = 0
source = '11:22:33:44:55:66'
'''
fkMAC = 'FC:DD:55:03:D4:F1'
unauthMAC = 'FC:DD:55:03:D4:F1'
baseMAC = '12:34:56:78:98:76'
'''
interface = 'mon0'

def importvar():
	global baseMAC,fkMAC,unauthMAC
	f1 = open("alog.txt",'r')
	a = f1.readlines()
	baseMAC = a[0].strip(' \t\r\n')
	fkMAC =  a[1].strip(' \t\r\n')
	unauthMAC = a[2].strip(' \t\r\n')

	print baseMAC,fkMAC,unauthMAC


qtCreatorFile = "ips.ui"  # Enter file here.

Ui_MainWindow, QtBaseClass = uic.loadUiType(qtCreatorFile)

class MyApp(QtGui.QMainWindow, Ui_MainWindow):
	def __init__(self):
		global baseMAC,fkMAC,unauthMAC
		QtGui.QMainWindow.__init__(self)
		Ui_MainWindow.__init__(self)
		self.setupUi(self)
		self.setWindowTitle('Intrusion Prevention ')
		self.FinputTxt.setText(fkMAC)
		self.UinputTxt.setText(unauthMAC)
		self.FAPpushButton.clicked.connect(self.prevfakeap)
		self.UMACpushButton.clicked.connect(self.prevunauthmac)
		self.stop_fkbutton.clicked.connect(self.stop_prefkap)
		self.stop_unbutton.clicked.connect(self.stop_preunmac)
		self.wt = workerThread()
		self.wt2 = workerThread2()
		self.connect(self.wt, SIGNAL("fapdeauth"), self.fapGUI)
		self.connect(self.wt2, SIGNAL("unauthmac"), self.unGUI)

	def prevfakeap(self):
		self.FAPtextEdit.clear()
		self.wt.start()

	def prevunauthmac(self):
		self.UMACtextEdit.clear()
		self.wt2.start()

	def stop_prefkap(self):
		global  stop_fkvar
		stop_fkvar = 1

	def stop_preunmac(self):
		global stop_unvar
		stop_unvar = 1

	def fapGUI(self):
		global fktext
		self.FAPtextEdit.append(fktext)

	def unGUI(self):
		global untext
		self.UMACtextEdit.append(untext)

#Multithreading class used for GUI
class workerThread(QThread):
	def __int__(self, parent=None):
		super(workerThread, self).__init__(parent)

	def run(self):
		global fkMAC, interface,source
		#FakeAP Prevention by Deauthenticating the FakeAP
		def Prevent_FakeAP(source,fkMAC):
			global fktext,stop_fkvar
			proc1 = sp.Popen(['aireplay-ng','-0','0','-a',fkMAC,'--ignore-negative-one',interface])
			pid1 = str(proc1.pid)
			#p = Dot11(addr1 = source ,addr2 = fkMAC,addr3 = fkMAC) / Dot11Deauth()
			while (stop_fkvar != 1):
				#sendp(p,iface='mon0')
				#print "Securing AP  " + baseMAC + "  from Attacker  " + p.addr2
				if (fkMAC != None):
					fktext = "Securing AP <" + baseMAC + "> from Attacker <"+ fkMAC + ">"
					self.emit(SIGNAL("fapdeauth"))
				time.sleep(0.4)
			if (stop_fkvar == 1):
				pc1 = sp.Popen(['kill',pid1])
			stop_fkvar = 0
		print fkMAC
		Prevent_FakeAP(source,fkMAC)

#Multithreading class used for GUI,this is 2nd thread
class workerThread2(QThread):
	def __int__(self, parent=None):
		super(workerThread2, self).__init__(parent)

	def run(self):
		def Prevent_unauthMAC(source,unauthMAC):
			global untext,stop_unvar
			proc = sp.Popen(['aireplay-ng','-0','0','-a',unauthMAC,'--ignore-negative-one',interface])
			pid = str(proc.pid)
			'''
			print pid
			pc = sp.Popen(['kill',pid])
			print pc.pid
			'''
			#p = Dot11(addr1 = source ,addr2 = unauthMAC,addr3 = unauthMAC) / Dot11Deauth()
			while (stop_unvar != 1):
				#sendp(p,iface='mon0')
				#print "Securing AP  " + baseMAC + "  from Attacker  " + p.addr2
				if (unauthMAC != None):
					untext = "Disconnecting <<"+ unauthMAC +">> from AP <<" + baseMAC + ">>"
					self.emit(SIGNAL("unauthmac"))
				time.sleep(0.4)
			if (stop_unvar == 1):
				pc = sp.Popen(['kill',pid])

			stop_unvar = 0
		print unauthMAC
		Prevent_unauthMAC(source,unauthMAC)


if __name__ == "__main__":
	importvar()
	app = QtGui.QApplication(sys.argv)
	window = MyApp()
	window.show()
	sys.exit(app.exec_())