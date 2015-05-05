#!/usr/bin/env python 
import sys
from PyQt4 import QtCore, QtGui, uic
from PyQt4.QtCore import *
from PyQt4.QtGui import *
import os
import signal
import re
import datetime
import subprocess as sp
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
global interface , stopids
stopids = 0
interface = 'mon0'
unique = []
# Deauth and Fake AP
FakeAPThresold = 5
global start
global start2
global start_auth
deauthCount = 0
deauthThreshold = 5
START = 5

AuthCount = 0
AuthThreshold = 5

global time_var ,time_var2
time_var = 0
time_var2 = 0
global start_time ,start_time2,Deauthdiff,Authdiff
Deauthdiff = 0
Authdiff = 0
global Dprog, Dtext, Aprog,baseMAC,fkMAC,unauthMAC,fssid
fkMAC = ""
unauthMAC = ""
Dprog = 0
Aprog = 0
def set_start():
	global start
	global time_var
	global start_time
	set_t = datetime.datetime.now()
	if (time_var == 0):
		start_time = set_t
		time_var = 1
		return start_time
	else:
		return start

def set_start2():
	global start2
	global time_var2
	global start_time2
	set_t = datetime.datetime.now()
	if (time_var2 == 0):
		start_time2 = set_t
		time_var2 = 1
		return start_time2
	else:
		return start2

def exportvar():
	global baseMAC,fkMAC,unauthMAC
	f = open("alog.txt",'w+')
	if baseMAC != None:
		f.write(str(baseMAC) + "\n")
	if fkMAC != None:
		f.write(str(fkMAC) + "\n")
	if unauthMAC != None:
		f.write(str(unauthMAC) + "\n")
	f.close()

qtCreatorFile = "id.ui"  # Enter file here.

Ui_MainWindow, QtBaseClass = uic.loadUiType(qtCreatorFile)


class MyApp(QtGui.QMainWindow, Ui_MainWindow):
	def __init__(self):
		global baseMAC
		QtGui.QMainWindow.__init__(self)
		Ui_MainWindow.__init__(self)
		self.setupUi(self)
		self.setWindowTitle('Intrusion Detection ')
		self.id_pushbutton.clicked.connect(self.callid)
		self.ip_pushbutton.clicked.connect(self.start_ips)
		self.clearButton.clicked.connect(self.clearall)
		self.wt = workerThread()
		self.connect(self.wt, SIGNAL("Deauth"), self.DeauthGUI)
		self.connect(self.wt, SIGNAL("Auth"), self.AuthGUI)
		self.connect(self.wt, SIGNAL("Fkap"), self.FkapGUI)
		self.connect(self.wt, SIGNAL("unauthmac"), self.unauthGUI)
		self.pcap_pushbutton.clicked.connect(self.pcap_open)
		self.log_pushbutton.clicked.connect(self.log_open)
		self.exit_pushbutton.clicked.connect(self.exit_gui)
	def callid(self):
		global baseMAC ,fssid
		while True:
			bm, ok = QtGui.QInputDialog.getText(self, 'MAC Input Dialog', 'Enter MAC address of AP:')
			bm = str(bm).strip()
			if ok:
				if bm != "" :
					baseMAC = bm.lower()
					print(baseMAC)
					name, ok1 = QtGui.QInputDialog.getText(self, 'Name Input Dialog', 'Enter name of AP:')
					nm = str(name).strip()
					if ok1:
						if nm !="":
							nm = "\'"+ nm +"\'"
							fssid = nm.lower()
							print(fssid)
					else:
						continue
					break
			else:
				break
		self.wt.start()

	#clear text box
	def clearall(self):
		self.A_textEdit.clear()
		self.D_textEdit.clear()
		self.F_textEdit.clear()
		self.U_textEdit.clear()
		self.Aprogress.setValue(0)
		self.Dprogress.setValue(0)
		self.Fprogress.setValue(0)
		self.Uprogress.setValue(0)

	#open pcap file
	def pcap_open(self):
		global stopids
		stopids = 1
		sp.Popen(['wireshark', 'IDS_Analysis.pcap'])
	#open log file
	def log_open(self):
		global stopids
		stopids = 1
		os.system('sh pconv.sh')
		sp.Popen(['notepad', 'IDS_Analysis.txt'])
	#exit GUI
	def exit_gui(self):
		sys.exit()

	#start ids module
	def start_ips(self):
		e = sp.Popen(['python', 'ips.py'])
		if e >= 0:
			exportvar()
			window.hide()

	def DeauthGUI(self):
		global Dprog, Dtext ,Aprog
		self.Aprogress.setValue(0)
		self.Dprogress.setValue(0)
		self.Fprogress.setValue(0)
		self.Uprogress.setValue(0)
		self.D_textEdit.append(Dtext)
		self.Dprogress.setValue(100)

	def AuthGUI(self):
		global Aprog, Atext ,Dprog
		self.Dprogress.setValue(0)
		self.Aprogress.setValue(0)
		self.Fprogress.setValue(0)
		self.Uprogress.setValue(0)
		self.A_textEdit.append(Atext)
		self.Aprogress.setValue(100)

	def FkapGUI(self):
		global Fprog, Ftext ,Fprog
		self.Dprogress.setValue(0)
		self.Aprogress.setValue(0)
		self.Fprogress.setValue(0)
		self.Uprogress.setValue(0)
		self.F_textEdit.append(Ftext)
		self.Fprogress.setValue(100)

	def unauthGUI(self):
		global Fprog, Ftext ,Fprog,unauthText
		self.Dprogress.setValue(0)
		self.Aprogress.setValue(0)
		self.Fprogress.setValue(0)
		self.Uprogress.setValue(0)
		self.U_textEdit.append(unauthText)
		self.Uprogress.setValue(100)


#Multithreading class used for GUI
class workerThread(QThread):
	def __int__(self, parent=None):
		super(workerThread, self).__init__(parent)

	def run(self):
		global stopids
		#Detecting deauth DOS attack by keeping count of deauth packets
		def MonitorDeauth(pkt):
			global deauthCount, Dprog, Dtext ,Aprog ,start,start2, START, Authdiff,time_var2,AuthCount
			AuthCount = 0
			time_var2 = 0
			Aprog = 0
			deauthCount += 1
			diff = datetime.datetime.now() - start
			Deauthdiff = diff.seconds
			if ((diff.seconds > START) and ((deauthCount) > deauthThreshold)):
				print "Detected Deauth against : " + pkt.addr3
				Dprog = 100
				Dtext = "Deauth against : " + pkt.addr3
				self.emit(SIGNAL("Deauth"))

		#Detect Auth flood attack
		def MonitorAuth(pkt):
			global AuthCount,Dprog, Atext ,Aprog ,start ,start2, Deauthdiff,time_var,deauthCount
			deauthCount = 0
			time_var = 0
			Dprog = 0
			if ((pkt.type == 0) and (pkt.subtype == 11)):
				AuthCount += 1
				diff = datetime.datetime.now() - start2
				Authdiff = diff.seconds
				if ((diff.seconds > START) and ((AuthCount / Authdiff) > AuthThreshold)):
					print "Detected Auth Flood attack against : " + pkt.addr3
					Aprog = 100
					Atext = "Auth Flood attack against : " + pkt.addr3
					self.emit(SIGNAL("Auth"))
		#Fake AP detection
		def FakeAP(pkt):
			global fssid,baseMAC,Ftext,fkMAC
			fmac = baseMAC
			#fssid = "\'"+ fssid + "\'"
			pssid = pkt.sprintf("%Dot11Elt.info%")
			pmac = pkt.sprintf("%Dot11.addr2%")
			print fssid , pssid
			if(fssid == pssid):
				#print fssid
				if not (pmac == fmac):
					fkMAC = pmac
					print "Fake AP found -> "+pmac
					Ftext = "Fake AP found -> " + pmac
					self.emit(SIGNAL("Fkap"))

		#Detect Unauth MAC
		def Unauthmac(pkt):
			global unique, baseMAC,unauthText,unauthMAC
			adr1 = adr2 = adr3 = 'ff:ff:ff:ff:ff:ff'
			if (pkt.addr1 != None):
				adr1 = pkt.addr1
			if (pkt.addr2 != None):
				adr2 =pkt.addr2
			if (pkt.addr3 != None):
				adr3 = pkt.addr3
			if (adr1 == baseMAC or adr2 == baseMAC or adr3 == baseMAC):
				if (unique.count(adr1) == 0 and unique.count(adr2) == 0 and unique.count(adr3) == 0):
					print "Unathorized MAC->"
					print adr1
					print adr2
					print adr3
					if (adr2 != baseMAC):
						unauthText = "Unauthorized MAC->" + adr2
						unauthMAC = adr2
						self.emit(SIGNAL("unauthmac"))

		#MAIN IDS Function
		def IDS(pkt):
			global start,start2,stopids
			if (stopids == 1):
					stopids = 0
					raise KeyboardInterrupt
			'''
			if (pkt.haslayer(Dot11)):
				if ((pkt.getlayer(Dot11).type == 0) and (pkt.getlayer(Dot11).subtype == 12)):
					#MonitorDeauth(pkt.getlayer(Dot11)) #detect for deauth attack
					start2 = set_start2()
					MonitorDeauth(pkt)  #detect for deauth attack by monitoring change in radiotap header
				if ((pkt.getlayer(Dot11).type == 0) and (pkt.getlayer(Dot11).subtype == 11)):
					#detect for auth flood attack
					start2 = set_start2()
					#start2 = set_start()
					MonitorAuth(pkt)
			'''
			#Detect Auth Flood Attack
			if pkt.haslayer(Dot11Auth):
				start2 = set_start2()
				MonitorAuth(pkt)

			#Detect FakeAP
			if pkt.haslayer(Dot11Beacon):
				print "beacon"
				FakeAP(pkt)

			#Detect UnauthMAC
			if not pkt.haslayer(Dot11Beacon):
				if not pkt.haslayer(Dot11Auth):
					Unauthmac(pkt)

			if pkt.haslayer(Dot11Deauth) or pkt.haslayer(Dot11Disas):
				start = set_start()
				MonitorDeauth(pkt)


		global unique
		macfile = open("authmac", "r")
		temp = macfile.readlines()
		for line in temp:
			authmac = line.rstrip("\n \r")
			unique.append(authmac.lower())

		try:
			packets = sniff(iface=interface, prn=IDS)
			wrpcap('IDS_Analysis.pcap', packets)
		except KeyboardInterrupt:
				print "except"
				stopids = 0


if __name__ == "__main__":
	app = QtGui.QApplication(sys.argv)
	window = MyApp()
	window.show()
	sys.exit(app.exec_())
