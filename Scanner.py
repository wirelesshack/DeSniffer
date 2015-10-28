from threading import Thread, Lock
import logging
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import *
conf.verb = 0
from PyQt4 import QtCore, QtGui

def _translate(context, text, disambig):
    return QtGui.QApplication.translate(context, text, disambig)


class AP:
    def __init__(self,  ssid, bssid, channel,  enc):
        self.ssid = ssid
        self.bssid = bssid
        self.channel = str(channel)
        self.enc = enc
        self.data_count = 0
        self.sta_list = []

    def add_DataCount(self,  sta_mac):
        self.data_count += 1
        sta = filter(lambda sta: sta.sta_mac == sta_mac, self.sta_list)
        #new sta
        if sta == []:
            self.sta_list.append(STA(sta_mac))
        else:
            sta[0].data_count += 1

class STA:
    def __init__(self,  sta_mac):
        self.sta_mac = sta_mac
        self.data_count = 1

class hoppingThread(Thread):
    SLEEP_TIME = 0.5
    def __init__(self, scanner):
        Thread.__init__(self)
        self.scanner = scanner
        self.__exit = False

    def run(self):
        while True:
            time.sleep(self.SLEEP_TIME)
            self.scanner.channel_hopping()

            if self.__exit:
                break

    def exit(self):
        self.__exit = True

class SniffingThread(Thread):
    def __init__(self,  scanner):
        Thread.__init__(self)
        self.__exit = False
        self.scanner = scanner

    def run(self):
        sniff(iface=self.scanner.wlan.interface, store=0, prn=self.cb_sniff,  stop_filter=self.cb_stop)

    def cb_sniff(self,  pkt):
        #1.  AP Search (Beacon, ProbeResponse)
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            p = pkt[Dot11Elt]
            cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
            "{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split('+')

            crypto = ''
            while isinstance(p, Dot11Elt):
                if p.ID == 0:
                    ssid = p.info
                elif p.ID == 3:
                    channel = ord(p.info)
                elif p.ID == 48 and crypto == '':
                    crypto = 'WPA2'
                elif p.ID == 221 and p.info.startswith('\x00P\xf2\x01\x01\x00') and crypto == '':
                    crypto = 'WPA'
                p = p.payload
            if crypto == '':
                if 'privacy' in cap:
                    crypto = 'WEP'
                else:
                    crypto = 'OPEN'
            bssid = pkt.addr3
            
            #new ap
            if not self.scanner.ap_check(bssid ,  ssid):
                self.scanner.ap_list.append(AP(ssid, bssid, channel,  crypto))
        #2. Data counter
        elif pkt.haslayer(Dot11QoS):
            ap = self.scanner.ap_check(pkt.addr1)
            sta_mac = pkt.addr2
            if ap == False:
                ap = self.scanner.ap_check(pkt.addr2)
                sta_mac = pkt.addr1
                if ap == False:
                    return
            ap.add_DataCount(sta_mac)

    def cb_stop(self, pkt):
        if self.__exit:
            return True

    def exit(self):
        self.__exit = True

class Scanner:
    def __init__(self, ui,  wlan):
        self.ui = ui
        self.wlan = wlan
        conf.iface = self.wlan.interface
        self.hopping_thread = None
        self.sniffing_thread = None

        self.ignore = ['ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00', '33:33:00:', '33:33:ff:', '01:80:c2:00:00:00', '01:00:5e:']
        self.ignore.append(self.wlan.mac)
        self.ap_list = []

    def ap_check(self, bssid, ssid=''):
        ap = filter(lambda ap: ap.bssid == bssid, self.ap_list)
        if ap == []:
            return False
        if ssid != '' and ap[0].ssid == '':
            ap[0].ssid = ssid
        return ap[0]

    def start(self):
        if not (self.hopping_thread and self.sniffing_thread):
            self.__resetTree()
            self.hopping_thread = hoppingThread(self)
            self.hopping_thread .start()
            self.sniffing_thread = SniffingThread(self)
            self.sniffing_thread.start()
        
    def stop(self):
        if self.hopping_thread:
            self.hopping_thread.exit()
            del self.hopping_thread
            self.hopping_thread = None
            
        if self.sniffing_thread:
            self.sniffing_thread.exit()
            del self.sniffing_thread
            self.sniffing_thread = None

    def channel_hopping(self):
        #setting self.ui
        self.ui.label_cur_channel.setText('Channel : %s' % self.wlan.channel)

        for index, ap  in enumerate(self.ap_list):
            if self.ui.treeWidget.topLevelItem(index) == None:
                QtGui.QTreeWidgetItem(self.ui.treeWidget)
            self.ui.treeWidget.topLevelItem(index).setText(0, _translate("MainWindow", ap.ssid, None))
            self.ui.treeWidget.topLevelItem(index).setText(1, _translate("MainWindow", str(len(ap.sta_list)), None))
            self.ui.treeWidget.topLevelItem(index).setText(2, _translate("MainWindow", ap.channel, None))
            self.ui.treeWidget.topLevelItem(index).setText(3, _translate("MainWindow", ap.enc, None))
            self.ui.treeWidget.topLevelItem(index).setText(4, _translate("MainWindow", str(ap.data_count), None))
            self.ui.treeWidget.topLevelItem(index).setText(5, _translate("MainWindow", ap.bssid, None))

            for index2, sta in enumerate(ap.sta_list):
                if self.ui.treeWidget.topLevelItem(index).child(index2) == None:
                    QtGui.QTreeWidgetItem(self.ui.treeWidget.topLevelItem(index))
                self.ui.treeWidget.topLevelItem(index).child(index2).setText(0, _translate("MainWindow", "sta%d"%(index2+1), None))
                self.ui.treeWidget.topLevelItem(index).child(index2).setText(4, _translate("MainWindow", str( sta.data_count), None))
                self.ui.treeWidget.topLevelItem(index).child(index2).setText(5, _translate("MainWindow", sta.sta_mac, None))
                for i in range(1, 4):
                    self.ui.treeWidget.topLevelItem(index).child(index2).setText(i, _translate("MainWindow", '-', None))
        #hopping
        self.wlan.change_channel()

    def __resetTree(self):
            self.ap_list = []
            self.ui.treeWidget.clear()
