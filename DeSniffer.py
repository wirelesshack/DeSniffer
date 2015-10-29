# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '/home/bbolmin/바탕화면/DeSniffer/test.ui'
#
# Created: Fri Oct 23 21:05:11 2015
#      by: PyQt4 UI code generator 4.10.4
#
# WARNING! All changes made in this file will be lost!
import re,  sys,  os
import socket,  fcntl,  struct
from subprocess import Popen, PIPE
from PyQt4 import QtCore, QtGui
from PyQt4.Qt import *
import Scanner,  Sniffer

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    def _fromUtf8(s):
        return s

try:
    _encoding = QtGui.QApplication.UnicodeUTF8
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig, _encoding)
except AttributeError:
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig)

class Ui_MainWindow(object):
    def setMainProc(self,  mainProc):
        self.mainProc = mainProc
        
    def setupUi(self, MainWindow):
        MainWindow.setObjectName(_fromUtf8("MainWindow"))
        MainWindow.resize(760, 515)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(MainWindow.sizePolicy().hasHeightForWidth())
        MainWindow.setSizePolicy(sizePolicy)
        MainWindow.setToolButtonStyle(QtCore.Qt.ToolButtonIconOnly)
        MainWindow.setAnimated(False)
        MainWindow.setTabShape(QtGui.QTabWidget.Triangular)
        MainWindow.setDockOptions(QtGui.QMainWindow.ForceTabbedDocks)
        self.centralWidget = QtGui.QWidget(MainWindow)
        self.centralWidget.setObjectName(_fromUtf8("centralWidget"))
        self.verticalLayout = QtGui.QVBoxLayout(self.centralWidget)
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        self.verticalLayout_main = QtGui.QVBoxLayout()
        self.verticalLayout_main.setObjectName(_fromUtf8("verticalLayout_main"))
        self.tabWidget = QtGui.QTabWidget(self.centralWidget)
        self.tabWidget.setObjectName(_fromUtf8("tabWidget"))
        self.tab_scanner = QtGui.QWidget()
        self.tab_scanner.setObjectName(_fromUtf8("tab_scanner"))
        self.verticalLayout_4 = QtGui.QVBoxLayout(self.tab_scanner)
        self.verticalLayout_4.setObjectName(_fromUtf8("verticalLayout_4"))
        self.verticalLayout_scanner = QtGui.QVBoxLayout()
        self.verticalLayout_scanner.setObjectName(_fromUtf8("verticalLayout_scanner"))
        self.horizontalLayout_header = QtGui.QHBoxLayout()
        self.horizontalLayout_header.setSpacing(400)
        self.horizontalLayout_header.setSizeConstraint(QtGui.QLayout.SetMaximumSize)
        self.horizontalLayout_header.setObjectName(_fromUtf8("horizontalLayout_header"))
        self.label_cur_channel = QtGui.QLabel(self.tab_scanner)
        self.label_cur_channel.setObjectName(_fromUtf8("label_cur_channel"))
        self.horizontalLayout_header.addWidget(self.label_cur_channel)
        self.pushButton_apply = QtGui.QPushButton(self.tab_scanner)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.pushButton_apply.sizePolicy().hasHeightForWidth())
        self.pushButton_apply.setSizePolicy(sizePolicy)
        self.pushButton_apply.setObjectName(_fromUtf8("pushButton_apply"))
        self.horizontalLayout_header.addWidget(self.pushButton_apply)
        self.verticalLayout_scanner.addLayout(self.horizontalLayout_header)
        self.treeWidget = QtGui.QTreeWidget(self.tab_scanner)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Ignored, QtGui.QSizePolicy.Ignored)
        sizePolicy.setHorizontalStretch(1)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.treeWidget.sizePolicy().hasHeightForWidth())
        self.treeWidget.setSizePolicy(sizePolicy)
        self.treeWidget.setFrameShape(QtGui.QFrame.StyledPanel)
        self.treeWidget.setFrameShadow(QtGui.QFrame.Sunken)
        self.treeWidget.setWordWrap(False)
        self.treeWidget.setObjectName(_fromUtf8("treeWidget"))

        self.verticalLayout_scanner.addWidget(self.treeWidget)
        self.horizontalLayout_scanner = QtGui.QHBoxLayout()
        self.horizontalLayout_scanner.setSpacing(10)
        self.horizontalLayout_scanner.setMargin(10)
        self.horizontalLayout_scanner.setObjectName(_fromUtf8("horizontalLayout_scanner"))
        self.pushButton_scan_start = QtGui.QPushButton(self.tab_scanner)
        self.pushButton_scan_start.setObjectName(_fromUtf8("pushButton_scan_start"))
        self.horizontalLayout_scanner.addWidget(self.pushButton_scan_start)
        self.pushButton_scan_stop = QtGui.QPushButton(self.tab_scanner)
        self.pushButton_scan_stop.setObjectName(_fromUtf8("pushButton_scan_stop"))
        self.horizontalLayout_scanner.addWidget(self.pushButton_scan_stop)
        self.verticalLayout_scanner.addLayout(self.horizontalLayout_scanner)
        self.verticalLayout_4.addLayout(self.verticalLayout_scanner)
        self.tabWidget.addTab(self.tab_scanner, _fromUtf8(""))
        self.tab_sniffer = QtGui.QWidget()
        self.tab_sniffer.setObjectName(_fromUtf8("tab_sniffer"))
        self.horizontalLayout_6 = QtGui.QHBoxLayout(self.tab_sniffer)
        self.horizontalLayout_6.setObjectName(_fromUtf8("horizontalLayout_6"))
        self.horizontalLayout_sniffer = QtGui.QHBoxLayout()
        self.horizontalLayout_sniffer.setSpacing(30)
        self.horizontalLayout_sniffer.setObjectName(_fromUtf8("horizontalLayout_sniffer"))
        self.frame_sniffer = QtGui.QFrame(self.tab_sniffer)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.frame_sniffer.sizePolicy().hasHeightForWidth())
        self.frame_sniffer.setSizePolicy(sizePolicy)
        self.frame_sniffer.setFrameShape(QtGui.QFrame.StyledPanel)
        self.frame_sniffer.setFrameShadow(QtGui.QFrame.Raised)
        self.frame_sniffer.setObjectName(_fromUtf8("frame_sniffer"))
        self.verticalLayout_7 = QtGui.QVBoxLayout(self.frame_sniffer)
        self.verticalLayout_7.setSpacing(6)
        self.verticalLayout_7.setMargin(20)
        self.verticalLayout_7.setObjectName(_fromUtf8("verticalLayout_7"))
        self.gb_setting = QtGui.QGroupBox(self.frame_sniffer)
        self.gb_setting.setObjectName(_fromUtf8("gb_setting"))
        self.verticalLayout_5 = QtGui.QVBoxLayout(self.gb_setting)
        self.verticalLayout_5.setContentsMargins(-1, 9, -1, 30)
        self.verticalLayout_5.setObjectName(_fromUtf8("verticalLayout_5"))
        self.verticalLayout_setting = QtGui.QVBoxLayout()
        self.verticalLayout_setting.setObjectName(_fromUtf8("verticalLayout_setting"))
        self.horizontalLayout_ssid = QtGui.QHBoxLayout()
        self.horizontalLayout_ssid.setObjectName(_fromUtf8("horizontalLayout_ssid"))
        self.label_ssid = QtGui.QLabel(self.gb_setting)
        self.label_ssid.setObjectName(_fromUtf8("label_ssid"))
        self.horizontalLayout_ssid.addWidget(self.label_ssid)
        self.lineEdit_ssid = QtGui.QLineEdit(self.gb_setting)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.lineEdit_ssid.sizePolicy().hasHeightForWidth())
        self.lineEdit_ssid.setSizePolicy(sizePolicy)
        self.lineEdit_ssid.setObjectName(_fromUtf8("lineEdit_ssid"))
        self.horizontalLayout_ssid.addWidget(self.lineEdit_ssid)
        self.verticalLayout_setting.addLayout(self.horizontalLayout_ssid)
        self.horizontalLayout_bssid = QtGui.QHBoxLayout()
        self.horizontalLayout_bssid.setObjectName(_fromUtf8("horizontalLayout_bssid"))
        self.label_bssid = QtGui.QLabel(self.gb_setting)
        self.label_bssid.setObjectName(_fromUtf8("label_bssid"))
        self.horizontalLayout_bssid.addWidget(self.label_bssid)
        self.lineEdit_bssid = QtGui.QLineEdit(self.gb_setting)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.lineEdit_bssid.sizePolicy().hasHeightForWidth())
        self.lineEdit_bssid.setSizePolicy(sizePolicy)
        self.lineEdit_bssid.setObjectName(_fromUtf8("lineEdit_bssid"))
        self.horizontalLayout_bssid.addWidget(self.lineEdit_bssid)
        self.verticalLayout_setting.addLayout(self.horizontalLayout_bssid)
        self.horizontalLayout_channel = QtGui.QHBoxLayout()
        self.horizontalLayout_channel.setObjectName(_fromUtf8("horizontalLayout_channel"))
        self.label_channel = QtGui.QLabel(self.gb_setting)
        self.label_channel.setObjectName(_fromUtf8("label_channel"))
        self.horizontalLayout_channel.addWidget(self.label_channel)
        self.spinBox_channel = QtGui.QSpinBox(self.gb_setting)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.spinBox_channel.sizePolicy().hasHeightForWidth())
        self.spinBox_channel.setSizePolicy(sizePolicy)
        self.spinBox_channel.setObjectName(_fromUtf8("spinBox_channel"))
        self.spinBox_channel.setMinimum(1)
        self.spinBox_channel.setMaximum(13)
        self.horizontalLayout_channel.addWidget(self.spinBox_channel)
        self.verticalLayout_setting.addLayout(self.horizontalLayout_channel)
        self.horizontalLayout_enc = QtGui.QHBoxLayout()
        self.horizontalLayout_enc.setObjectName(_fromUtf8("horizontalLayout_enc"))
        self.label_enc = QtGui.QLabel(self.gb_setting)
        self.label_enc.setObjectName(_fromUtf8("label_enc"))
        self.horizontalLayout_enc.addWidget(self.label_enc)
        self.comboBox_enc = QtGui.QComboBox(self.gb_setting)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.comboBox_enc.sizePolicy().hasHeightForWidth())
        self.comboBox_enc.setSizePolicy(sizePolicy)
        self.comboBox_enc.setObjectName(_fromUtf8("comboBox_enc"))
        self.comboBox_enc.addItem(_fromUtf8(""))
        self.comboBox_enc.addItem(_fromUtf8(""))
        self.comboBox_enc.addItem(_fromUtf8(""))
        self.comboBox_enc.addItem(_fromUtf8(""))
        self.horizontalLayout_enc.addWidget(self.comboBox_enc)
        self.verticalLayout_setting.addLayout(self.horizontalLayout_enc)
        
        self.horizontalLayout_key = QtGui.QHBoxLayout()
        self.horizontalLayout_key.setObjectName(_fromUtf8("horizontalLayout_key"))
        self.label_key = QtGui.QLabel(self.gb_setting)
        self.label_key.setObjectName(_fromUtf8("label_key"))
        self.horizontalLayout_key.addWidget(self.label_key)
        self.lineEdit_key = QtGui.QLineEdit(self.gb_setting)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.lineEdit_key.sizePolicy().hasHeightForWidth())
        self.lineEdit_key.setSizePolicy(sizePolicy)
        self.lineEdit_key.setText(_fromUtf8(""))
        self.lineEdit_key.setObjectName(_fromUtf8("lineEdit_key"))
        self.horizontalLayout_key.addWidget(self.lineEdit_key)
        self.verticalLayout_setting.addLayout(self.horizontalLayout_key)
        
        self.horizontalLayout_hex = QtGui.QHBoxLayout()
        self.horizontalLayout_hex.setObjectName(_fromUtf8("horizontalLayout_hex"))
        spacerItem = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_hex.addItem(spacerItem)
        self.checkBox_hex = QtGui.QCheckBox(self.gb_setting)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.lineEdit_key.sizePolicy().hasHeightForWidth())
        self.checkBox_hex.setSizePolicy(sizePolicy)
        self.checkBox_hex.setText(_fromUtf8(""))
        self.checkBox_hex.setObjectName(_fromUtf8("checkBox_hex"))
        self.horizontalLayout_hex.addWidget(self.checkBox_hex)
        self.verticalLayout_setting.addLayout(self.horizontalLayout_hex)
       
        self.verticalLayout_5.addLayout(self.verticalLayout_setting)
        self.verticalLayout_7.addWidget(self.gb_setting)
        self.gb_options = QtGui.QGroupBox(self.frame_sniffer)
        self.gb_options.setObjectName(_fromUtf8("gb_options"))
        self.horizontalLayout_4 = QtGui.QHBoxLayout(self.gb_options)
        self.horizontalLayout_4.setContentsMargins(-1, -1, -1, 40)
        self.horizontalLayout_4.setObjectName(_fromUtf8("horizontalLayout_4"))
        self.verticalLayout_opions = QtGui.QVBoxLayout()
        self.verticalLayout_opions.setObjectName(_fromUtf8("verticalLayout_opions"))
        self.horizontalLayout_sta = QtGui.QHBoxLayout()
        self.horizontalLayout_sta.setObjectName(_fromUtf8("horizontalLayout_sta"))
        self.label_sta = QtGui.QLabel(self.gb_options)
        self.label_sta.setObjectName(_fromUtf8("label_sta"))
        self.horizontalLayout_sta.addWidget(self.label_sta)
        self.lineEdit_sta = QtGui.QLineEdit(self.gb_options)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.lineEdit_sta.sizePolicy().hasHeightForWidth())
        self.lineEdit_sta.setSizePolicy(sizePolicy)
        self.lineEdit_sta.setObjectName(_fromUtf8("lineEdit_sta"))
        self.horizontalLayout_sta.addWidget(self.lineEdit_sta)
        self.verticalLayout_opions.addLayout(self.horizontalLayout_sta)
        self.horizontalLayout_deauth = QtGui.QHBoxLayout()
        self.horizontalLayout_deauth.setObjectName(_fromUtf8("horizontalLayout_deauth"))
        self.label_deauth = QtGui.QLabel(self.gb_options)
        self.label_deauth.setObjectName(_fromUtf8("label_deauth"))
        self.horizontalLayout_deauth.addWidget(self.label_deauth)
        self.checkBox_deauth = QtGui.QCheckBox(self.gb_options)
        self.checkBox_deauth.setText(_fromUtf8(""))
        self.checkBox_deauth.setObjectName(_fromUtf8("checkBox_deauth"))
        self.horizontalLayout_deauth.addWidget(self.checkBox_deauth)
        self.verticalLayout_opions.addLayout(self.horizontalLayout_deauth)
        self.horizontalLayout_4.addLayout(self.verticalLayout_opions)
        self.verticalLayout_7.addWidget(self.gb_options)
        self.horizontalLayout_8 = QtGui.QHBoxLayout()
        self.horizontalLayout_8.setObjectName(_fromUtf8("horizontalLayout_8"))
        self.pushButton_sniff_start = QtGui.QPushButton(self.frame_sniffer)
        self.pushButton_sniff_start.setObjectName(_fromUtf8("pushButton_sniff_start"))
        self.horizontalLayout_8.addWidget(self.pushButton_sniff_start)
        self.pushButton_sniff_stop = QtGui.QPushButton(self.frame_sniffer)
        self.pushButton_sniff_stop.setObjectName(_fromUtf8("pushButton_sniff_stop"))
        self.horizontalLayout_8.addWidget(self.pushButton_sniff_stop)
        self.verticalLayout_7.addLayout(self.horizontalLayout_8)
        self.horizontalLayout_sniffer.addWidget(self.frame_sniffer)
        self.verticalLayout_log = QtGui.QVBoxLayout()
        self.verticalLayout_log.setContentsMargins(-1, 20, -1, -1)
        self.verticalLayout_log.setObjectName(_fromUtf8("verticalLayout_log"))
        self.gb_log = QtGui.QGroupBox(self.tab_sniffer)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.gb_log.sizePolicy().hasHeightForWidth())
        self.gb_log.setSizePolicy(sizePolicy)
        self.gb_log.setObjectName(_fromUtf8("gb_log"))
        self.verticalLayout_6 = QtGui.QVBoxLayout(self.gb_log)
        self.verticalLayout_6.setSpacing(9)
        self.verticalLayout_6.setContentsMargins(0, 20, 20, 20)
        self.verticalLayout_6.setObjectName(_fromUtf8("verticalLayout_6"))
        self.textEdit_log = QtGui.QTextEdit(self.gb_log)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.textEdit_log.sizePolicy().hasHeightForWidth())
        self.textEdit_log.setSizePolicy(sizePolicy)
        self.textEdit_log.setObjectName(_fromUtf8("textEdit_log"))
        self.verticalLayout_6.addWidget(self.textEdit_log)
        self.horizontalLayout = QtGui.QHBoxLayout()
        self.horizontalLayout.setSpacing(6)
        self.horizontalLayout.setContentsMargins(0, -1, -1, -1)
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        spacerItem = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem)
        self.pushButton_clear = QtGui.QPushButton(self.gb_log)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.pushButton_clear.sizePolicy().hasHeightForWidth())
        self.pushButton_clear.setSizePolicy(sizePolicy)
        self.pushButton_clear.setMinimumSize(QtCore.QSize(85, 0))
        self.pushButton_clear.setMaximumSize(QtCore.QSize(85, 16777215))
        self.pushButton_clear.setBaseSize(QtCore.QSize(0, 0))
        self.pushButton_clear.setObjectName(_fromUtf8("pushButton_clear"))
        self.horizontalLayout.addWidget(self.pushButton_clear)
        self.verticalLayout_6.addLayout(self.horizontalLayout)
        self.verticalLayout_log.addWidget(self.gb_log)
        self.horizontalLayout_sniffer.addLayout(self.verticalLayout_log)
        self.horizontalLayout_6.addLayout(self.horizontalLayout_sniffer)
        self.tabWidget.addTab(self.tab_sniffer, _fromUtf8(""))
        self.verticalLayout_main.addWidget(self.tabWidget)
        self.verticalLayout.addLayout(self.verticalLayout_main)
        MainWindow.setCentralWidget(self.centralWidget)
        self.statusBar = QtGui.QStatusBar(MainWindow)
        self.statusBar.setStatusTip(_fromUtf8(""))
        self.statusBar.setObjectName(_fromUtf8("statusBar"))
        MainWindow.setStatusBar(self.statusBar)

        self.retranslateUi(MainWindow)
        self.tabWidget.setCurrentIndex(0)
        self.__eventSetting()
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def __eventSetting(self):
        QtCore.QObject.connect(self.pushButton_clear, QtCore.SIGNAL(_fromUtf8("clicked()")), self.textEdit_log.clear)
        QtCore.QObject.connect(self.pushButton_scan_start, QtCore.SIGNAL(_fromUtf8("clicked()")), self.__h_scan_start)
        QtCore.QObject.connect(self.pushButton_scan_stop,  QtCore.SIGNAL(_fromUtf8("clicked()")), self.__h_scan_stop)
        QtCore.QObject.connect(self.pushButton_apply,  QtCore.SIGNAL(_fromUtf8("clicked()")), self.__h_apply)
        QtCore.QObject.connect(self.pushButton_sniff_start, QtCore.SIGNAL(_fromUtf8("clicked()")), self.__h_sniff_start)
        QtCore.QObject.connect(self.pushButton_sniff_stop,  QtCore.SIGNAL(_fromUtf8("clicked()")), self.__h_sniff_stop)
        
    def __h_scan_start(self):
        self.mainProc.start_scan()

    def __h_scan_stop(self):
        self.mainProc.stop_scan()
        
    def __h_apply(self):
        apply_item = self.treeWidget.currentItem()
        if apply_item == None:
            return
        if apply_item.parent() != None:
            #sta_mac filter
            self.lineEdit_sta.setText(apply_item.text(5))
            apply_item = apply_item.parent()
        else:
            self.lineEdit_sta.setText('')
        
        self.lineEdit_ssid.setText(apply_item.text(0))                 #ssid
        self.comboBox_enc.setCurrentIndex(['OPEN',  'WEP','WPA', 'WPA2'].index(apply_item.text(3))) #enc
        self.spinBox_channel.setValue(int(apply_item.text(2)))  #channel
        self.lineEdit_bssid.setText(apply_item.text(5))                #bssid
        
    def __h_sniff_start(self):
        self.mainProc.start_sniff()

    def __h_sniff_stop(self):
        self.mainProc.stop_sniff()
        
    def retranslateUi(self, MainWindow):
        MainWindow.setWindowTitle(_translate("MainWindow", "802.11 sniffer", None))
        self.tabWidget.setToolTip(_translate("MainWindow", "<html><head/><body><p><br/></p></body></html>", None))
        self.tabWidget.setWhatsThis(_translate("MainWindow", "<html><head/><body><p>sdfsdf</p></body></html>", None))
        self.label_cur_channel.setText(_translate("MainWindow", "Channel : -", None))
        self.pushButton_apply.setText(_translate("MainWindow", "apply ", None))
        self.treeWidget.headerItem().setText(0, _translate("MainWindow", "AP", None))
        self.treeWidget.headerItem().setText(1, _translate("MainWindow", "STA Count", None))
        self.treeWidget.headerItem().setText(2, _translate("MainWindow", "CHANNEL", None))
        self.treeWidget.headerItem().setText(3, _translate("MainWindow", "ENC", None))
        self.treeWidget.headerItem().setText(4, _translate("MainWindow", "DATAs", None))
        self.treeWidget.headerItem().setText(5, _translate("MainWindow", "BSSID", None))
        __sortingEnabled = self.treeWidget.isSortingEnabled()
 
        self.pushButton_scan_start.setText(_translate("MainWindow", "start", None))
        self.pushButton_scan_stop.setText(_translate("MainWindow", "stop", None))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_scanner), _translate("MainWindow", "scanner", None))
        self.gb_setting.setTitle(_translate("MainWindow", "AP Setting", None))
        self.label_ssid.setText(_translate("MainWindow", "SSID", None))
        self.label_bssid.setText(_translate("MainWindow", "BSSID", None))
        self.label_channel.setText(_translate("MainWindow", "channel", None))
        self.label_enc.setText(_translate("MainWindow", "encrypt", None))
        self.comboBox_enc.setItemText(0, _translate("MainWindow", "OPEN", None))
        self.comboBox_enc.setItemText(1, _translate("MainWindow", "WEP", None))
        self.comboBox_enc.setItemText(2, _translate("MainWindow", "WPA/TKIP", None))
        self.comboBox_enc.setItemText(3, _translate("MainWindow", "WPA2/CCMP", None))
        self.label_key.setText(_translate("MainWindow", "key", None))
        self.checkBox_hex.setText(_translate("MainWindow", "hex", None))
        self.gb_options.setTitle(_translate("MainWindow", "options", None))
        self.label_sta.setText(_translate("MainWindow", "STA MAC", None))
        self.label_deauth.setText(_translate("MainWindow", "Auto Deauth", None))
        self.pushButton_sniff_start.setText(_translate("MainWindow", "start", None))
        self.pushButton_sniff_stop.setText(_translate("MainWindow", "stop", None))
        self.gb_log.setTitle(_translate("MainWindow", "Log", None))
        self.pushButton_clear.setText(_translate("MainWindow", "clear", None))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_sniffer), _translate("MainWindow", "sniffer", None))
        self.statusBar.showMessage(_fromUtf8('stopped'))


class Interface_Dialog(object):
    def setupUi(self, Dialog):
        Dialog.setObjectName(_fromUtf8("Dialog"))
        Dialog.resize(231, 157)
        self.horizontalLayout = QtGui.QHBoxLayout(Dialog)
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        self.listWidget = QtGui.QListWidget(Dialog)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.listWidget.sizePolicy().hasHeightForWidth())
        self.listWidget.setSizePolicy(sizePolicy)
        self.listWidget.setObjectName(_fromUtf8("listWidget"))
        self.horizontalLayout.addWidget(self.listWidget)
        self.buttonBox = QtGui.QDialogButtonBox(Dialog)
        self.buttonBox.setOrientation(QtCore.Qt.Vertical)
        self.buttonBox.setStandardButtons(QtGui.QDialogButtonBox.Cancel|QtGui.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName(_fromUtf8("buttonBox"))
        self.horizontalLayout.addWidget(self.buttonBox)

        self.retranslateUi(Dialog)
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL(_fromUtf8("accepted()")), Dialog.accept)
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL(_fromUtf8("rejected()")), Dialog.reject)
        QtCore.QObject.connect(self.listWidget, QtCore.SIGNAL(_fromUtf8("currentItemChanged(QListWidgetItem*,QListWidgetItem*)")), self.__setInterface)
        QtCore.QMetaObject.connectSlotsByName(Dialog)
        
    def retranslateUi(self, Dialog):
        Dialog.setWindowTitle(_translate("Dialog", "Interfaces", None))
        __sortingEnabled = self.listWidget.isSortingEnabled()
        self.listWidget.setSortingEnabled(False)
        
        interface_list = self.__search_Interface()
        for i in range(len(interface_list)):
            item = QtGui.QListWidgetItem()
            self.listWidget.addItem(item)
            item.setText(_translate("Dialog", interface_list[i], None))
        self.listWidget.setSortingEnabled(__sortingEnabled)

    def __setInterface(self):
        self.interface = self.listWidget.currentItem().text()

    def get_interface(self):
        return str(self.interface)
        
    def __search_Interface(self):
        try:
            p = Popen('iwconfig', stdout=PIPE, stderr=PIPE)
        except OSError:
            print '[-] Could not execute \'iwconfig\''
            exit(-1)
    
        response = p.communicate()[0]
        interface_list = []
        try:
            interface_list = map(lambda x: x[:-4].strip(' '),  re.findall('([^\s].* IEEE)', response))
        except:
            interface_list = []
        return interface_list
        
class WLAN:
    MAX_CHANNEL = 13
    def __init__(self):
        self.interface =''
        self.mac = ''
        self.channel = 1
        
    def start_monitor(self):
        try:
            p = Popen(['iwconfig',  self.interface], stdout=PIPE, stderr=PIPE)
        except OSError:
            print '[-] Could not execute \'iwconfig\''
            exit(-1)
            
        response = p.communicate()[0]
        if response.find('Monitor') == -1:
            try:
                os.system('ifconfig %s down' % self.interface)
                os.system('iwconfig %s mode monitor' % self.interface)
                os.system('ifconfig %s up' % self.interface)
            except:
                print '[-] Could not setting monitor mode'
                exit(-1)
            
    def change_channel(self,  channel=-1):
        if channel == -1:
            self.channel = (self.channel % self.MAX_CHANNEL )+ 1
        else:
            self.channel = channel
        os.system('iwconfig %s channel %d' % (self.interface, self.channel))

    def __get_mac(self, iface):
        '''http://stackoverflow.com/questions/159137/getting-mac-address'''
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', iface[:15]))
        self.mac = ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]

    def set_interface(self,  interface):
        self.interface = interface
        self.__get_mac(self.interface)
        
class MainProc:
    def __init__(self,  ui):
        self.ui = ui
        self.ui.setMainProc(self)
        self.wlan = WLAN()
        self.scanner = Scanner.Scanner(ui, self.wlan)
        self.sniffer = Sniffer.Sniffer(ui,  self.wlan)
        self.is_scanning = False
        self.is_sniffing= False
        
    def start_scan(self):
        if self.__thread_check():
            return
        interface = self.__wlan_popup()
        if interface == '':
            return
        self.wlan.set_interface(interface)
        
        self.ui.statusBar.showMessage(_fromUtf8('scanning ...'))
        self.is_scanning = True
        self.wlan.start_monitor()
        self.scanner.start()
    
    def stop_scan(self):
        if self.is_scanning:
            self.is_scanning = False
            self.scanner.stop()
            self.ui.statusBar.showMessage(_fromUtf8('stopped'))
            
    def start_sniff(self):
        if self.__thread_check():
            return
        interface = self.__wlan_popup()
        if interface == '':
            return
        self.wlan.set_interface(interface)
        
        self.ui.statusBar.showMessage(_fromUtf8('sniffing ...'))
        self.is_sniffing = True
        self.wlan.start_monitor()
        status = self.sniffer.start()
        if status != None:
            self.ui.statusBar.showMessage(_fromUtf8('stopped'))
            self.__alert_message(status)
            self.is_sniffing = False
            
    def __thread_check(self):
        if self.is_scanning:
            self.__alert_message('scanning thread is running')
            return True
        elif self.is_sniffing:
            self.__alert_message('sniffing thread is running')
            return True
        return False
        
    def __alert_message(self,  text):
        msgBox = QMessageBox()
        msgBox.setWindowTitle('error')
        msgBox.setText(text)
        msgBox.exec_()
        
    def __wlan_popup(self):
            self.ui.Dialog = QtGui.QDialog()
            ui = Interface_Dialog()
            ui.setupUi(self.ui.Dialog)
            self.ui.Dialog.show()
            
            if self.ui.Dialog.exec_() == 1:
                return ui.get_interface()
            return ''
            
    def stop_sniff(self):
        if self.is_sniffing:
            self.is_sniffing = False
            self.sniffer.stop()
            self.ui.statusBar.showMessage(_fromUtf8('stopped'))
          
if __name__ == "__main__":
    app = QtGui.QApplication(sys.argv)
    MainWindow = QtGui.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    mainProc = MainProc(ui)
    
    sys.exit(app.exec_())

