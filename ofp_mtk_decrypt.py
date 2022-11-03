#!/usr/bin/env python3
# Oppo OFP MTK Decrypter (c) B. Kerler 2022
# UI designed by Faizal Hamzah [The Firefox Flasher]
# Licensed under MIT License

import os
import sys
import platform
import hashlib
import ctypes
from Crypto.Cipher import AES
from struct import unpack
from binascii import unhexlify, hexlify
from PyQt5.QtGui import QTextCursor
from PyQt5.QtCore import Qt, QSize, QRunnable, QThreadPool, pyqtSignal, pyqtSlot
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QGridLayout, QLabel, QLineEdit, QToolButton, QTextEdit, QPushButton, QProgressBar, QMessageBox, QFileDialog, QStyleFactory, QSizePolicy


keytables = [
    ["67657963787565E837D226B69A495D21",
     "F6C50203515A2CE7D8C3E1F938B7E94C",
     "42F2D5399137E2B2813CD8ECDF2F4D72"],

    ["9E4F32639D21357D37D226B69A495D21",
     "A3D8D358E42F5A9E931DD3917D9A3218",
     "386935399137416B67416BECF22F519A"],

    ["892D57E92A4D8A975E3C216B7C9DE189",
     "D26DF2D9913785B145D18C7219B89F26",
     "516989E4A1BFC78B365C6BC57D944391"],

    ["27827963787265EF89D126B69A495A21",
     "82C50203285A2CE7D8C3E198383CE94C",
     "422DD5399181E223813CD8ECDF2E4D72"],

    ["3C4A618D9BF2E4279DC758CD535147C3",
     "87B13D29709AC1BF2382276C4E8DF232",
     "59B7A8E967265E9BCABE2469FE4A915E"],

    ["1C3288822BF824259DC852C1733127D3",
     "E7918D22799181CF2312176C9E2DF298",
     "3247F889A7B6DECBCA3E28693E4AAAFE"],

    ["1E4F32239D65A57D37D2266D9A775D43",
     "A332D3C3E42F5A3E931DD991729A321D",
     "3F2A35399A373377674155ECF28FD19A"],

    ["122D57E92A518AFF5E3C786B7C34E189",
     "DD6DF2D9543785674522717219989FB0",
     "12698965A132C76136CC88C5DD94EE91"],

    ["ab3f76d7989207f2",
     "2bf515b3a9737835"]
]

progressing = '''
    QProgressBar {
        color: rgb(0, 0, 0)
    }
    QProgressBar::chunk {
        background-color: rgb(242, 242, 24)
    }
'''
progressFailed = '''
    QProgressBar {
        color: rgb(255, 255, 255)
    }
    QProgressBar::chunk {
        background-color: rgb(168, 24, 24)
    }
'''
progressSuccess = '''
    QProgressBar {
        color: rgb(255, 255, 255)
    }
    QProgressBar::chunk {
        background-color: rgb(24, 168, 24)
    }
'''

class ofpDecrypt(object):
    def __init__(self, filename=None, outdir=None, parent=None):
        self.ui = parent

        if filename != None \
        and outdir != None:
            self.decrypt_all(filename, outdir)

    def swap(self, ch):
        return ((ch&0xF)<<4) + ((ch&0xF0)>>4)

    def keyshuffle(self, key, hkey):
        for i in range(0, 0x10, 4):
            key[i] = self.swap((hkey[i]^key[i]))
            key[i+1] = self.swap(hkey[i+1]^key[i+1])
            key[i+2] = self.swap(hkey[i+2]^key[i+2])
            key[i+3] = self.swap(hkey[i+3]^key[i+3])

        return key

    def mtk_shuffle(self, key, keylength, input, inputlength):
        for i in range(0, inputlength):
            k = key[(i % keylength)]
            h = ((((input[i]) & 0xF0) >> 4) | (16 * ((input[i]) & 0xF)))
            input[i] = k ^ h

        return input

    def mtk_shuffle2(self, key, keylength, input, inputlength):
        for i in range(0, inputlength):
            tmp = key[i % keylength] ^ input[i]
            input[i] = ((tmp & 0xF0) >> 4) | (16 * (tmp & 0xF))

        return input

    def aes_cfb(self, key, iv, data, decrypt=True, segment_size=128):
        cipher = AES.new(key, AES.MODE_CFB, IV=iv, segment_size=segment_size)
        if decrypt:
            plaintext = cipher.decrypt(data)
            return plaintext
        else:
            ciphertext = cipher.encrypt(data)
            return ciphertext

    def getkey(self, index):
        kt = keytables[index]
        if len(kt) == 3:
            obskey = bytearray(unhexlify(kt[0]))
            encaeskey = bytearray(unhexlify(kt[1]))
            encaesiv = bytearray(unhexlify(kt[2]))
            aeskey = hexlify(hashlib.md5(self.mtk_shuffle2(obskey, 16,
                                                           encaeskey, 16)).digest())[:16]
            aesiv = hexlify(hashlib.md5(self.mtk_shuffle2(obskey, 16,
                                                          encaesiv, 16)).digest())[:16]
        else:
            aeskey = bytes(kt[0], "UTF-8")
            aesiv = bytes(kt[1], "UTF-8")
            if self.ui:
                self.ui.wroteLog.emit(fr"{aeskey} {aesiv}")
            else:
                print(aeskey, aesiv)

        return aeskey, aesiv

    def brutekey(self, rf):
        rf.seek(0)
        encdata = rf.read(16)

        for keyid in range(0, len(keytables)):
            aeskey, aesiv = self.getkey(keyid)
            data = self.aes_cfb(aeskey, aesiv, encdata, True)
            if data[:3] == b"MMM":
                return aeskey, aesiv

        if self.ui:
            self.ui.wroteLog.emit("<p>Unknown key. Please ask the author for support.<br/></p>")
        else:
            print("Unknown key. Please ask the author for support.")
        return

    def cleancstring(self, input):
        return input.replace(b"\x00", b"").decode("UTF-8")

    def decrypt_all(self, filename, outdir):
        if not os.path.exists(outdir):
            os.mkdir(outdir)

        error = 0
        endspan = "</b></span>"

        hdrkey = bytearray(b"geyixue")
        filesize = os.stat(filename).st_size
        hdrlength = 0x6C

        with open(filename, 'rb') as rf:
            aeskey, aesiv = self.brutekey(rf)
            rf.seek(filesize - hdrlength)
            hdr = self.mtk_shuffle(hdrkey,
                                   len(hdrkey),
                                   bytearray(rf.read(hdrlength)),
                                   hdrlength)

            prjname, unknownval, reserved, cpu, flashtype, hdr2entries, prjinfo, crc = \
            unpack("46s Q 4s 7s 5s H 32s H", hdr)

            hdr2length = hdr2entries * 0x60

            prjname = self.cleancstring(prjname)
            prjinfo = self.cleancstring(prjinfo)
            cpu = self.cleancstring(cpu)
            flashtype = self.cleancstring(flashtype)

            setspan = "<span style=\"color: #CFC000\"><b>"

            if prjname != "":
                self.ui.wroteLog.emit(f"<p>Detected prjname: {setspan}{prjname}{endspan}<br/></p>") \
                if self.ui else print(f"Detected prjname: {prjname}")
            if prjinfo != "":
                self.ui.wroteLog.emit(f"<p>Detected prjinfo: {setspan}{prjinfo}{endspan}<br/></p>") \
                if self.ui else print(f"Detected prjinfo: {prjinfo}")
            if cpu != "":
                self.ui.wroteLog.emit(f"<p>Detected cpu: {setspan}{cpu}{endspan}<br/></p>") \
                if self.ui else print(f"Detected cpu: {cpu}")
            if flashtype != "":
                self.ui.wroteLog.emit(f"<p>Detected flash: {setspan}{flashtype}{endspan}<br/></p>") \
                if self.ui else print(f"Detected flash: {flashtype}")

            rf.seek(filesize - hdr2length - hdrlength)
            hdr2 = self.mtk_shuffle(hdrkey,
                                    len(hdrkey),
                                    bytearray(rf.read(hdr2length)),
                                    hdr2length)
            
            self.total = 0
            for i in range(0, len(hdr2)//0x60):
                name, start, length, enclength, filename, crc = \
                unpack("<32s Q Q Q 32s Q", hdr2[i*0x60:(i*0x60)+0x60])

                name = name.replace(b"\x00", b"").decode("UTF-8")
                filename = filename.replace(b"\x00", b"").decode("UTF-8")
                sizelength = length

                if self.ui:
                    setspan = "<span style=\"color: #0A62CB\"><b>"
                    self.ui.wroteLog.emit(f"<p>Writing {setspan}{name}{endspan} as {setspan}{filename}{endspan}... ")
                else:
                    print(f"Writing \"{name}\" as \"{os.sep.join([outdir, filename])}\"...")

                self.process = 0
                self.write_file(filename, rf, outdir,
                                [filesize, start, length, enclength, sizelength, crc],
                                [aeskey, aesiv],
                                log=True)

                if os.stat(os.sep.join([outdir, filename])).st_size >= sizelength:
                    setspan = "<span style=\"color: #3BC100\"><b>"
                    if self.ui:
                        self.ui.wroteLog.emit(f" {setspan}SUCCESS{endspan}<br/></p>")
                else:
                    error += 1
                    setspan = "<span style=\"color: #DD0202\"><b>"
                    if self.ui:
                        self.ui.wroteLog.emit(f" {setspan}ERROR{endspan}<br/></p>")

        if self.ui:
            self.ui.finished.emit(error)
        else:
            print(f"Files successfully decrypted to subdirectory {outdir}")

    def read_file(self, filename, outdir=None, isRead=False, target=None, format=None):
        if outdir == None:
            outdir = os.environ["TMPDIR"]

        if not os.path.exists(outdir):
            os.mkdir(outdir)

        hdrkey = bytearray(b"geyixue")
        filesize = os.stat(filename).st_size
        hdrlength = 0x6C

        with open(filename, 'rb') as rf:
            aeskey, aesiv = self.brutekey(rf)
            rf.seek(filesize - hdrlength)
            hdr = self.mtk_shuffle(hdrkey,
                                   len(hdrkey),
                                   bytearray(rf.read(hdrlength)),
                                   hdrlength)

            prjname, unknownval, reserved, cpu, flashtype, hdr2entries, prjinfo, crc = \
            unpack("46s Q 4s 7s 5s H 32s H", hdr)

            hdr2length = hdr2entries * 0x60

            rf.seek(filesize - hdr2length - hdrlength)
            hdr2 = self.mtk_shuffle(hdrkey,
                                    len(hdrkey),
                                    bytearray(rf.read(hdr2length)),
                                    hdr2length)
            
            for i in range(0, len(hdr2)//0x60):
                formats = locals()
                name, start, length, enclength, filename, crc = \
                unpack("<32s Q Q Q 32s Q", hdr2[i*0x60:(i*0x60)+0x60])

                name = name.replace(b"\x00", b"").decode("UTF-8")
                filename = filename.replace(b"\x00", b"").decode("UTF-8")
                sizelength = length

                formats["name"] = name
                formats["start"] = start
                formats["length"] = length
                formats["enclength"] = enclength
                formats["filename"] = filename
                formats["crc"] = crc

                if name == target and format:
                    return formats[format]

                if name == target:
                    self.write_file(filename, rf, outdir,
                                    [filesize, start, length, enclength, sizelength, crc], 
                                    [aeskey, aesiv], log=False)

                if isRead and name == "scatter":
                    return os.sep.join([outdir, filename])

    def write_file(self, filename, srcfile, outdir, info, brutekey, log=False):
        filesize, start, length, enclength, sizelength, crc = info
        aeskey, aesiv = brutekey

        with open(os.sep.join([outdir, filename]), 'wb') as wb:
            if enclength > 0:
                srcfile.seek(start)
                encdata = srcfile.read(enclength)
                if enclength % 16 != 0:
                    encdata += b"\x00" * (16 - (enclength % 16))
                data = self.aes_cfb(aeskey, aesiv, encdata, True)
                wb.write(data[:enclength])
                length -= enclength
                if log:
                    self.process += len(data[:enclength])
                    self.total += len(data[:enclength])
                    if self.ui:
                        self.callback(self.process, sizelength,
                                      self.ui.progressBar_file)
                        self.callback(self.total, filesize,
                                      self.ui.progressBar_total)
            while length > 0:
                size = 0x200000
                if length < size:
                    size = length
                data = srcfile.read(size)
                length -= size
                wb.write(data)
                if log:
                    self.process += len(data)
                    self.total += len(data)
                    if self.ui:
                        self.callback(self.process, sizelength,
                                      self.ui.progressBar_file)
                        self.callback(self.total, filesize,
                                      self.ui.progressBar_total)

    def callback(self, tempsize, filesize, parent):
        percent = int(tempsize / filesize * 100)
        self.ui.gotProgressValue.emit([percent, parent])

class ofpWorker(QRunnable):
    def __init__(self, fn, *args, **kwargs):
        super(ofpWorker, self).__init__()
        self.main = fn
        self.args = args
        self.kwargs = kwargs

    @pyqtSlot()
    def run(self):
        self.main(*self.args, **self.kwargs)

class ofpGui(QWidget):
    wroteLog = pyqtSignal(str)
    gotProgressValue = pyqtSignal(list)
    finished = pyqtSignal(int)

    def __init__(self, posdir=None, parent=None):
        super(ofpGui, self).__init__(parent)
        self.posdir = posdir
        self.setupUi()
        self.connectUi()

    def setupUi(self):
        self.widgetLayout = QGridLayout(self)
        self.gridLayout = QGridLayout()
        self.ofp = QLabel()
        self.ofp.setText("&OFP file:")
        self.gridLayout.addWidget(self.ofp, 0, 0, 1, 1)
        self.ofp_LineEdit = QLineEdit()
        self.gridLayout.addWidget(self.ofp_LineEdit, 0, 1, 1, 1)
        self.browse_ofp = QToolButton()
        self.browse_ofp.setMinimumWidth(40)
        self.browse_ofp.setObjectName("ofp")
        self.browse_ofp.setText("...")
        self.gridLayout.addWidget(self.browse_ofp, 0, 2, 1, 1)
        self.output = QLabel()
        self.output.setText("Out&put directory:")
        self.gridLayout.addWidget(self.output, 1, 0, 1, 1)
        self.output_LineEdit = QLineEdit()
        self.gridLayout.addWidget(self.output_LineEdit, 1, 1, 1, 1)
        self.browse_dir = QToolButton()
        self.browse_dir.setMinimumWidth(40)
        self.browse_dir.setObjectName("output")
        self.browse_dir.setText("...")
        self.gridLayout.addWidget(self.browse_dir, 1, 2, 1, 1)
        self.widgetLayout.addLayout(self.gridLayout, 0, 0, 1, 2)

        self.textEdit = QTextEdit()
        self.textEdit.setReadOnly(True)
        self.widgetLayout.addWidget(self.textEdit, 1, 0, 1, 2)
        self.extractButton = QPushButton(self)
        self.extractButton.setMinimumWidth(88)
        self.extractButton.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)
        self.extractButton.setText("&Decrypt")
        self.extractButton.setEnabled(False)
        self.widgetLayout.addWidget(self.extractButton, 2, 1, 2, 1)
        self.progressBar_file = QProgressBar()
        self.progressBar_file.setValue(0)
        self.progressBar_file.setObjectName("File")
        self.progressBar_file.setTextVisible(False)
        self.progressBar_file.setAlignment(Qt.AlignCenter)
        self.widgetLayout.addWidget(self.progressBar_file, 2, 0, 1, 1)
        self.progressBar_total = QProgressBar()
        self.progressBar_total.setValue(0)
        self.progressBar_total.setObjectName("Total")
        self.progressBar_total.setTextVisible(False)
        self.progressBar_total.setAlignment(Qt.AlignCenter)
        self.widgetLayout.addWidget(self.progressBar_total, 3, 0, 1, 1)

    def connectUi(self):
        self.browse_ofp.clicked.connect(self.browseDialog)
        self.browse_dir.clicked.connect(self.browseDialog)
        self.extractButton.clicked.connect(self.extract)

        self.ofp.setBuddy(self.ofp_LineEdit)
        self.output.setBuddy(self.output_LineEdit)

    def browseDialog(self):
        result = False
        sender = self.sender()

        if sender.objectName() == "ofp":
            title = "Select file"
            self.filter = "OFP file (*.ofp)"
            self.posdir = self.posdir if not self.posdir else self.ofp_LineEdit.text()
            result = QFileDialog.getOpenFileName(self, title, self.posdir, self.filter)[0]

        elif sender.objectName() == "output":
            title = "Save decrypted files to folder"
            self.posdir = self.posdir if not self.posdir else self.output_LineEdit.text()
            result = QFileDialog.getExistingDirectory(self, title, self.posdir)

        if result:
            self.objectAdded(result, sender)

    def objectAdded(self, result, sender=None):
        if not sender or sender.objectName() == "ofp":
            self.ofp_LineEdit.setText(os.path.normpath(result))
            self.output_LineEdit.setText(os.path.normpath(os.path.dirname(result)))
            self.extractButton.setEnabled(True)
            self.textEdit.insertHtml(f"<p>Opened file: <span style=\"color: #CFC000\"><b>{self.ofp_LineEdit.text()}</b></span><br/></p>")

        elif sender.objectName() == "output":
            self.output_LineEdit.setText(os.path.normpath(result))

        for progressBar in [self.progressBar_file, self.progressBar_total]:
            progressBar.setStyleSheet("")
            progressBar.setTextVisible(True)
            progressBar.setFormat("Ready")
            progressBar.setValue(0)

    def extract(self):
        self.textEdit.insertHtml(f"<p><br/></p>")
        for progressBar in [self.progressBar_file, self.progressBar_total]:
            progressBar.setStyleSheet(progressing)
            progressBar.setTextVisible(True)
            progressBar.setFormat(f"{progressBar.objectName()}: %p%")

        for button in [
            self.extractButton,
            self.ofp_LineEdit, self.output_LineEdit,
            self.browse_ofp, self.browse_dir]:
            button.setEnabled(False)

        QApplication.processEvents()
        self.wroteLog.connect(self.setTextHtml)
        self.gotProgressValue.connect(self.setProgressValue)
        self.finished.connect(self.extractFinish)
        self.worker = ofpWorker(lambda: ofpDecrypt(filename=self.ofp_LineEdit.text(),
                                                   outdir=self.output_LineEdit.text(),
                                                   parent=self))

        self.thread = QThreadPool()
        self.thread.start(self.worker)

    @pyqtSlot(int)
    def extractFinish(self, report):
        if report <= 0:
            self.setTextHtml(f"<p><br/>Successfully decrypted.</p>")
            for progressBar in [self.progressBar_file, self.progressBar_total]:
                progressBar.setValue(100)
                progressBar.setStyleSheet(progressSuccess)
                progressBar.setFormat("Completed")
        else:
            self.setTextHtml(f"<p><br/>Failed decrypted.</p>")
            for progressBar in [self.progressBar_file, self.progressBar_total]:
                progressBar.setValue(100)
                progressBar.setStyleSheet(progressFailed)
                progressBar.setFormat("Try again")

        for button in [
            self.extractButton,
            self.ofp_LineEdit, self.output_LineEdit,
            self.browse_ofp, self.browse_dir]:
            button.setEnabled(True)

    @pyqtSlot(str)
    def setTextHtml(self, text):
        self.textEdit.insertHtml(text)
        self.textEdit.moveCursor(QTextCursor.End)

    @pyqtSlot(list)
    def setProgressValue(self, list):
        list[1].setValue(list[0])

class main(QMainWindow):
    def __init__(self):
        super(main, self).__init__()
        self.resize(QSize(540, 560))
        self.setMinimumSize(QSize(420, 360))
        self.setAcceptDrops(True)
        self.setWindowFlags(Qt.WindowCloseButtonHint|Qt.WindowMinimizeButtonHint)
        self.widget = ofpGui(None, self)
        self.setCentralWidget(self.widget)

    def dragEnterEvent(self, event):
        data = event.mimeData()
        if data.hasUrls():
            url = data.urls()[0].toLocalFile()
            if os.path.splitext(url)[1].lower() == ".ofp":
                event.accept()

    def dropEvent(self, event):
        data = event.mimeData()
        path = data.urls()[0].toLocalFile()
        self.widget.objectAdded(path)

if __name__ == "__main__":
    if sys.argv[1:2] == ["--about"]:
        print("MTK OFP Decrypter (c) B. Kerler 2022")
        print("UI designed by Faizal Hamzah [The Firefox Flasher]")
        print("Licensed under MIT License")

        sys.exit(1)
    elif sys.argv[1:2] == ["--help"] \
    or sys.argv[1:2] == ["-h"]:
        print ("Oppo MTK OFP decrypt tool 1.1 (c) B.Kerler 2020-2022\n")
        print ("Usage: %s <filename> <directory to extract>" % __file__)

        sys.exit(1)
    elif len(sys.argv) != 3:
        QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
        QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

        app = QApplication(sys.argv)
        app.setApplicationName("MTK OFP Decrypter")
        widget = QWidget()

        system = platform.system()
        system_version = platform.version() if not sys.platform == "win32" else \
        list(int(i) for i in platform.version().split("."))

        os.environ["TMPDIR"] = \
        os.environ["TEMP"] if sys.platform == "win32" else \
        str("{}" if os.path.isdir("{}") else "/var{}").format("/tmp")

        if sys.platform == "linux":
            app.setStyle(QStyleFactory.create("Fusion"))
            os.environ["TMPDIR"] = os.path.join(os.environ["TMPDIR"], str("runtime-{}").format(os.environ["USER"]))
        elif sys.platform == "win32" and system_version > [6,0,6002]:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(sys.argv[0])
        else:
            title = app.applicationName()
            script = os.path.basename(sys.argv[0])
            caption = fr"{script} cannot be run in {system} {platform.release()}"
            sys.exit(QMessageBox.critical(widget, title, caption, QMessageBox.Close))

        if os.getenv("XDG_RUNTIME_DIR") and \
        not os.environ["XDG_RUNTIME_DIR"] == os.environ["TMPDIR"]:
            from subprocess import call
            os.environ["XDG_RUNTIME_DIR"] = os.environ["TMPDIR"]
            sys.exit(call(["env", fr"XDG_RUNTIME_DIR={os.environ['XDG_RUNTIME_DIR']}", *sys.argv]))

        form = main()
        form.show()
        sys.exit(app.exec_())
    else:
        filename = sys.argv[1]
        outdir = sys.argv[2]

        ofpDecrypt(filename, outdir)
        sys.exit()
