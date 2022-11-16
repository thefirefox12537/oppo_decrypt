#!/usr/bin/env python3
# Oppo OFP Decrypter (c) B. Kerler 2022
# UI designed by Faizal Hamzah [The Firefox Flasher]
# Licensed under MIT License

import os
import sys
import ctypes
import hashlib
import math
import platform
import shutil
import subprocess
import xml.etree.ElementTree as ET
from binascii import unhexlify, hexlify
from struct import unpack
from time import sleep
from zipfile import ZipFile
from Crypto.Cipher import AES
from PyQt5.QtGui import QFont, QIcon, QColor, QDesktopServices, QTextCursor
from PyQt5.QtCore import Qt, QCoreApplication, QUrl, QSize, QPoint, QRect, QSettings, QObject, QRunnable, QThreadPool, pyqtSignal as Signal, pyqtSlot as Slot
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QHBoxLayout, QGridLayout, QTableWidget, QTableWidgetItem, QCheckBox, QLabel, QLineEdit, QToolButton, QTextEdit, QPushButton, QProgressBar, QMessageBox, QFileDialog, QStyleFactory, QSizePolicy, QAbstractItemView


class ofpQcomDecrypt(object):
    def __init__(self, filename=None, outdir=None, parent=None):
        self.ui = parent

        if filename != None and outdir != None:
            self.decrypt_all(filename, outdir)

    def swap(self, ch):
        return ((ch & 0xF) << 4) + ((ch & 0xF0) >> 4)

    def keyshuffle(self, key, hkey):
        for i in range(0, 0x10, 4):
            key[i] = self.swap((hkey[i] ^ key[i]))
            key[i + 1] = self.swap(hkey[i + 1] ^ key[i + 1])
            key[i + 2] = self.swap(hkey[i + 2] ^ key[i + 2])
            key[i + 3] = self.swap(hkey[i + 3] ^ key[i + 3])

        return key

    def ROL(self, x, n, bits = 32):
        n = bits - n
        mask = (2 ** n) - 1
        mask_bits = x & mask
        return (x >> n) | (mask_bits << (bits - n))

    def generatekey1(self):
        key1 = bytearray.fromhex("42F2D5399137E2B2813CD8ECDF2F4D72")
        key2 = bytearray.fromhex("F6C50203515A2CE7D8C3E1F938B7E94C")
        key3 = bytearray.fromhex("67657963787565E837D226B69A495D21")

        key2 = self.keyshuffle(key2, key3)
        key = bytes(hashlib.md5(key2).hexdigest()[0:16], "UTF-8")
        key1 = self.keyshuffle(key1, key3)
        iv = bytes(hashlib.md5(key1).hexdigest()[0:16], "UTF-8")

        return key, iv

    def generatekey2(self, filename):
        keytables = [
            ["V1.4.17/1.4.27",
             "27827963787265EF89D126B69A495A21",
             "82C50203285A2CE7D8C3E198383CE94C",
             "422DD5399181E223813CD8ECDF2E4D72"],

            ["V1.6.17",
             "E11AA7BB558A436A8375FD15DDD4651F",
             "77DDF6A0696841F6B74782C097835169",
             "A739742384A44E8BA45207AD5C3700EA"],

            ["V1.5.13",
             "67657963787565E837D226B69A495D21",
             "F6C50203515A2CE7D8C3E1F938B7E94C",
             "42F2D5399137E2B2813CD8ECDF2F4D72"],

            ["V1.6.6/1.6.9/1.6.17/1.6.24/1.6.26/1.7.6",
             "3C2D518D9BF2E4279DC758CD535147C3",
             "87C74A29709AC1BF2382276C4E8DF232",
             "598D92E967265E9BCABE2469FE4A915E"],

            ["V1.7.2",
             "8FB8FB261930260BE945B841AEFA9FD4",
             "E529E82B28F5A2F8831D860AE39E425D",
             "8A09DA60ED36F125D64709973372C1CF"],

            ["V2.0.3",
             "E8AE288C0192C54BF10C5707E9C4705B",
             "D64FC385DCD52A3C9B5FBA8650F92EDA",
             "79051FD8D8B6297E2E4559E997F63B7F"]
        ]

        for dkey in keytables:
            key = bytearray()
            iv = bytearray()
            mc = bytearray.fromhex(dkey[1])
            userkey = bytearray.fromhex(dkey[2])
            ivec = bytearray.fromhex(dkey[3])

            key = (hashlib.md5(self.deobfuscate(userkey, mc)).hexdigest()[0:16]).encode()
            iv = (hashlib.md5(self.deobfuscate(ivec, mc)).hexdigest()[0:16]).encode()
        
            pagesize, data = self.extract_xml(filename, key, iv)
            if pagesize != 0:
                return pagesize, key, iv, data

        return 0, None, None, None

    def deobfuscate(self, data, mask):
        ret = bytearray()
        for i in range(0, len(data)):
            v = self.ROL((data[i] ^ mask[i]), 4, 8)
            ret.append(v)
        return ret

    def extract_xml(self, filename, key, iv):
        with open(filename, "rb") as rf:
            pagesize = 0
            for x in [0x200, 0x1000]:
                rf.seek(self.filesize - x + 0x10)
                if unpack("<I", rf.read(4))[0] == 0x7CEF:
                    pagesize = x
                    break 

            if pagesize == 0:
                if self.ui:
                    self.ui.signal.wroteLog.emit("<p>Unknown pagesize. Aborting<br/></p>")
                return
            
            xmloffset = self.filesize - pagesize
            rf.seek(xmloffset + 0x14)
            offset = unpack("<I", rf.read(4))[0] * pagesize
            length = unpack("<I", rf.read(4))[0]

            if length < 200:
                length = xmloffset - offset - 0x57

            rf.seek(offset)
            data = rf.read(length)
            dec = self.aes_cfb(data, key, iv)

            if b"<?xml" in dec:
                return pagesize, dec
            else:
                return 0, ""

    def aes_cfb(self, data, key, iv):
        ctx = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128)
        decrypted = ctx.decrypt(data)
        return decrypted

    def getItemDecrypt(self, item, pagesize):
        sha256sum = ""
        md5sum = ""
        label = ""
        wfilename = ""
        start = -1
        rlength = 0
        decryptsize = 0x40000

        if "Path" in item.attrib:
            wfilename = item.attrib["Path"]
            label = wfilename
        elif "filename" in item.attrib:
            wfilename = item.attrib["filename"]
            label = wfilename

        if "sha256" in item.attrib:
            sha256sum = item.attrib["sha256"]

        if "md5" in item.attrib:
            md5sum = item.attrib["md5"]

        if "FileOffsetInSrc" in item.attrib:
            start = int(item.attrib["FileOffsetInSrc"]) * pagesize
        elif "SizeInSectorInSrc" in item.attrib:
            start = int(item.attrib["SizeInSectorInSrc"]) * pagesize

        if "SizeInByteInSrc" in item.attrib:
            rlength = int(item.attrib["SizeInByteInSrc"])

        if "SizeInSectorInSrc" in item.attrib:
            length = int(item.attrib["SizeInSectorInSrc"]) * pagesize
        else:
            length = rlength

        if "label" in item.attrib:
            label = item.attrib["label"]

        return wfilename, label, start, length, rlength, [sha256sum, md5sum], decryptsize

    def decrypt_select(self, filename, outdir=None, target=None, format=None):
        if outdir == None:
            outdir = os.environ["TMPDIR"]

        self.total = 0
        self.filesize = os.stat(filename).st_size
        pk = False

        with open(filename, "rb") as rf:
            if rf.read(2) == b"PK":
                pk = True

        if pk == True:
            zippasswd = bytes("flash@realme$50E7F7D847732396F1582CD62DD385ED7ABB0897", "UTF-8")
            with ZipFile(filename) as file:
                for zfile in file.namelist():
                    if zfile == target:
                        file.extract(zfile, pwd=zippasswd, path=outdir)

                return

        pagesize, key, iv, data = self.generatekey2(filename)
        if pagesize == 0:
            return
        else:
            xml = data[:data.rfind(b">") + 1].decode("UTF-8")

        if target != None and outdir != None:
            file_handle = open(os.sep.join([outdir, "ProFile.xml"]), "w")
            file_handle.write(xml)
            file_handle.close()

        root = ET.fromstring(xml)
        for child in root:
            for item in child:
                if "Path" not in item.attrib and "filename" not in item.attrib:
                    for subitem in item:
                        wfilename, label, start, length, rlength, checksums, decryptsize = \
                        self.getItemDecrypt(subitem, pagesize)

                        if wfilename == "" or start == -1:
                            continue

                        if subitem == target:
                            self.writeData(filename, wfilename, outdir,
                                           [start, length, rlength, checksums, decryptsize], 
                                           [key, iv], log)

                wfilename, label, start, length, rlength, checksums, decryptsize = \
                self.getItemDecrypt(item, pagesize)

                if wfilename == "" or start == -1:
                    continue

                if child.tag in ["Sahara"]:
                    decryptsize = rlength

                if child.tag in ["Config", "Provision", "ChainedTableOfDigests", "DigestsToSign", "Firmware"]:
                    length = rlength

                if item == target:
                    if child.tag in ["DigestsToSign", "ChainedTableOfDigests", "Firmware"]:
                        self.writeData(filename, wfilename, outdir,
                                       [start, length, checksums], 
                                       log)
                    else:
                        self.writeData(filename, wfilename, outdir,
                                       [start, length, rlength, checksums, decryptsize], 
                                       [key, iv], log)
        
    def decrypt_all(self, filename, outdir):
        if not os.path.exists(outdir):
            os.mkdir(outdir)

        self.error = 0
        self.success = 0
        self.total = 0
        self.filesize = os.stat(filename).st_size
        endspan = "</span>"
        pk = False

        with open(filename, "rb") as rf:
            if rf.read(2) == b"PK":
                pk = True

        if pk == True:
            if self.ui:
                self.ui.signal.wroteLog.emit("<p>Zip file detected, trying to decrypt files...<br/></p>")

            zippasswd = bytes("flash@realme$50E7F7D847732396F1582CD62DD385ED7ABB0897", "UTF-8")
            with ZipFile(filename) as file:
                for zipinfo in file.filelist:
                    zfile = zipinfo.filename
                    length = zipinfo.file_size

                    if self.ui:
                        setspan = "<span style=\"color: #0A62CB\"><b>"
                        resultlog = " ".join([setspan, zfile, endspan])
                        self.ui.signal.wroteLog.emit("<p>Decrypting %s... " % resultlog)

                    file.extract(zfile, pwd=zippasswd, path=outdir)
                    if self.ui:
                        if os.stat(os.sep.join([outdir, zfile])).st_size >= length:
                            self.success += 1
                            setspan = "<span style=\"color: #3BC100\"><b>"
                            self.ui.signal.wroteLog.emit(" %s SUCCESS %s<br/></p>" % (setspan, endspan))
                        else:
                            self.error += 1
                            setspan = "<span style=\"color: #DD0202\"><b>"
                            self.ui.signal.wroteLog.emit(" %s ERROR %s<br/></p>" % (setspan, endspan))

                if self.ui:
                    self.ui.signal.finished.emit(self.success, self.error)
                return

        pagesize, key, iv, data = self.generatekey2(filename)
        if pagesize == 0:
            if self.ui:
                self.ui.signal.wroteLog.emit("<p>Unknown key. Aborting<br/></p>")
            return
        else:
            xml = data[:data.rfind(b">") + 1].decode("UTF-8")

        if "/" in filename:
            path = filename[:filename.rfind("/")]
        elif "\\" in filename:
            path = filename[:filename.rfind("\\")]
        else:
            path = ""

        path = os.path.join(path, outdir)

        if os.path.exists(path):
            shutil.rmtree(path)
            os.mkdir(path)
        else:
            os.mkdir(path)

        if self.ui:
            self.ui.signal.wroteLog.emit("<p>Saving ProFile.xml<br/></p>")

        file_handle = open(os.sep.join([path, "ProFile.xml"]), "w")
        file_handle.write(xml)
        file_handle.close()
    
        root = ET.fromstring(xml)
        for child in root:
            for item in child:
                if "Path" not in item.attrib and "filename" not in item.attrib:
                    for subitem in item:
                        wfilename, label, start, length, rlength, checksums, decryptsize = \
                        self.getItemDecrypt(subitem, pagesize)

                        if wfilename == "" or start == -1:
                            continue

                        self.writeData(filename, wfilename, outdir,
                                       [start, length, rlength, checksums, decryptsize], 
                                       [key, iv], log=True)

                wfilename, label, start, length, rlength, checksums, decryptsize = \
                self.getItemDecrypt(item, pagesize)

                if wfilename == "" or start == -1:
                    continue

                if child.tag in ["Sahara"]:
                    decryptsize = rlength

                if child.tag in ["Config", "Provision", "ChainedTableOfDigests", "DigestsToSign", "Firmware"]:
                    length = rlength

                if child.tag in ["DigestsToSign", "ChainedTableOfDigests", "Firmware"]:
                    self.writeData(filename, wfilename, outdir,
                                   [start, length, checksums], 
                                   log=True)
                else:
                    self.writeData(filename, wfilename, outdir,
                                   [start, length, rlength, checksums, decryptsize], 
                                   [key, iv], log=True)

        if self.ui:
            self.ui.signal.finished.emit(self.success, self.error)

    def readData(self, filename, target=None, format=None, readTable=False):
        result = []

        self.filesize = os.stat(filename).st_size
        pagesize, key, iv, data = self.generatekey2(filename)
        if pagesize == 0:
            return
        else:
            xml = data[:data.rfind(b">") + 1].decode("UTF-8")

        root = ET.fromstring(xml)
        for child in root:
            for item in child:
                if "Path" not in item.attrib and "filename" not in item.attrib:
                    for subitem in item:
                        formats = locals()
                        wfilename, label, start, length, rlength, checksums, decryptsize = \
                        self.getItemDecrypt(subitem, pagesize)

                        if wfilename == "" or start == -1:
                            continue

                        formats["name"] = label
                        formats["start"] = start
                        formats["length"] = length
                        formats["enclength"] = decryptsize
                        formats["filename"] = wfilename

                        result.append({
                            "isChecked":   True,
                            "label":       formats["name"],
                            "start_addr":  formats["start"],
                            "length":      formats["length"],
                            "filename":    formats["filename"]
                        })

                        if subitem == target and format:
                            return formats[format]

                formats = locals()
                wfilename, label, start, length, rlength, checksums, decryptsize = \
                self.getItemDecrypt(item, pagesize)

                if wfilename == "" or start == -1:
                    continue

                if child.tag in ["Sahara"]:
                    decryptsize = rlength

                if child.tag in ["Config", "Provision", "ChainedTableOfDigests", "DigestsToSign", "Firmware"]:
                    length = rlength

                formats["name"] = label
                formats["start"] = start
                formats["length"] = length
                formats["enclength"] = decryptsize
                formats["filename"] = wfilename

                result.append({
                    "isChecked":   True,
                    "label":       formats["name"],
                    "start_addr":  formats["start"],
                    "length":      formats["length"],
                    "filename":    formats["filename"]
                })

                if item == target and format:
                    return formats[format]

                if not readTable and item == "ProFile":
                    return os.sep.join([outdir, filename])

        return result

    def writeData(self, filename, srcfile, outdir, info, brutekey=[], log=False):
        dfile = os.sep.join([outdir, srcfile])
        endspan = "</span>"
        self.process = 0

        if brutekey == []:
            start, length, checksums = info

            if self.ui:
                setspan = "<span style=\"color: #0A62CB\"><b>"
                resultlog = " ".join([setspan, srcfile, endspan])
                self.ui.signal.wroteLog.emit("<p>Decrypting %s... "% resultlog)

            with open(filename, "rb") as rf:
                with open(dfile, "wb") as wf:
                    rf.seek(start)
                    data = rf.read(length)
                    wf.write(data)

                    if log:
                        self.process += len(data)
                        self.total += len(data)
                        if self.ui:
                            self.callback(self.process, length, self.ui.progressBar_file)
                            self.callback(self.total, self.filesize, self.ui.progressBar_total)

        else:
            key, iv = brutekey
            start, length, rlength, checksums, decryptsize = info
            self.sizelength = length

            if self.ui:
                setspan = "<span style=\"color: #0A62CB\"><b>"
                resultlog = " ".join([setspan, srcfile, endspan])
                self.ui.signal.wroteLog.emit("<p>Decrypting %s... " % resultlog)

            if rlength == length:
                tlen = length
                length = (length // 0x4 * 0x4)
                if tlen % 0x4 != 0:
                    length += 0x4

            with open(filename, "rb") as rf:
                with open(dfile, "wb") as wf:
                    rf.seek(start)
                    size = decryptsize
                    if rlength < decryptsize:
                        size = rlength

                    data = rf.read(size)
                    if size % 4:
                        data += (4 - (size % 4)) * b"\x00"

                    outp = self.aes_cfb(data, key, iv)
                    wf.write(outp[:size])

                    if rlength > decryptsize:
                        length = rlength - size
                        rf.seek(start + size)
                        while length > 0:
                            size = 0x100000
                            if length < 0x100000:
                                size = length

                            data = rf.read(size)
                            wf.write(data)
                            length -= size

                            if log:
                                self.process += len(data)
                                self.total += len(data)
                                if self.ui:
                                    self.callback(self.process, self.sizelength, self.ui.progressBar_file)
                                    self.callback(self.total, self.filesize, self.ui.progressBar_total)

                    if rlength % 0x1000 != 0:
                        fill = bytearray([0x00 for i in range(0x1000 - (rlength % 0x1000))])

                    if log:
                        self.process += len(outp[:size])
                        self.total += len(outp[:size])
                        if self.ui:
                            self.callback(self.process, self.sizelength, self.ui.progressBar_file)
                            self.callback(self.total, self.filesize, self.ui.progressBar_total)

        if checksums != []:
            sha256sum = checksums[0]
            md5sum = checksums[1]

            with open(dfile, "rb") as rf:
                size = os.stat(dfile).st_size
                md5 = hashlib.md5(rf.read(0x40000))

                sha256bad = False
                md5bad = False
                md5status = "empty"
                sha256status = "empty"

                if sha256sum != "":
                    for x in [0x40000, size]:
                        rf.seek(0)
                        sha256 = hashlib.sha256(rf.read(x))

                        if sha256sum != sha256.hexdigest():
                            sha256bad = True
                            sha256status = "bad"
                        else:
                            sha256status = "verified"
                            break

                if md5sum != "":
                    if md5sum != md5.hexdigest():
                        md5bad = True
                        md5status = "bad"
                    else:
                        md5status = "verified"

                if self.ui:
                    if (sha256bad and md5bad) or (sha256bad and md5sum == "") or (md5bad and sha256sum == ""):
                        self.error += 1
                        setspan = "<span style=\"color: #DD0202\"><b>"
                        self.ui.signal.wroteLog.emit(" %s ERROR %s<br/></p>" % (setspan, endspan))
                    else:
                        self.success += 1
                        setspan = "<span style=\"color: #3BC100\"><b>"
                        self.ui.signal.wroteLog.emit(" %s SUCCESS %s<br/></p>" % (setspan, endspan))

    def callback(self, tempsize, filesize, bar):
        percent = int(tempsize / filesize * 100)
        self.ui.signal.gotProgressValue.emit([percent, bar])


class ofpMtkDecrypt(object):
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

    def __init__(self, filename=None, outdir=None, parent=None):
        self.ui = parent

        if filename != None and outdir != None:
            self.decrypt_all(filename, outdir)

    def swap(self, ch):
        return ((ch & 0xF) << 4) + ((ch & 0xF0) >> 4)

    def keyshuffle(self, key, hkey):
        for i in range(0, 0x10, 4):
            key[i] = self.swap((hkey[i] ^ key[i]))
            key[i + 1] = self.swap(hkey[i + 1] ^ key[i + 1])
            key[i + 2] = self.swap(hkey[i + 2] ^ key[i + 2])
            key[i + 3] = self.swap(hkey[i + 3] ^ key[i + 3])

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
        kt = self.keytables[index]
        if len(kt) == 3:
            obskey = bytearray(unhexlify(kt[0]))
            encaeskey = bytearray(unhexlify(kt[1]))
            encaesiv = bytearray(unhexlify(kt[2]))
            key = hexlify(hashlib.md5(self.mtk_shuffle2(obskey, 16,
                                                        encaeskey, 16)).digest())[:16]
            iv = hexlify(hashlib.md5(self.mtk_shuffle2(obskey, 16,
                                                       encaesiv, 16)).digest())[:16]
        else:
            key = bytes(kt[0], "UTF-8")
            iv = bytes(kt[1], "UTF-8")

        return key, iv

    def brutekey(self, rf):
        rf.seek(0)
        encdata = rf.read(16)

        for keyid in range(0, len(self.keytables)):
            key, iv = self.getkey(keyid)
            data = self.aes_cfb(key, iv, encdata, True)
            if data[:3] == b"MMM":
                return key, iv

        if self.ui:
            self.ui.signal.wroteLog.emit("<p>Unknown key. Please ask the author for support.<br/></p>")
        return

    def cleancstring(self, input):
        return input.replace(b"\x00", b"").decode("UTF-8")

    def decrypt_select(self, filename, outdir=None, target=None):
        if outdir == None:
            outdir = os.environ["TMPDIR"]

        if not os.path.exists(outdir):
            os.mkdir(outdir)

        self.filesize = os.stat(filename).st_size
        hdrkey = bytearray(b"geyixue")
        hdrlength = 0x6C

        with open(filename, "rb") as rf:
            try:
                key, iv = self.brutekey(rf)
            except TypeError:
                return
            rf.seek(self.filesize - hdrlength)
            hdr = self.mtk_shuffle(hdrkey,
                                   len(hdrkey),
                                   bytearray(rf.read(hdrlength)),
                                   hdrlength)

            prjname, unknownval, reserved, cpu, flashtype, hdr2entries, prjinfo, crc = \
            unpack("46s Q 4s 7s 5s H 32s H", hdr)

            hdr2length = hdr2entries * 0x60

            rf.seek(self.filesize - hdr2length - hdrlength)
            hdr2 = self.mtk_shuffle(hdrkey,
                                    len(hdrkey),
                                    bytearray(rf.read(hdr2length)),
                                    hdr2length)

            for i in range(0, len(hdr2) // 0x60):
                name, start, length, enclength, filename, crc = \
                unpack("<32s Q Q Q 32s Q", hdr2[i * 0x60:(i * 0x60) + 0x60])

                name = name.replace(b"\x00", b"").decode("UTF-8")
                filename = filename.replace(b"\x00", b"").decode("UTF-8")
                self.sizelength = length

                if name == target:
                    self.writeData(filename, rf, outdir,
                                   [start, length, enclength, crc], 
                                   [key, iv], log)
                    break

    def decrypt_all(self, filename, outdir):
        if not os.path.exists(outdir):
            os.mkdir(outdir)

        self.error = 0
        self.success = 0
        self.total = 0
        endspan = "</b></span>"

        self.filesize = os.stat(filename).st_size
        hdrkey = bytearray(b"geyixue")
        hdrlength = 0x6C

        with open(filename, "rb") as rf:
            key, iv = self.brutekey(rf)
            rf.seek(self.filesize - hdrlength)
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

            if self.ui:
                if prjname != "":
                    resultlog = " ".join([setspan, prjname, endspan])
                    self.ui.signal.wroteLog.emit("<p>Detected prjname: %s<br/></p>" % resultlog)
                if prjinfo != "":
                    resultlog = " ".join([setspan, prjinfo, endspan])
                    self.ui.signal.wroteLog.emit("<p>Detected prjinfo: %s<br/></p>" % resultlog)
                if cpu != "":
                    resultlog = " ".join([setspan, cpu, endspan])
                    self.ui.signal.wroteLog.emit("<p>Detected cpu: %s<br/></p>" % resultlog)
                if flashtype != "":
                    resultlog = " ".join([setspan, flashtype, endspan])
                    self.ui.signal.wroteLog.emit("<p>Detected flash: %s<br/></p>" % resultlog)

            rf.seek(self.filesize - hdr2length - hdrlength)
            hdr2 = self.mtk_shuffle(hdrkey,
                                    len(hdrkey),
                                    bytearray(rf.read(hdr2length)),
                                    hdr2length)

            for i in range(0, len(hdr2) // 0x60):
                name, start, length, enclength, filename, crc = \
                unpack("<32s Q Q Q 32s Q", hdr2[i * 0x60:(i * 0x60) + 0x60])

                name = name.replace(b"\x00", b"").decode("UTF-8")
                filename = filename.replace(b"\x00", b"").decode("UTF-8")
                self.sizelength = length

                if self.ui:
                    setspan = "<span style=\"color: #0A62CB\"><b>"
                    resultlog = " ".join([setspan, filename, endspan])
                    self.ui.signal.wroteLog.emit("<p>Decrypting %s... " % resultlog)

                self.process = 0
                self.writeData(filename, rf, outdir,
                               [start, length, enclength, crc],
                               [key, iv], log=True)

                if self.ui:
                    if os.stat(os.sep.join([outdir, filename])).st_size >= self.sizelength:
                        self.success += 1
                        setspan = "<span style=\"color: #3BC100\"><b>"
                        self.ui.signal.wroteLog.emit(" %s SUCCESS %s<br/></p>" % (setspan, endspan))
                    else:
                        self.error += 1
                        setspan = "<span style=\"color: #DD0202\"><b>"
                        self.ui.signal.wroteLog.emit(" %s ERROR %s<br/></p>" % (setspan, endspan))

        if self.ui:
            self.ui.signal.finished.emit(self.success, self.error)

    def readData(self, filename, isRead=False, target=None, format=None, readTable=False):
        self.filesize = os.stat(filename).st_size
        hdrkey = bytearray(b"geyixue")
        hdrlength = 0x6C

        with open(filename, "rb") as rf:
            try:
                key, iv = self.brutekey(rf)
            except TypeError:
                return
            rf.seek(self.filesize - hdrlength)
            hdr = self.mtk_shuffle(hdrkey,
                                   len(hdrkey),
                                   bytearray(rf.read(hdrlength)),
                                   hdrlength)

            prjname, unknownval, reserved, cpu, flashtype, hdr2entries, prjinfo, crc = \
            unpack("46s Q 4s 7s 5s H 32s H", hdr)

            hdr2length = hdr2entries * 0x60

            rf.seek(self.filesize - hdr2length - hdrlength)
            hdr2 = self.mtk_shuffle(hdrkey,
                                    len(hdrkey),
                                    bytearray(rf.read(hdr2length)),
                                    hdr2length)

            result = []

            for i in range(0, len(hdr2) // 0x60):
                formats = locals()
                name, start, length, enclength, filename, crc = \
                unpack("<32s Q Q Q 32s Q", hdr2[i * 0x60:(i * 0x60) + 0x60])

                name = name.replace(b"\x00", b"").decode("UTF-8")
                filename = filename.replace(b"\x00", b"").decode("UTF-8")

                formats["name"] = name
                formats["start"] = start
                formats["length"] = length
                formats["enclength"] = enclength
                formats["filename"] = filename
                formats["crc"] = crc

                result.append({
                    "isChecked":   True,
                    "label":       formats["name"],
                    "start_addr":  formats["start"],
                    "length":      formats["length"],
                    "filename":    formats["filename"]
                })

                if name == target and format:
                    return formats[format]

                if not readTable and name == "scatter":
                    return os.sep.join([outdir, filename])

        return result

    def writeData(self, filename, srcfile, outdir, info, brutekey, log=False):
        start, length, enclength, crc = info
        key, iv = brutekey

        with open(os.sep.join([outdir, filename]), "wb") as wb:
            if enclength > 0:
                srcfile.seek(start)
                encdata = srcfile.read(enclength)

                if enclength % 16 != 0:
                    encdata += b"\x00" * (16 - (enclength % 16))

                data = self.aes_cfb(key, iv, encdata, True)
                wb.write(data[:enclength])
                length -= enclength

                if log:
                    self.process += len(data[:enclength])
                    self.total += len(data[:enclength])
                    if self.ui:
                        self.callback(self.process, self.sizelength, self.ui.progressBar_file)
                        self.callback(self.total, self.filesize, self.ui.progressBar_total)

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
                        self.callback(self.process, self.sizelength, self.ui.progressBar_file)
                        self.callback(self.total, self.filesize, self.ui.progressBar_total)

    def callback(self, tempsize, filesize, bar):
        percent = int(tempsize / filesize * 100)
        self.ui.signal.gotProgressValue.emit([percent, bar])


class ofpSignal(QObject):
    wroteLog = Signal(str)
    gotProgressValue = Signal(list)
    finished = Signal(int, int)


class ofpWorker(QRunnable):
    def __init__(self, main, *args, **kwargs):
        super(ofpWorker, self).__init__()
        self.main = main
        self.args = args
        self.kwargs = kwargs

    @Slot()
    def run(self):
        self.main(*self.args, **self.kwargs)


class ofpGui(QWidget):
    def __init__(self, posdir=None, parent=None):
        super(ofpGui, self).__init__(parent)
        self.progressDefault = '''
            QProgressBar {
                color: rgb(0, 0, 0);
                border: 1px solid rgb(168, 168, 168);
                background-color: rgb(222, 222, 222);
            }
            QProgressBar::chunk {
                background-color: rgb(24, 24, 168);
            }
        '''
        self.thread = QThreadPool()
        self.posdir = posdir
        self.setupUi()
        self.connectUi()

    def setupUi(self):
        self.widgetLayout = QGridLayout(self)
        self.gridLayout = QGridLayout()
        self.tableView = QTableWidget()
        self.tableView.setFocusPolicy(Qt.NoFocus)
        self.tableView.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tableView.setSelectionMode(QAbstractItemView.NoSelection)
        self.tableView.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tableView.setProperty("showDropIndicator", False)
        self.tableView.setCornerButtonEnabled(False)
        self.tableView.setDragDropOverwriteMode(False)
        self.tableView.setWordWrap(False)
        if sys.platform == "win32":
            self.tableView.setShowGrid(False)
        self.tableView.setColumnCount(4)
        item = QTableWidgetItem()
        item.setTextAlignment(Qt.AlignLeading | Qt.AlignVCenter)
        self.tableView.setHorizontalHeaderItem(0, item)
        self.tableView.horizontalHeaderItem(0).setText("Label")
        self.tableView.setColumnWidth(0, 175)
        item = QTableWidgetItem()
        item.setTextAlignment(Qt.AlignLeading | Qt.AlignVCenter)
        self.tableView.setHorizontalHeaderItem(1, item)
        self.tableView.horizontalHeaderItem(1).setText("Start Address")
        self.tableView.setColumnWidth(1, 90)
        item = QTableWidgetItem()
        item.setTextAlignment(Qt.AlignLeading | Qt.AlignVCenter)
        self.tableView.setHorizontalHeaderItem(2, item)
        self.tableView.horizontalHeaderItem(2).setText("File Size")
        self.tableView.setColumnWidth(2, 90)
        item = QTableWidgetItem()
        item.setTextAlignment(Qt.AlignLeading | Qt.AlignVCenter)
        self.tableView.setHorizontalHeaderItem(3, item)
        self.tableView.horizontalHeaderItem(3).setText("File Name")
        self.tableView.horizontalHeader().setMinimumSectionSize(22)
        self.tableView.horizontalHeader().setStretchLastSection(True)
        self.tableView.horizontalHeader().setHighlightSections(False)
        self.tableView.verticalHeader().setDefaultSectionSize(10)
        self.tableView.verticalHeader().setHighlightSections(False)
        self.tableView.verticalHeader().setVisible(False)
        self.widgetLayout.addWidget(self.tableView, 0, 0, 4, 1)
        self.ofp_LineEdit = QLineEdit()
        self.ofp_LineEdit.setPlaceholderText("OFP file")
        self.ofp_LineEdit.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        self.gridLayout.addWidget(self.ofp_LineEdit, 0, 0, 1, 1)
        self.browse_ofp = QToolButton()
        self.browse_ofp.setMinimumWidth(40)
        self.browse_ofp.setObjectName("ofp")
        self.browse_ofp.setText("...")
        self.gridLayout.addWidget(self.browse_ofp, 0, 1, 1, 1)
        self.output_LineEdit = QLineEdit()
        self.output_LineEdit.setPlaceholderText("Destination folder")
        self.output_LineEdit.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        self.gridLayout.addWidget(self.output_LineEdit, 1, 0, 1, 1)
        self.browse_dir = QToolButton()
        self.browse_dir.setMinimumWidth(40)
        self.browse_dir.setObjectName("output")
        self.browse_dir.setText("...")
        self.gridLayout.addWidget(self.browse_dir, 1, 1, 1, 1)
        self.widgetLayout.addLayout(self.gridLayout, 0, 1, 1, 1)

        self.textEdit = QTextEdit()
        self.textEdit.setReadOnly(True)
        self.textEdit.setFixedWidth(468)
        self.widgetLayout.addWidget(self.textEdit, 2, 1, 1, 1)
        self.buttonLayout = QHBoxLayout()
        self.visitButton = QPushButton(self)
        self.visitButton.setText("&Visit my project")
        self.buttonLayout.addWidget(self.visitButton)
        self.aboutButton = QPushButton(self)
        self.aboutButton.setText("&About")
        self.buttonLayout.addWidget(self.aboutButton)
        self.widgetLayout.addLayout(self.buttonLayout, 3, 1, 1, 1)
        self.label = QLabel()
        self.label.setFixedHeight(2)
        self.widgetLayout.addWidget(self.label, 4, 0, 1, 2)
        self.progressLayout = QGridLayout()
        self.progressBar_file = QProgressBar()
        self.progressBar_file.setValue(0)
        self.progressBar_file.setObjectName("File")
        self.progressBar_file.setStyleSheet(self.progressDefault)
        self.progressBar_file.setTextVisible(False)
        self.progressBar_file.setAlignment(Qt.AlignCenter)
        self.progressBar_file.setFixedHeight(18)
        self.progressLayout.addWidget(self.progressBar_file, 0, 0, 1, 1)
        self.progressBar_total = QProgressBar()
        self.progressBar_total.setValue(0)
        self.progressBar_total.setObjectName("Total")
        self.progressBar_total.setStyleSheet(self.progressDefault)
        self.progressBar_total.setTextVisible(False)
        self.progressBar_total.setAlignment(Qt.AlignCenter)
        self.progressBar_total.setFixedHeight(18)
        self.progressLayout.addWidget(self.progressBar_total, 1, 0, 1, 1)
        self.extractButton = QPushButton()
        self.extractButton.setText("&Decrypt")
        self.extractButton.setEnabled(False)
        self.extractButton.setFixedWidth(105)
        self.extractButton.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Expanding)
        self.progressLayout.addWidget(self.extractButton, 0, 1, 2, 1)
        self.widgetLayout.addLayout(self.progressLayout, 5, 0, 1, 2)

    def connectUi(self):
        self.browse_ofp.clicked.connect(self.browseDialog)
        self.browse_dir.clicked.connect(self.browseDialog)
        self.extractButton.clicked.connect(self.extract)
        self.aboutButton.clicked.connect(self.about)
        self.visitButton.clicked.connect(self.visit)

    def browseDialog(self):
        result = False
        sender = self.sender()

        if sender.objectName() == "ofp":
            title = "Select file"
            self.filter = "OFP file (*.ofp)"
            result = QFileDialog.getOpenFileName(self, title, self.posdir, self.filter)[0]

        elif sender.objectName() == "output":
            title = "Save decrypted files to folder"
            result = QFileDialog.getExistingDirectory(self, title, self.posdir)

        if result:
            self.posdir = result
            self.objectAdded(result, sender)

    def objectAdded(self, result, sender=None):
        result = os.path.normpath(result)

        if not sender or sender.objectName() == "ofp":
            self.ofp_LineEdit.setText(result)
            self.output_LineEdit.setText((os.path.dirname(result)))
            self.textEdit.insertHtml("<p>Opened file: <span style=\"color: #CFC000\"><b>%s</b></span><br/></p>" % result)
            self.extractButton.setEnabled(True)

            decrypt = mtk() if mtk().readData(result, target="scatter", format="name") else \
                      qcom()

            rows = 0
            tableData = ["label", "start_addr", "length", "filename"]

            for item in decrypt.readData(result, readTable=True):
                for column in range(len(tableData)):
                    value = tableData[column]
                    self.tableView.setRowCount(rows + 1)
                    if value == "start_addr":
                        text = "0x%X" % item["start_addr"]
                        tableItem = QTableWidgetItem()
                        tableItem.setTextAlignment(Qt.AlignLeading | Qt.AlignVCenter)
                        tableItem.setData(Qt.ToolTipRole, text)
                        self.tableView.setItem(rows, column, tableItem)
                        self.tableView.item(rows, column).setText(text)
                    elif value == "length":
                        text = setFormatSize(item["length"])
                        tableItem = QTableWidgetItem()
                        tableItem.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
                        tableItem.setData(Qt.ToolTipRole, text)
                        self.tableView.setItem(rows, column, tableItem)
                        self.tableView.item(rows, column).setText(text)
                    else:
                        tableItem = QTableWidgetItem()
                        tableItem.setTextAlignment(Qt.AlignLeading | Qt.AlignVCenter)
                        tableItem.setData(Qt.ToolTipRole, str(item[value]))
                        self.tableView.setItem(rows, column, tableItem)
                        self.tableView.item(rows, column).setText(str(item[value]))
                        if self.tableView.item(rows, 0).text() == "":
                            self.tableView.item(rows, 0).setText("<NO LABEL>")

                QApplication.processEvents()
                sleep(.01)    
                rows += 1

        elif sender.objectName() == "output":
            self.output_LineEdit.setText(result)

        for bar in [self.progressBar_file, self.progressBar_total]:
            bar.setStyleSheet(self.progressDefault)
            bar.setTextVisible(True)
            bar.setFormat("Ready")
            bar.setValue(0)

    def extract(self):
        filename = self.ofp_LineEdit.text()
        outdir = self.output_LineEdit.text()

        self.textEdit.insertHtml("<p><br/></p>")
        for bar in [self.progressBar_file, self.progressBar_total]:
            bar.setStyleSheet('''
                QProgressBar {
                    color: rgb(0, 0, 0);
                    border: 1px solid rgb(168, 168, 168);
                    background-color: rgb(222, 222, 222);
                }
                QProgressBar::chunk {
                    background-color: rgb(242, 242, 24);
                }
            ''')
            bar.setTextVisible(True)
            bar.setFormat("Processing... [%s" % bar.objectName() + ": %p%]")

        for button in [
            self.extractButton,
            self.ofp_LineEdit, self.output_LineEdit,
            self.browse_ofp, self.browse_dir]:
            button.setEnabled(False)

        QApplication.processEvents()
        self.thread = QThreadPool()
        self.signal = ofpSignal()
        self.worker = ofpWorker(lambda: mtk(filename, outdir, self) \
                                        if mtk().readData(filename, target="scatter", format="name") else \
                                        qcom(filename, outdir, self))

        self.signal.wroteLog.connect(self.setTextHtml)
        self.signal.gotProgressValue.connect(self.setProgressValue)
        self.signal.finished.connect(self.extractFinish)
        self.thread.start(self.worker)

    @Slot(int, int)
    def extractFinish(self, success: int, error: int):
        if success > error:
            self.setTextHtml("<p><br/>Successfully decrypted.<br/><br/></p>")
            for bar in [self.progressBar_file, self.progressBar_total]:
                bar.setValue(100)
                bar.setStyleSheet('''
                    QProgressBar {
                        color: rgb(255, 255, 255);
                        border: 1px solid rgb(168, 168, 168);
                        background-color: rgb(222, 222, 222);
                    }
                    QProgressBar::chunk {
                        background-color: rgb(24, 168, 24);
                    }
                ''')
                bar.setFormat("Completed")
        else:
            self.setTextHtml("<p><br/>Failed decrypted.<br/><br/></p>")
            for bar in [self.progressBar_file, self.progressBar_total]:
                bar.setValue(100)
                bar.setStyleSheet('''
                    QProgressBar {
                        color: rgb(255, 255, 255);
                        border: 1px solid rgb(168, 168, 168);
                        background-color: rgb(222, 222, 222);
                    }
                    QProgressBar::chunk {
                        background-color: rgb(168, 24, 24);
                    }
                ''')
                bar.setFormat("Try again")

        for button in [
            self.extractButton,
            self.ofp_LineEdit, self.output_LineEdit,
            self.browse_ofp, self.browse_dir]:
            button.setEnabled(True)

    @Slot(str)
    def setTextHtml(self, text: str):
        self.textEdit.insertHtml(text)
        self.textEdit.moveCursor(QTextCursor.End)

    @Slot(list)
    def setProgressValue(self, list):
        list[1].setValue(list[0])

    def visit(self):
        Url = QUrl(app.organizationDomain())
        QDesktopServices.openUrl(Url)

    def about(self):        
        QMessageBox.about(self, app.applicationName(),
                          "Oppo OFP Decrypter (c) B. Kerler 2022\n"
                          "UI designed by Faizal Hamzah [The Firefox Flasher]\n"
                          "Licensed under MIT License")


class main(QMainWindow):
    def __init__(self, posdir=None, sender=None):
        super(main, self).__init__()
        self.sender = sender
        self.setFixedSize(QSize(1078, 525))
        self.setAcceptDrops(True)
        self.setWindowFlags(Qt.WindowCloseButtonHint | Qt.WindowMinimizeButtonHint)
        self.widget = ofpGui(posdir, self)
        self.setCentralWidget(self.widget)

    def closeEvent(self, event):
        if self.sender != None:
            self.sender.setEnabled(True)
        try:
            dirname = os.path.dirname(self.widget.posdir) \
                      if os.path.isfile(self.widget.posdir) else \
                      self.widget.posdir
            settings.setValue("LastDir", os.path.normpath(dirname))
        except NameError:
            pass
        self.close()
        self.widget.thread.deleteLater()

    def dragEnterEvent(self, event):
        data = event.mimeData()
        if data.hasUrls():
            Url = data.urls()[0].toLocalFile()
            if os.path.splitext(Url)[1].lower() == ".ofp":
                event.accept()

    def dropEvent(self, event):
        data = event.mimeData()
        path = data.urls()[0].toLocalFile()
        self.widget.objectAdded(path)


def setFormatSize(size: int):
    if float(size) == 1.0:
        format = "byte"
    else:
        try:
            digit = math.floor(math.log(size, 1024))
            result = round(size / math.pow(1024, digit), 2)
            size = str(result).rstrip("0").rstrip(".")
        except ValueError:
            digit = 0

        format = ("bytes", "KB", "MB", "GB", "TB", "PB", "EB")[digit]

    return "%s %s" % (str(size), format)


if __name__ == "__main__":
    system = platform.system()
    system_version = platform.version() if not sys.platform == "win32" else \
                     list(int(i) for i in platform.version().split("."))

    homedir = os.environ["USERPROFILE" if sys.platform == "win32" else "HOME"]
    os.environ["TMPDIR"] = os.environ["TEMP"] if sys.platform == "win32" else \
                           ("/%s" if os.path.isdir("/%s") else "/var/%s") % "tmp"


    QCoreApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QCoreApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    app.setApplicationName("OFP Decrypter")
    app.setOrganizationName("The Firefox Flasher")
    app.setOrganizationDomain("https://github.com/thefirefox12537")
    widget = QWidget()
    mtk = ofpMtkDecrypt
    qcom = ofpQcomDecrypt

    if sys.platform == "linux":
        app.setStyle(QStyleFactory.create("Fusion"))
        runtimedir = os.path.join(os.environ["TMPDIR"], "runtime-%s" % os.environ["USER"])

    elif sys.platform == "win32" and system_version > [6,0,6002]:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(sys.argv[0])

    else:
        script = os.path.basename(__file__)
        os_detail = " ".join([system, platform.release()])
        sys.exit(QMessageBox.critical(widget, app.applicationName(),
                                      "%s cannot be run in %s" % (script, os_detail),
                                      QMessageBox.Close))

    if os.getenv("XDG_RUNTIME_DIR") and not os.environ["XDG_RUNTIME_DIR"] == runtimedir:
        setenv = ["env", "XDG_RUNTIME_DIR=%s" % runtimedir]
        sys.exit(subprocess.call([*setenv, *sys.argv]))

    settings = QSettings(app.organizationName(), app.applicationName())
    posdir = settings.value("LastDir") if settings.contains("LastDir") else \
             os.sep.join([homedir, "Documents" if sys.platform == "win32" else ""])


    main = main(posdir)
    main.show()
    sys.exit(app.exec())
