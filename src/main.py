import sys
from PyQt5.QtWidgets import QApplication, QMainWindow
from functools import partial
import hashlib
import GUI
import sm3
import time
import hmac

def MD5():
    time1 = time.perf_counter_ns()
    text = ui.In.toPlainText()
    length = ui.length.toPlainText()
    k = ui.Key.toPlainText()
    # 输入校验
    for c in length:
        if c.isdigit() == False:
            ui.Out.setText("请输入10进制整数作为分组长度！")
            ui.log.append(time.strftime('%Y-%m-%d %H:%M:%S : ERROR: 分组长度格式错误',time.localtime(time.time())))
            return
    text_bin = bin(int.from_bytes(text.encode('utf-8'), byteorder='big'))[2:]   #消息的二进制表示
    length = int(length)
    if length >= len(text_bin):
        ui.Out.setText("分组长度超出消息长度！")
        ui.log.append(time.strftime('%Y-%m-%d %H:%M:%S : ERROR: 分组过长', time.localtime(time.time())))
        return
    #右半部分长度
    length2 = len(text_bin) - length
    #Feistel开始
    L0 = text_bin[0:length]
    R0 = text_bin[length:]
    L1 = R0
    R1 = bin(int(L0, 2) ^ int(hashlib.md5((k + str(int(R0,2))).encode("utf-8")).hexdigest(), 16))[2:].zfill(128)[0:length]
    L2 = R1
    R2 = bin(int(L1, 2) ^ int(hashlib.md5((k + str(int(R1,2))).encode("utf-8")).hexdigest(), 16))[2:].zfill(128)[0:length2]
    L3 = R2
    R3 = bin(int(L2, 2) ^ int(hashlib.md5((k + str(int(R2,2))).encode("utf-8")).hexdigest(), 16))[2:].zfill(128)[0:length]
    enText = hex(int(L3 + R3, 2))[2:]
    HMAC = hmac.new(k.encode('utf-8'), text.encode('utf-8'), hashlib.sha1).hexdigest()
    sign = "1"
    #消息摘要 = 1位明密文标志 + 40位消息认证码 + 密文
    msg_digest = sign + HMAC + enText
    ui.Out.setText(msg_digest)
    time2 = time.perf_counter_ns()
    ui.log.append(time.strftime('%Y-%m-%d %H:%M:%S : Success: MD5加密成功', time.localtime(time.time())))
    ui.log.append("响应时间：%fms" % ((time2 - time1)/1000000))


def SHA1():
    time1 = time.perf_counter_ns()
    text = ui.In.toPlainText()
    length = ui.length.toPlainText()
    k = ui.Key.toPlainText()
    # 输入校验
    for c in length:
        if c.isdigit() == False:
            ui.Out.setText("请输入10进制整数作为分组长度！")
            ui.log.append(time.strftime('%Y-%m-%d %H:%M:%S : ERROR: 分组长度格式错误', time.localtime(time.time())))
            return
    text_bin = bin(int.from_bytes(text.encode('utf-8'), byteorder='big'))[2:]  # 消息的二进制表示
    length = int(length)
    if length >= len(text_bin):
        ui.Out.setText("分组长度超出消息长度！")
        ui.log.append(time.strftime('%Y-%m-%d %H:%M:%S : ERROR: 分组过长', time.localtime(time.time())))
        return
    # 右半部分长度
    length2 = len(text_bin) - length
    # Feistel开始
    L0 = text_bin[0:length]
    R0 = text_bin[length:]
    L1 = R0
    R1 = bin(int(L0, 2) ^ int(hashlib.sha1((k + str(int(R0, 2))).encode("utf-8")).hexdigest(), 16))[2:].zfill(128)[
         0:length]
    L2 = R1
    R2 = bin(int(L1, 2) ^ int(hashlib.sha1((k + str(int(R1, 2))).encode("utf-8")).hexdigest(), 16))[2:].zfill(128)[
         0:length2]
    L3 = R2
    R3 = bin(int(L2, 2) ^ int(hashlib.sha1((k + str(int(R2, 2))).encode("utf-8")).hexdigest(), 16))[2:].zfill(128)[
         0:length]
    enText = hex(int(L3 + R3, 2))[2:]
    HMAC = hmac.new(k.encode('utf-8'), text.encode('utf-8'), hashlib.sha1).hexdigest()
    sign = "1"
    # 消息摘要 = 1位明密文标志 + 40位消息认证码 + 密文
    msg_digest = sign + HMAC + enText
    ui.Out.setText(msg_digest)
    time2 = time.perf_counter_ns()
    ui.log.append(time.strftime('%Y-%m-%d %H:%M:%S : Success: SHA1加密成功', time.localtime(time.time())))
    ui.log.append("响应时间：%fms" % ((time2 - time1) / 1000000))

def SHA2_256():
    time1 = time.perf_counter_ns()
    text = ui.In.toPlainText()
    length = ui.length.toPlainText()
    k = ui.Key.toPlainText()
    # 输入校验
    for c in length:
        if c.isdigit() == False:
            ui.Out.setText("请输入10进制整数作为分组长度！")
            ui.log.append(time.strftime('%Y-%m-%d %H:%M:%S : ERROR: 分组长度格式错误', time.localtime(time.time())))
            return
    text_bin = bin(int.from_bytes(text.encode('utf-8'), byteorder='big'))[2:]  # 消息的二进制表示
    length = int(length)
    if length >= len(text_bin):
        ui.Out.setText("分组长度超出消息长度！")
        ui.log.append(time.strftime('%Y-%m-%d %H:%M:%S : ERROR: 分组过长', time.localtime(time.time())))
        return
    # 右半部分长度
    length2 = len(text_bin) - length
    # Feistel开始
    L0 = text_bin[0:length]
    R0 = text_bin[length:]
    L1 = R0
    R1 = bin(int(L0, 2) ^ int(hashlib.sha256((k + str(int(R0, 2))).encode("utf-8")).hexdigest(), 16))[2:].zfill(128)[0:length]
    L2 = R1
    R2 = bin(int(L1, 2) ^ int(hashlib.sha256((k + str(int(R1, 2))).encode("utf-8")).hexdigest(), 16))[2:].zfill(128)[0:length2]
    L3 = R2
    R3 = bin(int(L2, 2) ^ int(hashlib.sha256((k + str(int(R2, 2))).encode("utf-8")).hexdigest(), 16))[2:].zfill(128)[0:length]
    enText = hex(int(L3 + R3, 2))[2:]
    HMAC = hmac.new(k.encode('utf-8'), text.encode('utf-8'), hashlib.sha1).hexdigest()
    sign = "1"
    # 消息摘要 = 1位明密文标志 + 40位消息认证码 + 密文
    msg_digest = sign + HMAC + enText
    ui.Out.setText(msg_digest)
    time2 = time.perf_counter_ns()
    ui.log.append(time.strftime('%Y-%m-%d %H:%M:%S : Success: SHA256加密成功', time.localtime(time.time())))
    ui.log.append("响应时间：%fms" % ((time2 - time1) / 1000000))

def SHA2_512():
    time1 = time.perf_counter_ns()
    text = ui.In.toPlainText()
    length = ui.length.toPlainText()
    k = ui.Key.toPlainText()
    # 输入校验
    for c in length:
        if c.isdigit() == False:
            ui.Out.setText("请输入10进制整数作为分组长度！")
            ui.log.append(time.strftime('%Y-%m-%d %H:%M:%S : ERROR: 分组长度格式错误', time.localtime(time.time())))
            return
    text_bin = bin(int.from_bytes(text.encode('utf-8'), byteorder='big'))[2:]  # 消息的二进制表示
    length = int(length)
    if length >= len(text_bin):
        ui.Out.setText("分组长度超出消息长度！")
        ui.log.append(time.strftime('%Y-%m-%d %H:%M:%S : ERROR: 分组过长', time.localtime(time.time())))
        return
    # 右半部分长度
    length2 = len(text_bin) - length
    # Feistel开始
    L0 = text_bin[0:length]
    R0 = text_bin[length:]
    L1 = R0
    R1 = bin(int(L0, 2) ^ int(hashlib.sha512((k + str(int(R0, 2))).encode("utf-8")).hexdigest(), 16))[2:].zfill(128)[0:length]
    L2 = R1
    R2 = bin(int(L1, 2) ^ int(hashlib.sha512((k + str(int(R1, 2))).encode("utf-8")).hexdigest(), 16))[2:].zfill(128)[0:length2]
    L3 = R2
    R3 = bin(int(L2, 2) ^ int(hashlib.sha512((k + str(int(R2, 2))).encode("utf-8")).hexdigest(), 16))[2:].zfill(128)[0:length]
    enText = hex(int(L3 + R3, 2))[2:]
    HMAC = hmac.new(k.encode('utf-8'), text.encode('utf-8'), hashlib.sha1).hexdigest()
    sign = "1"
    # 消息摘要 = 1位明密文标志 + 40位消息认证码 + 密文
    msg_digest = sign + HMAC + enText
    ui.Out.setText(msg_digest)
    time2 = time.perf_counter_ns()
    ui.log.append(time.strftime('%Y-%m-%d %H:%M:%S : Success: SHA512加密成功', time.localtime(time.time())))
    ui.log.append("响应时间：%fms" % ((time2 - time1) / 1000000))

def SHA3_256():
    time1 = time.perf_counter_ns()
    text = ui.In.toPlainText()
    length = ui.length.toPlainText()
    k = ui.Key.toPlainText()
    # 输入校验
    for c in length:
        if c.isdigit() == False:
            ui.Out.setText("请输入10进制整数作为分组长度！")
            ui.log.append(time.strftime('%Y-%m-%d %H:%M:%S : ERROR: 分组长度格式错误', time.localtime(time.time())))
            return
    text_bin = bin(int.from_bytes(text.encode('utf-8'), byteorder='big'))[2:]  # 消息的二进制表示
    length = int(length)
    if length >= len(text_bin):
        ui.Out.setText("分组长度超出消息长度！")
        ui.log.append(time.strftime('%Y-%m-%d %H:%M:%S : ERROR: 分组过长', time.localtime(time.time())))
        return
    # 右半部分长度
    length2 = len(text_bin) - length
    # Feistel开始
    L0 = text_bin[0:length]
    R0 = text_bin[length:]
    L1 = R0
    R1 = bin(int(L0, 2) ^ int(hashlib.sha3_256((k + str(int(R0, 2))).encode("utf-8")).hexdigest(), 16))[2:].zfill(128)[0:length]
    L2 = R1
    R2 = bin(int(L1, 2) ^ int(hashlib.sha3_256((k + str(int(R1, 2))).encode("utf-8")).hexdigest(), 16))[2:].zfill(128)[0:length2]
    L3 = R2
    R3 = bin(int(L2, 2) ^ int(hashlib.sha3_256((k + str(int(R2, 2))).encode("utf-8")).hexdigest(), 16))[2:].zfill(128)[0:length]
    enText = hex(int(L3 + R3, 2))[2:]
    HMAC = hmac.new(k.encode('utf-8'), text.encode('utf-8'), hashlib.sha1).hexdigest()
    sign = "1"
    # 消息摘要 = 1位明密文标志 + 40位消息认证码 + 密文
    msg_digest = sign + HMAC + enText
    ui.Out.setText(msg_digest)
    time2 = time.perf_counter_ns()
    ui.log.append(time.strftime('%Y-%m-%d %H:%M:%S : Success: SHA3-256加密成功', time.localtime(time.time())))
    ui.log.append("响应时间：%fms" % ((time2 - time1) / 1000000))

def SHA3_512():
    time1 = time.perf_counter_ns()
    text = ui.In.toPlainText()
    length = ui.length.toPlainText()
    k = ui.Key.toPlainText()
    # 输入校验
    for c in length:
        if c.isdigit() == False:
            ui.Out.setText("请输入10进制整数作为分组长度！")
            ui.log.append(time.strftime('%Y-%m-%d %H:%M:%S : ERROR: 分组长度格式错误', time.localtime(time.time())))
            return
    text_bin = bin(int.from_bytes(text.encode('utf-8'), byteorder='big'))[2:]  # 消息的二进制表示
    length = int(length)
    if length >= len(text_bin):
        ui.Out.setText("分组长度超出消息长度！")
        ui.log.append(time.strftime('%Y-%m-%d %H:%M:%S : ERROR: 分组过长', time.localtime(time.time())))
        return
    # 右半部分长度
    length2 = len(text_bin) - length
    # Feistel开始
    L0 = text_bin[0:length]
    R0 = text_bin[length:]
    L1 = R0
    R1 = bin(int(L0, 2) ^ int(hashlib.sha256((k + str(int(R0, 2))).encode("utf-8")).hexdigest(), 16))[2:].zfill(128)[0:length]
    L2 = R1
    R2 = bin(int(L1, 2) ^ int(hashlib.sha256((k + str(int(R1, 2))).encode("utf-8")).hexdigest(), 16))[2:].zfill(128)[0:length2]
    L3 = R2
    R3 = bin(int(L2, 2) ^ int(hashlib.sha256((k + str(int(R2, 2))).encode("utf-8")).hexdigest(), 16))[2:].zfill(128)[0:length]
    enText = hex(int(L3 + R3, 2))[2:]
    HMAC = hmac.new(k.encode('utf-8'), text.encode('utf-8'), hashlib.sha1).hexdigest()
    sign = "1"
    # 消息摘要 = 1位明密文标志 + 40位消息认证码 + 密文
    msg_digest = sign + HMAC + enText
    ui.Out.setText(msg_digest)
    time2 = time.perf_counter_ns()
    ui.log.append(time.strftime('%Y-%m-%d %H:%M:%S : Success: SHA3-512加密成功', time.localtime(time.time())))
    ui.log.append("响应时间：%fms" % ((time2 - time1) / 1000000))

def SM3():
    time1 = time.perf_counter_ns()
    text = ui.In.toPlainText()
    length = ui.length.toPlainText()
    k = ui.Key.toPlainText()
    # 输入校验
    for c in length:
        if c.isdigit() == False:
            ui.Out.setText("请输入10进制整数作为分组长度！")
            ui.log.append(time.strftime('%Y-%m-%d %H:%M:%S : ERROR: 分组长度格式错误', time.localtime(time.time())))
            return
    text_bin = bin(int.from_bytes(text.encode('utf-8'), byteorder='big'))[2:]  # 消息的二进制表示
    length = int(length)
    if length >= len(text_bin):
        ui.Out.setText("分组长度超出消息长度！")
        ui.log.append(time.strftime('%Y-%m-%d %H:%M:%S : ERROR: 分组过长', time.localtime(time.time())))
        return
    # 右半部分长度
    length2 = len(text_bin) - length
    # Feistel开始
    L0 = text_bin[0:length]
    R0 = text_bin[length:]
    L1 = R0
    R1 = bin(int(L0, 2) ^ int(sm3.Main((k + str(int(R0, 2))).encode("utf-8")), 16))[2:].zfill(128)[0:length]
    L2 = R1
    R2 = bin(int(L1, 2) ^ int(sm3.Main((k + str(int(R1, 2))).encode("utf-8")), 16))[2:].zfill(128)[0:length2]
    L3 = R2
    R3 = bin(int(L2, 2) ^ int(sm3.Main((k + str(int(R2, 2))).encode("utf-8")), 16))[2:].zfill(128)[0:length]
    enText = hex(int(L3 + R3, 2))[2:]
    HMAC = hmac.new(k.encode('utf-8'), text.encode('utf-8'), hashlib.sha1).hexdigest()
    sign = "1"
    # 16进制消息摘要 = 1位明密文标志 + 40位HMAC_SHA1 + 密文
    msg_digest = sign + HMAC + enText
    ui.Out.setText(msg_digest)
    time2 = time.perf_counter_ns()
    ui.log.append(time.strftime('%Y-%m-%d %H:%M:%S : Success: SM3加密成功', time.localtime(time.time())))
    ui.log.append("响应时间：%fms" % ((time2 - time1) / 1000000))

def encrypt():
    mode = ui.mode.currentText()

    if mode == 'SM3':
        SM3()
    elif mode == 'MD5':
        MD5()
    elif mode == 'SHA-1':
        SHA1()
    elif mode == 'SHA-2-256':
        SHA2_256()
    elif mode == 'SHA-2-512':
        SHA2_512()
    elif mode == 'SHA-3-256':
        SHA3_256()
    elif mode == 'SHA-3-512':
        SHA3_512()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    MainWindow = QMainWindow()
    ui = GUI.Ui_Window()
    ui.setupUi(MainWindow)
    MainWindow.show()
    #此处执行操作
    ui.Encrypt.clicked.connect(encrypt)
    ui.log.append("Info：输出摘要包括1位的明密文标志位，40位HMAC_SHA1和加密结果")
    sys.exit(app.exec_())