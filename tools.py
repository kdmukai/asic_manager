'''
 * @Author: passby
 * @Date: 2020-07-23 00:16:29 
 * @Last Modified by: passby
 * @Last Modified time: 2020-07-23 00:16:58
 * @for whatsminer API v1.1
 * @Activate this function: (whatsminertools)
 * @1.modify admin password
 * @2.open API
 pyinstaller -i ico.ico -F tools.py -w --windowed --noconsole
'''
import socket
import json
import sys
import os
import struct
import os.path
from os import walk
import tkinter as tk
from tkinter import *
from tkinter import filedialog
from tkinter.messagebox import *
from tkinter.filedialog import askdirectory
import base64
import win32file
import select
from hashlib import md5
import passlib.hash
from passlib.hash import md5_crypt
import re
import sys
from ctypes import *
import string
import hashlib
from Crypto.Cipher import AES
import binascii
from binascii import b2a_hex
from binascii import a2b_hex
import datetime
import time
from datetime import datetime
from datetime import timedelta
import configparser

import logging
import requests

# server = 'http://192.168.2.23:4028'
# payload = '{"cmd":"summary"}'
# print(payload)
# response = requests.get(server, json=payload, timeout=1.5)
# # data = response.json()
# # print(data)
# exit()




cf = configparser.ConfigParser()

def create_config():
  global cf
  cf.add_section('SETTING')
  cf.set('SETTING','IP','')
  f=open('config.ini','w+')
  cf.write(f)#写入配置文件
  print('create config.ini')

def set_config(user):
  cf.set('SETTING','IP',user)
  cf.write(open('config.ini','w+'))#写入配置文件

try:
  cf.read("config.ini")
  IP = cf.get("SETTING", "IP")
  print(IP)
except:
  create_config()


root = tk.Tk()

host_ip = 0
host_tcp_port = 0
host_token = 0
host_sign = 0
host_passwd = tk.StringVar()
host_passwd_md5 = 0


# md5-crypt
def crypt(word, salt):
    standard_salt = re.compile('\s*\$(\d+)\$([\w\./]*)\$')
    match = standard_salt.match(salt)
    if not match:
        raise ValueError("salt format is not correct")
    extra_str = match.group(2)
    entryptor = passlib.hash.md5_crypt
    result = entryptor.encrypt(word, salt=extra_str)
    return result

def add_to_16(s):
    while len(s) % 16 != 0:
        s += '\0'
    return str.encode(s)  # return bytes

def txt_wrap_by(start_str, end, html):
    start = html.find(start_str)
    if start >= 0:
        start += len(start_str)
        end = html.find(end, start)
        if end >= 0:
            return html[start:end].strip()

#onlyread api: summary,pools,get_version,edves... 
#The onlyread API supports plaintext and ciphertext transmission
def exec_command(api_cmd, json_param=None, sz_file=None, file_dat=None, onlyread=False):
    global host_ip
    global host_tcp_port
    global host_sign
    global host_passwd_md5
    global host_token

    api_packet_str = api_cmd
    #create json string
    api_json = {"command": api_cmd} #{"cmd": api_cmd} is ok also
    if json_param != None:
        api_json.update(json_param)
    if onlyread == False:
        api_json['token'] = host_sign
    api_json_str = json.dumps(api_json)
    print("(JSON CMD)%s" % api_json_str)

    #encode json string
    api_packet_str = api_json_str
    if onlyread == False:
        print('(API,PWD,SIGN) (%s,%s,%s)' %
                (api_json_str, host_passwd_md5, host_sign))
        if host_sign != 0:
            aeskey = hashlib.sha256(host_passwd_md5.encode()).hexdigest()
            aeskey = binascii.unhexlify(aeskey.encode())
            aes = AES.new(aeskey, AES.MODE_ECB)
            api_json_str_enc = str(base64.encodebytes(
                aes.encrypt(add_to_16(api_json_str))),
                                    encoding='utf8').replace('\n', '')
            data_enc = {'enc': 1}
            data_enc['data'] = api_json_str_enc
            api_packet_str = json.dumps(data_enc)
            print("(ENC CMD) %s" % api_packet_str)
        else:
            tk.messagebox.showerror('token error', 'token is none')
            return

    #create socket & send
    host_ip = entry_mac.get()
    set_config(host_ip)
    host_tcp_port = entry_port.get()
    #socket.setdefaulttimeout(2)#FIXME:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    #s.setblocking(False)
    try:
        s.connect((host_ip, int(host_tcp_port)))
    except socket.timeout as e:
        tk.messagebox.showerror('socket error', 'tcp timeout')
        return

    start_time = time.time()# TODO: 
    s.send(api_packet_str.encode())
    print("(TCP SENT)%s" % api_packet_str)

    #receive and process whatsminer return msg
    #response = s.recv(1024 * 4)
    response = recv_response(s)
    print("(TCP RECV)%s" % response)
    if api_cmd == "update_firmware":
        ret_msg = response
        try:
            d = json.loads(ret_msg)
            ret_msg = d["enc"].encode()
        except:
            tk.messagebox.showerror('update_firmware error', 'response error')
            s.close()
            return

        crypt_data = ret_msg.decode()
        aeskey = hashlib.sha256(host_passwd_md5.encode()).hexdigest()
        aeskey = binascii.unhexlify(aeskey.encode())
        aes = AES.new(aeskey, AES.MODE_ECB)
        ret_msg = str(
            aes.decrypt(
                base64.decodebytes(bytes(
                    crypt_data,
                    encoding='utf8'))).rstrip(b'\0').decode("utf8"))
        print("(FW decrypted_text):%s" % ret_msg)

        try:
            d = json.loads(ret_msg)
            ret_msg = d["Msg"].encode()
        except:
            s.close()
            return

        if ret_msg.decode() != 'ready':
            tk.messagebox.showerror('error', 'response error')
            s.close()
            return
        print("(UPDATE FW) ready ok")
        s.send(sz_file)
        s.send(file_dat)
        response = recv_response(s)
    elif api_cmd == "download_logs":
        ret_msg = response
        try:
            d = json.loads(ret_msg)
            ret_msg = d["enc"].encode()
        except:
            tk.messagebox.showerror('download_logs error', 'response error')
            s.close()
            return

        crypt_data = ret_msg.decode()
        aeskey = hashlib.sha256(host_passwd_md5.encode()).hexdigest()
        aeskey = binascii.unhexlify(aeskey.encode())
        aes = AES.new(aeskey, AES.MODE_ECB)
        ret_msg = str(
            aes.decrypt(
                base64.decodebytes(bytes(
                    crypt_data,
                    encoding='utf8'))).rstrip(b'\0').decode("utf8"))
        print("(logs decrypted_text):%s" % ret_msg)
        '''
        try:
            d = json.loads(ret_msg)
            msg = d["Msg"]
            recv_file(s, int(msg['logfilelen']), name=str(t_mac.get()) + datetime.now() +'.tgz')
        except:
            print('download_logs recv data error')
            s.close()
            return
        '''
        d = json.loads(ret_msg)
        msg = d["Msg"]
        dt=datetime.now()
        ymd=dt.strftime('%Y%m%d%H%M%S')
        recv_file(s, int(msg['logfilelen']), name=str(t_mac.get()) + '.' + ymd +'.tgz')

    s.close()
    end_time = time.time()  #TODO:
    print("start_time:\t%s" % start_time)
    print("end_time:\t%s" % end_time)
    print("time:\t%s" % ((end_time - start_time) * 1000))
    if response == False:
        tk.messagebox.showerror('tcp recv error', "whatsminer response none")

    #parse ret msg
    ret_msg = response
    label_ret_msg['text'] = ''
    if onlyread == True:
        if api_cmd == "get_token":  #generate key and token sign:
            try:
                r = json.loads(ret_msg)
                d = r['Msg']
            except:
                tk.messagebox.showerror('get token error', "is not json")
            else:
                if isinstance(d, dict):
                    passwd = entry_passwd.get()
                    print("(PWD, SALT,TIME,NEWSALT) %s, %s,%s,%s" % (passwd,d["salt"],d["time"],d["newsalt"]))
                    pwd = crypt(passwd, "$1$" + d["salt"] + '$')
                    pwd = pwd.split('$')
                    host_passwd_md5 = pwd[3]

                    tmp = crypt(pwd[3] + d["time"], "$1$" + d["newsalt"] + '$')
                    tmp = tmp.split('$')
                    host_sign = tmp[3]
                    host_token = d["time"] + ',' + d["newsalt"] + ',' + host_sign
                    print(
                        '(PWD,MD5,SIGN) %s, %s, %s'
                        % (passwd, host_passwd_md5, host_sign))
    else:
        if len(ret_msg) < 256: #FIXME: json > 256Byte will crash
            try:
                d = json.loads(ret_msg)
            except:
                tk.messagebox.showerror('error', 'load json')
            else:
                if 'enc' in d.keys():
                    enc_data = d['enc']
                    aeskey = hashlib.sha256(host_passwd_md5.encode()).hexdigest()
                    aeskey = binascii.unhexlify(aeskey.encode())
                    aes = AES.new(aeskey, AES.MODE_ECB)
                    ret_msg = str(
                        aes.decrypt(base64.decodebytes(bytes(
                            enc_data, encoding='utf8'))).rstrip(b'\0').decode("utf8"))
        else:
            pass#TODO: The privilege API respone msg less then 256Bytes generally.
    label_ret_msg['text'] = ret_msg
    # print(ret_msg)


def recv_response(s, timeout=15):
    s.setblocking(False)
    ready = select.select([s], [], [], timeout)
    if ready[0]:
        data = s.recv(1024 * 8)
        return data
    else:
        tk.messagebox.showerror('error', 'socket recv timeout')
        return False

def recv_file(s, length, name, timeout=8):
    print('ready recv name:%s len:%x' % (name,length))
    fo = open(name, "wb+")
    filelen = length
    while True:
        s.setblocking(False)
        ready = select.select([s], [], [], timeout)
        if ready[0]:
            data = s.recv(filelen)
            fo.write(data)
            filelen -= len(data)
            if filelen == 0:
                break;
        else:
            tk.messagebox.showerror('error', 'socket recv timeout')
            return False
    fo.close()
    return True

def fn_update_pool():
    exec_command("update_pools",{"pool1":entry_pool1.get(),"worker1":entry_pool1_usr.get(),\
    "passwd1":entry_pool1_pwd.get(), "share1":t_pool4.get(), "pool2":entry_pool2.get(),"worker2":entry_pool2_usr.get(),\
    "passwd2":entry_pool2_pwd.get(), "share2":t_pool24.get(), "pool3":entry_pool3.get(),"worker3":entry_pool3_usr.get(),\
    "passwd3":entry_pool3_pwd.get(), "share3":t_pool34.get(), })


def fn_reboot_btminer():
    exec_command("restart_btminer")


def fn_power_off():
    exec_command("power_off", {"respbefore":"true"})


def fn_power_on():
    exec_command("power_on")

def fn_adjust_norm_temp():
    exec_command("adjust_norm_temp")

def fn_led_ctl():
    exec_command("set_led", {"color":entry_led_color.get(),"period":int(entry_led_cycle.get()),\
    "duration":int(entry_led_duty.get()),"start":int(entry_led_oft.get())})


def fn_mode_low():
    exec_command("set_low_power")


def fn_mode_normal():
    exec_command("set_normal_power")


def fn_mode_high():
    exec_command("set_high_power")

def fn_enable_btminer_fast_boot():
    exec_command("enable_btminer_fast_boot")

def fn_disable_btminer_fast_boot():
    exec_command("disable_btminer_fast_boot")

def fn_update_firmware():
    label_ret_msg['text'] = ''
    path = filedialog.askopenfilename(title='firmware file', filetypes=\
    [('bin tgz', '*.bin *.tgz'),('All Files', '*')])
    if len(path) != 0:
        print(path)
        update_file_Label['text'] = path
    else:
        return
    sz = os.path.getsize(path)
    sz = int(sz)
    sz_file = struct.pack('i', sz)
    f = open(path, 'rb')
    c = f.read()
    f.close()
    exec_command("update_firmware", None, sz_file, c)


def fn_set_zone():
    exec_command("set_zone",{"timezone":entry_timezone.get(),"zonename":entry_zonename.get()})

def fn_load_log():
    exec_command("load_log", {"ip":entry_log_ip.get(),"port":entry_log_port.get(),"proto":v_logd_udp_tcp.get()})

def fn_set_fan_manual():
    exec_command("set_fan_manual",{"speed":entry_set_fan_manual.get()})

def fn_set_target_freq():
    exec_command("set_target_freq",{"percent":entry_set_target_freq.get()})

def fn_set_fan_speed():
    exec_command("set_fan_speed", {"percent":entry_set_fan_speed.get()})

def fn_reboot_sys():
    exec_command("reboot")

def fn_time_randomized():
    dt1 = int(entry_time_start.get())
    dt2 = int(entry_time_stop.get())
    exec_command("time_randomized", {"start":dt1,"stop":dt2})

def fn_reset_factory():
    exec_command("factory_reset")

def fn_modify_passwd():
    exec_command("update_pwd", {
        "old": entry_passwd.get(),
        "new": entry_admin_pwd.get()
    })
    host_passwd.set(entry_admin_pwd.get())

def fn_download_logs():
    exec_command("download_logs")

def fn_net_dhcp():
    exec_command("net_config", {"param": "dhcp"})


def fn_get_token():
    exec_command("get_token", onlyread = True)


def fn_ssh_open():
    exec_command("ssh_open")


def fn_ssh_close():
    exec_command("ssh_close")


def fn_get_psu():
    exec_command("get_psu", onlyread = True)


def fn_get_version():
    exec_command("get_version", onlyread = True)


def fn_summary():
    exec_command("summary", onlyread = True)

def fn_status():
    exec_command("status")

def fn_pools():
    exec_command("pools", onlyread = True)


def fn_edevs():
    exec_command("edevs", onlyread = True)

def fn_edevdetails():
    exec_command("devdetails", onlyread = True)

def fn_led_auto():
    exec_command("set_led", {"param": "auto"})

def fn_network_set():
    exec_command("net_config", {"ip":entry_network_ip.get(),"mask":entry_network_msk.get(),\
    "gate":entry_network_gate.get(),"dns":t_network_dns.get(),"host":"whatsminer"})

def select_tcp_udp():
    pass

def fn_set_hostname():
    exec_command("set_hostname", {"hostname": "automan"})

def fn_read_host():
    exec_command("read_host", onlyread = True)

def fn_setpower_pct():
    exec_command("set_power_pct", {"percent":entry_set_power_pct.get()})

def fn_enable_web_pools():
    exec_command("enable_web_pools")

def fn_disable_web_pools():
    exec_command("disable_web_pools")

def fn_disable_btminer_init():
    exec_command("disable_btminer_init")

def fn_enable_btminer_init():
    exec_command("enable_btminer_init")

#set_target_freq
if __name__ == '__main__':
    global label_ret_msg
    global update_file_Label

    #myname = socket.getfqdn(socket.gethostname())
    #myaddr = socket.gethostbyname(myname)

    root.title("API demo v0.2 API1.3.3")
    root.geometry('800x600+30+30')

    t_mac = tk.StringVar()
    t_port = tk.StringVar()
    # t_mac.set('192.168.2.213')
    t_mac.set(IP)
    t_port.set('4028')
    entry_mac = tk.Entry(root, textvariable=t_mac)
    entry_port = tk.Entry(root, textvariable=t_port)
    host_passwd.set('admina')
    entry_passwd = tk.Entry(root, textvariable=host_passwd)
    t_pool1 = tk.StringVar()
    t_pool1.set('stratum+tcp://btc.ss.poolin.com:443')
    entry_pool1 = tk.Entry(root, textvariable=t_pool1)
    t_pool2 = tk.StringVar()
    t_pool2.set('microbtinit1')
    entry_pool1_usr = tk.Entry(root, textvariable=t_pool2)
    t_pool3 = tk.StringVar()
    t_pool3.set('123')
    entry_pool1_pwd = tk.Entry(root, textvariable=t_pool3)
    t_pool4 = tk.IntVar()
    t_pool4.set(4)
    entry_pool1_share = tk.Entry(root, textvariable=t_pool4)

    t_pool21 = tk.StringVar()
    t_pool21.set('stratum+tcp://btc.ss.poolin.com:443')
    entry_pool2 = tk.Entry(root, textvariable=t_pool21)
    t_pool22 = tk.StringVar()
    t_pool22.set('microbtinit2')
    entry_pool2_usr = tk.Entry(root, textvariable=t_pool22)
    t_pool23 = tk.StringVar()
    t_pool23.set('123')
    t_pool24 = tk.IntVar()
    t_pool24.set(5)
    entry_pool2_share = tk.Entry(root, textvariable=t_pool24)

    entry_pool2_pwd = tk.Entry(root, textvariable=t_pool23)
    t_pool31 = tk.StringVar()
    t_pool31.set('stratum+tcp://btc.ss.poolin.com:443')
    entry_pool3 = tk.Entry(root, textvariable=t_pool31)
    t_pool32 = tk.StringVar()
    t_pool32.set('microbtinit3')
    entry_pool3_usr = tk.Entry(root, textvariable=t_pool32)
    t_pool33 = tk.StringVar()
    t_pool33.set('123')
    t_pool34 = tk.IntVar()
    t_pool34.set(6)
    entry_pool3_share = tk.Entry(root, textvariable=t_pool34)

    entry_pool3_pwd = tk.Entry(root, textvariable=t_pool33)
    t_led = tk.StringVar()
    t_led.set('red')
    entry_led_color = tk.Entry(root, textvariable=t_led)
    t_ledcycle = tk.StringVar()
    t_ledcycle.set('2000')
    entry_led_cycle = tk.Entry(root, textvariable=t_ledcycle)
    t_ledduty = tk.StringVar()
    t_ledduty.set('1000')
    entry_led_duty = tk.Entry(root, textvariable=t_ledduty)
    t_ledoft = tk.StringVar()
    t_ledoft.set('0')
    entry_led_oft = tk.Entry(root, textvariable=t_ledoft)
    entry_admin_oldpwd = tk.Entry(root,
                                  textvariable=host_passwd,
                                  state=DISABLED)

    t_timestart = tk.StringVar()
    t_timestart.set('0')
    entry_time_start = tk.Entry(root, textvariable=t_timestart)
    t_timestop = tk.StringVar()
    t_timestop.set('1')
    entry_time_stop = tk.Entry(root, textvariable=t_timestop)
    label_time_start = tk.Label(root, text='start')
    label_time_stop = tk.Label(root, text='stop')

    t_adminpwd = tk.StringVar()
    t_adminpwd.set('newpasswd')
    entry_admin_pwd = tk.Entry(root, textvariable=t_adminpwd)
    t_network_ip = tk.StringVar()
    t_network_ip.set("192.168.0.107")
    entry_network_ip = tk.Entry(root, textvariable=t_network_ip)
    t_network_msk = tk.StringVar()
    t_network_msk.set('255.255.255.0')
    entry_network_msk = tk.Entry(root, textvariable=t_network_msk)
    t_network_gate = tk.StringVar()
    t_network_gate.set('192.168.2.1')
    entry_network_gate = tk.Entry(root, textvariable=t_network_gate)
    t_network_dns = tk.StringVar()
    t_network_dns.set('192.168.2.1')
    entry_network_dns = tk.Entry(root, textvariable=t_network_dns)
    label_machine_ip = tk.Label(root, text='whatsminer IP')
    label_machine_port = tk.Label(root, text='port')
    label_machine_passwd = tk.Label(root, text='admin passwd')
    btn_updatepool = tk.Button(root,
                               wraplength = 50,
                               text='update pool',
                               font=("宋体", 7, 'bold'),
                               width=8,
                               height=3,
                               command=fn_update_pool)
    btn_reboot_btminer = tk.Button(root,
                                   wraplength = 50,
                                   text='restart btminer',
                                   font=("宋体", 7, 'bold'),
                                   width=8,
                                   height=3,
                                   command=fn_reboot_btminer)
    btn_power_off = tk.Button(root,
                              wraplength = 50,
                              text='power off',
                              font=("宋体", 7, 'bold'),
                              width=8,
                              height=3,
                              command=fn_power_off)
    btn_power_on = tk.Button(root,
                             wraplength = 50,
                             text='power on',
                             font=("宋体", 7, 'bold'),
                             width=8,
                             height=3,
                             command=fn_power_on)
    btn_led_auto = tk.Button(root,
                             wraplength = 50,
                             text='auto LED',
                             font=("宋体", 7, 'bold'),
                             width=8,
                             height=3,
                             command=fn_led_auto)
    label_led_color = tk.Label(root, text='color')
    label_led_cycle = tk.Label(root, text='cycle')
    label_led_duty = tk.Label(root, text='duty')
    label_led_oft = tk.Label(root, text='offset')
    btn_led_ctl = tk.Button(root,
                            wraplength = 50,
                            text='control LED',
                            font=("宋体", 7, 'bold'),
                            width=8,
                            height=3,
                            command=fn_led_ctl)
    btn_mode_low = tk.Button(root,
                              wraplength = 50,
                              text='low power',
                              font=("宋体", 7, 'bold'),
                              width=8,
                              height=3,
                              command=fn_mode_low)
    btn_set_hostname = tk.Button(root,
                              wraplength = 50,
                              text='set hostname',
                              font=("宋体", 7, 'bold'),
                              width=8,
                              height=3,
                              command=fn_set_hostname)

    btn_read_host = tk.Button(root,
                              wraplength = 50,
                              text='read_host',
                              font=("宋体", 7, 'bold'),
                              width=8,
                              height=3,
                              command=fn_read_host)


    t_set_power_pct = tk.StringVar()
    t_set_power_pct.set('0')
    label_set_power_pct = tk.Label(root, text='%')
    entry_set_power_pct = tk.Entry(root, textvariable=t_set_power_pct)
    btn_setpower_pct = tk.Button(root,
                              wraplength = 50,
                              text='set power pct',
                              font=("宋体", 7, 'bold'),
                              width=8,
                              height=3,
                              command=fn_setpower_pct)

    btn_adjust_norm_temp = tk.Button(root,
                              wraplength = 50,
                              text='adjust_norm_temp',
                              font=("宋体", 7, 'bold'),
                              width=8,
                              height=3,
                              command=fn_adjust_norm_temp)

    btn_enable_web_pools = tk.Button(root,
                              wraplength = 50,
                              text='enable_web_pools',
                              font=("宋体", 7, 'bold'),
                              width=8,
                              height=3,
                              command=fn_enable_web_pools)

    btn_disable_web_pools = tk.Button(root,
                              wraplength = 50,
                              text='disable_web_pools',
                              font=("宋体", 7, 'bold'),
                              width=8,
                              height=3,
                              command=fn_disable_web_pools)

    btn_disable_btminer_init = tk.Button(root,
                              wraplength = 50,
                              text='disable_btminer_init',
                              font=("宋体", 7, 'bold'),
                              width=8,
                              height=3,
                              command=fn_disable_btminer_init)

    btn_enable_btminer_init = tk.Button(root,
                              wraplength = 50,
                              text='enable_btminer_init',
                              font=("宋体", 7, 'bold'),
                              width=8,
                              height=3,
                              command=fn_enable_btminer_init)

    btn_enable_btminer_fast_boot = tk.Button(root,
                                 wraplength = 50,
                                 text='enable fast boot',
                                 font=("宋体", 7, 'bold'),
                                 width=8,
                                 height=3,
                                 command=fn_enable_btminer_fast_boot)

    btn_disable_btminer_fast_boot = tk.Button(root,
                                 wraplength = 50,
                                 text='disable fast boot',
                                 font=("宋体", 7, 'bold'),
                                 width=8,
                                 height=3,
                                 command=fn_disable_btminer_fast_boot)

    btn_mode_normal = tk.Button(root,
                                 wraplength = 50,
                                 text='norm power',
                                 font=("宋体", 7, 'bold'),
                                 width=8,
                                 height=3,
                                 command=fn_mode_normal)

    btn_mode_high = tk.Button(root,
                               wraplength = 50,
                               text='high power',
                               font=("宋体", 7, 'bold'),
                               width=8,
                               height=3,
                               command=fn_mode_high)
    btn_update_firmware = tk.Button(root,
                                    wraplength = 50,
                                    text='FW update',
                                    font=("宋体", 7, 'bold'),
                                    width=8,
                                    height=3,
                                    command=fn_update_firmware)

    btn_set_zone = tk.Button(root,
                                    wraplength = 50,
                                    text='set zone',
                                    font=("宋体", 7, 'bold'),
                                    width=8,
                                    height=3,
                                    command=fn_set_zone)
    t_set_timezone = tk.StringVar()
    t_set_timezone.set('CST-8')
    label_timezone = tk.Label(root, wraplength = 40, text='time zone')
    t_set_zonename = tk.StringVar()
    t_set_zonename.set('Asia/Shanghai')
    label_zonename = tk.Label(root, wraplength = 40, text='zone name')
    entry_timezone = tk.Entry(root, textvariable=t_set_timezone)
    entry_zonename = tk.Entry(root, textvariable=t_set_zonename)


    t_log_ip = tk.StringVar()
    t_log_port = tk.StringVar()
    t_log_ip.set('192.168.2.100')
    t_log_port.set('514')
    entry_log_ip = tk.Entry(root, textvariable=t_log_ip)
    entry_log_port = tk.Entry(root, textvariable=t_log_port)

    btn_load_log = tk.Button(root,
                                    wraplength = 50,
                                    text='load log',
                                    font=("宋体", 7, 'bold'),
                                    width=8,
                                    height=3,
                                    command=fn_load_log)

    btn_time_randomized = tk.Button(root,
                                    wraplength = 50,
                                    text='time randomized',
                                    font=("宋体", 7, 'bold'),
                                    width=8,
                                    height=3,
                                    command=fn_time_randomized)

    btn_set_fan_manual = tk.Button(root,
                                    wraplength = 50,
                                    text='set fan manual',
                                    font=("宋体", 7, 'bold'),
                                    width=8,
                                    height=3,
                                    command=fn_set_fan_manual)
    t_set_fan_manual = tk.StringVar()
    t_set_fan_manual.set('500')
    label_set_fan_manual = tk.Label(root, text='speed')
    entry_set_fan_manual = tk.Entry(root, textvariable=t_set_fan_manual)


    btn_set_target_freq = tk.Button(root,
                                    wraplength = 50,
                                    text='set target freq',
                                    font=("宋体", 7, 'bold'),
                                    width=8,
                                    height=3,
                                    command=fn_set_target_freq)
    t_set_target_freq = tk.StringVar()
    t_set_target_freq.set('0')
    label_set_target_freq = tk.Label(root, text='%')
    entry_set_target_freq = tk.Entry(root, textvariable=t_set_target_freq)

    btn_download_logs = tk.Button(root,
                                    wraplength = 50,
                                    text='download logs',
                                    font=("宋体", 7, 'bold'),
                                    width=8,
                                    height=3,
                                    command=fn_download_logs)

    btn_set_fan_speed = tk.Button(root,
                                    wraplength = 50,
                                    text='set fan speed',
                                    font=("宋体", 7, 'bold'),
                                    width=8,
                                    height=3,
                                    command=fn_set_fan_speed)

    t_set_fan_speed = tk.StringVar()
    t_set_fan_speed.set('50')
    entry_set_fan_speed = tk.Entry(root, textvariable=t_set_fan_speed)
    label_set_fan_speed = tk.Label(root, text='percent')


    btn_reboot_sys = tk.Button(root,
                               wraplength = 50,
                               text='system reboot',
                               font=("宋体", 7, 'bold'),
                               width=8,
                               height=3,
                               command=fn_reboot_sys)

    btn_reset_factory = tk.Button(root,
                                  wraplength = 50,
                                  text='restore setting',
                                  font=("宋体", 7, 'bold'),
                                  width=8,
                                  height=3,
                                  command=fn_reset_factory)
    btn_ssh_open = tk.Button(root,
                             wraplength = 50,
                             text='open ssh',
                             font=("宋体", 7, 'bold'),
                             width=8,
                             height=3,
                             command=fn_ssh_open)
    btn_ssh_close = tk.Button(root,
                              wraplength = 50,
                              text='close ssh',
                              font=("宋体", 7, 'bold'),
                              width=8,
                              height=3,
                              command=fn_ssh_close)
    btn_get_psu = tk.Button(root,
                            wraplength = 50,
                            text='get PSU',
                            font=("宋体", 7, 'bold'),
                            width=8,
                            height=3,
                            command=fn_get_psu)
    btn_get_version = tk.Button(root,
                                wraplength = 50,
                                text='get version',
                                font=("宋体", 7, 'bold'),
                                width=8,
                                height=3,
                                command=fn_get_version)
    btn_modify_passwd = tk.Button(root,
                                  wraplength = 50,
                                  text='modify passwd',
                                  font=("宋体", 7, 'bold'),
                                  width=8,
                                  height=3,
                                  command=fn_modify_passwd)
    btn_net_dhcp = tk.Button(root,
                             wraplength = 50,
                             text='DHCP',
                             font=("宋体", 7, 'bold'),
                             width=8,
                             height=3,
                             command=fn_net_dhcp)
    label_network_ip = tk.Label(root, text='ip')
    label_network_msk = tk.Label(root, text='msk')
    label_network_gate = tk.Label(root, text='gate')
    label_network_dns = tk.Label(root, text='dns')
    btn_network_set = tk.Button(root,
                                wraplength = 50,
                                text='network config',
                                font=("宋体", 7, 'bold'),
                                width=8,
                                height=3,
                                command=fn_network_set)
    btn_get_token = tk.Button(root,
                              wraplength = 50,
                              text='get token',
                              font=("宋体", 7, 'bold'),
                              width=8,
                              height=3,
                              command=fn_get_token)

    btn_status = tk.Button(root,
                            wraplength = 50,
                            text='status',
                            font=("宋体", 7, 'bold'),
                            width=8,
                            height=3,
                            command=fn_status)

    btn_summary = tk.Button(root,
                            wraplength = 50,
                            text='summary',
                            font=("宋体", 7, 'bold'),
                            width=8,
                            height=3,
                            command=fn_summary)
    btn_pools = tk.Button(root,
                          wraplength = 50,
                          text='pools',
                          font=("宋体", 7, 'bold'),
                          width=8,
                          height=3,
                          command=fn_pools)
    btn_edevs = tk.Button(root,
                          wraplength = 50,
                          text='edevs/devs',
                          font=("宋体", 7, 'bold'),
                          width=8,
                          height=3,
                          command=fn_edevs)
    btn_edevdetails = tk.Button(root,
                                wraplength = 50,
                                text='edevdetails',
                                font=("宋体", 7, 'bold'),
                                width=8,
                                height=3,
                                command=fn_edevdetails)

    btn_modify_passwd.pack()
    btn_net_dhcp.pack()
    btn_network_set.pack()
    btn_get_token.pack()
    btn_reboot_btminer.pack()
    btn_power_off.pack()
    btn_power_on.pack()
    btn_led_ctl.pack()
    label_led_color.pack()
    label_led_duty.pack()
    label_led_cycle.pack()
    label_led_oft.pack()
    label_machine_ip.pack()
    label_machine_port.pack()
    label_machine_passwd.pack()
    btn_led_auto.pack()
    btn_mode_low.pack()
    btn_set_hostname.pack()
    btn_read_host.pack()
    btn_setpower_pct.pack()
    btn_adjust_norm_temp.pack()
    btn_enable_web_pools.pack()
    btn_disable_web_pools.pack()
    btn_disable_btminer_init.pack()
    btn_enable_btminer_init.pack()
    btn_mode_normal.pack()
    btn_disable_btminer_fast_boot.pack()
    btn_enable_btminer_fast_boot.pack()
    btn_mode_high.pack()
    btn_update_firmware.pack()
    btn_reboot_sys.pack()
    btn_reset_factory.pack()
    btn_ssh_open.pack()
    btn_ssh_close.pack()
    btn_get_psu.pack()
    btn_get_version.pack()
    btn_summary.pack()
    btn_status.pack()
    btn_pools.pack()
    btn_edevs.pack()
    btn_edevdetails.pack()
    btn_set_zone.pack()
    btn_load_log.pack()
    entry_log_ip.pack()
    entry_log_port.pack()
    btn_time_randomized.pack()
    btn_set_fan_manual.pack()
    btn_set_target_freq.pack()
    btn_download_logs.pack()
    btn_set_fan_speed.pack()
    entry_set_fan_speed.pack()
    label_set_fan_speed.pack()
    label_set_fan_manual.pack()
    label_set_target_freq.pack()
    label_set_power_pct.pack()
    label_timezone.pack()
    label_zonename.pack()
    entry_timezone.pack()
    entry_zonename.pack()
    entry_set_fan_manual.pack()
    entry_set_target_freq.pack()
    entry_set_power_pct.pack()
    label_network_ip.pack()
    label_network_msk.pack()
    label_network_gate.pack()
    label_network_dns.pack()
    btn_updatepool.pack()
    entry_admin_pwd.pack()
    entry_time_start.pack()
    entry_time_stop.pack()
    label_time_start.pack()
    label_time_stop.pack()
    entry_network_ip.pack()
    entry_network_msk.pack()
    entry_network_gate.pack()
    entry_network_dns.pack()
    entry_admin_oldpwd.pack()
    entry_led_oft.pack()
    entry_led_duty.pack()
    entry_led_cycle.pack()
    entry_mac.pack()
    entry_port.pack()
    entry_passwd.pack()
    entry_pool1.pack()
    entry_pool2_usr.pack()
    entry_pool3_usr.pack()
    entry_pool3_pwd.pack()
    entry_pool1_share.pack()
    entry_pool2_share.pack()
    entry_pool3_share.pack()
    entry_led_color.pack()
    entry_pool3.pack()
    entry_pool2_pwd.pack()
    entry_pool2.pack()
    entry_pool1_pwd.pack()
    entry_pool1_usr.pack()

    xpow = 0
    ypos = 0
    height = 40
    entry_mac.place(x=xpow + 60, y=height * ypos, width=90, anchor=tk.NW)
    entry_port.place(x=xpow + 60 + 150,
                     y=height * ypos,
                     width=40,
                     anchor=tk.NW)
    entry_passwd.place(x=xpow + 100 + 150 + 112,
                       y=height * ypos,
                       width=100,
                       anchor=tk.NW)
    label_machine_ip.place(x=xpow, y=height * ypos, width=60, anchor=tk.NW)
    label_machine_port.place(x=xpow + 150 + 10,
                             y=height * ypos,
                             width=40,
                             anchor=tk.NW)
    label_machine_passwd.place(x=xpow + 150 + 100 + 10,
                               y=height * ypos,
                               width=100,
                               anchor=tk.NW)

    ypos += 1
    btn_updatepool.place(x=xpow, y=height * ypos - 10, anchor=tk.NW)
    entry_pool1.place(x=xpow + 75,
                      y=height * ypos + 4,
                      width=270,
                      anchor=tk.NW)
    entry_pool1_usr.place(x=xpow + 75,
                          y=height * ypos + 4 + 30,
                          width=80,
                          anchor=tk.NW)
    entry_pool1_pwd.place(x=xpow + 175,
                          y=height * ypos + 4 + 30,
                          width=80,
                          anchor=tk.NW)
    entry_pool1_share.place(x=xpow + 175 + 90,
                          y=height * ypos + 4 + 30,
                          width=40,
                          anchor=tk.NW)


    ypos += 0.7
    btn_get_psu.place(x=xpow, y=height * ypos, anchor=tk.NW)
    ypos += 0.8
    entry_pool2.place(x=xpow + 75,
                      y=height * ypos + 4,
                      width=270,
                      anchor=tk.NW)
    entry_pool2_usr.place(x=xpow + 75,
                          y=height * ypos + 4 + 30,
                          width=80,
                          anchor=tk.NW)
    entry_pool2_pwd.place(x=xpow + 175,
                          y=height * ypos + 4 + 30,
                          width=80,
                          anchor=tk.NW)
    entry_pool2_share.place(x=xpow + 175 + 90,
                          y=height * ypos + 4 + 30,
                          width=40,
                          anchor=tk.NW)

    ypos += 0.1
    btn_get_version.place(x=xpow, y=height * ypos, anchor=tk.NW)
    ypos += 0.9
    btn_reboot_btminer.place(x=xpow, y=height * ypos, anchor=tk.NW)
    ypos += 0.5
    entry_pool3.place(x=xpow + 75,
                      y=height * ypos + 4,
                      width=270,
                      anchor=tk.NW)
    entry_pool3_usr.place(x=xpow + 75,
                          y=height * ypos + 4 + 30,
                          width=80,
                          anchor=tk.NW)
    entry_pool3_pwd.place(x=xpow + 175,
                          y=height * ypos + 4 + 30,
                          width=80,
                          anchor=tk.NW)
    entry_pool3_share.place(x=xpow + 175 + 90,
                          y=height * ypos + 4 + 30,
                          width=40,
                          anchor=tk.NW)

    ypos += 0.5
    btn_reset_factory.place(x=xpow, y=height * ypos, anchor=tk.NW)
    ypos += 1
    btn_reboot_sys.place(x=xpow + 70 * 2, y=height * ypos, anchor=tk.NW)

    btn_power_off.place(x=xpow, y=height * ypos, anchor=tk.NW)
    btn_power_on.place(x=xpow + 70, y=height * ypos, anchor=tk.NW)
    label_led_color.place(x=xpow + 70 * 2,
                          y=height * ypos + 16,
                          width=40,
                          anchor=tk.NW)
    label_led_cycle.place(x=xpow + 70 * 2 + 50,
                          y=height * ypos + 16,
                          width=40,
                          anchor=tk.NW)
    label_led_duty.place(x=xpow + 70 * 2 + 50 * 2,
                         y=height * ypos + 16,
                         width=40,
                         anchor=tk.NW)
    label_led_oft.place(x=xpow + 70 * 2 + 50 * 3,
                        y=height * ypos + 16,
                        width=40,
                        anchor=tk.NW)
    ypos += 1

    btn_led_ctl.place(x=xpow + 70, y=height * ypos, anchor=tk.NW)
    entry_led_color.place(x=xpow + 70 * 2,
                          y=height * ypos + 4,
                          width=40,
                          anchor=tk.NW)
    entry_led_cycle.place(x=xpow + 70 * 2 + 50,
                          y=height * ypos + 4,
                          width=40,
                          anchor=tk.NW)
    entry_led_duty.place(x=xpow + 70 * 2 + 50 * 2,
                         y=height * ypos + 4,
                         width=40,
                         anchor=tk.NW)
    entry_led_oft.place(x=xpow + 70 * 2 + 50 * 3,
                        y=height * ypos + 4,
                        width=40,
                        anchor=tk.NW)

    btn_led_auto.place(x=xpow, y=height * ypos, anchor=tk.NW)
    ypos += 1

    btn_mode_low.place(x=xpow, y=height * ypos, anchor=tk.NW)
    btn_mode_normal.place(x=xpow + 70, y=height * ypos, anchor=tk.NW)
    btn_mode_high.place(x=xpow + 70 * 2, y=height * ypos, anchor=tk.NW)
    btn_ssh_open.place(x=xpow + 70 * 3, y=height * ypos, anchor=tk.NW)
    btn_ssh_close.place(x=xpow + 70 * 4, y=height * ypos, anchor=tk.NW)
    ypos += 1
    btn_enable_btminer_fast_boot.place(x=xpow + 70, y=height * ypos, anchor=tk.NW)
    btn_disable_btminer_fast_boot.place(x=xpow + 70 + 70, y=height * ypos, anchor=tk.NW)
    btn_set_hostname.place(x=xpow, y=height * ypos, anchor=tk.NW)
    ypos += 1
    btn_download_logs.place(x=xpow, y=height * ypos, anchor=tk.NW)
    btn_set_target_freq.place(x=xpow + 70, y=height * ypos, anchor=tk.NW)
    entry_set_target_freq.place(x=xpow + 70 + 65, y=height * ypos + 4, width=30, anchor=tk.NW)
    label_set_target_freq.place(x=xpow + 70 + 105, y=height * ypos + 4, anchor=tk.NW)
    ypos += 1
    entry_set_power_pct.place(x=xpow + 70 + 65, y=height * ypos + 4, width=30, anchor=tk.NW)
    label_set_power_pct.place(x=xpow + 70 + 105, y=height * ypos + 4, anchor=tk.NW)
    btn_read_host.place(x=xpow, y=height * ypos, anchor=tk.NW)
    btn_setpower_pct.place(x=xpow + 70, y=height * ypos, anchor=tk.NW)
    ypos += 1
    btn_adjust_norm_temp.place(x=xpow + 70, y=height * ypos, anchor=tk.NW)
    btn_enable_web_pools.place(x=xpow, y=height * ypos, anchor=tk.NW)
    ypos += 1
    btn_disable_web_pools.place(x=xpow, y=height * ypos, anchor=tk.NW)
    ypos += 1
    btn_enable_btminer_init.place(x=xpow, y=height * ypos, anchor=tk.NW)
    ypos += 1
    btn_disable_btminer_init.place(x=xpow, y=height * ypos, anchor=tk.NW)

    ypos -= 7
    label_ret_msg = tk.Label(root, text='', wraplength=350, justify='left')
    label_ret_msg.pack()
    label_ret_msg.place(x=xpow + 210, y=height * ypos + 30)

    xpow = 350
    ypos = 1

    btn_load_log.place(x=xpow, y=height * ypos, anchor=tk.NW)
    entry_log_ip.place(x=xpow + 60, y=height * ypos + 4, width=100, anchor=tk.NW)
    entry_log_port.place(x=xpow + 165, y=height * ypos + 4, width=40, anchor=tk.NW)


    v_logd_udp_tcp=StringVar()
    logd_tcp_select = Radiobutton(root,text='tcp',value='tcp',variable=v_logd_udp_tcp,command=select_tcp_udp)
    logd_tcp_select.pack()
    logd_udp_select = Radiobutton(root,text='udp',value='udp',variable=v_logd_udp_tcp,command=select_tcp_udp)
    logd_udp_select.pack()
    logd_tcp_select.place(x=xpow + 165 + 40, y=height * ypos + 2, width=40, anchor=tk.NW)
    logd_udp_select.place(x=xpow + 165 + 80, y=height * ypos + 2, width=40, anchor=tk.NW)
    v_logd_udp_tcp.set('tcp')


    ypos += 1
    btn_set_fan_speed.place(x=xpow, y=height * ypos, anchor=tk.NW)
    label_set_fan_speed.place(x=xpow+60, y=height * ypos, anchor=tk.NW)
    entry_set_fan_speed.place(x=xpow+120, y=height * ypos, width=40, anchor=tk.NW)
    ypos += 1

    btn_time_randomized.place(x=xpow, y=height * ypos, anchor=tk.NW)

    label_time_start.place(x=xpow+60, y=height * ypos + 4, width=40, anchor=tk.NW)
    entry_time_start.place(x=xpow+100, y=height * ypos + 4, width=40, anchor=tk.NW)
    label_time_stop.place(x=xpow+140, y=height * ypos + 4, width=40, anchor=tk.NW)
    entry_time_stop.place(x=xpow+180, y=height * ypos + 4, width=40, anchor=tk.NW)
    ypos += 1
    btn_set_fan_manual.place(x=xpow, y=height * ypos, anchor=tk.NW)
    label_set_fan_manual.place(x=xpow+60, y=height * ypos, anchor=tk.NW)
    entry_set_fan_manual.place(x=xpow+120, y=height * ypos, width=40, anchor=tk.NW)
    ypos += 1

    btn_modify_passwd.place(x=xpow, y=height * ypos, anchor=tk.NW)
    entry_admin_oldpwd.place(x=xpow + 70,
                             width=90,
                             y=height * ypos + 4,
                             anchor=tk.NW)
    entry_admin_pwd.place(x=xpow + 70 + 120,
                          width=90,
                          y=height * ypos + 4,
                          anchor=tk.NW)
    ypos += 1

    btn_net_dhcp.place(x=xpow, y=height * ypos, anchor=tk.NW)
    btn_network_set.place(x=xpow + 70, y=height * ypos, anchor=tk.NW)

    entry_network_ip.place(x=xpow + 70 * 2 + 20,
                           y=height * ypos,
                           width=90,
                           anchor=tk.NW)
    entry_network_msk.place(x=xpow + 70 * 2 + 100 + 40,
                            y=height * ypos,
                            width=90,
                            anchor=tk.NW)
    entry_network_gate.place(x=xpow + 70 * 2 + 20,
                             y=height * ypos + 30,
                             width=90,
                             anchor=tk.NW)
    entry_network_dns.place(x=xpow + 70 * 2 + 100 + 40,
                            y=height * ypos + 30,
                            width=90,
                            anchor=tk.NW)
    label_network_ip.place(x=xpow + 70 * 2 - 10,
                           y=height * ypos,
                           width=24,
                           anchor=tk.NW)
    label_network_msk.place(x=xpow + 70 * 2 + 100 + 8,
                            y=height * ypos,
                            width=24,
                            anchor=tk.NW)
    label_network_gate.place(x=xpow + 70 * 2 - 10,
                             y=height * ypos + 30,
                             width=24,
                             anchor=tk.NW)
    label_network_dns.place(x=xpow + 70 * 2 + 100 + 8,
                            y=height * ypos + 30,
                            width=24,
                            anchor=tk.NW)
    ypos += 1.5

    btn_get_token.place(x=xpow, y=height * ypos, anchor=tk.NW)
    btn_set_zone.place(x=xpow + 70, y=height * ypos, anchor=tk.NW)
    label_timezone.place(x=xpow+130, y=height * ypos + 0, width=40, anchor=tk.NW)
    label_zonename.place(x=xpow+130+100, y=height * ypos + 0, width=40, anchor=tk.NW)
    entry_timezone.place(x=xpow+130+40, y=height * ypos + 8, width=60, anchor=tk.NW)
    entry_zonename.place(x=xpow+130+140, y=height * ypos + 8, width=100, anchor=tk.NW)

    xpow = 350 * 2
    ypos = 0
    btn_status.place(x=xpow, y=height * ypos, anchor=tk.NW)
    ypos = 1
    btn_summary.place(x=xpow, y=height * ypos, anchor=tk.NW)
    ypos += 1
    btn_pools.place(x=xpow, y=height * ypos, anchor=tk.NW)
    ypos += 1
    btn_edevs.place(x=xpow, y=height * ypos, anchor=tk.NW)
    ypos += 1
    btn_edevdetails.place(x=xpow, y=height * ypos, anchor=tk.NW)
    ypos += 1
    btn_update_firmware.place(x=xpow, y=height * ypos, anchor=tk.NW)
    update_file_Label = tk.Label(root, text='', wraplength=260, justify='left')
    update_file_Label.pack()
    update_file_Label.place(x=xpow + 60, y=height * ypos)

    root.mainloop()
