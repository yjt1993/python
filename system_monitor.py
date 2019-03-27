#!/home/deployer/anaconda2/bin/python
# -*- coding:utf-8 -*-
#create at 2018-12-12
'this is a system monitor scripts'
__author__="yjt"

import os
import time
import sys
import datetime
import socket
import psutil
import re
import json
import commands

#以下是变量值，自己定义
CPUT = 2      #计算CPU利用率的时间间隔
NETT = 2      #计算网卡流量的时间间隔

#获取系统基本信息
def baseinfo():
    hostname = socket.gethostname()
    user_conn = len(psutil.users())
    sys_start_time = datetime.datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")
    now_time = time.strftime("%Y-%m-%d %H:%M:%S")
    sys_runtime = os.popen('w').readline().split('users')[0].split('up')[1].strip()[:-1].strip()[:-1]
    process = os.popen('ps -ef |wc -l').read().split()[0]
    value_base = {
                   "baseinfo":
                               {
                                "hostname":hostname,
                                "user_conn":user_conn,
                                "sys_start_time":sys_start_time,
                                "now_time":now_time,
                                "sys_runtime":sys_runtime,
                                "process":process
                              }
                  }
    return value_base
#print(baseinfo())
def cpuinfo():
    #以下三项值获取瞬时值
    #user_cpu_percent = psutil.cpu_times_percent().user #用户使用CPU百分比
    #sys_cpu_percent = psutil.cpu_times_percent().system #系统使用cpu百分比
    #free_cpu_percent = psutil.cpu_times_percent().idle #CPU空闲百分比

    user_time = psutil.cpu_times().user  #用户态使用CPU时间
    sys_time = psutil.cpu_times().system #系统态使用CPU时间
    idle_time = psutil.cpu_times().idle #CPU空闲时间
    total_cpu = 0
    for i in range(len(psutil.cpu_times())):
        total_cpu += psutil.cpu_times()[i]
    user_cpu_percent = float(user_time) / total_cpu * 100
    sys_cpu_percent = float(sys_time) / total_cpu * 100
    free_cpu_percent = float(idle_time) / total_cpu * 100
    #获取CPU多少秒内的平均使用率
    cpu_ave_percent = psutil.cpu_percent(CPUT)
    #CPU平均负载
    cpu_ave_load = ' '.join(os.popen('uptime').readline().split(":")[-1].split())
    #获取系统逻辑cpu个数和物理CPU个数
    logical_cpu = psutil.cpu_count()
    pyhsical_cpu = psutil.cpu_count(logical=False)
    #获取系统占用cpu最高的前20个进程
    i,process_user,pid,process_cpu_percent,process_name,process_status = 0,[],[],[],[],[]
    while i < 20:
        try:
            process_info = psutil.Process(int(os.popen("ps aux|grep -v PID|sort -rn -k +3").readlines()[i].split()[1])) #获取进程信息
            pid_bak = process_info.pid #获取pid
            process_status_bak = process_info.status()#获取进程状态
            process_user_bak = process_info.username() #获取进程用户
            process_name_bak = ' '.join(os.popen('ps aux |grep -v PID|sort -k3 -nr').readlines()[i].split()[10:])  #获取进程名字
            process_cpu_percent_bak = ''.join(os.popen('ps aux |grep -v PID|sort -k3 -nr').readlines()[i].split()[2]) #获取进程CPU使用

            process_cpu_percent.append(process_cpu_percent_bak)
            pid.append(pid_bak)
            process_status.append(process_status_bak)
            process_user.append(process_user_bak)
            process_name.append(process_name_bak)
      
            i += 1
        except:
            pass
        continue
    cpu_info = []
    cpu_list = ["user","pid","cpu_use","process_cmd","status"]
    cpu_value = list(zip(process_user,pid,process_cpu_percent,process_name,process_status))
    cpu_value_len = len(cpu_value)
    for i in range(cpu_value_len):
        cpu_info.append(dict(zip(cpu_list,cpu_value[i])))
    #print(cpu_info)
    #获取逻辑CPU个数以及使用率
    cpu_item = commands.getoutput('cat /proc/stat').split('\n')
    cpu_number,cpu_use_percent =[],[]
    for i in cpu_item:
        if re.search("^cpu[0-9]{1,}",i):
            cpu_logi_info = i.split()
            cpu_number.append(cpu_logi_info[0])
            cpu_total = 0
            for num in cpu_logi_info[1:]:
                cpu_total += float(num)
                cpu_free = float(cpu_logi_info[4])
            cpu_use = (1 - cpu_free / cpu_total) * 100
            cpu_use_percent.append(cpu_use)
    cpu_logi_info = []
    cpu_logi_list = ["cpu_number","cpu_use_percent"]
    cpu_logi_value = list(zip(cpu_number,cpu_use_percent))
    cpu_logi_len = len(cpu_logi_value)
    for i in range(cpu_logi_len):
        cpu_logi_info.append(dict(zip(cpu_logi_list,cpu_logi_value[i])))
    value_cpuinfo =   {
                        "cpuinfo":{
                                    "ave_load":cpu_ave_load,
                                    "user_use":user_cpu_percent,
                                    "sys_use":sys_cpu_percent,
                                    "idle":free_cpu_percent,
                                    "cpu_pre":cpu_ave_percent,
                                    "logical_cpu":logical_cpu,
                                    "pyhsical_cpu":pyhsical_cpu,
                                    "logical_cpu_use_info":cpu_logi_info,
                                    "cpu_top20":cpu_info
                                 }
                      }
    return value_cpuinfo

#print(cpuinfo())
#获取memory信息
def meminfo():
    total_mem = psutil.virtual_memory().total / 1024 /1024
    use_mem = psutil.virtual_memory().used / 1024 /1024
    mem_percent = psutil.virtual_memory().percent
    free_mem = psutil.virtual_memory().free / 1024 /1024
    swap_mem = psutil.swap_memory().total / 1024 /1024
    swap_use = psutil.swap_memory().used / 1024 /1024
    swap_free = psutil.swap_memory().free / 1024 /1024
    swap_percent = psutil.swap_memory().percent
    l1,l2,l3,l4,l5,l6 = [],[],[],[],[],[]
    i = 0
    while i < 20:
        try:
            info = psutil.Process(int(os.popen('ps aux|grep -v PID|sort -rn -k +4').readlines()[i].split()[1]))
            pid = info.pid
            user = info.username()
            process_name = ' '.join(os.popen('ps aux |grep -v PID|sort -k4 -nr').readlines()[i].split()[10:])
            mem_use = info.memory_percent()
            status = info.status()
            l1.append(user)
            l2.append(pid)
            l3.append(mem_use)
            l4.append(process_name)
            l5.append(status)
            i += 1
        except:
            pass
        continue
    m0 = []
    l = ["user","pid","mem_use","process_cmd","status"]
    mem_value = list(zip(l1,l2,l3,l4,l5))
    mem_len = len(mem_value)
    for i in range(mem_len):
        m0.append(dict(zip(l,mem_value[i])))

    value_meminfo =  {"mem_info":{
               "total_mem":total_mem,
               "use_mem":use_mem,
               "free_mem":free_mem,
               "mem_percent":mem_percent,
               "swap_mem":swap_mem,
               "swap_use":swap_use,
               "swap_free":swap_free,
               "swap_percent":swap_percent,
               "mem_top20":m0
             }}
    return value_meminfo
#print(meminfo())
#获取磁盘信息
def diskinfo():
    disk_num = int(''.join(os.popen("ls /dev/sd[a-z]|wc -l").readlines()[0].split()))
    d1,d2,d3,d4,d5 = [],[],[],[],[]
    disk_total,disk_used,disk_free = 0,0,0
    disk_len = len(psutil.disk_partitions())
    for info in range(disk_len):
        disk = psutil.disk_partitions()[info][1]
        if len(disk) < 10:
            d1.append(disk)
            total = psutil.disk_usage(disk).total /1024/1024/1024
            total_num = psutil.disk_usage(disk).total
            disk_total  += total_num
            free = psutil.disk_usage(disk).free /1024/1024/1024
            disk_free += psutil.disk_usage(disk).free
            used = psutil.disk_usage(disk).used /1024/1024/1024
            disk_used += psutil.disk_usage(disk).used
            percent = str(psutil.disk_usage(disk).percent)
            d2.append(total)
            d3.append(free)
            d4.append(used)
            d5.append(percent)
    disk_total = disk_total /1024/1024/1024
    disk_free = disk_free /1024/1024/1024
    disk_used = disk_used /1024/1024/1024
    disk_used_percent = float(disk_used) / disk_total * 100
    #disk_free_percent = round(float(disk_free) / disk_total * 100,2)
    d0 = []
    d = ["mount","total","free","used","percent"]
    disk_value = list(zip(d1,d2,d3,d4,d5))
    disk_len = len(disk_value)
    for i in range(disk_len):
        d0.append(dict(zip(d,disk_value[i])))
    value_disk =  {"disk_info":{
               "disk":[
                        {"disk_num":disk_num},
                        {"disk_total":disk_total},
                        {"disk_used":disk_used},
                        {"disk_free":disk_free},
                        {"disk_used_percent":disk_used_percent}
                      ],
               "partitions":d0
             }}
    return value_disk
#print(diskinfo())
#获取网卡信息
def netinfo():
    net_len = len(commands.getoutput('cat /proc/net/dev').split('\n')[2:])
    net_card,rece_flow,tran_flow,net_ip  = [],[],[],[]
    rece_1,rece_2,tran_1,tran_2 = [],[],[],[]
    for i in range(net_len):
        net_cards = commands.getoutput('cat /proc/net/dev').split('\n')[2:][i].split(':')[0].strip()
        net_card.append(net_cards)
        ip = psutil.net_if_addrs()[net_card[i]][0].address
        ip_len = len(ip.split('.'))
        if ip_len == 4:
            ip =ip
        else:
            ip = 'null'
        net_ip.append(ip)
        net_info_1 = commands.getoutput('cat /proc/net/dev').split('\n')[2:][i].split(':')[1].split()
        rece_1.append(int(net_info_1[0]))
        tran_1.append(int(net_info_1[8]))
    time.sleep(NETT)
    for i in range(net_len):
        net_info_2 = commands.getoutput('cat /proc/net/dev').split('\n')[2:][i].split(':')[1].split()
        rece_2.append(int(net_info_2[0]))
        tran_2.append(int(net_info_2[8]))
    for i in range(len(rece_1)):
        rece = float(rece_2[i] - rece_1[i]) /1024/NETT
        tran = float(tran_2[i] - tran_1[i]) /1024/NETT
        rece_flow.append(rece)
        tran_flow.append(tran)
    net_status = []
    net_status_1 = 'PhysicsNetwork'
    net_status_2 = 'VirtualNetwork'
    net_name = commands.getoutput('ls /sys/devices/virtual/net/').split('\n')
    for i in net_card:
        if i in net_name:
            net_status.append(net_status_2)
        else:
            net_status.append(net_status_1)
    net_data = []
    net_list = ["network_card","ip","transmit","received",'net_type']
    net_value = list(zip(net_card,net_ip,tran_flow,rece_flow,net_status))
    list_len = len(net_value)
    for i in range(list_len):
        net_data.append(dict(zip(net_list,net_value[i])))
    value_net = {"net_info":{
             "network":net_data
            }}
    return value_net
    #print(net_card,net_ip,rece_flow,tran_flow)
#print(netinfo())
#获取TCP连接数
def tcpinfo():
    status_list = ["LISTEN","ESTABLISHED","TIME_WAIT","CLOSE_WAIT","LAST_ACK","SYN_SENT"]
    status_init = []
    net_conn =  psutil.net_connections()
    n1 = []
    for key in net_conn:
        status_init.append(key.status)
    for value in status_list:
        num = status_init.count(value)
        n1.append(num)
    value_tcp =    {"tcp_info":{
            "LISTEN":n1[0],
            "ESTABLISHED":n1[1],
            "TIME_WAIT":n1[2],
            "CLOSE_WAIT":n1[3],
            "LAST_ACK":n1[4],
            "SYN_SENT":n1[5]
           }}
    return value_tcp
#获取hadoop job list
def jobinfo():
    hadoop_process = ['JournalNode','ResourceManager','HMaster','DataNode','DFSZKFailoverController','QuorumPeerMain','HQuorumPeerMain','JobHistory','Kafka','NodeManager','Worker','Master','HRegionServer','NameNode','PrestoServer','RunJar']
    job_value = []
    job_lst = os.popen('/data1/jdk/bin/jps').readlines()
    for i in job_lst:
        value = i.split()[1]
        if value in hadoop_process:
           job_value.append(value)
    job_value = list(set(job_value))
    value_job = {"hadoop_process_info":job_value}
    return value_job


value_json = {}
#获取baseinfo的值
value_baseinfo = baseinfo()
value_json.update(value_baseinfo)
#获取CPU的值
value_cpuinfo = cpuinfo()
value_json.update(value_cpuinfo)
#获取memory的值
value_meminfo = meminfo()
value_json.update(value_meminfo)
#获取disk的值
value_diskinfo = diskinfo()
value_json.update(value_diskinfo)
#获取network的值
value_netinfo = netinfo()
value_json.update(value_netinfo)
#获取tcp的值
value_tcpinfo = tcpinfo()
value_json.update(value_tcpinfo)
#获取jobinfo的值
value_jobinfo = jobinfo()
value_json.update(value_jobinfo)
#格式化成json
monitor_info = json.dumps(value_json)
print(monitor_info)
