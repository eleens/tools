# _*_ coding:utf-8 _*_

"""
#=============================================================================
#  ProjectName: qdata-mgr
#     FileName: check_qlink_iblink
#         Desc:
#       Author: yutingting
#        Email:
#     HomePage:
#       Create: 2020-05-20 16:59
#=============================================================================
"""

import re
import sys
import json
import time
import logging
import paramiko
import argparse
import threading
import subprocess
from termcolor import colored


USERNAME = "root"
PASSWORD = "cljslrl0620"
# KEY_FILE = "/root/.ssh/id_rsa"
KEY_FILE = None
FILE_PATH = "../data.txt"
IOWAIT = {
    'COM': {
        "AWAIT": 100,
        "SVCTM": 10
    },
    'STO': {
        "AWAIT": 100,
        "SVCTM": 10
    }
}
FLAG = 0

CLUSTER_DATA = '[{"ibcard_ip": ["172.16.129.6", "172.16.131.6", "172.16.130.6", "172.16.128.6"], "name": "com6", "ip": "10.10.100.6", "cluster_uuid": "QD-0003VDPM", "type": "compute", "id": 2}, ' \
               '{"ibcard_ip": ["172.16.128.7", "172.16.129.7"], "name": "sto7", "ip": "10.10.100.7", "cluster_uuid": "QD-0003VDPM", "type": "storage", "id": 1}, ' \
               '{"ibcard_ip": ["172.16.128.8", "172.16.129.8"], "name": "sto8", "ip": "10.10.100.8", "cluster_uuid": "QD-0003VDPM", "type": "storage", "id": 2}]'

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', filename='../check_iblink.log')
LOG = logging.getLogger(__name__)



def init_env():
    cmd = "rm -rf {}".format(FILE_PATH)
    subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def write_data(data, msg=None):
    with open('../data.txt', 'a') as f:
        if msg:
            f.write(msg)
        f.write(data)


class Printer(object):

    @classmethod
    def print_error(cls, msg):
        color_format = {"color": "red"}

        head = colored("[ ERROR ]", **color_format)
        body = "{}:{}".format(head, msg)
        print body

    @classmethod
    def print_ok(cls, msg):
        color_format = {"color": "green"}
        head = colored("[ OK ]", **color_format)
        body = "{}:{}".format(head, msg)
        print body

    @classmethod
    def print_war(cls, msg):
        color_format = {"color": "yellow"}
        head = colored("[ WARNING ]", **color_format)
        body = "{}:{}".format(head, msg)
        print body

    @classmethod
    def print_cyan(cls, msg):
        color_format = {"color": "cyan"}
        colore_msg = colored(msg, **color_format)
        print colore_msg

    @classmethod
    def print_blue(cls, msg):
        color_format = {"color": "blue"}
        colore_msg = colored(msg, **color_format)
        print colore_msg


    @classmethod
    def print_green(cls, msg):
        color_format = {"color": "green"}
        colore_msg = colored(msg, **color_format)
        print colore_msg

    @classmethod
    def print_title(cls, msg):
        color_format = {"color": "green"}
        msg = msg.center(86, '-')
        colore_msg = colored(msg, **color_format)
        print colore_msg

    @classmethod
    def print_white(cls, msg):
        color_format = {"color": "white"}
        colore_msg = colored(msg, **color_format)
        print colore_msg


class SSH(object):
    def __init__(self, host, port=22, username='root', password=None,
                 key_file=None, timeout=60):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.key_file = key_file
        self.timeout = timeout
        self.ssh = None
        self.conn()

    def conn(self):
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.ssh.connect(hostname=self.host, port=self.port,
                         timeout=self.timeout, username=self.username,
                         key_filename=self.key_file, password=self.password)

    def execute(self, cmd):
        stdin, stdout, stderr = self.ssh.exec_command(cmd)
        data = stdout.read()
        error = stderr.read()
        if error:
            print error
        return data

    def __del__(self):
        self.ssh.close()


class Collect(object):
    """ 采集信息"""

    def collect_cluster_info(self):
        """ 采集集群信息 """
        cmd = "/usr/local/bin/api-qdatamgr conf show -s"
        # output = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = CLUSTER_DATA
        data = json.loads(output)
        LOG.info(data)
        write_data(output)
        return data

    def collect_com_qlink(self, ssh):
        """ 采集计算节点的qlink链路信息 """
        Printer.print_white("Collecting qlink link information for compute node {}".format(ssh.host))
        cmd = "/usr/local/bin/api-qdatamgr qlink show -c"
        output = ssh.execute(cmd)
        ret = json.loads(output)
        write_data(ssh.execute("/usr/local/bin/qdatamgr qlink show -c"))
        return {"node": ssh.host, "ret": ret}

    def collect_sto_qlink(self, ssh):
        """ 采集存储节点的qlink的lun的信息 """
        Printer.print_white("Collecting qlink lun information for storage node {} ".format(ssh.host))
        cmd = "/usr/local/bin/api-qdatamgr qlink show -t"
        output = ssh.execute(cmd)
        ret = json.loads(output)
        write_data(ssh.execute("/usr/local/bin/qdatamgr qlink show -t"))
        return {"node": ssh.host, "ret": ret}

    def collect_ib_link(self, ssh):
        """ 采集ib卡的信息 """
        cmd = "/usr/sbin/iblinkinfo --cas-only"
        output = ssh.execute(cmd)
        link_info = {}
        all_link_info = []
        node1 = ""
        for line in output.splitlines():
            match = re.search(r'^CA: (.+):$', line)
            if match:
                node1 = match.group(1).strip()
                continue
            match = re.search(
                '\s*.*(\d+)\[\s+\] ==\(.* (\d+\.\d+ Gbps) .*\)==>.*(\d+)\[\s*\]\s*"(.*)" \((.*)\)',
                line)
            if match and node1:
                link_status = line.split("==>")[0].split()[-2][:-1]
                port1 = match.group(1)
                rate = match.group(2)
                port2 = match.group(3)
                node2 = match.group(4).strip()
                message = match.group(5)
                link_info[node1] = port1
                link_info[node2] = port2
                link_info['ca'] = node1
                link_info["status"] = link_status
                link_info["rate"] = rate
                link_info['msg'] = message
                link_info['port1'] = port1
                if link_info not in all_link_info:
                    all_link_info.append(link_info)
                # 初始化
                link_info = {}

        return all_link_info

    def collect_ib_info(self, ssh):
        Printer.print_white("Collecting IB information for node {}".format(ssh.host))
        cmd = "/usr/local/bin/api-qdatamgr collect ib_info -i"
        output = ssh.execute(cmd)
        ret = json.loads(output)
        result = []
        hca_map = ret.get('ib_hca_map', {})
        for hca_guid, values in ret.get('hca_devices', {}).items():
            port_item = values.get('ports', [])
            for port in port_item:
                port['hca_ip'] = hca_map.get(port['port_guid'], {}).get('hca_ip')
            result.extend(port_item)
        return result


class Check(object):
    """分析检查信息"""

    def __init__(self, com_qlink=None, ib_info=None):
        self.com_qlink = com_qlink
        self.ib_info = ib_info

    def check_qlink_state(self):
        """ 检查计算节点的qlink链路状态 """
        print "\n"
        Printer.print_title("Begin: Check the qlink state of compute node")
        qlink_links = []
        for qlink in self.com_qlink:
            lun_list = [lun for ret in qlink['ret'] for tar
                        in ret['qlink'] for lun_list in tar['targets'] for lun
                        in lun_list['lun_list']]
            qlink_links.append({"node": qlink['node'], "lun_list": lun_list})
        error_qlink = 1

        for lun_list in qlink_links:
            for link in lun_list["lun_list"]:
                error_disk = [disk['ib_ip'] for disk in link['disks'] if
                              disk['status'] != 'active']
                if not error_disk and link['m_status'] in ['enabled', 'active']:
                    error_qlink = 0
                else:
                    state = 'inactive' if error_disk else 'active'
                    Printer.print_error("The mapth {} is {}, the ib link {} is {} of node {}".format(link['m_path'], link['m_status'], error_disk, state,  lun_list["node"]))

            if not error_qlink:
                Printer.print_ok(
                    "All of the qlink link state is active of node {}".format(lun_list["node"]))
        Printer.print_title("END: Check the qlink state of compute node")
        print "\n"

    # todo 重构
    def check_ib_state_and_rate(self):
        """ 检查ib端口的状态和ib端口速率 """
        Printer.print_green("------开始检查：IB状态和IB速率--------")
        error_state = 1
        error_rate = 1
        for info in self.ib_info:
            if info['status'] != 'Active':
                error_state = 0
                Printer.print_error(
                    "{}，端口{}的状态是{}，请手工恢复".format(info['ca'], info['port1'],
                                                 info['status']))
            if info['msg'] and not info['msg'].isspace():
                error_rate = 0
                Printer.print_error("{}，端口{}的速率不正常，当前是{}, {}".format(info['ca'],
                                                                     info[
                                                                         'port1'],
                                                                     info[
                                                                         'rate'],
                                                                     info[
                                                                         'msg']))
        if error_state:
            Printer.print_ok("所有的IB端口状态都正常")
        if error_rate:
            Printer.print_ok("所有的IB速率都正常")
        Printer.print_green("------结束检查：IB状态和IB速率--------")

    def check_ib_state(self):
        """ 检查ib端口的状态 """
        Printer.print_title("Begin: Check the state of IB card")
        error_state = 0
        for node, node_info in self.ib_info.items():
            for info in node_info:
                if info['state'] != 'Active' and info['hca_ip']:
                    error_state = 1
                    Printer.print_error("node_ip: {}, ib_ip: {}, hca_name: {}, port: {}, current state is {}".format(node, info['hca_ip'], info['name'], info['port'], info['state']))
        if not error_state:
            Printer.print_ok("All IB card is Active")
        Printer.print_title("END: Check the state of IB card ")
        print "\n"

    def check_ib_rate(self):
        """ 检查ib端口速率 """
        Printer.print_title("Begin: Check the rate of IB card")
        error_rate = 0
        max_rate = 0
        for node, node_info in self.ib_info.items():
            for info in node_info:
                if not info['hca_ip']:
                    continue
                if float(info['rate']) < max_rate:
                    error_rate = 1
                    Printer.print_error(
                        "}node_ip: {}, ib_ip: {}, hca_name: {}, port: {}, current rate is {}, is less than others {}".format(node, info['hca_ip'], info['name'], info['port'], info['rate'], max_rate))
                max_rate = max(max_rate, float(info['rate']))
        if not error_rate:
            Printer.print_ok("The rate of all IB cards is {}".format(max_rate))
        Printer.print_title("END: Check the rate of IB card")
        print "\n"

    def check_ib_sm_lid(self, com_node, sto_node):
        Printer.print_title("Begin: Check the SM lid for IB link")
        ib_sm_lid = {ib['hca_ip'].split('/')[0]: ib['sm_lid'] for data in self.ib_info.values() for ib in  data if ib['hca_ip']}
        com_ib_ip = [ib for node in com_node for ib in node['ibcard_ip']]
        sto_ib_ip = [ib for node in sto_node for ib in node['ibcard_ip']]

        for com_ib in com_ib_ip:
            for sto_ib in sto_ib_ip:
                if com_ib.split('.')[:-1] == sto_ib.split('.')[:-1]:
                    msg = "COM NODE: {} SM lid: {} =>> STO NODE: {} SM lid: {}".format(com_ib, ib_sm_lid[com_ib], sto_ib, ib_sm_lid[sto_ib])
                    if ib_sm_lid[com_ib] == ib_sm_lid[sto_ib]:
                        Printer.print_ok(msg)
                    else:
                        Printer.print_error(msg)
        Printer.print_title("Begin: Check the SM lid for IB link")
        print '\n'


class CheckLatency(object):
    """ 通过测试检查信息"""

    def check_net_lat(self, com_node, sto_node, ib_link_info):
        """ 测试ib网络延时 """

        Printer.print_title("Begin: Check the IB read lantency for IB card")
        com_ssh_dict = {}
        sto_ssh_dict = {}
        for com in com_node:
            ssh = SSH(host=com['ip'], username=USERNAME,
                      password=PASSWORD, key_file=KEY_FILE)
            com_ssh_dict[com['ip']] = dict(node=com, ssh=ssh)

        for sto in sto_node:
            ssh = SSH(host=sto['ip'], username=USERNAME,
                      password=PASSWORD, key_file=KEY_FILE)
            sto_ssh_dict[sto['ip']] = dict(node=sto, ssh=ssh)

        for com_ip, com in com_ssh_dict.iteritems():
                com_node = com['node']
                for ib_ip in com_node['ibcard_ip']:
                    if '16.130' in ib_ip or '16.131' in ib_ip:
                        pass
                    else:
                        com_ib_info = [ib for ib in ib_link_info[com_ip] if
                         ib_ip in ib['hca_ip']]
                        com_hca = com_ib_info[0].get('name', "") if com_ib_info else ""
                        com_port = com_ib_info[0].get('port', "").replace("Port", "") if com_ib_info else ""
                        for sto_ip, sto in sto_ssh_dict.iteritems():
                            sto_ib_ip = ib_ip.split('.')[:-1]
                            sto_ib_ip.append(sto_ip.split('.')[-1])
                            sto_ib_ip = '.'.join(sto_ib_ip)
                            sto_ib_info = [ib for ib in ib_link_info[sto_ip] if
                                           sto_ib_ip in ib['hca_ip']]
                            sto_hca = sto_ib_info[0].get('name',
                                                         "") if sto_ib_info else ""
                            sto_port = sto_ib_info[0].get('port', "").replace(
                                "Port", "") if sto_ib_info else ""

                            global FLAG
                            FLAG = 0
                            t1 = threading.Thread(target=self.com_run_ib_read,
                                                 args=(com['ssh'], com_hca, com_port))
                            t1.start()
                            time.sleep(2)
                            print "begin to sto"
                            count = 0

                            # while not FLAG and count < 6:
                            #     count += 1
                            #     time.sleep(0.5)

                            read_ret = self.sto_run_ib_read(sto['ssh'], ib_ip, sto_hca, sto_port)
                            Printer.print_cyan(
                                "sto_node: {} ==> com_node: {}".format(
                                    sto_ib_ip, ib_ip))
                            Printer.print_blue("ib_read_lat:")
                            if read_ret:
                                print "{}\n{}".format("-" * 86, read_ret)
                            else:
                                Printer.print_war(
                                    "Unable to init the socket connection \n")
                                com['ssh'].execute(
                                    "ps -ef | grep ib_read_lat | awk '{print $2}' | xargs kill -9")
                            t1.join()

                            t2 = threading.Thread(target=self.com_run_ib_write,
                                                  args=(com['ssh'], com_hca, com_port))
                            t2.start()
                            time.sleep(1)

                            write_ret = self.sto_run_ib_write(sto['ssh'], ib_ip, sto_hca, sto_port)

                            Printer.print_blue("ib_write_lat:")
                            if write_ret:
                                print "{}\n{}".format("-" * 86, write_ret)
                            else:
                                Printer.print_war(
                                    "Unable to init the socket connection \n")
                                com['ssh'].execute(
                                    "ps -ef | grep ib_write_lat | awk '{print $2}' | xargs kill -9")
                            t2.join()

                com['ssh'].execute(
                    "ps -ef | grep ib_read_lat | awk '{print $2}' | xargs kill -9")
                com['ssh'].execute(
                    "ps -ef | grep ib_write_lat | awk '{print $2}' | xargs kill -9")


        Printer.print_title("END: Check the IB read lantency for IB card")

    def com_run_ib_read(self, com_ssh, hca, port):
        com_cmd = "ib_read_lat -a -R --ib-dev {} --ib-port {}".format(hca, port)
        com_ssh.execute(com_cmd)
        global FLAG
        FLAG = 1
        print com_cmd
        print "com_ib_read_thread"

    def com_run_ib_write(self, com_ssh, hca, port):
        com_cmd = "ib_write_lat -a -R --ib-dev {} --ib-port {}".format(hca, port)
        com_ssh.execute(com_cmd)
        print "com_ib_write_thread"

    def sto_run_ib_read(self, sto_ssh, ib_ip, hca, port):
        sto_cmd = "ib_read_lat -a -R -F {} --ib-dev {} --ib-port {}".format(ib_ip, hca, port)
        output = sto_ssh.execute(sto_cmd)
        print "sto_ib_read_thread"
        print sto_cmd
        match = re.search('.*(#bytes[\s\S]*)', output)
        if match:
            output = match.group(1)
        return output

    def sto_run_ib_write(self, sto_ssh, ib_ip, hca, port):
        sto_cmd = "ib_write_lat -a -R {} --ib-dev {} --ib-port {}".format(ib_ip, hca, port)
        output = sto_ssh.execute(sto_cmd)
        print "sto_ib_write_thread"
        match = re.search('.*(#bytes[\s\S]*)', output)
        if match:
            output = match.group(1)
        return output


class CheckIOStat(object):
    def check_com_io_wait(self, com_qlink):
        """ 测试iowait """
        Printer.print_green("------开始检查：计算节点磁盘IO延时--------")
        for com in com_qlink:
            cmd = "iostat -y -x 1 3 /dev/qdata/* /dev/nvme*"
            com_ssh = SSH(host=com['node'], username=USERNAME,
                          password='cljslrl0620')
            output = com_ssh.execute(cmd)

            link_dev = com_ssh.execute("/bin/ls -l -G /dev/qdata/mpath* | awk {'print $8, $10'}")
            link_data = {link.split()[1].replace('../', ''): link.split()[0] for link in link_dev.splitlines()}
            iostat_data = output.split('avg-cpu')
            option = {}

            for iod in iostat_data:
                match = re.search('(Device[\s\S]*)', iod)
                if not match:
                    continue
                datas = match.group(1).splitlines()
                for data in datas[1:]:
                    if not data:
                        continue

            large_await, large_svctm = self.parse_io_wait(output, node_type='COM')

            if large_await:
                Printer.print_error(
                    "计算节点 {} 中的部分磁盘的AWAIT比较高，正常是小于 {}，当前磁盘的延时分别是 {} ".format(
                        com['node'], IOWAIT['COM'].get('AWAIT'), json.dumps(large_await)))
            if large_svctm:
                Printer.print_error(
                    "计算节点 {} 中的部分磁盘的SVCTM比较高，正常是小于 {}，当前磁盘的延时分别是 {} ".format(
                        com['node'], IOWAIT['COM'].get('SVCTM'), json.dumps(large_svctm)))
            if not large_await and not large_svctm:
                Printer.print_ok("计算节点 {} 中的磁盘IO延时正常".format(com['node']))

        Printer.print_green("------结束检查：计算节点磁盘IO延时--------\n\n")

    # def check_com_io_wait(self, com_qlink):
    #     """ 测试iowait """
    #     Printer.print_green("------开始检查：计算节点磁盘IO延时--------")
    #     for com in com_qlink:
    #         cmd = "iostat -y -x 1 3 /dev/qdata/*"
    #         com_ssh = SSH(host=com['node'], username=USERNAME,
    #                       password='cljslrl0620')
    #         output = com_ssh.execute(cmd)
    #         link_dev = com_ssh.execute("ll /dev/qdata/mpath* | awk {'print $8, $10'}")
    #         link_data = link_dev.split()
    #
    #         large_await, large_svctm = self.parse_io_wait(output, node_type='COM')
    #
    #         if large_await:
    #             Printer.print_error(
    #                 "计算节点 {} 中的部分磁盘的AWAIT比较高，正常是小于 {}，当前磁盘的延时分别是 {} ".format(
    #                     com['node'], IOWAIT['COM'].get('AWAIT'), json.dumps(large_await)))
    #         if large_svctm:
    #             Printer.print_error(
    #                 "计算节点 {} 中的部分磁盘的SVCTM比较高，正常是小于 {}，当前磁盘的延时分别是 {} ".format(
    #                     com['node'], IOWAIT['COM'].get('SVCTM'), json.dumps(large_svctm)))
    #         if not large_await and not large_svctm:
    #             Printer.print_ok("计算节点 {} 中的磁盘IO延时正常".format(com['node']))
    #
    #     Printer.print_green("------结束检查：计算节点磁盘IO延时--------\n\n")

    def check_sto_io_wait(self, sto_luns):
        Printer.print_green("------开始检查：存储节点磁盘IO延时--------")
        for sto in sto_luns:
            lun_list = [lun['path'] for qlink in sto['ret'] for lun in
                        qlink['lun_info']]
            cmd = "iostat -y -x 1 3 {}".format(' '.join(lun_list))
            com_ssh = SSH(host=sto['node'], username=USERNAME,
                          password='cljslrl0620')
            output = com_ssh.execute(cmd)
            link_dev = com_ssh.execute(
                "ll /dev/qdisk/* | awk {'print $8, $10'}")
            large_await, large_svctm = self.parse_io_wait(output, node_type='COM')

            if large_await:
                Printer.print_error(
                    "存储节点 {} 中的部分磁盘的AWAIT比较高，正常是小于 {}，当前磁盘的延时分别是 {} ".format(
                        sto['node'], IOWAIT['STO'].get('AWAIT'), json.dumps(large_await)))
            if large_svctm:
                Printer.print_error(
                    "存储节点 {} 中的部分磁盘的SVCTM比较高，正常是小于 {}，当前磁盘的延时分别是 {} ".format(
                        sto['node'], IOWAIT['STO'].get('SVCTM'), json.dumps(large_svctm)))
            if not large_await and not large_svctm:
                Printer.print_ok("计算节点 {} 中的磁盘IO延时正常".format(sto['node']))
        Printer.print_green("------结束检查：存储节点磁盘IO延时--------\n\n")

    def parse_io_wait(self, output, node_type='COM'):

        iostat_data = output.split('avg-cpu')
        option = {}
        for iod in iostat_data:
            match = re.search('(Device[\s\S]*)', iod)
            if not match:
                continue
            datas = match.group(1).splitlines()
            for data in datas[1:]:
                if not data:
                    continue
                value = data.split()
                option[value[0]] = dict(await=max(value[9],
                                                  option.get(value[0],
                                                             {}).get(
                                                      'await', 0)),
                                        svctm=max(value[12],
                                                  option.get(value[0],
                                                             {}).get(
                                                      'svctm', 0)))
        large_await = {d: v['await'] for d, v in option.iteritems() if
                       float(v['await']) > IOWAIT[node_type].get('AWAIT')}
        large_svctm = {d: v['svctm'] for d, v in option.iteritems() if
                       float(v['svctm']) > IOWAIT[node_type].get('SVCTM')}
        return large_await, large_svctm


def print_ret():
    print "\n"
    Printer.print_title("Begin: Check the qlink state of compute node")
    Printer.print_error(
        "The mapth /dev/qdata/mpath-s01.3295.01.LUN36 is inactive, the ib link 172.16.128.68 is inactive of node 10.10.100.6")
    Printer.print_error(
        "The mapth /dev/qdata/mpath-s01.3295.01.LUN35 is active, the ib link 172.16.128.68 is inactive of node 10.10.100.6")
    Printer.print_error(
        "The mapth /dev/qdata/mpath-s01.3295.01.LUN34 is inactive, the ib link 172.16.128.68 is active of node 10.10.100.6")
    Printer.print_ok("All of the qlink link state is active of node 10.10.100.6")
    Printer.print_title("END: Check the qlink state of compute node")
    print "\n"

    Printer.print_title("Begin: Check the state of IB card")
    Printer.print_error("node_ip: 10.10.100.8, ib_ip: 172.16.128.8 , hca_name: mxl4_0, port: Port1, current state is Down")
    Printer.print_ok("All of the IB card is Active")
    Printer.print_title("END: Check the state of IB card ")
    print "\n"

    Printer.print_title("Begin: Check the rate of IB card")
    Printer.print_error(
        "node_ip: 10.10.100.8, ib_ip: 172.16.128.8, hca_name: mxl4_0, port: Port1, current rate is 40.0, is less than others 56.0")
    Printer.print_ok("The rate of all IB cards is 56.0")
    Printer.print_title("END: Check the rate of IB card")
    print "\n"

    # Printer.print_green("------开始检查：计算节点磁盘io延时--------")
    # Printer.print_green("------结束检查：计算节点磁盘io延时--------\n\n")
    #
    # Printer.print_green("------开始检查：存储节点磁盘io延时--------")
    # Printer.print_green("------结束检查：存储节点磁盘io延时--------\n\n")

    # Printer.print_green("------开始检查：IB网络延时--------")
    # Printer.print_green("------结束检查：IB网络延时--------\n\n")


class QdataCheckIB(object):
    def get_parse(self):
        parser = argparse.ArgumentParser(description='Process some integers.')
        subparsers = parser.add_subparsers(metavar="<subcommands>")

        parser_iostat = subparsers.add_parser("iostat",
                                                    help="Check iostat")
        parser_iostat.add_argument("-a", "--await",
                                     required=True,
                                     action="store",
                                     dest="qdata_type",
                                     help="specify the server type")
        parser_iostat.add_argument("-c", "--count",
                                     required=True,
                                     action="store",
                                     dest="qdata_type",
                                     help="specify the server type")
        parser_iostat.set_defaults(func=self.do_iostat)

        parser_ib = subparsers.add_parser("ib", help="Check IB link")
        parser_ib.add_argument("-l", "--iblat",
                                     required=True,
                                     action="store",
                                     dest="qdata_type",
                                     help="specify the server type")
        parser_ib.set_defaults(func=self.do_ib)

        parser_collect = subparsers.add_parser("collect",
                                               help="Collect information")
        parser_collect.set_defaults(func=self.do_collect)

    def do_iostat(self):
        pass

    def do_ib(self):
        pass

    def do_collect(self):
        pass

    def main(self, argv):
        subcommand_parser = self.get_parse()
        args = subcommand_parser.parse_args(argv)
        args.func(args)


def main():
    data = {}

    import time
    t1 = time.time()
    # init_env()
    collect = Collect()
    cluster = collect.collect_cluster_info()
    com_qlinks = []
    sto_luns = []
    ib_link_info = {}
    com_node = [node for node in cluster if node['type'] == 'compute']
    sto_node = [node for node in cluster if node['type'] == 'storage']
    Printer.print_title("BEGINING COLLECT INFORMATION")

    for node in cluster:
        ssh = SSH(host=node['ip'], username=USERNAME, password=PASSWORD)
        if node['type'] == 'compute':
            qlink = collect.collect_com_qlink(ssh)
            com_qlinks.append(qlink)
        else:
            lun = collect.collect_sto_qlink(ssh)
            sto_luns.append(lun)
        ib_info = collect.collect_ib_info(ssh)
        ib_link_info[node['ip']] = ib_info


    print_ret()

    # check = Check(com_qlinks, ib_link_info)
    # check.check_qlink_state()
    # check.check_ib_state()
    # check.check_ib_rate()
    # check.check_ib_sm_lid(com_node, sto_node)

    iostat = CheckIOStat()
    iostat.check_com_io_wait(com_qlinks)
    iostat.check_sto_io_wait(sto_luns)

    # latency = CheckLatency()
    # latency.check_net_lat(com_node, sto_node, ib_link_info)
    t2 = time.time()
    print t2 - t1


def main1():
    test = QdataCheckIB()
    argv = sys.argv[1:]
    # print argv
    test.main(argv)


if __name__ == "__main__":
    main()

