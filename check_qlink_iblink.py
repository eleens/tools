# _*_ coding:utf-8 _*_

"""
#=============================================================================
#  ProjectName: qdata-mgr
#     FileName: check_qlink_iblink
#         Desc: Collect information and Check IB link
#       Author: yutingting
#        Email:
#     HomePage:
#       Create: 2020-05-20 16:59
#=============================================================================
"""

import re
import os
import json
import time
import socket
import logging
import paramiko
import argparse
import threading
import functools

from termcolor import colored


USERNAME = "root"
PASSWORD = None
KEY_FILE = "/root/.ssh/id_rsa"
FILE_PATH = "/tmp/check_iblink_ret.txt"

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    filename='/tmp/check_iblink.log')
LOG = logging.getLogger(__name__)


def timer(func):
    @functools.wraps(func)
    def inner(*args, **kwargs):
        t1 = time.time()
        func(*args, **kwargs)
        t2 = time.time()
        print "func:{}, timer: {}".format(func.func_name, t2-t1)
    return inner


def init_env():
    if os.path.exists(FILE_PATH):
        cmd = "/usr/bin/rm -rf {}".format(FILE_PATH)
        os.system(cmd)


def write_data(data, msg=None):
    with open(FILE_PATH, 'a') as f:
        if msg:
            f.write("\n\n{}\n".format(msg))
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

    def execute(self, cmd, timeout=60):
        try:
            data = self.exec_cmd(cmd, timeout)
        except Exception as e:
            LOG.error(e.message)
            data = '[]'
        return data

    def exec_cmd(self, cmd, timeout=60):
        stdin, stdout, stderr = self.ssh.exec_command(cmd, timeout=timeout)
        data = stdout.read()
        error = stderr.read()
        if error:
            LOG.error(error)
        return data

    def __del__(self):
        self.ssh.close()


class Collect(object):
    """ 采集信息"""

    def collect_cluster_info(self, ssh):
        """ 采集集群信息 """
        Printer.print_white(
            "Collecting qdata cluster information on compute node {}".format(
                ssh.host))
        cmd = "/usr/local/bin/api-qdatamgr conf show -s"
        output = ssh.execute(cmd)
        data = json.loads(output)
        LOG.info(data)
        output2 = ssh.execute("/usr/local/bin/qdatamgr conf show -s")
        write_data(output2, msg="cluster information, cmd: /usr/local/bin/qdatamgr conf show -s")
        return data

    def collect_com_qlink(self, ssh):
        """ 采集计算节点的qlink链路信息 """
        Printer.print_white(
            "Collecting qlink link information for compute node {}".format(
                ssh.host))
        cmd = "/usr/local/bin/api-qdatamgr qlink show -c"
        output = ssh.execute(cmd)
        ret = json.loads(output)
        cmd2 = "/usr/local/bin/qdatamgr qlink show -c"
        write_data(ssh.execute(cmd2),
                   msg="node: {}, cmd: {}".format(ssh.host, cmd2))
        return {"node": ssh.host, "ret": ret}

    def collect_ib_info(self, ssh):
        """ 采集各节点上的ib卡信息 """
        Printer.print_white(
            "Collecting IB information for node {}".format(ssh.host))
        cmd = "/usr/local/bin/api-qdatamgr collect ib_info -i"
        output = ssh.execute(cmd)
        cmd2 = "/usr/local/bin/qdatamgr collect ib_info -i"
        write_data(ssh.execute(cmd2),
                   msg="node: {}, cmd: {}".format(ssh.host, cmd2))
        ret = json.loads(output)
        result = []
        hca_map = ret.get('ib_hca_map', {})
        for hca_guid, values in ret.get('hca_devices', {}).items():
            port_item = values.get('ports', [])
            for port in port_item:
                port['hca_ip'] = hca_map.get(port['port_guid'], {}).get(
                    'hca_ip')
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
                    Printer.print_error(
                        "The mapth {} is {}, the ib link {} is {} of node {}".format(
                            link['m_path'], link['m_status'], error_disk, state,
                            lun_list["node"]))

            if not error_qlink:
                Printer.print_ok(
                    "All of the qlink link state is active of node {}".format(
                        lun_list["node"]))
        Printer.print_title("END: Check the qlink state of compute node")
        print "\n"

    def check_ib_state(self):
        """ 检查ib端口的状态 """
        Printer.print_title("Begin: Check the state of IB card")
        error_state = 0
        for node, node_info in self.ib_info.items():
            for info in node_info:
                if info['state'] != 'Active' and info['hca_ip']:
                    error_state = 1
                    Printer.print_error(
                        "node_ip: {}, ib_ip: {}, hca_name: {}, port: {}, current state is {}".format(
                            node, info['hca_ip'], info['name'], info['port'],
                            info['state']))
        if not error_state:
            Printer.print_ok("All IB card is Active")
        Printer.print_title("END: Check the state of IB card ")
        print "\n"

    def check_ib_rate(self):
        """ 检查ib端口速率 """
        Printer.print_title("Begin: Check the rate of IB card")
        error_rate = 0
        rate_list = [float(re.sub("\(.*\)", "", info['rate']) or 0) for
                     node_info in self.ib_info.values() for info in node_info]

        max_rate = max(rate_list)
        for node, node_info in self.ib_info.items():
            for info in node_info:
                if not info['hca_ip']:
                    continue
                if float(re.sub("\(.*\)", "", info['rate']) or 0) < max_rate:
                    error_rate = 1
                    Printer.print_error(
                        "node_ip: {}, ib_ip: {}, hca_name: {}, port: {}, current rate is {}, is less than others {}".format(
                            node, info['hca_ip'], info['name'], info['port'],
                            info['rate'], max_rate))
        if not error_rate:
            Printer.print_ok("The rate of all IB cards is {}".format(max_rate))
        Printer.print_title("END: Check the rate of IB card")
        print "\n"

    def check_ib_sm_lid(self, com_node, sto_node):
        Printer.print_title("Begin: Check the SM lid for IB link")
        ib_sm_lid = {ib['hca_ip'].split('/')[0]: ib['sm_lid'] for data in
                     self.ib_info.values() for ib in data if ib['hca_ip']}
        com_ib_ip = [ib for node in com_node for ib in node['ibcard_ip']]
        sto_ib_ip = [ib for node in sto_node for ib in node['ibcard_ip']]

        for com_ib in com_ib_ip:
            for sto_ib in sto_ib_ip:
                if com_ib.split('.')[:-1] == sto_ib.split('.')[:-1]:
                    msg = "COM NODE: {} SM lid: {} =>> STO NODE: {} SM lid: {}".format(
                        com_ib, ib_sm_lid[com_ib], sto_ib, ib_sm_lid[sto_ib])
                    if ib_sm_lid[com_ib] == ib_sm_lid[sto_ib]:
                        Printer.print_ok(msg)
                    else:
                        Printer.print_error(msg)
        Printer.print_title("Begin: Check the SM lid for IB link")
        print '\n'


class CheckLatency(object):
    """ 通过测试检查信息"""

    def run_lat(self, ib_ip, com, ib_link_info, sto_ssh_dict, num):
        com_ip = com['com_ip']
        com_ib_info = [ib for ib in ib_link_info[com_ip] if
                       ib_ip in ib['hca_ip']]
        com_hca = com_ib_info[0].get('name',
                                     "") if com_ib_info else ""
        com_port = com_ib_info[0].get('port', "").replace("Port",
                                                          "") if com_ib_info else ""

        com_read_cmd = "ib_read_lat -a -R --ib-dev {} --ib-port {} --iters {} -F".format(com_hca, com_port, num)
        com_write_cmd = "ib_write_lat -a -R --ib-dev {} --ib-port {} --iters {} -F".format(
            com_hca, com_port, num)
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

            sto_read_cmd = "ib_read_lat -a -R {} --ib-dev {} --ib-port {} --iters {} -F".format(
                ib_ip, sto_hca, sto_port, num)

            sto_write_cmd = "ib_write_lat -a -R {} --ib-dev {} --ib-port {} --iters {} -F".format(
                ib_ip,
                sto_hca,
                sto_port, num)

            t1 = threading.Thread(target=self.com_run_ib_read,
                                  args=(com['ssh'], com_read_cmd))
            t1.start()
            time.sleep(1)
            read_ret, rtimeout = '', False
            try:
                read_ret = self.sto_run_ib_read(sto['ssh'],
                                            sto_read_cmd)
            except socket.timeout as e:
                LOG.error(e.message)
                rtimeout = True
            except Exception as e:
                LOG.error(e.message)
            Printer.print_cyan(
                "sto_node: {} ==> com_node: {} ib_read_lat".format(
                    sto_ib_ip, ib_ip))
            if read_ret:
                print "{}ib_read{}\n{}".format("-" * 86, ib_ip, read_ret)
            else:
                msg = "timeout with 1min " if rtimeout else "Unable to init the socket connection \n"
                Printer.print_war(msg)
                Printer.print_war(
                    "com_cmd: {}, sto_cmd: {} \n".format(com_write_cmd,
                                                         sto_write_cmd))
                com['ssh'].execute(
                    "ps -ef | grep '{}' | awk '{{print $2}}' | xargs kill -9".format(com_read_cmd))

            t1.join()
            t2 = threading.Thread(target=self.com_run_ib_write,
                                  args=(
                                      com['ssh'], com_write_cmd))
            t2.start()
            time.sleep(1)
            write_ret, timeout = '', False
            try:
                write_ret = self.sto_run_ib_write(sto['ssh'], sto_write_cmd)
            except socket.timeout as e:
                LOG.error(e.message)
                timeout = True
            except Exception as e:
                LOG.error(e.message)

            Printer.print_cyan(
                "sto_node: {} ==> com_node: {} ib_write_lat ".format(
                    sto_ib_ip, ib_ip))
            if write_ret:
                print "{}ib_write{}\n{}".format("-" * 86, ib_ip, write_ret)
            else:
                msg = "timeout with 1min " if timeout else "Unable to init the socket connection \n"
                Printer.print_war(msg)
                Printer.print_war(
                    "com_cmd: {}, sto_cmd: {} \n".format(com_write_cmd, sto_write_cmd))
                com['ssh'].execute(
                    "ps -ef | grep '{}' | awk '{{print $2}}' | xargs kill -9".format(com_write_cmd))

            t2.join()

        com['ssh'].execute(
            "ps -ef | grep '{}' | awk '{{print $2}}' | xargs kill -9".format(com_read_cmd))
        com['ssh'].execute(
            "ps -ef | grep '{}' | awk '{{print $2}}' | xargs kill -9".format(com_write_cmd))

    @timer
    def check_net_lat(self, com_node, sto_node, ib_link_info, iters):
        """ 测试ib网络延时 """

        Printer.print_title("Begin: Check the IB lantency for IB card")
        com_ssh_dict = {}
        sto_ssh_dict = {}
        thread_list = []
        for com in com_node:
            ssh = SSH(host=com['ip'], username=USERNAME,
                      password=PASSWORD, key_file=KEY_FILE)
            for ib_ip in com['ibcard_ip']:
                if '16.130' in ib_ip or '16.131' in ib_ip:
                    continue
                com_ssh_dict[ib_ip] = dict(com_ip=com['ip'], ssh=ssh)

        for sto in sto_node:
            ssh = SSH(host=sto['ip'], username=USERNAME,
                      password=PASSWORD, key_file=KEY_FILE)
            sto_ssh_dict[sto['ip']] = dict(node=sto, ssh=ssh)

        for ib_ip, com in com_ssh_dict.iteritems():
            time.sleep(2)
            t = threading.Thread(target=self.run_lat, args=(ib_ip, com, ib_link_info, sto_ssh_dict, iters))
            thread_list.append(t)
            t.start()

        for t in thread_list:
            t.join()

        Printer.print_title("END: Check the IB lantency for IB card")

    def check_net_lat_sync(self, com_node, sto_node, ib_link_info, num):
        """ 测试ib网络延时 """

        Printer.print_title("Begin: Check the IB lantency for IB card")
        com_ssh_dict = {}
        sto_ssh_dict = {}
        for com in com_node:
            ssh = SSH(host=com['ip'], username=USERNAME,
                      password=PASSWORD, key_file=KEY_FILE)
            for ib_ip in com['ibcard_ip']:
                if '16.130' in ib_ip or '16.131' in ib_ip:
                    continue
                com_ssh_dict[ib_ip] = dict(com_ip=com['ip'], ssh=ssh)

        for sto in sto_node:
            ssh = SSH(host=sto['ip'], username=USERNAME,
                      password=PASSWORD, key_file=KEY_FILE)
            sto_ssh_dict[sto['ip']] = dict(node=sto, ssh=ssh)

        for ib_ip, com in com_ssh_dict.iteritems():
            com_ip = com['com_ip']
            com_ib_info = [ib for ib in ib_link_info[com_ip] if
                               ib_ip in ib['hca_ip']]
            com_hca = com_ib_info[0].get('name',
                                             "") if com_ib_info else ""
            com_port = com_ib_info[0].get('port', "").replace("Port",
                                                              "") if com_ib_info else ""
            com_read_cmd = "ib_read_lat -a -R --ib-dev {} --ib-port {} --iters {} -F".format(
                com_hca, com_port, num)
            com_write_cmd = "ib_write_lat -a -R --ib-dev {} --ib-port {} --iters {} -F".format(
                com_hca, com_port, num)

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
                sto_read_cmd = "ib_read_lat -a -R {} --ib-dev {} --ib-port {} --iters {} -F".format(
                    ib_ip, sto_hca, sto_port, num)

                sto_write_cmd = "ib_write_lat -a -R {} --ib-dev {} --ib-port {} --iters {} -F".format(
                    ib_ip,
                    sto_hca,
                    sto_port, num)

                t1 = threading.Thread(target=self.com_run_ib_read,
                                      args=(com['ssh'], com_read_cmd))
                t1.start()
                time.sleep(1)

                read_ret = self.sto_run_ib_read(sto['ssh'], sto_read_cmd)
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
                                      args=(
                                          com['ssh'], com_write_cmd))
                t2.start()
                time.sleep(1)

                write_ret = self.sto_run_ib_write(sto['ssh'], sto_write_cmd)

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

        Printer.print_title("END: Check the IB lantency for IB card")

    def com_run_ib_read(self, com_ssh, com_cmd):
        LOG.info("com node: {}, cmd: {}".format(com_ssh.host, com_cmd))
        try:
            output = com_ssh.exec_cmd(com_cmd)
        except Exception as e:
            LOG.error(e.message)
            output = e.message
        write_data(output, msg="com node: {}, cmd: {}".format(com_ssh.host, com_cmd))

    def com_run_ib_write(self, com_ssh, com_cmd):
        LOG.info("com node: {}, cmd: {}".format(com_ssh.host, com_cmd))
        try:
            output = com_ssh.exec_cmd(com_cmd)
        except Exception as e:
            LOG.error(e.message)
            output = e.message
        write_data(output, msg="com node: {}, cmd: {}".format(com_ssh.host, com_cmd))

    def sto_run_ib_read(self, sto_ssh, sto_cmd):
        LOG.info(sto_cmd)
        output = sto_ssh.exec_cmd(sto_cmd)
        write_data(output, msg="sto node: {}, cmd: {}".format(sto_ssh.host, sto_cmd))
        match = re.search('.*(#bytes[\s\S]*)', output)
        if match:
            output = match.group(1)
        return output

    def sto_run_ib_write(self, sto_ssh, sto_cmd):
        LOG.info(sto_cmd)
        output = sto_ssh.exec_cmd(sto_cmd)
        write_data(output, msg="sto node: {}, cmd: {}".format(sto_ssh.host, sto_cmd))
        match = re.search('.*(#bytes[\s\S]*)', output)
        if match:
            output = match.group(1)
        return output


@timer
def main():
    init_env()
    parser = argparse.ArgumentParser(description='Check iblink')
    parser.add_argument('-t', '--type', default="all", choices=['all', 'lat', 'check'],
                        help="all: check for all node, lat: only check ib latency, check: check other infomation")
    parser.add_argument('-c', '--compute', default=None, help=" Compute node ip")
    parser.add_argument('-s', '--storage', default=None, help="Storage node ip")
    parser.add_argument('-n', '--iters', default=100, help="Number of exchanges (at least 5, default 1000)")
    args = parser.parse_args()
    com_ip = args.compute
    sto_ip = args.storage
    rtype = args.type
    iters = args.iters

    node_ip = socket.gethostbyname(socket.gethostname())
    ssh = SSH(host=node_ip, username=USERNAME, password=PASSWORD,
              key_file=KEY_FILE)
    collect = Collect()
    Printer.print_title("BEGINING COLLECT INFORMATION")
    cluster = collect.collect_cluster_info(ssh)
    ib_link_info = {}
    com_qlinks = []
    if com_ip and sto_ip:
        cluster = [node for node in cluster if
                   node['ip'] in [com_ip, sto_ip]]
    com_node = [node for node in cluster if node['type'] == 'compute']
    sto_node = [node for node in cluster if node['type'] == 'storage']

    for node in cluster:
        ssh = SSH(host=node['ip'], username=USERNAME, password=PASSWORD,
                  key_file=KEY_FILE)
        if node['type'] == 'compute' and rtype in ['all', "check"]:
            qlink = collect.collect_com_qlink(ssh)
            com_qlinks.append(qlink)
        ib_info = collect.collect_ib_info(ssh)
        ib_link_info[node['ip']] = ib_info

    if rtype in ['all', "check"]:
        check = Check(com_qlinks, ib_link_info)
        check.check_qlink_state()
        check.check_ib_state()
        check.check_ib_rate()
        check.check_ib_sm_lid(com_node, sto_node)

    if rtype in ['all', 'lat']:
        latency = CheckLatency()
        latency.check_net_lat(com_node, sto_node, ib_link_info, iters)


if __name__ == "__main__":
    main()
