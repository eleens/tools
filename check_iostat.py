# _*_ coding:utf-8 _*_

"""
#=============================================================================
#  ProjectName: WoQuTech
#     FileName: check_iostat
#         Desc: check iostat on for one node
#       Author: yutingting
#        Email:
#     HomePage:
#       Create: 2020-05-28 10:16
#=============================================================================
"""
import json
import socket
import argparse
import paramiko
from datetime import datetime


USERNAME = "root"
PASSWORD = None
KEY_FILE = "/root/.ssh/id_rsa"


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

    def execute_line(self, cmd):
        stdin, stdout, stderr = self.ssh.exec_command(cmd, get_pty=True)
        return stdout

    def __del__(self):
        self.ssh.close()


class BaseIOStat(object):
    def __init__(self, node_ip):
        self.node_ip = node_ip
        self.ssh = SSH(node_ip, username=USERNAME, password=PASSWORD, key_file=KEY_FILE)
        self.path_map_cmd = ""
        self.cmd = ""
        self.path_map = {}

    def node_type(self):
        cluster_cmd = "/usr/local/bin/api-qdatamgr conf show -s"
        cluster_out = self.ssh.execute(cluster_cmd)
        cluster = json.loads(cluster_out)
        node = [node for node in cluster if node['ip'] == self.node_ip]
        node = node[0] if node else {}
        return node.get('type', 'compute')

    def get_path_map(self):
        link_dev = self.ssh.execute(self.path_map_cmd)
        link_map = {link.split()[1].replace('../', ''): link.split()[0] for
                     link in link_dev.splitlines() if not link.isspace()}
        self.path_map = link_map
        return self.path_map

    @property
    def device_len(self):
        if not self.path_map:
            return 20
        device_len = len(max(self.path_map.values(), key=lambda x: len(x)))
        return device_len


class ComIOStat(BaseIOStat):
    """ 查看计算节点的iostat"""

    def __init__(self, node_ip, await_max=None, count=None):
        super(ComIOStat, self).__init__(node_ip)
        self.await_max = await_max
        self.count = count
        self.path_map_cmd = "/bin/ls -l -G /dev/qdata/mpath* | awk {'print $8, $10'}"
        self.cmd = "/usr/bin/iostat -dmx 1 {} /dev/qdata/* /dev/nvme* /dev/sd*".format(self.count)
        self.qlink_map = {}
        self.get_path_map()
        self.get_qlink_map()

    def get_qlink_map(self):
        output = self.ssh.execute("/usr/local/bin/api-qdatamgr qlink show -c")
        qlink_data = json.loads(output)
        lun_list = [lun for ret in qlink_data for tar
                    in ret['qlink'] for lun_list in tar['targets'] for lun
                    in lun_list['lun_list']]
        qlink_map = {}
        for lun in lun_list:
            qlink_map[lun['m_path']] = {dev['mapped_disk'].replace('/dev/', ''): dev['ib_ip'] for dev in lun['disks']}

        self.qlink_map = qlink_map

    def parse_data(self, data, nvme_data):
        ret = []
        title = ""
        for line in data:
            values = line.split()
            if line.startswith("Device:"):
                title = line
                title = title.replace(values[0], values[0].ljust(
                    self.device_len + len(values[0])))
                continue
            if len(values) > 11 and not values[9].isalpha():
                await = float(values[9])
                dm = values[0]
                line = line.strip().replace(dm, self.path_map.get(dm, dm).ljust(
                    self.device_len + len(dm)))
                if await < self.await_max:
                    continue
                option = {"parrent": line, "child": []}
                for nvme in nvme_data:
                    device = nvme.split()[0]
                    map_device = self.qlink_map.get(
                        self.path_map.get(values[0], values[0]), {})
                    if device in map_device.keys():
                        nvme = nvme.strip().replace(
                            device, "   |--- {}({})".format(
                                device, map_device[device]).ljust(
                                self.device_len + len(device)))
                        option["child"].append(nvme)
                ret.append(option)

        if not title:
            return
        print "{}".format(datetime.now()).center(120, "=")
        print "\n"
        print title
        for line in ret:
            print line["parrent"]
            for child in line["child"]:
                print child
        print "\n"

    def check_io(self):
        data = []
        nvme_data = []
        try:
            stdout = self.ssh.execute_line(self.cmd)
            for line in iter(stdout.readline, ""):
                if line.startswith("nvme") or line.startswith("sd"):
                    nvme_data.append(line)
                else:
                    data.append(line)
                if line.startswith("avg-cpu") or line == '\r\n':
                    self.parse_data(data, nvme_data)
                    data = []
                    nvme_data = []
            self.parse_data(data, nvme_data)
        except Exception as e:
            print e


class StoIOStat(BaseIOStat):
    def __init__(self, node_ip, await_max=None, count=None):
        super(StoIOStat, self).__init__(node_ip)
        self.await_max = await_max
        self.count = count
        self.path_map_cmd = "/bin/ls -l -G /dev/qdisk/ | awk {'print $8, $10'}"
        self.cmd = "iostat -y -x 1 {} /dev/qdisk/*".format(self.count)
        self.get_path_map()

    def parse_data(self, data):
        ret = []
        title = ""
        for line in data:
            values = line.split()
            if line.startswith("Device:"):
                title = line
                title = title.replace(values[0], values[0].ljust(
                    self.device_len + len(values[0]) + len("/dev/qdisk/")))
                continue
            if len(values) > 11 and not values[9].isalpha():
                await = float(values[9])
                dm = values[0]
                line = line.strip().replace(dm, "/dev/qdisk/{}".format(self.path_map.get(dm, dm).ljust(
                    self.device_len + len(dm))))
                if await >= self.await_max:
                    ret.append(line)

        if not title:
            return
        print "{}".format(datetime.now()).center(120, "=")
        print "\n"
        print title
        for line in ret:
            print line
        print "\n"

    def check_io(self):
        data = []
        try:
            stdout = self.ssh.execute_line(self.cmd)

            for line in iter(stdout.readline, ""):
                data.append(line)
                if line.startswith("avg-cpu") or line == '\r\n':
                    self.parse_data(data)
                    data = []
            self.parse_data(data)
        except Exception as e:
            print e


def main():
    parser = argparse.ArgumentParser(description='Check iostat')
    parser.add_argument('-i', '--ip', default=socket.gethostbyname(socket.gethostname()))
    parser.add_argument('-t', '--type', default=None)
    parser.add_argument('-c', '--count', default=3, type=int)
    parser.add_argument('-a', '--await', default=0.0, type=float)
    args = parser.parse_args()

    node_ip = args.ip
    type = args.type

    if not args.type:
        type = BaseIOStat(node_ip).node_type()
    if type == "compute":
        iostat = ComIOStat(node_ip, args.await, args.count)
    else:
        iostat = StoIOStat(node_ip, args.await, args.count)

    iostat.check_io()


if __name__ == "__main__":
    main()