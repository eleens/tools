# _*_ coding:utf-8 _*_

"""
#=============================================================================
#  ProjectName: WoQuTech
#     FileName: check_iostat
#         Desc: 
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


USERNAME = "root"
PASSWORD = "cljslrl0620"
# KEY_FILE = "/root/.ssh/id_rsa"
KEY_FILE = None
FILE_PATH = "/tmp/check_iblink_ret.txt"


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

    def line_buffered(self, f):
        line_buf = ""
        while not f.channel.exit_status_ready():
            line_buf += f.read(1)
            if line_buf.endswith('\n'):
                yield line_buf
                line_buf = ''

    def check_io(self):
        pass


class ComIOStat(BaseIOStat):

    def __init__(self, node_ip, await_max=None, count=None):
        super(ComIOStat, self).__init__(node_ip)
        self.await_max = await_max
        self.count = count
        self.path_map_cmd = "/bin/ls -l -G /dev/qdata/mpath* | awk {'print $8, $10'}"
        self.cmd = "/usr/bin/iostat -dmx 1 {} /dev/qdata/* /dev/nvme*".format(self.count)
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
                line = line.replace(dm, self.path_map.get(dm, dm).ljust(
                    self.device_len + len(dm)))
                if await >= self.await_max:
                    option = {"parrent": line, "child": []}
                    for nvme in nvme_data:
                        device = nvme.split()[0]
                        map_device = self.qlink_map.get(
                            self.path_map.get(values[0], values[0]), {})
                        if device in map_device.keys():
                            nvme = nvme.replace(device,
                                                "   |--- {}({})".format(device,
                                                                     map_device[
                                                                         device]).ljust(
                                                    self.device_len + len(device)))
                            option["child"].append(nvme)
                    ret.append(option)

        print title
        for line in ret:
            print line["parrent"]
            for child in line["child"]:
                print child
        print "\n"

    # def check_io(self):
    #     def line_buffered(f):
    #         line_buf = ""
    #         while not f.channel.exit_status_ready():
    #             line_buf += f.read(1)
    #             if line_buf.endswith('\n'):
    #                 yield line_buf
    #                 line_buf = ''
    #     try:
    #         sout = self.ssh.execute_line(self.cmd)
    #         data = []
    #         nvme_data = []
    #         for line in line_buffered(sout):
    #             if line.startswith("nvme"):
    #                 nvme_data.append(line)
    #             else:
    #                 data.append(line)
    #             if line == '\n':
    #                 self.parse_data(data, nvme_data)
    #                 data = []
    #                 nvme_data = []
    #         self.parse_data(data, nvme_data)
    #     except Exception as e:
    #         print e

    def check_io(self):
        data = []
        nvme_data = []
        try:
            stdout = self.ssh.execute_line(self.cmd)
            for line in iter(stdout.readline, ""):
                # print line
                if line.startswith("nvme"):
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
                line = line.replace(dm, "/dev/qdisk/{}".format(self.path_map.get(dm, dm).ljust(
                    self.device_len + len(dm))))
                if await >= self.await_max:
                    ret.append(line)

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
                if line.startswith("avg-cpu"):
                    self.parse_data(data)
                    data = []
                # print line
            self.parse_data(data)

            # sout = self.ssh.execute_line(self.cmd)
            # data = []
            # self.path_map['Device:'] = "Device:"
            # for line in self.line_buffered(sout):
            #     data.append(line)
            #     if line == '\n':
            #         self.parse_data(data)
            #         data = []
            # self.parse_data(data)
        except Exception as e:
            print e


class CheckIOStat(object):
    def __init__(self, node_ip):
        self.node_ip = node_ip
        self.ssh = SSH(node_ip, username=USERNAME, password=PASSWORD, key_file=KEY_FILE)

    def check_com_io_wait(self, num):
        """ 测试iowait """

        cluster_cmd = "/usr/local/bin/api-qdatamgr conf show -s"

        cluster_out = self.ssh.execute(cluster_cmd)
        cluster = json.loads(cluster_out)
        node = [node for node in cluster if node['ip'] == self.node_ip]
        node = node[0] if node else {}
        if node.get('type', 'compute') == 'compute':
            cmd = "/usr/bin/iostat -dmx 1 {} /dev/qdata/* /dev/nvme*".format(num)
            cmd_map = "/bin/ls -l -G /dev/qdata/mpath* | awk {'print $8, $10'}"
        else:
            cmd = "iostat -y -x 1 {} /dev/qdata/*".format(num)
            cmd_map = "/bin/ls -l -G /dev/qdisk/ | awk {'print $8, $10'}"

        link_dev = self.ssh.execute(cmd_map)
        link_map = {link.split()[1].replace('../', ''): link.split()[0] for
                     link in link_dev.splitlines()}

        qlink_map = {"/dev/qdata/mpath-s01.3262.01.S0P1IX1B8p1": {"nvme4n1": "172.16.128.7",  "nvme5n1":"172.16.129.7"}}

        device_len = len(max(qlink_map.keys(), key=lambda x: len(x)))
        await_max = 1

        sout = self.ssh.execute_line(cmd)

        data = []
        nvme_data = []
        ret = []

        def parse_data(data):
            title = ""
            for line in data:
                values = line.split()
                if line.startswith("Device:"):
                    title = line
                    title = title.replace(values[0], values[0].ljust(device_len+len(values[0])))
                    continue
                if len(values) > 11 and not values[9].isalpha():
                    await = float(values[9])
                    dm = values[0]
                    line = line.replace(dm, link_map.get(dm, dm).ljust(device_len+len(dm)))
                    if await > await_max:
                        option = {"parrent": line, "child": []}
                        for nvme in nvme_data:
                            device = nvme.split()[0]
                            map_device = qlink_map.get(link_map.get(values[0], values[0]), {})
                            if device in map_device.keys():
                                nvme = nvme.replace(device, "|--- {}({})".format(device, map_device[device]).ljust(device_len+len(device)))
                                option["child"].append(nvme)
                        ret.append(option)
            print title
            for line in ret:
                print line["parrent"]
                for child in line["child"]:
                    print child

        def line_buffered(f):
            line_buf = ""
            while not f.channel.exit_status_ready():
                line_buf += f.read(1)
                if line_buf.endswith('\n'):
                    yield line_buf
                    line_buf = ''


        for l in line_buffered(sout):
            # values = l.split()
            # if len(values) > 11 and not values[9].isalpha():
            #     await = float(values[9])
            #     l = l.replace(values[0], link_map.get(values[0], values[0]))
            #     if await < await_max:
            #         continue

            print l

            # if l.startswith("nvme"):
            #     nvme_data.append(l)
            # else:
            #     data.append(l)

        #     if l == '\n':
        #         parse_data(data)
        #         data = []
        #         nvme_data = []
        # parse_data(data)



        # output = self.ssh.execute(cmd)
        #
        # print output
        #
        # match = re.search('(Device[\s\S]*)', output)
        # if not match:
        #     pass
        #
        # datas = match.group(1).splitlines()
        #
        # for data in datas[1:]:
        #     if not data:
        #         continue

    #     Printer.print_green("------开始检查：计算节点磁盘IO延时--------")
    #     for com in com_qlink:
    #         cmd = "iostat -y -x 1 3 /dev/qdata/* /dev/nvme*"
    #         com_ssh = SSH(host=com['node'], username=USERNAME,
    #                       password='cljslrl0620')
    #         output = com_ssh.execute(cmd)
    #
    #         link_dev = com_ssh.execute("/bin/ls -l -G /dev/qdata/mpath* | awk {'print $8, $10'}")
    #         link_data = {link.split()[1].replace('../', ''): link.split()[0] for link in link_dev.splitlines()}
    #         iostat_data = output.split('avg-cpu')
    #         option = {}
    #
    #         for iod in iostat_data:
    #             match = re.search('(Device[\s\S]*)', iod)
    #             if not match:
    #                 continue
    #             datas = match.group(1).splitlines()
    #             for data in datas[1:]:
    #                 if not data:
    #                     continue
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
    #
    #
    #
    # def check_sto_io_wait(self, sto_luns):
    #     Printer.print_green("------开始检查：存储节点磁盘IO延时--------")
    #     for sto in sto_luns:
    #         lun_list = [lun['path'] for qlink in sto['ret'] for lun in
    #                     qlink['lun_info']]
    #         cmd = "iostat -y -x 1 3 {}".format(' '.join(lun_list))
    #         com_ssh = SSH(host=sto['node'], username=USERNAME,
    #                       password='cljslrl0620')
    #         output = com_ssh.execute(cmd)
    #         link_dev = com_ssh.execute(
    #             "ll /dev/qdisk/* | awk {'print $8, $10'}")
    #         large_await, large_svctm = self.parse_io_wait(output, node_type='COM')
    #
    #         if large_await:
    #             Printer.print_error(
    #                 "存储节点 {} 中的部分磁盘的AWAIT比较高，正常是小于 {}，当前磁盘的延时分别是 {} ".format(
    #                     sto['node'], IOWAIT['STO'].get('AWAIT'), json.dumps(large_await)))
    #         if large_svctm:
    #             Printer.print_error(
    #                 "存储节点 {} 中的部分磁盘的SVCTM比较高，正常是小于 {}，当前磁盘的延时分别是 {} ".format(
    #                     sto['node'], IOWAIT['STO'].get('SVCTM'), json.dumps(large_svctm)))
    #         if not large_await and not large_svctm:
    #             Printer.print_ok("计算节点 {} 中的磁盘IO延时正常".format(sto['node']))
    #     Printer.print_green("------结束检查：存储节点磁盘IO延时--------\n\n")
    #
    # def parse_io_wait(self, output, node_type='COM'):
    #
    #     iostat_data = output.split('avg-cpu')
    #     option = {}
    #     for iod in iostat_data:
    #         match = re.search('(Device[\s\S]*)', iod)
    #         if not match:
    #             continue
    #         datas = match.group(1).splitlines()
    #         for data in datas[1:]:
    #             if not data:
    #                 continue
    #             value = data.split()
    #             option[value[0]] = dict(await=max(value[9],
    #                                               option.get(value[0],
    #                                                          {}).get(
    #                                                   'await', 0)),
    #                                     svctm=max(value[12],
    #                                               option.get(value[0],
    #                                                          {}).get(
    #                                                   'svctm', 0)))
    #     large_await = {d: v['await'] for d, v in option.iteritems() if
    #                    float(v['await']) > IOWAIT[node_type].get('AWAIT')}
    #     large_svctm = {d: v['svctm'] for d, v in option.iteritems() if
    #                    float(v['svctm']) > IOWAIT[node_type].get('SVCTM')}
    #     return large_await, large_svctm


def main():
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('-i', '--ip', default=socket.gethostbyname(socket.gethostname()))
    parser.add_argument('-t', '--type', default=None)
    parser.add_argument('-c', '--count', default=3, type=int)
    parser.add_argument('-a', '--await', default=0.0, type=float)
    args = parser.parse_args()

    node_ip = args.ip
    type = args.type
    count = args.count
    await = args.await
    #
    # iostat = CheckIOStat(node_ip)
    # iostat.check_com_io_wait(count)

    if not type:
        type = BaseIOStat(node_ip).node_type()
    if type == "compute":
        iostat = ComIOStat(node_ip, await, count)
    else:
        iostat = StoIOStat(node_ip, await, count)

    iostat.check_io()


if __name__ == "__main__":
    main()