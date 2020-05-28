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
    iostat = CheckIOStat()
    iostat.check_com_io_wait(com_qlinks)
    iostat.check_sto_io_wait(sto_luns)


def main1():
    test = QdataCheckIB()
    argv = sys.argv[1:]
    # print argv
    test.main(argv)


if __name__ == "__main__":
    main()