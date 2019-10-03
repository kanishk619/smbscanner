import csv
from logging import StreamHandler, Formatter, DEBUG
from elasticsearch_dsl import *
from elasticsearch_dsl.connections import connections


scan_title = 'smbscanner-' + datetime.now().strftime('%d_%B_%Y-%H_%M_%S').lower()


class Share(InnerDoc):
    name = Keyword()
    permission = Keyword()


class SMBObj(Document):
    remoteHost = Ip()
    currentDialect = Keyword()
    supportedDialects = Keyword()
    isGuest = Integer()
    hostName = Keyword()
    domain = Keyword()
    dnsFQDN = Keyword()
    os = Keyword()
    shares = Nested(Share)

    class Index:
        name = scan_title
        settings = {
            'number_of_shards': 1
        }


class ElasticHandler(StreamHandler):
    def __init__(self, host, port, stream=None):
        super(ElasticHandler, self).__init__(stream=stream)
        host = "{}:{}".format(host, port)
        self.connection = connections.create_connection(hosts=[host])
        SMBObj.init()

    def emit(self, record):
        smb_info = getattr(record, 'smb_info', None)
        if smb_info:
            smbObj = SMBObj()
            smbObj.remoteHost = smb_info['remoteHost']
            smbObj.supportedDialects = smb_info['supportedDialects']
            smbObj.currentDialect = smb_info['currentDialect']
            smbObj.hostName = smb_info['hostName']
            smbObj.domain = smb_info['domain']
            smbObj.isGuest = smb_info['isGuest']
            smbObj.os = smb_info['os']
            smbObj.dnsFQDN = smb_info['dnsFQDN']
            for s in smb_info['shares']:
                smbObj.shares.append(Share(name=s['name'], permission=s['permission']))
            smbObj.save()


class ConsoleHandler(StreamHandler):
    def __init__(self, level=DEBUG, stream=None):
        super(ConsoleHandler, self).__init__(stream=stream)
        self.level = level
        self.formatter = Formatter('[%(asctime)s][%(name)s][%(levelname)s] - %(message)s', datefmt='%d-%m-%Y %I:%M:%S')


class CsvHandler(StreamHandler):
    def __init__(self, file=scan_title, stream=None):
        super(CsvHandler, self).__init__(stream=stream)
        self._csv_file = open(file + '.csv', 'w')
        self.csv_writer = csv.writer(self._csv_file, lineterminator='\n')
        headers = ['IP', 'Supported Dialects', 'Dialect', 'Hostname', 'Domain', 'Guest', 'OS', 'DnsFQDN', 'Shares']
        self.csv_writer.writerow(headers)

    def emit(self, record):
        smb_info = getattr(record, 'smb_info', None)
        if smb_info:
            s = smb_info.values()
            row = s[0], '|'.join(s[1]), s[2], s[3], s[4], s[5], s[6], s[7], '|'.join(["{}::{}".format(i['name'], i['permission']) for i in s[8]])
            self.csv_writer.writerow(row)
