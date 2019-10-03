from ipaddress import IPv4Network
from smbCon import SMBCon
import logging
import threading
import struct
import socket
from outputHandler import ConsoleHandler


logger = logging.getLogger('smbscanner')
logger.setLevel(logging.INFO)
logger.addHandler(ConsoleHandler())


def log(level, msg, ip='', extra_context=None):
    _log = getattr(logger, level.lower())
    log_context = {'ip': '[%s]' % ip if ip else ''}
    if extra_context:
        log_context.update(extra_context)
    _log(msg, extra=log_context)


class SMBScanner(object):
    def __init__(self, username, password, domain, threads=50, thread_timeout=10, smb_packet_timeout=60):
        self.username = username
        self.password = password
        self.domain = domain
        self.threads = threads
        self.thread_timeout = thread_timeout
        self.smb_packet_timeout = smb_packet_timeout

        self.__scanned_hosts = 0

    def ip_range(self, start, end):
        start = struct.unpack('>I', socket.inet_aton(start))[0]
        end = struct.unpack('>I', socket.inet_aton(end))[0]
        ip_range = [socket.inet_ntoa(struct.pack('>I', i)) for i in range(start, end + 1)]
        return ip_range

    def __scan(self, ip):
        if self.is_port_open(ip):
            smb_con = SMBCon(ip, ip, self.username, self.password, self.domain, timeout=self.smb_packet_timeout)
            smb_info = smb_con.info
            msg = "%s, %s, %s, %s, %s" % (smb_info['remoteHost'], smb_info['hostName'], smb_info['domain'], smb_info['dnsFQDN'], smb_info['os'])
            log('info', msg, ip, extra_context={'smb_info': smb_info})
            self.__scanned_hosts += 1

    @staticmethod
    def chunks(l, n):
        for i in range(0, len(l), n):
            yield l[i:i + n]

    def scan(self, ip_range):
        log('info', 'Initializing scanner')
        checks = [delim in ip_range for delim in ['-', '/']]
        ips = []
        if all(checks):
            raise ValueError('IP Range should be either Start-END or CIDR and not both')
        elif any(checks):
            if '-' in ip_range:
                if len(ip_range.split('-')) == 2:
                    ips = self.ip_range(ip_range.split('-')[0].strip(), ip_range.split('-')[1].strip())
                else:
                    raise ValueError('Invalid IP Range specified')
            elif '/' in ip_range:
                tmp_range = IPv4Network(unicode(ip_range), strict=False)  # looping in generator can be heavy
                ips = self.ip_range(str(tmp_range[0]), str(tmp_range[-1]))
        elif not all(checks):
            ips = self.ip_range(ip_range, ip_range)

        log('info', 'Total hosts to scan %s' % len(ips))
        ip_sets = self.chunks(ips, self.threads)
        for ip_set in ip_sets:
            log('info', 'Scanning for %s hosts within range [%s - %s]' % (len(ip_set), ip_set[0], ip_set[-1]))
            threads = []
            for ip in ip_set:
                t = threading.Thread(name="Scanner--" + ip, target=self.__scan, args=(ip, ))
                threads.append(t)

            for t in threads:
                t.setDaemon(True)
                t.start()

            for t in threads:
                t.join(self.thread_timeout)
                if t.isAlive():
                    log('warn', 'Thread timed out for %s' % t.getName())

        log('info', 'Found hosts: %s' % self.__scanned_hosts, '')

    def is_port_open(self, ip, port=445):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                sock.close()
                return True
            else:
                return False
        except Exception as e:
            return False
