import errno
import logging
import ntpath
import random
import socket
import string
import time
from collections import OrderedDict

from impacket.nmb import NetBIOSTimeout, NetBIOSError
from impacket.smb3structs import (
    SMB2_DIALECT_002,
    SMB2_DIALECT_21,
    SMB2_DIALECT_30,
    SMB2_DIALECT_302,
    SMB2_DIALECT_311,
    SMB2_DIALECT_WILDCARD
)
from impacket.smbconnection import (
    SMBConnection,
    SessionError,
    SMB_DIALECT
)

logger = logging.getLogger('smbCon')
logger.setLevel(logging.DEBUG)
fmt = logging.Formatter('[%(asctime)s][%(name)s]%(ip)s[%(levelname)s] - %(message)s', datefmt='%d-%m-%Y %I:%M:%S')
fh = logging.FileHandler('scan.log')
fh.setFormatter(fmt)
logger.addHandler(fh)


def log(level, msg, ip):
    _log = getattr(logger, level.lower())
    _log(msg, extra={'ip': '[%s]' % ip if ip else ''})


class SMBEssential(object):
    PERM_DIR = ''.join(random.sample(string.ascii_letters, 10))

    ACCESS_DENIED = (0, 'ad')
    READ_ONLY = (1, 'ro')
    READ_WRITE = (2, 'rw')

    ALL_DIALECTS = {
        SMB_DIALECT: 'SMB1',
        SMB2_DIALECT_002: 'SMB2',
        SMB2_DIALECT_21: 'SMB2.1',
        SMB2_DIALECT_30: 'SMB3',
        SMB2_DIALECT_302: 'SMB3',
        SMB2_DIALECT_311: 'SMB3.1',
        SMB2_DIALECT_WILDCARD: 'SMB2.?'
    }


# noinspection PyBroadException
class SMBCon(object, SMBConnection):
    def __init__(self, remoteName='', remoteHost='', username='', password='', domain='',
                 myName=None, sess_port=445, timeout=60,
                 preferredDialect=None, existingConnection=None, manualNegotiate=False):
        SMBConnection.__init__(self, remoteName, remoteHost, myName, sess_port, timeout, preferredDialect,
                               existingConnection, manualNegotiate)

        self.username = username
        self.password = password
        self.domain = domain
        self.shares = []
        self.is_logged_in = False

    def login(self, *args, **kwargs):
        try:
            super(SMBCon, self).login(user=self.username, password=self.password, domain=self.domain)
            self.is_logged_in = True
        except SessionError as e:
            log('error', e, self.remote_host)
        except Exception as e:
            log('exception', e, self.remote_host)

    def logout(self):
        self.logoff()
        self.is_logged_in = False

    def get_shares(self):
        self.shares = []
        try:
            shareList = self.listShares()
            for item in range(len(shareList)):
                self.shares.append(shareList[item]['shi1_netname'][:-1])
            log('info', 'Shares Found : %s' % '|'.join(self.shares), self.remote_host)
        except (SessionError, NetBIOSError) as e:
            log('error', e, self.remote_host)
        except socket.error as e:  # We don't like to log all socket errors
            if e.errno != errno.WSAECONNRESET:
                log('error', e, self.remote_host)
        except Exception as e:
            # log('exception', e, self.remote_host)
            pass
        return self.shares

    def list_path(self, share, path):
        pwd = self.pathify(path)
        try:
            pathList = self.listPath(share, pwd)

            for item in pathList:
                filesize = item.get_filesize()
                readonly = 'w' if item.is_readonly() > 0 else 'r'
                try:
                    date = time.ctime(float(item.get_mtime_epoch()))
                except ValueError as e:
                    date = ''
                isDir = 'd' if item.is_directory() > 0 else 'f'
                filename = item.get_longname()

                return {
                    'isdir': isDir,
                    'filesize': filesize,
                    'readonly': readonly,
                    'date': date,
                    'filename': filename
                }
        except SessionError as e:
            log('error', '%s for share %s' % (e.getErrorString()[0], share), self.remote_host)
        except Exception as e:
            log('exception', e, self.remote_host)

    def pathify(self, path):
        root = ntpath.join(path, '*').replace('/', '\\')
        return root

    def get_shares_with_permission(self):
        for s in self.get_shares():
            yield s, self.get_share_permission(s)

    def get_share_permission(self, share):
        try:
            root = ntpath.normpath('\\%s' % SMBEssential.PERM_DIR)
            self.createDirectory(share, root)
            permission = SMBEssential.READ_WRITE
            self.deleteDirectory(share, root)
        except Exception as e:
            permission = SMBEssential.ACCESS_DENIED

        try:
            if permission == SMBEssential.ACCESS_DENIED:
                readable = self.list_path(share, '')
                if readable:
                    permission = SMBEssential.READ_ONLY
                else:
                    permission = SMBEssential.ACCESS_DENIED
        except Exception as e:
            permission = SMBEssential.ACCESS_DENIED
        return permission

    def negotiateSession(self, *args, **kwargs):
        """
        We override this to handle Timeout Errors
        """
        try:
            return super(SMBCon, self).negotiateSession(*args, **kwargs)
        except NetBIOSTimeout as e:
            log('error', e, self.remote_host)
        except socket.error as e:
            if e.errno != errno.WSAECONNRESET:
                log('error', e, self.remote_host)
        except Exception as e:
            # Catch some errors which we don't like to log in importing modules
            pass

    @property
    def supported_dialects(self):
        self.is_logged_in = False
        supported = []
        for d_k, d_v in SMBEssential.ALL_DIALECTS.items():
            try:
                self.negotiateSession(d_k)
                supported.append(d_v)
                log('debug', 'SMB Negotiation successful with dialect : ' + d_v, self.remote_host)
            except Exception as e:
                log('debug', 'SMB Negotiation failed with dialect : ' + d_v, self.remote_host)
        return supported

    @property
    def info(self):
        # DO NOT REARRANGE ORDER
        data = OrderedDict()
        data['remoteHost'] = self.remote_host
        data['supportedDialects'] = self.supported_dialects

        if not self.is_logged_in:  # we check this here because the share enumeration need valid session,
            self.login()

        # These should be populated after valid session only
        # data['clientName'] = self.client_name
        # data['remoteName'] = self.remote_name
        # data['serverName'] = self.server_name
        data['currentDialect'] = self.dialect
        data['hostName'] = self.server_name
        data['domain'] = self.server_domain
        data['isGuest'] = self.is_guest_session
        data['dnsFQDN'] = self.server_dnsDomainName
        data['os'] = self.server_os
        data['shares'] = []

        for s, p in self.get_shares_with_permission():
            data['shares'].append({'name': s, 'permission': p[1]})
        return data

    @property
    def dialect(self):
        try:
            return SMBEssential.ALL_DIALECTS[self.getDialect()]
        except Exception as e:
            # catch this maybe?
            pass

    @property
    def client_name(self):
        return self.__get_property('getClientName')

    @property
    def remote_host(self):
        return self._remoteHost

    @property
    def remote_name(self):
        return self.__get_property('getRemoteName')

    @property
    def server_name(self):
        return self.__get_property('getServerName')

    @property
    def server_domain(self):
        return self.__get_property('getServerDomain')

    @property
    def server_dnsDomainName(self):
        return self.__get_property('getServerDNSDomainName')

    @property
    def server_os(self):
        return self.__get_property('getServerOS')

    @property
    def is_guest_session(self):
        return self.__get_property('isGuestSession')

    def __get_property(self, property_name):
        try:
            return getattr(self, property_name)()
        except Exception as e:
            log('error', e, self.remote_host)
            return None
