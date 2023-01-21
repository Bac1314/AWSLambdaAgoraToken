import json
import hmac
import base64
import struct
import secrets
import time
import random
from collections import OrderedDict

from hashlib import sha256
from zlib import crc32
import zlib

# Get the Agora App ID and App appCertificate
appId = ""
appCertificate = ""
uid = ""

VERSION_LENGTH = 3
APP_ID_LENGTH = 32

def lambda_handler(event, context):
    
    channel = ""
    if ('queryStringParameters' in event and 'channel' in event['queryStringParameters']) :
        channel=event['queryStringParameters']['channel'] 
    else:
        return {
        "isBase64Encoded": False,
        "statusCode": 403,
        "headers": {"Content-Type": "application/json"},
        "multiValueHeaders": {},
        "body": "channel not found"
        }

    # UID of 0 means, the token lets any UID  join the channel
    # If you specify a UID, then you can only join the channel with the specified UID
    
     if ('queryStringParameters' in event and 'uid' in event['queryStringParameters']) :
         uid=event['queryStringParameters']['uid']
    else:
        uid = 0

        
    return {
        'statusCode': 200,
        'body': get_token(channel, uid)
    }

def get_token(channel, uid):
    token = AccessToken(appId, appCertificate)
    privilege_expire = 0

    service_rtc = ServiceRtc(channel, uid)
    service_rtc.add_privilege(ServiceRtc.kPrivilegeJoinChannel, privilege_expire)
    service_rtc.add_privilege(ServiceRtc.kPrivilegePublishAudioStream, privilege_expire)
    service_rtc.add_privilege(ServiceRtc.kPrivilegePublishVideoStream, privilege_expire)
    service_rtc.add_privilege(ServiceRtc.kPrivilegePublishDataStream, privilege_expire)
    
    token.add_service(service_rtc)
    return {"token": token.build(), "uid": uid}
        
def get_version():
    return '007'



# ACCESS TOKEN 2

class AccessToken:
    # kServices = {
    #     ServiceRtc.kServiceType: ServiceRtc,
    #     ServiceRtm.kServiceType: ServiceRtm,
    #     ServiceFpa.kServiceType: ServiceFpa,
    #     ServiceChat.kServiceType: ServiceChat,
    #     ServiceEducation.kServiceType: ServiceEducation,
    # }

    def __init__(self, app_id='', app_certificate='', issue_ts=0, expire=600000):
        self.__app_id = app_id
        self.__app_cert = app_certificate

        self.__issue_ts = issue_ts if issue_ts != 0 else int(time.time())
        self.__expire = expire
        self.__salt = secrets.SystemRandom().randint(1, 99999999)

        self.__service = {}

    def __signing(self):
        signing = hmac.new(pack_uint32(self.__issue_ts),
                           self.__app_cert, sha256).digest()
        signing = hmac.new(pack_uint32(self.__salt), signing, sha256).digest()
        return signing

    def __build_check(self):
        def is_uuid(data):
            if len(data) != 32:
                return False
            try:
                bytes.fromhex(data)
            except:
                return False
            return True

        if not is_uuid(self.__app_id) or not is_uuid(self.__app_cert):
            return False
        if not self.__service:
            return False
        return True

    def add_service(self, service):
        self.__service[service.service_type()] = service

    def build(self):
        if not self.__build_check():
            return ''

        self.__app_id = self.__app_id.encode('utf-8')
        self.__app_cert = self.__app_cert.encode('utf-8')
        signing = self.__signing()
        signing_info = pack_string(self.__app_id) + pack_uint32(self.__issue_ts) + pack_uint32(self.__expire) + \
                       pack_uint32(self.__salt) + pack_uint16(len(self.__service))

        for _, service in self.__service.items():
            signing_info += service.pack()

        signature = hmac.new(signing, signing_info, sha256).digest()

        return get_version() + base64.b64encode(zlib.compress(pack_string(signature) + signing_info)).decode('utf-8')

    def from_string(self, origin_token):
        try:
            origin_version = origin_token[:VERSION_LENGTH]
            if origin_version != get_version():
                return False

            buffer = zlib.decompress(
                base64.b64decode(origin_token[VERSION_LENGTH:]))
            signature, buffer = unpack_string(buffer)
            self.__app_id, buffer = unpack_string(buffer)
            self.__issue_ts, buffer = unpack_uint32(buffer)
            self.__expire, buffer = unpack_uint32(buffer)
            self.__salt, buffer = unpack_uint32(buffer)
            service_count, buffer = unpack_uint16(buffer)

            for i in range(service_count):
                service_type, buffer = unpack_uint16(buffer)
                service = AccessToken.kServices[service_type]()
                buffer = service.unpack(buffer)
                self.__service[service_type] = service
        except Exception as e:
            print('Error: {}'.format(repr(e)))
            raise ValueError('Error: parse origin token failed')
        return True


class Service:
    def __init__(self, service_type):
        self.__type = service_type
        self.__privileges = {}

    def __pack_type(self):
        return pack_uint16(self.__type)

    def __pack_privileges(self):
        privileges = OrderedDict(
            sorted(iter(self.__privileges.items()), key=lambda x: int(x[0])))
        return pack_map_uint32(privileges)

    def add_privilege(self, privilege, expire):
        self.__privileges[privilege] = expire

    def service_type(self):
        return self.__type

    def pack(self):
        return self.__pack_type() + self.__pack_privileges()

    def unpack(self, buffer):
        self.__privileges, buffer = unpack_map_uint32(buffer)
        return buffer


class ServiceRtc(Service):
    kServiceType = 1

    kPrivilegeJoinChannel = 1
    kPrivilegePublishAudioStream = 2
    kPrivilegePublishVideoStream = 3
    kPrivilegePublishDataStream = 4

    def __init__(self, channel_name='', uid=0):
        super(ServiceRtc, self).__init__(ServiceRtc.kServiceType)
        self.__channel_name = channel_name.encode('utf-8')
        self.__uid = b'' if uid == 0 else str(uid).encode('utf-8')

    def pack(self):
        return super(ServiceRtc, self).pack() + pack_string(self.__channel_name) + pack_string(self.__uid)

    def unpack(self, buffer):
        buffer = super(ServiceRtc, self).unpack(buffer)
        self.__channel_name, buffer = unpack_string(buffer)
        self.__uid, buffer = unpack_string(buffer)
        return buffer

def pack_uint16(x):
    return struct.pack('<H', int(x))

def unpack_uint16(buffer):
    data_length = struct.calcsize('H')
    return struct.unpack('<H', buffer[:data_length])[0], buffer[data_length:]

def pack_uint32(x):
    return struct.pack('<I', int(x))

def unpack_uint32(buffer):
    data_length = struct.calcsize('I')
    return struct.unpack('<I', buffer[:data_length])[0], buffer[data_length:]

def pack_int16(x):
    return struct.pack('<h', int(x))

def unpack_int16(buffer):
    data_length = struct.calcsize('h')
    return struct.unpack('<h', buffer[:data_length])[0], buffer[data_length:]

def pack_string(string):
    if isinstance(string, str):
        string = string.encode('utf-8')
    return pack_uint16(len(string)) + string

def unpack_string(buffer):
    data_length, buffer = unpack_uint16(buffer)
    return struct.unpack('<{}s'.format(data_length), buffer[:data_length])[0], buffer[data_length:]

def pack_map_uint32(m):
    return pack_uint16(len(m)) + b''.join([pack_uint16(k) + pack_uint32(v) for k, v in m.items()])

def unpack_map_uint32(buffer):
    data_length, buffer = unpack_uint16(buffer)

    data = {}
    for i in range(data_length):
        k, buffer = unpack_uint16(buffer)
        v, buffer = unpack_uint32(buffer)
        data[k] = v
    return data, buffer

def pack_map_string(m):
    return pack_uint16(len(m)) + b''.join([pack_uint16(k) + pack_string(v) for k, v in m.items()])

def unpack_map_string(buffer):

    data_length, buffer = unpack_uint16(buffer)

    data = {}
    for i in range(data_length):
        k, buffer = unpack_uint16(buffer)
        v, buffer = unpack_string(buffer)
        data[k] = v
    return data, buffer
