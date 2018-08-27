#coding=utf-8

import abc
import base64
import copy
import functools
import json
import logging
import os
import re
import six
import subprocess
import tempfile
import errno
import configparser

import ctypes
from ctypes import wintypes
from ctypes import windll
import uuid
import struct
import sys
import wmi
from six.moves import winreg
import random
import socket
import time
import netifaces
import datetime


OS_LATEST = 'latest'
OS_FOLSOM = '2012-08-10'
OS_GRIZZLY = '2013-04-04'
OS_HAVANA = '2013-10-17'
OS_LIBERTY = '2015-10-15'
OS_VERSIONS = (
    OS_FOLSOM,
    OS_GRIZZLY,
    OS_HAVANA,
    OS_LIBERTY,
)

KEY_COPIES = (
    ('local-hostname', 'hostname', False),
    ('instance-id', 'uuid', True),
)


kernel32 = windll.kernel32
rpcrt4 = windll.rpcrt4
setupapi = ctypes.windll.setupapi
msvcrt = ctypes.cdll.msvcrt
ntdll = ctypes.windll.ntdll
OFFSET_BOOT_RECORD = 0x8000
OFFSET_BLOCK_SIZE = OFFSET_BOOT_RECORD + 128
PEEK_SIZE = 2
OFFSET_ISO_ID = OFFSET_BOOT_RECORD + 1
ISO_ID = b'CD001'
# Little-endian unsigned short size values.
OFFSET_VOLUME_SIZE = OFFSET_BOOT_RECORD + 80
MAX_SECTOR_SIZE = 4096
DIGCF_PRESENT = 2
DIGCF_DEVICEINTERFACE = 0x10
INVALID_HANDLE_VALUE = 0xFFFFFFFF
ERROR_INSUFFICIENT_BUFFER = 122
FILE_SHARE_READ = 1
OPEN_EXISTING = 3
IOCTL_STORAGE_GET_DEVICE_NUMBER = 0x002D1080
BOND_NAME = "Team1"
VER_MAJORVERSION = 1
VER_MINORVERSION = 2
VER_BUILDNUMBER = 4
VER_GREATER_EQUAL = 3
STATUS_REVISION_MISMATCH = 0xC0000059
STATUS_SUCCESS = 1001
STATUS_ERR_RETRY_NEXT_REBOOT = 1002
FILE_DEVICE_DISK = 0x00000007
IOCTL_DISK_BASE = FILE_DEVICE_DISK
METHOD_BUFFERED = 0
FILE_ANY_ACCESS = 0
GAA_FLAG_SKIP_ANYCAST = 2
GAA_FLAG_SKIP_MULTICAST = 4
MAX_ADAPTER_ADDRESS_LENGTH = 8
MAX_DHCPV6_DUID_LENGTH = 130
AF_UNSPEC = 0
VERSION_2_2 = (2 << 8) + 2
IP_ADAPTER_ADDRESSES_SIZE_2003 = 144
IP_ADAPTER_DHCP_ENABLED = 4
IP_ADAPTER_IPV4_ENABLED = 0x80
IP_ADAPTER_IPV6_ENABLED = 0x0100
_DHCP_COOKIE = b'\x63\x82\x53\x63'
_OPTION_END = b'\xff'
OPTION_MTU = 26
ERROR_NO_DATA = 232
ERROR_BUFFER_OVERFLOW = 111


class IP_ADAPTER_ADDRESSES_Struct1(ctypes.Structure):
    _fields_ = [
        ('Length', wintypes.ULONG),
        ('IfIndex', wintypes.DWORD),
    ]


class IP_ADAPTER_ADDRESSES_Union1(ctypes.Union):
    _fields_ = [
        ('Alignment', wintypes.ULARGE_INTEGER),
        ('Struct1', IP_ADAPTER_ADDRESSES_Struct1),
    ]


class SOCKADDR(ctypes.Structure):
    _fields_ = [
        ('sa_family', wintypes.USHORT),
        ('sa_data', ctypes.c_char * 14),
    ]


class SOCKET_ADDRESS(ctypes.Structure):
    _fields_ = [
        ('lpSockaddr', ctypes.POINTER(SOCKADDR)),
        ('iSockaddrLength', wintypes.INT),
    ]


class IP_ADAPTER_UNICAST_ADDRESS(ctypes.Structure):
    _fields_ = [
        ('Union1', IP_ADAPTER_ADDRESSES_Union1),
        ('Next', wintypes.LPVOID),
        ('Address', SOCKET_ADDRESS),
        ('PrefixOrigin', wintypes.DWORD),
        ('SuffixOrigin', wintypes.DWORD),
        ('DadState', wintypes.DWORD),
        ('ValidLifetime', wintypes.ULONG),
        ('PreferredLifetime', wintypes.ULONG),
        ('LeaseLifetime', wintypes.ULONG),
    ]


class IP_ADAPTER_DNS_SERVER_ADDRESS_Struct1(ctypes.Structure):
    _fields_ = [
        ('Length', wintypes.ULONG),
        ('Reserved', wintypes.DWORD),
    ]


class IP_ADAPTER_DNS_SERVER_ADDRESS_Union1(ctypes.Union):
    _fields_ = [
        ('Alignment', wintypes.ULARGE_INTEGER),
        ('Struct1', IP_ADAPTER_DNS_SERVER_ADDRESS_Struct1),
    ]


class IP_ADAPTER_DNS_SERVER_ADDRESS(ctypes.Structure):
    _fields_ = [
        ('Union1', IP_ADAPTER_DNS_SERVER_ADDRESS_Union1),
        ('Next', wintypes.LPVOID),
        ('Address', SOCKET_ADDRESS),
    ]


class IP_ADAPTER_PREFIX_Struct1(ctypes.Structure):
    _fields_ = [
        ('Length', wintypes.ULONG),
        ('Flags', wintypes.DWORD),
    ]


class IP_ADAPTER_PREFIX_Union1(ctypes.Union):
    _fields_ = [
        ('Alignment', wintypes.ULARGE_INTEGER),
        ('Struct1', IP_ADAPTER_PREFIX_Struct1),
    ]


class IP_ADAPTER_PREFIX(ctypes.Structure):
    _fields_ = [
        ('Union1', IP_ADAPTER_PREFIX_Union1),
        ('Next', wintypes.LPVOID),
        ('Address', SOCKET_ADDRESS),
        ('PrefixLength', wintypes.ULONG),
    ]


class NET_LUID_LH(ctypes.Union):
    _fields_ = [
        ('Value', wintypes.ULARGE_INTEGER),
        ('Info', wintypes.ULARGE_INTEGER),
    ]


class GUID(ctypes.Structure):

    _fields_ = [
        ("data1", wintypes.DWORD),
        ("data2", wintypes.WORD),
        ("data3", wintypes.WORD),
        ("data4", wintypes.BYTE * 8)
    ]

    def __init__(self, dw=0, w1=0, w2=0, b1=0, b2=0, b3=0, b4=0, b5=0, b6=0,
                 b7=0, b8=0):
        self.data1 = dw
        self.data2 = w1
        self.data3 = w2
        self.data4[0] = b1
        self.data4[1] = b2
        self.data4[2] = b3
        self.data4[3] = b4
        self.data4[4] = b5
        self.data4[5] = b6
        self.data4[6] = b7
        self.data4[7] = b8


class IP_ADAPTER_ADDRESSES(ctypes.Structure):
    _fields_ = [
        ('Union1', IP_ADAPTER_ADDRESSES_Union1),
        ('Next', wintypes.LPVOID),
        ('AdapterName', ctypes.c_char_p),
        ('FirstUnicastAddress',
         ctypes.POINTER(IP_ADAPTER_UNICAST_ADDRESS)),
        ('FirstAnycastAddress',
         ctypes.POINTER(IP_ADAPTER_DNS_SERVER_ADDRESS)),
        ('FirstMulticastAddress',
         ctypes.POINTER(IP_ADAPTER_DNS_SERVER_ADDRESS)),
        ('FirstDnsServerAddress',
         ctypes.POINTER(IP_ADAPTER_DNS_SERVER_ADDRESS)),
        ('DnsSuffix', wintypes.LPWSTR),
        ('Description', wintypes.LPWSTR),
        ('FriendlyName', wintypes.LPWSTR),
        ('PhysicalAddress', ctypes.c_ubyte * MAX_ADAPTER_ADDRESS_LENGTH),
        ('PhysicalAddressLength', wintypes.DWORD),
        ('Flags', wintypes.DWORD),
        ('Mtu', wintypes.DWORD),
        ('IfType', wintypes.DWORD),
        ('OperStatus', wintypes.DWORD),
        ('Ipv6IfIndex', wintypes.DWORD),
        ('ZoneIndices', wintypes.DWORD * 16),
        ('FirstPrefix', ctypes.POINTER(IP_ADAPTER_PREFIX)),
        # kernel >= 6.0
        ('TransmitLinkSpeed', wintypes.ULARGE_INTEGER),
        ('ReceiveLinkSpeed', wintypes.ULARGE_INTEGER),
        ('FirstWinsServerAddress',
         ctypes.POINTER(IP_ADAPTER_DNS_SERVER_ADDRESS)),
        ('FirstGatewayAddress',
         ctypes.POINTER(IP_ADAPTER_DNS_SERVER_ADDRESS)),
        ('Ipv4Metric', wintypes.ULONG),
        ('Ipv6Metric', wintypes.ULONG),
        ('Luid', NET_LUID_LH),
        ('Dhcpv4Server', SOCKET_ADDRESS),
        ('CompartmentId', wintypes.DWORD),
        ('NetworkGuid', GUID),
        ('ConnectionType', wintypes.DWORD),
        ('TunnelType', wintypes.DWORD),
        ('Dhcpv6Server', SOCKET_ADDRESS),
        ('Dhcpv6ClientDuid', ctypes.c_ubyte * MAX_DHCPV6_DUID_LENGTH),
        ('Dhcpv6ClientDuidLength', wintypes.ULONG),
        ('Dhcpv6Iaid', wintypes.ULONG),
    ]


class WSADATA(ctypes.Structure):
    _fields_ = [
        ('opaque_data', wintypes.BYTE * 400),
    ]


GUID_DEVINTERFACE_DISK = GUID(0x53f56307, 0xb6bf, 0x11d0, 0x94, 0xf2,
                              0x00, 0xa0, 0xc9, 0x1e, 0xfb, 0x8b)


class Win32_SP_DEVICE_INTERFACE_DATA(ctypes.Structure):
    _fields_ = [
        ('cbSize', wintypes.DWORD),
        ('InterfaceClassGuid', GUID),
        ('Flags', wintypes.DWORD),
        ('Reserved', ctypes.POINTER(wintypes.ULONG))
    ]


class Win32_DiskGeometry(ctypes.Structure):

    FixedMedia = 12

    _fields_ = [
        ('Cylinders', wintypes.LARGE_INTEGER),
        ('MediaType', wintypes.DWORD),
        ('TracksPerCylinder', wintypes.DWORD),
        ('SectorsPerTrack', wintypes.DWORD),
        ('BytesPerSector', wintypes.DWORD)
    ]


class Win32_OSVERSIONINFOEX_W(ctypes.Structure):
    _fields_ = [
        ('dwOSVersionInfoSize', wintypes.DWORD),
        ('dwMajorVersion', wintypes.DWORD),
        ('dwMinorVersion', wintypes.DWORD),
        ('dwBuildNumber', wintypes.DWORD),
        ('dwPlatformId', wintypes.DWORD),
        ('szCSDVersion', wintypes.WCHAR * 128),
        ('wServicePackMajor', wintypes.WORD),
        ('wServicePackMinor', wintypes.WORD),
        ('wSuiteMask', wintypes.WORD),
        ('wProductType', wintypes.BYTE),
        ('wReserved', wintypes.BYTE)
    ]


class Win32_STORAGE_DEVICE_NUMBER(ctypes.Structure):
    _fields_ = [
        ('DeviceType', wintypes.DWORD),
        ('DeviceNumber', wintypes.DWORD),
        ('PartitionNumber', wintypes.DWORD)
    ]


class Win32_SP_DEVICE_INTERFACE_DETAIL_DATA_W(ctypes.Structure):
    _fields_ = [
        ('cbSize', wintypes.DWORD),
        ('DevicePath', ctypes.c_byte * 2)
    ]


class Win32_PARTITION_INFORMATION_MBR(ctypes.Structure):

    _fields_ = [
        ('PartitionType', wintypes.BYTE),
        ('BootIndicator', wintypes.BOOLEAN),
        ('RecognizedPartition', wintypes.BOOLEAN),
        ('HiddenSectors', wintypes.DWORD)
    ]


class Win32_PARTITION_INFORMATION_GPT(ctypes.Structure):

    _fields_ = [
        ('PartitionType', GUID),
        ('PartitionId', GUID),
        ('Attributes', wintypes.ULARGE_INTEGER),
        ('Name', wintypes.WCHAR * 36)
    ]


class PARTITION_INFORMATION(ctypes.Union):

    _fields_ = [
        ('Mbr', Win32_PARTITION_INFORMATION_MBR),
        ('Gpt', Win32_PARTITION_INFORMATION_GPT)
    ]


class Win32_PARTITION_INFORMATION_EX(ctypes.Structure):

    _anonymous_ = ('PartitionInformation',)

    _fields_ = [
        ('PartitionStyle', wintypes.DWORD),
        ('StartingOffset', wintypes.LARGE_INTEGER),
        ('PartitionLength', wintypes.LARGE_INTEGER),
        ('PartitionNumber', wintypes.DWORD),
        ('RewritePartition', wintypes.BOOLEAN),
        ('PartitionInformation', PARTITION_INFORMATION)
    ]


class Win32_DRIVE_LAYOUT_INFORMATION_MBR(ctypes.Structure):

    _fields_ = [
        ('Signature', wintypes.ULONG)
    ]


class Win32_DRIVE_LAYOUT_INFORMATION_GPT(ctypes.Structure):

    _fields_ = [
        ('DiskId', GUID),
        ('StartingUsableOffset', wintypes.LARGE_INTEGER),
        ('UsableLength', wintypes.LARGE_INTEGER),
        ('MaxPartitionCount', wintypes.ULONG)
    ]


class DRIVE_FORMAT(ctypes.Union):

    _fields_ = [
        ('Mbr', Win32_DRIVE_LAYOUT_INFORMATION_MBR),
        ('Gpt', Win32_DRIVE_LAYOUT_INFORMATION_GPT)
    ]


class Win32_DRIVE_LAYOUT_INFORMATION_EX(ctypes.Structure):

    _anonymous_ = ('DriveFormat',)

    _fields_ = [
        ('PartitionStyle', wintypes.DWORD),
        ('PartitionCount', wintypes.DWORD),
        ('DriveFormat', DRIVE_FORMAT),
        ('PartitionEntry', Win32_PARTITION_INFORMATION_EX * 128)
    ]


def CTL_CODE(DeviceType, Function, Method, Access):
    return (DeviceType << 16) | (Access << 14) | (Function << 2) | Method

IOCTL_DISK_GET_DRIVE_GEOMETRY = CTL_CODE(IOCTL_DISK_BASE, 0x0000, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_DISK_GET_DRIVE_LAYOUT_EX = CTL_CODE(IOCTL_DISK_BASE, 0x0014, METHOD_BUFFERED, FILE_ANY_ACCESS)

WSAStartup = windll.Ws2_32.WSAStartup

GetAdaptersAddresses = windll.Iphlpapi.GetAdaptersAddresses
GetAdaptersAddresses.argtypes = [
    wintypes.ULONG, wintypes.ULONG, wintypes.LPVOID,
    ctypes.POINTER(IP_ADAPTER_ADDRESSES),
    ctypes.POINTER(wintypes.ULONG)]
GetAdaptersAddresses.restype = wintypes.ULONG

WSAGetLastError = windll.Ws2_32.WSAGetLastError
WSAAddressToStringW = windll.Ws2_32.WSAAddressToStringW
WSAAddressToStringW.argtypes = [
    ctypes.POINTER(SOCKADDR), wintypes.DWORD, wintypes.LPVOID,
    wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
WSAAddressToStringW.restype = wintypes.INT

WSACleanup = windll.Ws2_32.WSACleanup
WSACleanup.argtypes = []
WSACleanup.restype = wintypes.INT


CONF_FILE = 'C:\\Program Files\\Cloudbase Solutions\\Cloudbase-Init\\LocalScripts\\bms-network-config.conf'


def config_get(session, key, default=None):
    if not os.path.exists(CONF_FILE):
        return default
    try:
        config = configparser.ConfigParser()
        config.read(CONF_FILE)
        value = config.get(session, key)
        if not value:
            return default
        return value
    except Exception:
        return default


def config_modify(session, key, value):
    if os.path.exists(CONF_FILE):
        config = configparser.ConfigParser()
        config.read(CONF_FILE)
        config.set(session, key, value)
        with open(CONF_FILE, "r+") as config_file:
            config.write(config_file)
            return True
    else:
        return False

log_path = tempfile.mkdtemp()
logfile = os.path.join(log_path, 'network-config.log')
LOG = logging.getLogger()
handler = logging.FileHandler(logfile)
formatter = logging.Formatter('%(asctime)s - '
                              '%(filename)s[%(levelname)s]: %(message)s')
handler.setFormatter(formatter)
LOG.addHandler(handler)
LOG.setLevel(logging.INFO)


def mac_hw(addr):
    valid_hw = re.compile(r'''
                      (^([0-9A-F]{1,2}[-]){5}([0-9A-F]{1,2})$
                      |^([0-9A-F]{1,2}[:]){5}([0-9A-F]{1,2})$
                      |^([0-9A-F]{1,2}[.]){5}([0-9A-F]{1,2})$)
                      ''',
                          re.VERBOSE | re.IGNORECASE)
    return valid_hw.match(addr) is not None


def decode_binary_hw(blob, encoding='utf-8'):
    if isinstance(blob, six.text_type):
        return blob
    return blob.decode(encoding)


def load_json_hw(text, root_types=(dict,)):
    decoded = json.loads(decode_binary_hw(text))
    if not isinstance(decoded, tuple(root_types)):
        expects = ", ".join([str(t) for t in root_types])
        raise TypeError("(%s) root types expected, got %s instead"
                        % (expects, type(decoded)))
    return decoded


FILES_V1 = {
    'etc/network/interfaces': ('network_config', lambda x: x, ''),
    'meta.js': ('meta_js', load_json_hw, {}),
    "root/.ssh/authorized_keys": ('authorized_keys', lambda x: x, ''),
}


@six.add_metaclass(abc.ABCMeta)
class BaseDevice(object):
    """Base class for devices like disks and partitions.

    It has common methods for getting physical disk geometry,
    opening/closing the device and also seeking through it
    for reading certain amounts of bytes.
    """

    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    FILE_SHARE_READ = 1
    FILE_SHARE_WRITE = 2
    OPEN_EXISTING = 3
    FILE_ATTRIBUTE_READONLY = 1
    INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value
    FILE_BEGIN = 0
    INVALID_SET_FILE_POINTER = 0xFFFFFFFF

    def __init__(self, path, allow_write=False):
        self._path = path

        self._handle = None
        self._sector_size = None
        self._disk_size = None
        self._allow_write = allow_write
        self.fixed = None

    def __repr__(self):
        return "<{}: {}>".format(self.__class__.__name__, self._path)

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def _get_geometry(self):
        """Get details about the disk size bounds."""
        geom = Win32_DiskGeometry()
        bytes_returned = wintypes.DWORD()
        ret_val = kernel32.DeviceIoControl(
            self._handle,
            IOCTL_DISK_GET_DRIVE_GEOMETRY,
            0,
            0,
            ctypes.byref(geom),
            ctypes.sizeof(geom),
            ctypes.byref(bytes_returned),
            0)

        if not ret_val:
            raise Exception("Cannot get disk geometry.")

        _sector_size = geom.BytesPerSector
        _disk_size = (geom.Cylinders * geom.TracksPerCylinder *
                      geom.SectorsPerTrack * geom.BytesPerSector)
        fixed = geom.MediaType == Win32_DiskGeometry.FixedMedia
        return _sector_size, _disk_size, fixed

    def _seek(self, offset):
        high = wintypes.DWORD(offset >> 32)
        low = wintypes.DWORD(offset & 0xFFFFFFFF)

        ret_val = kernel32.SetFilePointer(self._handle, low,
                                          ctypes.byref(high),
                                          self.FILE_BEGIN)
        if ret_val == self.INVALID_SET_FILE_POINTER:
            raise Exception("Seek error.")

    def _read(self, size):
        buff = ctypes.create_string_buffer(size)
        bytes_read = wintypes.DWORD()
        ret_val = kernel32.ReadFile(self._handle, buff, size,
                                    ctypes.byref(bytes_read), 0)
        if not ret_val:
            raise Exception("Read exception.")
        return buff.raw[:bytes_read.value]    # all bytes without the null byte

    def open(self):
        access = self.GENERIC_READ
        share_mode = self.FILE_SHARE_READ
        if self._allow_write:
            access |= self.GENERIC_WRITE
            share_mode |= self.FILE_SHARE_WRITE
            attributes = 0
        else:
            attributes = self.FILE_ATTRIBUTE_READONLY

        handle = kernel32.CreateFileW(
            ctypes.c_wchar_p(self._path),
            access,
            share_mode,
            0,
            self.OPEN_EXISTING,
            attributes,
            0)
        if handle == self.INVALID_HANDLE_VALUE:
            raise Exception('Cannot open file.')
        self._handle = handle
        self._sector_size, self._disk_size, self.fixed =\
            self._get_geometry()

    def close(self):
        if self._handle:
            kernel32.CloseHandle(self._handle)
            self._handle = None

    def seek(self, offset):
        """Drive geometry safe seek.

        Seek for a given offset and return the valid set one.
        """
        safe_offset = int(offset / self._sector_size) * self._sector_size
        self._seek(safe_offset)
        return safe_offset

    def read(self, size, skip=0):
        """Drive geometry safe read.

        Read and extract exactly the requested content.
        """
        # Compute a size to fit both of the bytes we need to skip and
        # also the minimum read size.
        total = size + skip
        safe_size = ((int(total / self._sector_size) +
                      bool(total % self._sector_size)) * self._sector_size)
        content = self._read(safe_size)
        return content[skip:total]

    @abc.abstractmethod
    def size(self):
        """Returns the size in bytes of the actual opened device."""


class Disk(BaseDevice):
    """Disk class with seek/read support.

    It also has the capability of obtaining partition objects.
    """

    PARTITION_ENTRY_UNUSED = 0
    PARTITION_STYLE_MBR = 0
    PARTITION_STYLE_GPT = 1

    def _get_layout(self):
        layout = Win32_DRIVE_LAYOUT_INFORMATION_EX()
        bytes_returned = wintypes.DWORD()
        ret_val = kernel32.DeviceIoControl(
            self._handle,
            IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
            0,
            0,
            ctypes.byref(layout),
            ctypes.sizeof(layout),
            ctypes.byref(bytes_returned),
            0)

        if not ret_val:
            raise Exception("Cannot get disk layout.")
        return layout

    @staticmethod
    def _create_guid():
        guid = GUID()
        ret_val = rpcrt4.UuidCreate(ctypes.byref(guid))
        if ret_val:
            raise Exception("UuidCreate failed: %r" % ret_val)
        return guid

    def _get_partition_indexes(self, layout):
        partition_style = layout.PartitionStyle
        if partition_style not in (self.PARTITION_STYLE_MBR,
                                   self.PARTITION_STYLE_GPT):
            raise Exception("Invalid partition style %r" % partition_style)
        # If is GPT, then the count reflects the actual number of partitions
        # but if is MBR, then the number of partitions is a multiple of 4
        # and just the indexes for the used partitions must be saved.
        partition_indexes = []
        if partition_style == self.PARTITION_STYLE_GPT:
            partition_indexes.extend(range(layout.PartitionCount))
        else:
            for idx in range(layout.PartitionCount):
                if (layout.PartitionEntry[idx].Mbr.PartitionType !=
                        self.PARTITION_ENTRY_UNUSED):
                    partition_indexes.append(idx)
        return partition_indexes

    def partitions(self):
        """Return a list of partition objects available on disk."""
        layout = self._get_layout()
        partition_indexes = self._get_partition_indexes(layout)
        # Create and return the partition objects containing their sizes.
        partitions = []
        disk_index = re.search(r"(disk|drive)(\d+)", self._path,
                               re.I | re.M).group(2)
        for partition_index in partition_indexes:
            path = r'\\?\GLOBALROOT\Device\Harddisk{}\Partition{}'.format(
                disk_index, partition_index + 1)
            size = layout.PartitionEntry[partition_index].PartitionLength
            partition = Partition(path, size)
            partitions.append(partition)
        return partitions

    @property
    def size(self):
        return self._disk_size


class Partition(BaseDevice):
    """Partition class with seek/read support."""

    def __init__(self, path, size):
        super(Partition, self).__init__(path)
        self._partition_size = size

    @property
    def size(self):
        return self._partition_size


def is_64bit_arch_hw():
    # interpreter's bits
    return struct.calcsize("P") == 8


def get_physical_disks_hw():
    physical_disks = []
    disk_guid = GUID_DEVINTERFACE_DISK
    handle_disks = setupapi.SetupDiGetClassDevsW(
        ctypes.byref(disk_guid), None, None,
        DIGCF_PRESENT | DIGCF_DEVICEINTERFACE)
    if handle_disks == INVALID_HANDLE_VALUE:
        raise Exception(
            "SetupDiGetClassDevs failed")
    try:
        did = Win32_SP_DEVICE_INTERFACE_DATA()
        did.cbSize = ctypes.sizeof(Win32_SP_DEVICE_INTERFACE_DATA)
        index = 0
        while setupapi.SetupDiEnumDeviceInterfaces(
                handle_disks, None, ctypes.byref(disk_guid), index,
                ctypes.byref(did)):
            index += 1
            handle_disk = INVALID_HANDLE_VALUE
            required_size = wintypes.DWORD()
            if not setupapi.SetupDiGetDeviceInterfaceDetailW(
                    handle_disks, ctypes.byref(did), None, 0,
                    ctypes.byref(required_size), None):
                if (kernel32.GetLastError() !=
                        ERROR_INSUFFICIENT_BUFFER):
                    raise Exception(
                        "SetupDiGetDeviceInterfaceDetailW failed.")

            pdidd = ctypes.cast(
                msvcrt.malloc(ctypes.c_size_t(required_size.value)),
                ctypes.POINTER(Win32_SP_DEVICE_INTERFACE_DETAIL_DATA_W))
            try:
                pdidd.contents.cbSize = ctypes.sizeof(
                    Win32_SP_DEVICE_INTERFACE_DETAIL_DATA_W)
                if not is_64bit_arch_hw():
                    # NOTE(cpoieana): For some reason, on x86 platforms
                    # the alignment or content of the struct
                    # is not taken into consideration.
                    pdidd.contents.cbSize = 6
                if not setupapi.SetupDiGetDeviceInterfaceDetailW(
                        handle_disks, ctypes.byref(did), pdidd,
                        required_size, None, None):
                    raise Exception(
                        "SetupDiGetDeviceInterfaceDetailW failed.")
                device_path = ctypes.cast(
                    pdidd.contents.DevicePath, wintypes.LPWSTR).value
                handle_disk = kernel32.CreateFileW(
                    device_path, 0, FILE_SHARE_READ,
                    None, OPEN_EXISTING, 0, 0)
                if handle_disk == INVALID_HANDLE_VALUE:
                    raise Exception(
                        'CreateFileW failed')
                sdn = Win32_STORAGE_DEVICE_NUMBER()
                b = wintypes.DWORD()
                if not kernel32.DeviceIoControl(
                        handle_disk, IOCTL_STORAGE_GET_DEVICE_NUMBER,
                        None, 0, ctypes.byref(sdn), ctypes.sizeof(sdn),
                        ctypes.byref(b), None):
                    raise Exception(
                        'DeviceIoControl failed.')
                physical_disks.append(
                    r"\\.\PHYSICALDRIVE%d" % sdn.DeviceNumber)
            finally:
                msvcrt.free(pdidd)
                if handle_disk != INVALID_HANDLE_VALUE:
                    kernel32.CloseHandle(handle_disk)
    finally:
        setupapi.SetupDiDestroyDeviceInfoList(handle_disks)
    return physical_disks


def get_config_drive_from_raw_hdd_hw(target_path):
    disks = map(Disk, get_physical_disks_hw())
    return extract_iso_from_devices_hw(disks, target_path)


def _get_config_drive_from_partition(target_path):
    LOG.info('_get_config_drive_from_partition.')
    for disk_path in get_physical_disks_hw():
        physical_drive = Disk(disk_path)
        with physical_drive:
            partitions = physical_drive.partitions()
        extracted = extract_iso_from_devices_hw(partitions, target_path)
        if extracted:
            return True
    return True


def extract_iso_from_devices_hw(devices, target_path):
    """Search across multiple devices for a raw ISO."""
    extracted = False
    iso_file_path = os.path.join(target_path,
                                 str(uuid.uuid4()) + '.iso')
    for device in devices:
        try:
            with device:
                iso_file_size = get_iso_file_size_hw(device)
                if iso_file_size:
                    LOG.info('ISO9660 disk found on %s', device)
                    write_iso_file_hw(device, iso_file_path,
                                      iso_file_size)
                    extract_files_from_iso_hw(iso_file_path, target_path)
                    extracted = True
                    break
        except Exception as exc:
            LOG.warning('ISO extraction failed on %(device)s with '
                        '%(error)r', {"device": device, "error": exc})
    if os.path.isfile(iso_file_path):
        os.remove(iso_file_path)
    return extracted


def get_iso_file_size_hw(device):
    if not device.fixed:
        return None
    if not device.size > (OFFSET_BLOCK_SIZE + PEEK_SIZE):
        return None
    off = device.seek(OFFSET_ISO_ID)
    magic = device.read(len(ISO_ID), skip=OFFSET_ISO_ID - off)
    if ISO_ID != magic:
        return None
    off = device.seek(OFFSET_VOLUME_SIZE)
    volume_size_bytes = device.read(PEEK_SIZE,
                                    skip=OFFSET_VOLUME_SIZE - off)
    off = device.seek(OFFSET_BLOCK_SIZE)
    block_size_bytes = device.read(PEEK_SIZE,
                                   skip=OFFSET_BLOCK_SIZE - off)
    volume_size = struct.unpack("<H", volume_size_bytes)[0]
    block_size = struct.unpack("<H", block_size_bytes)[0]
    return volume_size * block_size


def write_iso_file_hw(device, iso_file_path, iso_file_size):
    with open(iso_file_path, 'wb') as stream:
        offset = 0
        # Read multiples of the sector size bytes
        # until the entire ISO content is written.
        while offset < iso_file_size:
            real_offset = device.seek(offset)
            bytes_to_read = min(MAX_SECTOR_SIZE, iso_file_size - offset)
            data = device.read(bytes_to_read, skip=offset - real_offset)
            stream.write(data)
            offset += bytes_to_read


def extract_files_from_iso_hw(iso_file_path, target_path):
    bsdtar_path = config_get("NETWORK_CONFIG", "bsdtar_path", "bsdtar.exe")
    args = [bsdtar_path, '-xf', iso_file_path,
            '-C', target_path]
    (out, err, exit_code) = execute_process_hw(args, False)
    if exit_code:
        raise Exception(
            'Failed to execute "bsdtar" from path "%(bsdtar_path)s" with '
            'exit code: %(exit_code)s\n%(out)s\n%(err)s' % {
                'bsdtar_path': bsdtar_path,
                'exit_code': exit_code,
                'out': out, 'err': err})


def execute_process_hw(args, shell=True, decode_output=False):
    p = subprocess.Popen(args,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,
                         shell=shell)
    (out, err) = p.communicate()
    if decode_output and sys.version_info < (3, 0):
        out = out.decode(sys.stdout.encoding)
        err = err.decode(sys.stdout.encoding)
    LOG.info("returned code: %s" % p.returncode)
    return out, err, p.returncode


def get_sysnative_dir():
    return os.path.expandvars('%windir%\\sysnative')


def get_syswow64_dir():
    return os.path.expandvars('%windir%\\syswow64')


def get_system32_dir():
    return os.path.expandvars('%windir%\\system32')


# def is_wow64():
#     return win32process.IsWow64Process()


def check_sysnative_dir_exists():
    sysnative_dir_exists = os.path.isdir(get_sysnative_dir())
    if not sysnative_dir_exists:
        LOG.warning('Unable to validate sysnative folder presence.')
    return sysnative_dir_exists


def get_sysnative_dir():
    return os.path.expandvars('%windir%\\sysnative')


def get_system_dir_hw(sysnative=True):
    """Return Windows system directory with compatibility support.
    Depending on the interpreter bits and platform architecture,
    the return value may vary between
    C:\Windows\(System32|SysWOW64|Sysnative).
    Note that "Sysnative" is just an alias (doesn't really exist on disk).
    More info about this can be found in documentation.
    """
    if sysnative and check_sysnative_dir_exists():
        return get_sysnative_dir()
    if not sysnative and is_64bit_arch_hw():
        return get_syswow64_dir()
    return get_system32_dir()


def execute_powershell_script_hw(script_path, sysnative=True):
    base_dir = get_system_dir_hw(sysnative)
    powershell_path = os.path.join(base_dir,
                                   'WindowsPowerShell\\v1.0\\'
                                   'powershell.exe')
    args = [powershell_path]
    args.append(script_path)

    return execute_process_hw(args, shell=False)


def check_os_version(major, minor, build=0):
    vi = Win32_OSVERSIONINFOEX_W()
    vi.dwOSVersionInfoSize = ctypes.sizeof(Win32_OSVERSIONINFOEX_W)
    vi.dwMajorVersion = major
    vi.dwMinorVersion = minor
    vi.dwBuildNumber = build
    mask = 0
    for type_mask in [VER_MAJORVERSION, VER_MINORVERSION, VER_BUILDNUMBER]:
        mask = kernel32.VerSetConditionMask(mask, type_mask,
                                            VER_GREATER_EQUAL)
    type_mask = VER_MAJORVERSION | VER_MINORVERSION | VER_BUILDNUMBER
    ret_val = ntdll.RtlVerifyVersionInfo(ctypes.byref(vi), type_mask, mask)

    if not ret_val:
        return True
    elif ret_val == STATUS_REVISION_MISMATCH:
        return False
    else:
        raise Exception("RtlVerifyVersionInfo failed with error: %s" % ret_val)


def get_network_adapters_hw():
    """Return available adapters as a list of tuples of (name, mac)."""
    conn = wmi.WMI(moniker='//./root/cimv2')
    # Get Ethernet adapters only
    wql = ('SELECT * FROM Win32_NetworkAdapter WHERE '
           'AdapterTypeId = 0 AND MACAddress IS NOT NULL')

    wql += ' AND PhysicalAdapter = True'
    q = conn.query(wql)
    LOG.info('wql:%s' % wql)
    return [(r.NetConnectionID, r.MACAddress) for r in q]


def subp_hw(args, data=None, rcs=None, capture=True, decode="replace"):
    if rcs is None:
        rcs = [0]

    dev_null_fp = None
    stdin = None
    stdout = None
    stderr = None
    if capture:
        stdout = subprocess.PIPE
        stderr = subprocess.PIPE
    if data is None:
        dev_null_fp = open(os.devnull)
        stdin = dev_null_fp
    else:
        stdin = subprocess.PIPE
        if not isinstance(data, bytes):
            data = data.encode()
    try:
        stdin = open(os.devnull)
        stdout = subprocess.PIPE
        stderr = subprocess.PIPE
        sp = subprocess.Popen(args, stdout=stdout,
                              stderr=stderr, stdin=stdin,
                              env=None, shell=False)
        (out, err) = sp.communicate()

        if not out and capture:
            out = b''
        if not err and capture:
            err = b''
        if decode:
            def ldecode(data, m='utf-8'):
                if not isinstance(data, bytes):
                    return data
                return data.decode(m, errors=decode)

            out = ldecode(out)
            err = ldecode(err)
    except OSError as e:
        raise IOError(cmd=args, reason=e, errno=e.errno)
    finally:
        if dev_null_fp:
            dev_null_fp.close()

    rc = sp.returncode
    if rc not in rcs:
        raise IOError(stdout=out, stderr=err, exit_code=rc, cmd=args)

    return out, err


def read_config_drive_hw(source_dir):
    reader = ConfigDriveReaderHW(source_dir)
    finders_info = [(reader.read_v2_hw, [], {}), (reader.read_v1_hw, [], {}),]
    excps = []
    for (func, args, kwargs) in finders_info:
        try:
            return func(*args, **kwargs)
        except IOError as e:
            excps.append(e)
    raise excps[-1]


def pipe_in_out_hw(in_fh, out_fh, chunk_size=1024, chunk_cb=None):
    bytes_piped = 0
    while True:
        datainfo = in_fh.read(chunk_size)
        if len(datainfo) == 0:
            break
        else:
            out_fh.write(datainfo)
            bytes_piped += len(datainfo)
            if chunk_cb:
                chunk_cb(bytes_piped)
    out_fh.flush()
    return bytes_piped


def handle_services_hw(network_json):
    serlist = network_json.get('services', [])
    if not serlist:
        LOG.error("Get services' info failed")
        return False, []
    return True, serlist


def handle_network_hw(network_json):
    netlist = network_json.get('networks', [])
    if not netlist:
        LOG.error("Get networks' info failed")
        return False, []
    return True, netlist


def handle_links_hw(network_json):
    links = network_json.get('links', [])
    if not links:
        LOG.error("Get links' info failed")
        return False, []
    return True, links


def get_network_json_hw(target_path):
    try:
        _get_config_drive_from_partition(target_path)
    except Exception as e:
        LOG.error('get config drive information failed: %s' % e)
        return False, []
    try:
        results = read_config_drive_hw(target_path)
    except Exception as e:
        LOG.error('read config drive failed: %s' % e)
        return False, []

    network_json = results.get('networkdata', {})

    return True, network_json


def load_file_hw(fname, read_cb=None, quiet=False, decode=True):
    LOG.info("Reading from %s (quiet=%s)", fname, quiet)
    ofh_info = six.BytesIO()
    try:
        with open(fname, 'rb') as ifh:
            pipe_in_out_hw(ifh, ofh_info, chunk_cb=read_cb)
    except IOError as e:
        if not quiet:
            raise
        if e.errno != errno.ENOENT:
            raise
    contents = ofh_info.getvalue()
    LOG.info("Read %s bytes from %s", len(contents), fname)
    if decode:
        return decode_binary_hw(contents)
    else:
        return contents


def apply_network_config_names_hw(phy_config):
    ethername = phy_config["nic_name"]
    newname = phy_config["id"]
    set_phy_cmd = '''Rename-NetAdapter -Name "%s"  \
                                -NewName "%s"''' % (ethername, newname)
    LOG.info("set_phy_cmd:%s " % set_phy_cmd)

    out, err, exit_code = execute_powershell_script_hw(set_phy_cmd)
    if exit_code:
        LOG.error("Could not rename phy.out:%s, err: %s" % (out, err))
        raise Exception("Could not rename phy.")
        return False
    return True


def apply_phy_hw(links):
    network_adapters = get_network_adapters_hw()
    LOG.info("network_adapters get sussess")

    if not network_adapters:
        raise Exception("no network adapters available")

    if not links:
        LOG.error("Not found links' info")
        return False, []

    macs = []
    for adapter in network_adapters:
        if adapter[1]:
            macs.append(adapter[1])

    ifphy_cfg = {}
    ifphy_cfg_total = []
    for linkdic in links:
        if linkdic.get('type', None) == 'phy' and\
                linkdic.get('ethernet_mac_address', None) and\
                linkdic.get('id', None):
            mac_in_config = linkdic["ethernet_mac_address"].upper()
            if mac_in_config in macs:
                    for nic in network_adapters:
                        if mac_in_config == nic[1]:
                            ifphy_cfg["nic_name"] = nic[0]
                            ifphy_cfg["nic_mac"] = nic[1]
                            ifphy_cfg["id"] = linkdic.get('id', None)
                            ifphy_cfg["ethernet_mac_address"] = linkdic.get('ethernet_mac_address', None)
                            LOG.info("ifphy_cfg:%s" % ifphy_cfg)
                            apply_network_config_names_hw(ifphy_cfg)
                        else:
                            continue
            else:
                LOG.error("not found match NIC by mac address.mac addr:%s" % mac_in_config)
            ifphy_cfg_total.append(linkdic)
    return True, ifphy_cfg_total


def apply_bond_hw(link_info, network_info):
    iface_cfg_total = []
    index = 0

    for linkdic in link_info:
        if linkdic.get('type', None) == 'bond' and\
                linkdic.get('ethernet_mac_address', None) and\
                linkdic.get('bond_links', None) and\
                linkdic.get('id', None):

            iface_cfg = {}
            bond_links = linkdic.get('bond_links')
            if len(bond_links) < 1:
                LOG.error("Bond info error %s: %s" % (linkdic.get('id'), " ".join(bond_links)))
                return False, []
            iface_cfg["mtu"] = linkdic.get('mtu')
            iface_cfg["bond_xmit_hash_policy"] = linkdic.get('bond_xmit_hash_policy')
            iface_cfg["bond_mode"] = linkdic.get('bond_mode')
            iface_cfg["bond_miimon"] = linkdic.get('bond_miimon')
            iface_cfg["bond_links"] = linkdic.get('bond_links')
            iface_cfg["ethernet_mac_address"] = linkdic.get('ethernet_mac_address', None)

            for networkdic in network_info:
                if networkdic.get('link', None) == linkdic.get('id'):
                    iface_cfg["network_type"] = networkdic["type"]
                    if iface_cfg["network_type"] == "ipv4":
                        iface_cfg["bond_ip"] == networkdic["ip_address"]
                        iface_cfg["netmask"] == networkdic["netmask"]
                        #bond_config["default_gateway"] == network["gateway"]
                    elif iface_cfg["network_type"] == "ipv4_dhcp":
                        LOG.info("Bond IPv4 mode DHCP")
                    else:
                        LOG.info("Bond IPv4 config not dhcp or static")
            index += 1
            iface_cfg_total.append(iface_cfg)
            LOG.info("apply bond nic by conf:%s" % iface_cfg)
    return True, iface_cfg_total


def apply_vlanif_hw(link_info, network_info):

    viface_cfg_total = []
    for linkdic in link_info:
        if linkdic.get('type', None) == 'vlan' and\
            linkdic.get('ethernet_mac_address', None) and\
            linkdic.get('vlan_link', None) and\
            linkdic.get('vlan_id', None) and\
                linkdic.get('vlan_mac_address', None):
            vlan_id = linkdic.get('vlan_id')

            try:
                if int(vlan_id) < 1 or int(vlan_id) > 4096:
                    LOG.error("Vlan id %s is invalid for vlan link %s " %
                              (vlan_id, linkdic.get('id')))
                    return False, []
            except Exception:
                LOG.error("Vlan id %s is not Interger for vlan link %s " %
                          (vlan_id, linkdic.get('id')))
                return False, []

            for network in network_info:
                vlan_config = {}
                if linkdic.get('id') == network["link"]:
                    # TODO(confirm config items) Confirm which items needs in vlan config
                    vlan_config["network_id"] = network["network_id"]
                    vlan_config["network_type"] = network["type"]
                    if network["type"] == "ipv4":
                        vlan_config["vlan_ip"] = network["ip_address"]
                        vlan_config["netmask"] = network["netmask"]
                    elif network["type"] == "ipv4_dhcp":
                        LOG.info("Vlan IPv4 mode DHCP")
                    else:
                        LOG.info("Vlan IPv4 config not dhcp or static")
                        continue
                    # vlan_config["networkes_net_id"] = network["id"]
                    vlan_config["vlan_link"] = linkdic.get("vlan_link")
                    vlan_config["ethernet_mac_address"] = linkdic.get("ethernet_mac_address")
                    vlan_config["vlan_id"] = linkdic.get("vlan_id")
                    vlan_config["vlan_mac_address"] = linkdic.get("vlan_mac_address")
                    #vlan_config["vlan_type"] = config["type"]
                    #vlan_config["vlan_net_id"] = config["id"]
                    LOG.info("apply vlan nic by conf: %s" % vlan_config)
                    viface_cfg_total.append(vlan_config)
                else:
                    continue
    return True, viface_cfg_total


@six.add_metaclass(abc.ABCMeta)
class BaseReaderHW(object):
    def __init__(self, base_path):
        self.base_path = base_path

    @abc.abstractmethod
    def _path_join_hw(self, base, *add_ons):
        pass

    @abc.abstractmethod
    def _path_read_hw(self, path, decode=False):
        pass

    @abc.abstractmethod
    def _fetch_available_versions_hw(self):
        pass

    @abc.abstractmethod
    def _read_ec2_metadata_hw(self):
        pass

    def _find_working_version_hw(self):
        try:
            ver_avail = self._fetch_available_versions_hw()
        except Exception as e:
            LOG.info("Unable to read openstack versions from %s due to: "
                      "%s", self.base_path, e)
            ver_avail = []

        supported = [v for v in reversed(list(OS_VERSIONS))]
        sel_ver = OS_LATEST

        for pot_ver in supported:
            if pot_ver not in ver_avail:
                continue
            sel_ver = pot_ver
            break

        return sel_ver

    def _read_content_path_hw(self, item, decode=False):
        path = item.get('content_path', '').lstrip("/")
        path_p = path.split("/")
        valid_p = [p for p in path_p if len(p)]
        if not valid_p:
            raise IOError("Item %s has no valid content path" % item)
        path = self._path_join_hw(self.base_path, "openstack", *path_p)
        return self._path_read_hw(path, decode=decode)

    def read_v2_hw(self):
        load_json_all = functools.partial(
            load_json_hw, root_types=(dict, list) + six.string_types)

        def data_files_hw(version):
            files = {}
            files['metadata'] = (
                self._path_join_hw("openstack", version, 'meta_data.json'),
                True,
                load_json_hw,
            )
            files['userdata'] = (
                self._path_join_hw("openstack", version, 'user_data'),
                False,
                lambda x: x,
            )
            files['vendordata'] = (
                self._path_join_hw("openstack", version, 'vendor_data.json'),
                False,
                load_json_all,
            )
            files['networkdata'] = (
                self._path_join_hw("openstack", version, 'network_data.json'),
                False,
                load_json_all,
            )
            return files

        results = {'userdata': '', 'version': 2}
        data = data_files_hw(self._find_working_version_hw())
        for (name, (path, required, translator)) in data.items():
            path = self._path_join_hw(self.base_path, path)
            data = None
            found_flag = False
            try:
                data = self._path_read_hw(path)
            except IOError as e:
                pass
            else:
                found_flag = True
            if required and not found_flag:
                raise IOError("Missing mandatory path: %s" % path)
            if found_flag and translator:
                try:
                    data = translator(data)
                except Exception as e:
                    raise IOError("Failed to process "
                                  "path %s: %s" % (path, e))
            if found_flag:
                results[name] = data

        metadata = results['metadata']
        if 'random_seed' in metadata:
            rand_s = metadata['random_seed']
            try:
                metadata['random_seed'] = base64.b64decode(rand_s)
            except (ValueError, TypeError) as e:
                raise IOError("Badly formatted metadata random_seed entry: %s" % e)

        files = {}
        metadata_files = metadata.get('files', [])
        for item in metadata_files:
            if 'path' not in item:
                continue
            path = item['path']
            try:
                files[path] = self._read_content_path_hw(item)
            except Exception as e:
                raise IOError("Failed to read provided "
                              "file %s: %s" % (path, e))
        results['files'] = files

        net_item = metadata.get("network_config", None)
        if net_item:
            try:
                content = self._read_content_path_hw(net_item, decode=True)
                results['network_config'] = content
            except IOError as e:
                raise IOError("Failed to read network configuration: %s" % e)

        try:
            results['dsmode'] = metadata['meta']['dsmode']
        except KeyError:
            pass

        results['ec2-metadata'] = self._read_ec2_metadata_hw()

        for (target_key, source_key, is_required) in KEY_COPIES:
            if is_required and source_key not in metadata:
                raise
            if source_key in metadata:
                metadata[target_key] = metadata.get(source_key)
        return results


class ConfigDriveReaderHW(BaseReaderHW):
    def __init__(self, base_path):
        super(ConfigDriveReaderHW, self).__init__(base_path)
        self._versions = None

    def _path_join_hw(self, base, *add_ons):
        comps = [base] + list(add_ons)
        return os.path.join(*comps)

    def _path_read_hw(self, path, decode=False):
        return load_file_hw(path, decode=decode)

    def _fetch_available_versions_hw(self):
        if self._versions is None:
            path = self._path_join_hw(self.base_path, 'openstack')
            found = [d for d in os.listdir(path)
                     if os.path.isdir(os.path.join(path))]
            self._versions = sorted(found)
        return self._versions

    def _read_ec2_metadata_hw(self):
        path = self._path_join_hw(self.base_path, 'ec2', 'latest', 'meta-data.json')
        if not os.path.exists(path):
            return {}
        else:
            try:
                return load_json_hw(self._path_read_hw(path))
            except Exception as e:
                raise IOError("Failed to process path %s: %s" % (path, e))

    def read_v1_hw(self):
        found = {}
        for name in FILES_V1.keys():
            path = self._path_join_hw(self.base_path, name)
            if os.path.exists(path):
                found[name] = path
        if len(found) == 0:
            raise IOError("%s: no files found" % (self.base_path))

        md = {}
        for (name, (key, translator, default)) in FILES_V1.items():
            if name in found:
                path = found[name]
                try:
                    contents = self._path_read_hw(path)
                except IOError:
                    raise IOError("Failed to read: %s" % path)
                try:
                    md[key] = translator(contents)
                except Exception as e:
                    raise IOError("Failed to process path %s: %s" % (path, e))
            else:
                md[key] = copy.deepcopy(default)

        key_data = md['authorized_keys']
        meta_js = md['meta_js']

        key_data = meta_js.get('public-keys', key_data)
        if key_data:
            lines = key_data.splitlines()
            md['public-keys'] = [l for l in lines
                                 if len(l) and not l.startswith("#")]

        if 'instance-id' in meta_js:
            md['instance-id'] = meta_js['instance-id']

        results = {'version': 1, 'metadata': md}

        if 'dsmode' in meta_js:
            results['dsmode'] = meta_js['dsmode']

        results['userdata'] = meta_js.get('user-data', '')
        results['files'] = {}
        subp_hw()
        return results


def bring_up_bond_hw(ifphy_cfg_total, bond_config):
    bond_mac = bond_config["ethernet_mac_address"]
    bond_links = bond_config["bond_links"]

    if bond_config["bond_mode"] == "4":
        bond_mode = "LACP"
    elif bond_config["bond_mode"] == "1":
        bond_mode = "SwitchIndependent"
    else:
        LOG.error("bond_mode is not support.")
        raise Exception("bond_mode is not support.")
        return False

    bond_links_string = ','.join(bond_links)
    create_bond_cmd = '''New-NetLbfoTeam \
                    -Name "%s" \
                    -TeamMembers %s \
                    -TeamingMode %s   \
                    -LoadBalancingAlgorithm IPAddresses \
                    -Confirm:$false''' % (BOND_NAME, bond_links_string, bond_mode)
    LOG.info("create_bond_cmd:%s " % create_bond_cmd)

    set_bond_mac_cmd = '''Set-NetAdapter -Name "%s" -MacAddress "%s" -Confirm:$false''' % (BOND_NAME, bond_mac)
    LOG.info("set_bond_mac:%s " % set_bond_mac_cmd)

    out, err, exit_code = execute_powershell_script_hw(create_bond_cmd)
    if exit_code:
        LOG.error("Could not create_bond.out:%s, err: %s" % (out, err))
        raise Exception("Could not create_bond.")
        return False

    out, err, exit_code = execute_powershell_script_hw(set_bond_mac_cmd)
    if exit_code:
        LOG.error("Could not set bond mac. out:%s, err: %s" % (out, err))

    if bond_config["bond_mode"] == "1":
        for ifphy_cfg in ifphy_cfg_total:
            phy_port = ifphy_cfg["id"]
            break

        set_bond_stanby_cmd = '''Set-NetLbfoTeamMember \
                        -Name "%s" \
                        -AdministrativeMode  Standby \
                        -Confirm:$false''' % (phy_port)
        out, err, exit_code = execute_powershell_script_hw(set_bond_stanby_cmd)
        if exit_code:
            LOG.error("Could not set bond stanby.out:%s, err: %s" % (out, err))
            #raise Exception("Could not set bond stanby.")
            #return False

    network_adapter = get_network_adapters_hw()
    for adapter in network_adapter:
        if adapter[0] == BOND_NAME:
            LOG.info("THe Bond Name is %s" % BOND_NAME)

    return True


def bring_up_viface_hw(vlan_config):
    if not vlan_config["vlan_id"]:
        LOG.error("NO vlanid given,exit vlan_set")
        return False

    vlan_id = vlan_config["vlan_id"]
    create_vlan_cmd = ''' Add-NetLbfoTeamNIC -Team "Team1" -VlanID %d -Confirm:$false''' % vlan_id
    LOG.info("creat_vlan_cmd:%s" % create_vlan_cmd)

    out, err, exit_code = execute_powershell_script_hw(create_vlan_cmd)
    if exit_code:
        LOG.error("Could not create vlan. out:%s, err: %s" % (out, err))
        return False

    vlan_nic_name = ("%s - VLAN %d" % (BOND_NAME, vlan_id))
    vlan_mac = vlan_config["ethernet_mac_address"]
    set_vlan_mac_cmd = '''Set-NetAdapter -Name "%s" -MacAddress "%s" -Confirm:$false ''' % (vlan_nic_name, vlan_mac)

    if vlan_config["network_type"] == "ipv4_dhcp":
        LOG.info("set_vlan_mac_cmd:%s" % set_vlan_mac_cmd)
        out, err, exit_code = execute_powershell_script_hw(set_vlan_mac_cmd)
        if exit_code:
            LOG.error("Could not set vlan mac. out:%s, err: %s" % (out, err))

    elif vlan_config["network_type"] == "ipv4":
        set_vlan_ip_cmd = '''get-netadapter "%s" | New-NetIPAddress \
            -IPAddress '%s' -AddressFamily IPv4 \
            -PrefixLength 24  ''' \
            % (vlan_nic_name, vlan_config["vlan_ip"])
        LOG.info("set_vlan_ip_cmd:%s" % set_vlan_ip_cmd)

        out, err, exit_code = execute_powershell_script_hw(set_vlan_ip_cmd)
        if exit_code:
            LOG.error("Could not set vlan ip. out:%s, err: %s" % (out, err))

    else:
        LOG.info("Vlan network_type not static ipv4 or ipv4_dhcp")
        return False

    return True


def _get_registry_dhcp_server(adapter_name):
    with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Services\\" +
            "Tcpip\\Parameters\\Interfaces\\%s" % adapter_name, 0,
            winreg.KEY_READ) as key:
        try:
            dhcp_server = winreg.QueryValueEx(key, "DhcpServer")[0]
            LOG.info("_get_registry_dhcp_server dhcp_server is: %s", dhcp_server)
            print(dhcp_server)
            if dhcp_server == "255.255.255.255":
                dhcp_server = None
            return dhcp_server
        except Exception as ex:
            # Not found
            if ex.errno != 2:
                raise


def init_wsa(version=VERSION_2_2):
    wsadata = WSADATA()
    WSAStartup(version, ctypes.byref(wsadata))


def _format_mac_address(phys_address, phys_address_len):
    mac_address = ""
    for i in range(0, phys_address_len):
        b = phys_address[i]
        if mac_address:
            mac_address += ":"
        mac_address += "%02X" % b
    return mac_address


def _socket_addr_to_str(socket_addr):
    addr_str_len = wintypes.DWORD(256)
    addr_str = ctypes.create_unicode_buffer(256)

    ret_val = WSAAddressToStringW(
        socket_addr.lpSockaddr,
        socket_addr.iSockaddrLength,
        None, addr_str, ctypes.byref(addr_str_len))
    if ret_val:
        raise Exception(
            "WSAAddressToStringW failed: %s" % WSAGetLastError())

    return addr_str.value


def get_adapter_addresses():
    net_adapters = []
    filter_flags = (GAA_FLAG_SKIP_ANYCAST |
                    GAA_FLAG_SKIP_MULTICAST)

    size = wintypes.ULONG()
    ret_val = GetAdaptersAddresses(
        AF_UNSPEC,
        filter_flags,
        None, None, ctypes.byref(size))
    LOG.info("GetAdaptersAddresses ret_val is: %s", ret_val)
    if ret_val == ERROR_NO_DATA:
        return net_adapters

    if ret_val == ERROR_BUFFER_OVERFLOW:
        proc_heap = kernel32.GetProcessHeap()
        p = kernel32.HeapAlloc(proc_heap, 0, size.value)
        if not p:
            raise Exception("Cannot allocate memory")

        init_wsa()

        try:
            p_addr = ctypes.cast(p, ctypes.POINTER(
                IP_ADAPTER_ADDRESSES))

            ret_val = GetAdaptersAddresses(
                AF_UNSPEC,
                filter_flags,
                None, p_addr, ctypes.byref(size))

            if ret_val == ERROR_NO_DATA:
                return net_adapters

            if ret_val:
                raise Exception(
                    "GetAdaptersAddresses failed: %r" % ret_val)

            p_curr_addr = p_addr
            while p_curr_addr:
                curr_addr = p_curr_addr.contents

                xp_data_only = (curr_addr.Union1.Struct1.Length <=
                                IP_ADAPTER_ADDRESSES_SIZE_2003)

                mac_address = _format_mac_address(
                    curr_addr.PhysicalAddress,
                    curr_addr.PhysicalAddressLength)

                dhcp_enabled = (
                    curr_addr.Flags & IP_ADAPTER_DHCP_ENABLED) != 0
                dhcp_server = None
                LOG.info("dhcp_enabled is: %s", dhcp_enabled)
                LOG.info("xp_data_only is: %s", xp_data_only)
                if dhcp_enabled:
                    if not xp_data_only:
                        if curr_addr.Flags & IP_ADAPTER_IPV4_ENABLED:
                            dhcp_addr = curr_addr.Dhcpv4Server

                        if ((curr_addr.Flags &
                             IP_ADAPTER_IPV6_ENABLED) and
                            (not dhcp_addr or
                             not dhcp_addr.iSockaddrLength)):
                            dhcp_addr = curr_addr.Dhcpv6Server
                            LOG.info("dhcp_addr is: %s", dhcp_addr)
                        LOG.info("dhcp_addr.iSockaddrLength is: %s", dhcp_addr.iSockaddrLength)
                        if dhcp_addr and dhcp_addr.iSockaddrLength:
                            dhcp_server = _socket_addr_to_str(dhcp_addr)
                            LOG.info("dhcp_server1 is: %s", dhcp_server)
                    else:
                        dhcp_server = _get_registry_dhcp_server(
                            curr_addr.AdapterName)
                        LOG.info("dhcp_server2 is: %s", dhcp_server)

                unicast_addresses = []

                p_unicast_addr = curr_addr.FirstUnicastAddress
                while p_unicast_addr:
                    unicast_addr = p_unicast_addr.contents
                    unicast_addresses.append((
                        _socket_addr_to_str(unicast_addr.Address),
                        unicast_addr.Address.lpSockaddr.contents.sa_family))
                    p_unicast_addr = ctypes.cast(
                        unicast_addr.Next,
                        ctypes.POINTER(IP_ADAPTER_UNICAST_ADDRESS))

                net_adapters.append(
                    {
                        "interface_index": curr_addr.Union1.Struct1.IfIndex,
                        "adapter_name": curr_addr.AdapterName,
                        "friendly_name": curr_addr.FriendlyName,
                        "description": curr_addr.Description,
                        "mtu": curr_addr.Mtu,
                        "mac_address": mac_address,
                        "dhcp_enabled": dhcp_enabled,
                        "dhcp_server": dhcp_server,
                        "interface_type": curr_addr.IfType,
                        "unicast_addresses": unicast_addresses
                    })
                LOG.info("net_adapters is: %s", net_adapters)
                p_curr_addr = ctypes.cast(
                    curr_addr.Next, ctypes.POINTER(
                        IP_ADAPTER_ADDRESSES))

        finally:
            kernel32.HeapFree(proc_heap, 0, p)
            WSACleanup()
    LOG.info("all net_adapters is: %s", net_adapters)
    return net_adapters


def _bind_dhcp_client_socket(s, max_bind_attempts, bind_retry_interval):
    bind_attempts = 1
    while True:
        try:
            s.bind(('', 68))
            break
        except socket.error as ex:
            if (bind_attempts >= max_bind_attempts or
                    ex.errno not in [48, 10048]):
                raise
            bind_attempts += 1
            LOG.exception(ex)
            LOG.info("Retrying to bind DHCP client port in %s seconds" %
                     bind_retry_interval)
            time.sleep(bind_retry_interval)


def get_dhcp_hosts_in_use():
    dhcp_hosts = []
    LOG.debug('dhcp_hosts begin')
    for net_addr in get_adapter_addresses():
        LOG.debug('net_addr ：%s' % net_addr)
        if net_addr["dhcp_enabled"] and net_addr["dhcp_server"]:
            LOG.debug('Get dhcp_servert ：%s' % net_addr["dhcp_server"])
            LOG.debug('Get dhcp_server mac_address ：%s' % net_addr["mac_address"])
            dhcp_hosts.append((net_addr["mac_address"],
                               net_addr["dhcp_server"]))
    return dhcp_hosts


def _get_mac_address_by_local_ip(ip_addr):
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        for addr in addrs[netifaces.AF_INET]:
            if addr['addr'] == ip_addr:
                return addrs[netifaces.AF_LINK][0]['addr']


def _get_dhcp_request_data(id_req, mac_address, requested_options,
                           vendor_id):

    mac_address_b = bytearray.fromhex(mac_address.replace(':', ''))
    # See: http://www.ietf.org/rfc/rfc2131.txt
    data = b'\x01'
    data += b'\x01'
    data += b'\x06'
    data += b'\x00'
    data += struct.pack('!L', id_req)
    data += b'\x00\x00'
    data += b'\x00\x00'
    data += b'\x00\x00\x00\x00'
    data += b'\x00\x00\x00\x00'
    data += b'\x00\x00\x00\x00'
    data += b'\x00\x00\x00\x00'
    data += mac_address_b
    data += b'\x00' * 10
    data += b'\x00' * 64
    data += b'\x00' * 128
    data += _DHCP_COOKIE
    data += b'\x35\x01\x01'

    if vendor_id:
        vendor_id_b = vendor_id.encode('ascii')
        data += b'\x3c' + struct.pack('b', len(vendor_id_b)) + vendor_id_b

    data += b'\x3d\x07\x01' + mac_address_b
    data += b'\x37' + struct.pack('b', len(requested_options))

    for option in requested_options:
        data += struct.pack('b', option)

    data += _OPTION_END
    return data


def _parse_dhcp_reply(data, id_req):
    message_type = struct.unpack('b', data[0:1])[0]

    if message_type != 2:
        return False, {}

    id_reply = struct.unpack('!L', data[4:8])[0]
    if id_reply != id_req:
        return False, {}

    if data[236:240] != _DHCP_COOKIE:
        return False, {}

    options = {}

    i = 240
    data_len = len(data)
    while i < data_len and data[i:i + 1] != _OPTION_END:
        id_option = struct.unpack('b', data[i:i + 1])[0]
        option_data_len = struct.unpack('b', data[i + 1:i + 2])[0]
        i += 2
        options[id_option] = data[i: i + option_data_len]
        i += option_data_len

    return True, options


def get_dhcp_options(dhcp_host, requested_options=[], timeout=5.0,
                     vendor_id='cloudbase-init', max_bind_attempts=10,
                     bind_retry_interval=3):
    id_req = random.randint(0, 2 ** 32 - 1)
    options = None

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        _bind_dhcp_client_socket(s, max_bind_attempts, bind_retry_interval)

        s.settimeout(timeout)
        s.connect((dhcp_host, 67))

        local_ip_addr = s.getsockname()[0]
        mac_address = _get_mac_address_by_local_ip(local_ip_addr)

        data = _get_dhcp_request_data(id_req, mac_address, requested_options,
                                      vendor_id)
        s.send(data)

        start = datetime.datetime.now()
        now = start
        replied = False
        while (not replied and
                now - start < datetime.timedelta(seconds=timeout)):
            data = s.recv(1024)
            (replied, options) = _parse_dhcp_reply(data, id_req)
            now = datetime.datetime.now()
    except socket.timeout:
        LOG.info('Get dhcp timeout')
        pass
    finally:
        s.close()

    return options


def set_network_adapter_mtu_hw(mac_address, mtu):
    iface_index_list = [
        net_addr["interface_index"] for net_addr
        in get_adapter_addresses()
        if net_addr["mac_address"] == mac_address]
    if not iface_index_list:
        raise Exception(
            'Network interface with MAC address "%s" not found' %
            mac_address)
    else:
        iface_index = iface_index_list[0]
        LOG.info('Setting MTU for interface "%(mac_address)s" with '
                  'value "%(mtu)s"',
                  {'mac_address': mac_address, 'mtu': mtu})
        base_dir = get_system_dir_hw()
        netsh_path = os.path.join(base_dir, 'netsh.exe')
        args = [netsh_path, "interface", "ipv4", "set", "subinterface",
                str(iface_index), "mtu=%s" % mtu,
                "store=persistent"]
        LOG.info('Setting MTU for interface %s' % args)
        (out, err, ret_val) = execute_process_hw(args, shell=False)
        if ret_val:
            raise Exception(
                'Setting MTU for interface "%(mac_address)s" with '
                'value "%(mtu)s" failed' % {'mac_address': mac_address,
                                            'mtu': mtu})


def set_interface_mtu_hw():
    if config_get("NETWORK_CONFIG", "mtu_use_dhcp_config", "True") == "True":
        try:
            dhcp_hosts = get_dhcp_hosts_in_use()
            LOG.info('Get dhcp_host done:%s' % dhcp_hosts)

            if not dhcp_hosts:
                LOG.error("dhcp_hosts not found.")
                return False

            for (mac_address, dhcp_host) in dhcp_hosts:
                options_data = get_dhcp_options(dhcp_host, [OPTION_MTU])
                if options_data:
                    LOG.info('Get options_data done')
                    mtu_option_data = options_data.get(OPTION_MTU)
                    if mtu_option_data:
                        LOG.info('Get mtu_option_data done:%s' % mtu_option_data)
                        mtu = struct.unpack('!H', mtu_option_data)[0]
                        set_network_adapter_mtu_hw(mac_address, mtu)
                    else:
                        LOG.info('Could not obtain the MTU configuration '
                                 'via DHCP for interface "%s"' % mac_address)
        except Exception as e:
            LOG.error("process network mtu failed:%s" % e)
            return False

        return True


def bring_up_interface_hw(ifphy_cfg_total, bond_cfg_total, viface_cfg_total):
    LOG.info("bring up interface start")

    LOG.info("bring up bond start")
    for bond_cfg in bond_cfg_total:
        ret = bring_up_bond_hw(ifphy_cfg_total, bond_cfg)
        if not ret:
            LOG.error("bring up bond failed.")
            return False
    LOG.info("bring up bond finish")

    for viface_cfg in viface_cfg_total:
        ret = bring_up_viface_hw(viface_cfg)
        if not ret:
            LOG.error("bring up bond vif failed.")
            return False
    LOG.info("bring up bond vif finish")

    return True


def process_network_hw():
    target_path = tempfile.mkdtemp()
    LOG.info("Log file is: %s", logfile)

    ret, network_json = get_network_json_hw(target_path)
    if not ret:
        LOG.error("Get network_json failed, network json is %s", network_json)
        return False
    LOG.info("Get network_json success , network json is %s", network_json)

    ret, serlist = handle_services_hw(network_json)
    if not ret:
        LOG.error("Handle_services failed, service list is %s", serlist)
    LOG.info("Handle_services success, service list is %s", serlist)

    ret, netlist = handle_network_hw(network_json)
    if not ret:
        LOG.error("Handle_network failed, network list is %s", netlist)
        return False
    LOG.info("Handle_network success, network list is %s", netlist)

    ret, links = handle_links_hw(network_json)
    if not ret:
        LOG.error("Handle_links failed, link is %s", links)
        return False
    LOG.info("Handle_links success, link is %s", links)

    ret, ifphy_cfg_total = apply_phy_hw(links)
    if not ret:
        LOG.error("Apply phy information failed")
        return False
    LOG.info("Apply phy information success")

    ret, ifbond_cfg_total = apply_bond_hw(links, netlist)
    if not ret:
        LOG.error("Apply bond failed")
        return False
    LOG.info("Apply bond success")

    ret, ifvif_cfg_total = apply_vlanif_hw(links, netlist)
    if not ret:
        LOG.error("Apply vlan failed")
        return False
    LOG.info("Apply vlan success")

    ret = bring_up_interface_hw(ifphy_cfg_total, ifbond_cfg_total, ifvif_cfg_total)
    if not ret:
        LOG.error("Bring up interface failed")
        return False
    LOG.info("Bring up interface success")

    ret = set_interface_mtu_hw()
    if not ret:
        LOG.error("set interface mtu failed")
        #return False
    LOG.info("set interface mtu success.")

    return True


def main():
    try:
        if config_get("NETWORK_CONFIG", "enable_bms_network", "True") == "True":
            ret = process_network_hw()
            if not ret:
                LOG.error("process network failed")
                return STATUS_ERR_RETRY_NEXT_REBOOT
            LOG.info("process network success")

            return STATUS_SUCCESS
    except Exception as e:
        LOG.error("process network failed:%s" % e)
        return STATUS_ERR_RETRY_NEXT_REBOOT

if __name__ == "__main__":
    bms_network_config_status = main()
    print(bms_network_config_status)
    sys.exit(bms_network_config_status)
