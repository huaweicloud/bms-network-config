#!/usr/bin/python3
import abc
import base64
import contextlib
import copy
import functools
import json
import logging
import os
import platform
import re
import shutil
import six
import sys
import tempfile
import time
import errno
import subprocess
import requests
from requests import exceptions
import configparser


SYS_CLASS_NET = "/sys/class/net/"
path = "/etc/sysconfig/network-scripts/"
TIME_OUT = 5
RETRY_NUM = 5
LEN_LINK_ADDR = 59
DHCLIENT_ID_PREFIX = "ff:00:00:00:00:00:02:00:00:02:c9:00:"
DHCPCLIENTCONFPATH = "/etc/dhcp/dhclient.conf"
HOSTNAMECONFPATH = "/etc/hostname"
UBUNTU_NETWORK_CONF_PATH = "/etc/network/interfaces.d/50-cloud-init.cfg"
FS_TYPES = ('vfat', 'iso9660')
LABEL_TYPES = ('config-2',)
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
REGEX = 'RTNETLINK answers: File exists'

KEY_COPIES = (
    ('local-hostname', 'hostname', False),
    ('instance-id', 'uuid', True),
)
PHY_CONF = ['bond-master', 'bond_miimon', 'bond_mode',
            'bond_xmit_hash_policy', 'mtu']

BOND_CONF = [ 'gateway', 'hwaddress', 'bond-slaves',
              'bond_miimon', 'bond_mode', 'bond_xmit_hash_policy', 'mtu']

VLAN_CONF = ['gateway', 'address', 'netmask',
             'hwaddress', 'mtu', 'vlan-raw-device', 'vlan-id']


BOND_TPL_OPTS = tuple([
    ('bond_mode', "mode=%s"),
    ('bond_xmit_hash_policy', "xmit_hash_policy=%s"),
    ('bond_miimon', "miimon=%s"),
])


CONF_FILE = '/opt/huawei/network_config/bms-network-config.conf'


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
            LOG.info("Modify conf successfully!")
            return True
    else:
        LOG.info("Config file not exist ! ")
        return False

LOG = logging.getLogger()
handler = logging.FileHandler("/var/log/network-config.log")
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


def is_partition_hw(device):
    if device.startswith("/dev/"):
        device_name = device[5:]
    return os.path.isfile("/sys/class/block/%s/partition" % device_name)


def find_devs_with_hw(criteria=None, oformat='device'):
    blkid_cmd = ['blkid']
    opt = []
    if criteria:
        opt.append("-t%s" % (criteria))

    if oformat:
        opt.append('-o%s' % (oformat))

    cmd = blkid_cmd + opt
    try:
        (out, _err) = subp_hw(cmd, rcs=[0, 2])
    except IOError as e:
        raise IOError('Fail to get result when execute the '
                      '%(cmd)s : %(e)s' % {'cmd': cmd, 'e': e})
    entries = []
    for lineinfo in out.splitlines():
        lineinfo = lineinfo.strip()
        if lineinfo:
            entries.append(lineinfo)
    return entries


def find_candidate_devs_hw():
    by_fs_t = []
    for fs_type in FS_TYPES:
        by_fs_t.extend(find_devs_with_hw("TYPE=%s" % fs_type))

    by_label_info = []
    for label in LABEL_TYPES:
        by_label_info.extend(find_devs_with_hw("LABEL=%s" % label))

    by_fs_t.sort(reverse=True)
    by_label_info.sort(reverse=True)

    candidates = (by_label_info + [d for d in by_fs_t if d not in by_label_info])

    devs = [d for d in candidates
            if d in by_label_info or not is_partition_hw(d)]
    return devs


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


def mount_cb_hw(device, callback, data=None, rw=False, mtype=None, sync=True):
    mtypes = None
    mount_point = None
    if isinstance(mtype, str):
        mtypes = [mtype]
    elif isinstance(mtype, (list, tuple)):
        mtypes = list(mtype)
    elif mtype is None:
        mtypes = None

    platsys = platform.system().lower()
    if platsys == "linux":
        if mtypes is None:
            mtypes = ["auto"]
    elif platsys.endswith("bsd"):
        if mtypes is None:
            mtypes = ['ufs', 'cd9660', 'vfat']
        for index, mtype in enumerate(mtypes):
            if mtype == "iso9660":
                mtypes[index] = "cd9660"
    else:
        mtypes = ['']
    mounted = mounts_hw()
    with tempdir_hw() as tmpd:
        umount = False
        if os.path.realpath(device) in mounted:
            mount_point = mounted[os.path.realpath(device)]['mountpoint']
        else:
            for mtype in mtypes:
                mount_point = None
                try:
                    mountcmd = ['mount']
                    mountopts = []
                    if rw:
                        mountopts.append('rw')
                    else:
                        mountopts.append('ro')
                    if sync:
                        mountopts.append("sync")
                    if mountopts:
                        mountcmd.extend(["-o", ",".join(mountopts)])
                    if mtype:
                        mountcmd.extend(['-t', mtype])
                    mountcmd.append(device)
                    mountcmd.append(tmpd)
                    subp_hw(mountcmd)
                    umount = tmpd
                    mount_point = tmpd
                    break
                except (IOError, OSError) as exc:
                    LOG.debug("Failed mount of '%s' as '%s': %s",
                              device, mtype, exc)
            if not mount_point:
                raise Exception('No found mountpoint')

        if not mount_point.endswith("/"):
            mount_point += "/"
        with unmounter_hw(umount):
            if data is None:
                ret = callback(mount_point)
            else:
                ret = callback(mount_point, data)
            LOG.info('end mount_cb')
            return ret


def read_config_drive_hw(source_dir):
    reader = ConfigDriveReaderHW(source_dir)
    finders_info = [(reader.read_v2_hw, [], {}),(reader.read_v1_hw, [], {}),]
    excps = []
    for (func, args, kwargs) in finders_info:
        try:
            return func(*args, **kwargs)
        except IOError as e:
            excps.append(e)
    raise excps[-1]


@contextlib.contextmanager
def unmounter_hw(umount):
    try:
        yield umount
    finally:
        if umount:
            umount_cmd_info = ["umount", umount]
            subp_hw(umount_cmd_info)


def mounts_hw():
    mounted = {}
    try:
        if os.path.exists("/proc/mounts"):
            mount_locs_info = load_file_hw("/proc/mounts").splitlines()
            method_cmd = 'proc'
        else:
            (mountoutput, _err) = subp_hw("mount")
            mount_locs_info = mountoutput.splitlines()
            method_cmd = 'mount'
        mountre = r'^(/dev/[\S]+) on (/.*) \((.+), .+, (.+)\)$'
        for mpline in mount_locs_info:
            try:
                if method_cmd == 'proc':
                    (dev, mp, fstype, opts, _freq, _passno) = mpline.split()
                else:
                    m = re.search(mountre, mpline)
                    dev = m.group(1)
                    mp = m.group(2)
                    fstype = m.group(3)
                    opts = m.group(4)
            except Exception:
                continue
            mp = mp.replace("\\040", " ")
            mounted[dev] = {
                'fstype': fstype,
                'mountpoint': mp,
                'opts': opts,
            }
            LOG.debug("Fetched info %s mounts from %s", mounted, method_cmd)
    except (IOError, OSError) as e:
        LOG.warning("Failed fetching mount points is: %s", e)
    return mounted


@contextlib.contextmanager
def tempdir_hw(**kwargs):
    tdir = tempfile.mkdtemp(**kwargs)
    try:
        yield tdir
    finally:
        shutil.rmtree(tdir)


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


def get_network_json_hw():
    results = {}
    found = None
    for dev in find_candidate_devs_hw():
        try:
            if dev.startswith("/dev/cd"):
                mtype = "cd9660"
                sync = False
            else:
                mtype = None
                sync = True
            results = mount_cb_hw(dev, read_config_drive_hw, mtype=mtype, sync=sync)
            found = dev
        except IOError:
            LOG.info('Broken config drive: %s' % dev)
        if found:
            break
    if not found:
        LOG.error('No found network metadata')
        return False, []
    network_json = results.get('networkdata', {})

    return True, network_json


def load_file_hw(fname, read_cb=None, quiet=False, decode=True):
    LOG.debug("Reading from %s (quiet=%s)", fname, quiet)
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
    LOG.debug("Read %s bytes from %s", len(contents), fname)
    if decode:
        return decode_binary_hw(contents)
    else:
        return contents


def read_sys_net_hw(devname, path, translate=None,
                    on_enoent=None, on_keyerror=None,
                    on_einval=None):
    dev_path = sys_dev_path_hw(devname, path)
    try:
        contents_info = load_file_hw(dev_path)
    except (OSError, IOError) as e:
        e_errno = getattr(e, 'errno', None)
        if e_errno in (errno.ENOENT, errno.ENOTDIR):
            if on_enoent is not None:
                return on_enoent(e)
        if e_errno in (errno.EINVAL,):
            if on_einval is not None:
                return on_einval(e)
        raise
    contents_info = contents_info.strip()
    if translate is None:
        return contents_info
    try:
        return translate[contents_info]
    except KeyError as e:
        if on_keyerror is not None:
            return on_keyerror(e)
        else:
            LOG.debug("Found unexpected (not translatable) value"
                      " '%s' in '%s", contents_info, dev_path)
            raise


def read_sys_net_safe_hw(iface, field, translate=None):
    def on_excp_false(e):
        return False
    return read_sys_net_hw(iface, field,on_keyerror=on_excp_false,
                           on_enoent=on_excp_false,on_einval=on_excp_false,
                           translate=translate)


def get_devicelist_hw():
    return os.listdir(SYS_CLASS_NET)


def sys_dev_path_hw(devname, path=""):
    return SYS_CLASS_NET + devname + "/" + path


def get_interface_mac_hw(ifname):
    path_info = "address"
    if os.path.isdir(sys_dev_path_hw(ifname, "bonding_slave")):
        path_info = "bonding_slave/perm_hwaddr"
    return read_sys_net_safe_hw(ifname, path_info)


def is_up_hw(devname):
    translate = {'up': True, 'unknown': True, 'down': False}
    return read_sys_net_safe_hw(devname, "operstate", translate=translate)


def _get_current_rename_info_hw(check_downable=True):
    names_info = get_devicelist_hw()
    by_mac = {}
    for n in names_info:
        by_mac[get_interface_mac_hw(n)] = {'name': n, 'up': is_up_hw(n), 'downable': None}

    if check_downable:
        nmatch = re.compile(r"[0-9]+:\s+(\w+)[@:]")
        ipv6, _err = subp_hw(['ip', '-6', 'addr', 'show', 'permanent', 'scope', 'global'], capture=True)
        ipv4, _err = subp_hw(['ip', '-4', 'addr', 'show'], capture=True)

        nics_with_addresses = set()
        for bytes_out in (ipv6, ipv4):
            nics_with_addresses.update(nmatch.findall(bytes_out))

        for d in by_mac.values():
            d['downable'] = (d['up'] is False or d['name'] not in nics_with_addresses)

    return by_mac


def _rename_interfaces_hw(renames, strict_present=True, strict_busy=True, current_info=None):
    if not len(renames):
        LOG.debug("no interfaces to rename")
        return False

    if current_info is None:
        current_info = _get_current_rename_info_hw()

    cur_bymac = {}
    for mac, data in current_info.items():
        cur = data.copy()
        cur['mac'] = mac
        cur_bymac[mac] = cur

    def update_byname_hw(bymac):
        return dict((data['name'], data) for data in bymac.values())

    def rename(cur, new):
        subp_hw(["ip", "link", "set", cur, "name", new], capture=True)

    def down(name):
        subp_hw(["ip", "link", "set", name, "down"], capture=True)

    def up(name):
        subp_hw(["ip", "link", "set", name, "up"], capture=True)

    ops = []
    errors = []
    ups = []
    cur_byname = update_byname_hw(cur_bymac)
    tmpname_fmt = "cirename%d"
    tmpi = -1

    for mac, new_name in renames:
        cur = cur_bymac.get(mac, {})
        cur_name = cur.get('name')
        cur_ops = []
        if cur_name == new_name:
            continue

        if not cur_name:
            if strict_present:
                errors.append("[nic not present] Cannot rename mac=%s to %s" ", not available." % (mac, new_name))
            continue

        if cur['up']:
            msg = "[busy] Error renaming mac=%s from %s to %s"
            if not cur['downable']:
                if strict_busy:
                    errors.append(msg % (mac, cur_name, new_name))
                continue
            cur['up'] = False
            cur_ops.append(("down", mac, new_name, (cur_name,)))
            ups.append(("up", mac, new_name, (new_name,)))

        if new_name in cur_byname:
            target = cur_byname[new_name]
            if target['up']:
                msg = "[busy-target] Error renaming mac=%s from %s to %s."
                if not target['downable']:
                    if strict_busy:
                        errors.append(msg % (mac, cur_name, new_name))
                    continue
                else:
                    cur_ops.append(("down", mac, new_name, (new_name,)))

            tmp_name = None
            while tmp_name is None or tmp_name in cur_byname:
                tmpi += 1
                tmp_name = tmpname_fmt % tmpi

            cur_ops.append(("rename", mac, new_name, (new_name, tmp_name)))
            target['name'] = tmp_name
            cur_byname = update_byname_hw(cur_bymac)
            if target['up']:
                ups.append(("up", mac, new_name, (tmp_name,)))

        cur_ops.append(("rename", mac, new_name, (cur['name'], new_name)))
        cur['name'] = new_name
        cur_byname = update_byname_hw(cur_bymac)
        ops += cur_ops

    opmap = {'rename': rename, 'down': down, 'up': up}

    if len(ops) + len(ups) == 0:
        if len(errors):
            LOG.debug("unable to do any work for renaming of %s", renames)
        else:
            LOG.debug("no work necessary for renaming of %s", renames)
    else:
        LOG.debug("achieving renaming of %s with ops %s", renames, ops + ups)

        for op, mac, new_name, params in ops + ups:
            try:
                opmap.get(op)(*params)
            except Exception as e:
                errors.append(
                    "[unknown] Error performing %s%s for %s, %s: %s" %
                    (op, params, mac, new_name, e))

    if len(errors):
        raise Exception('\n'.join(errors))

    return True


def apply_network_config_names_hw(ifphy_cfg_total):
    if not ifphy_cfg_total:
        LOG.error("Not found phy config")
        return False

    renames = []
    for ifphy_cfg in ifphy_cfg_total:
        mac = ifphy_cfg.get('hwaddress')
        name = ifphy_cfg.get('auto')
        if not mac:
            continue
        renames.append([mac, name])
    return _rename_interfaces_hw(renames)


def write_phy_conf_hw(ifphy_cfg_total):
    index = 1
    for ifphy_cfg in ifphy_cfg_total:
        try:
            if index == 1:
                phy_file = open(UBUNTU_NETWORK_CONF_PATH, 'w+')
            else:
                phy_file = open(UBUNTU_NETWORK_CONF_PATH, 'a')
        except:
            LOG.error("Can't create config file")
            return False

        try:
            phy_file.write('auto ' + ifphy_cfg.get('auto') + '\n')
            phy_file.write('iface ' + ifphy_cfg.get('iface') + '\n')
            for key, value in ifphy_cfg.items():
                if (key in PHY_CONF) and value:
                    phy_file.write(key + ' ' + value + '\n')
            phy_file.write('\n')
        except:
            LOG.error("Can't write config file")
            return False
        finally:
            index += 1
            phy_file.close()
    return True


def write_bond_conf_hw(iface_cfg_total):
    for iface_cfg in iface_cfg_total:
        try:
            iface_cfg_file = open(UBUNTU_NETWORK_CONF_PATH, 'a')
        except Exception as e:
            LOG.error("Can't open file %s: %s" % (UBUNTU_NETWORK_CONF_PATH, e))
            return False

        try:
            iface_cfg_file.write('auto ' + iface_cfg.get('auto') + '\n')
            iface_cfg_file.write('iface ' + iface_cfg.get('iface') + '\n')
            for key, value in iface_cfg.items():
                if (key in BOND_CONF) and value:
                    iface_cfg_file.write(key + ' ' + value + '\n')
            iface_cfg_file.write('\n')
        except Exception as e:
            LOG.error("Can't write config file %s: %s" % (UBUNTU_NETWORK_CONF_PATH, e))
            return False

        finally:
            iface_cfg_file.close()
            os.chmod(UBUNTU_NETWORK_CONF_PATH, 0o644)

    return True


def write_vlanif_conf_hw(viface_cfg_total):
    for viface_cfg in viface_cfg_total:
        try:
            viface_cfg_file = open(UBUNTU_NETWORK_CONF_PATH, 'a')
        except Exception as e:
            LOG.error("Can't open file %s: %s" % (UBUNTU_NETWORK_CONF_PATH, e))
            return False

        try:
            viface_cfg_file.write('auto ' + viface_cfg.get('auto') + '\n')
            viface_cfg_file.write('iface ' + viface_cfg.get('iface') + '\n')
            for key, value in viface_cfg.items():
                if (key in VLAN_CONF) and value:
                    viface_cfg_file.write(key + ' ' + value + '\n')
            viface_cfg_file.write('\n')
        except Exception as e:
            LOG.error("Can't write config file %s: %s" % (UBUNTU_NETWORK_CONF_PATH, e))
            return False

        finally:
            viface_cfg_file.close()
            os.chmod(UBUNTU_NETWORK_CONF_PATH, 0o644)

    return True


def apply_phy_hw(links, netlist):
    if not links:
        LOG.error("Not found links' info")
        return False, []
    if not netlist:
        LOG.error("Not found networks' info")
        return False, []

    ifphy_cfg_total = []
    for linkdic in links:
        if linkdic.get('type', None) == 'phy' and\
                linkdic.get('ethernet_mac_address', None) and\
                linkdic.get('id', None):
            ifphy_cfg = {}
            ifphy_cfg['auto'] = linkdic.get('id', None)
            ifphy_cfg['iface'] = "%s %s %s" % (linkdic.get('id', None), 'inet', 'manual')
            if linkdic.get('mtu', None):
                ifphy_cfg['mtu'] = str(linkdic.get('mtu', None))
            else:
                ifphy_cfg['mtu'] = ''
            ifphy_cfg['hwaddress'] = linkdic.get('ethernet_mac_address', None)
            ifphy_cfg_total.append(ifphy_cfg)

    if not ifphy_cfg_total:
        LOG.error("Phy apply failed")
        return False, []
    return True, ifphy_cfg_total


def render_phy_config_hw(bond_info, ifphy_cfg_total):
    ifphy_cfg_total_render = []

    for ifphy_cfg in ifphy_cfg_total:
        for bonddic in bond_info:
            if ifphy_cfg['auto'] in bonddic['bond_link']:
                ifphy_cfg['bond-master'] = bonddic['auto']
                ifphy_cfg['bond_miimon'] = str(bonddic['bond_miimon'])
                ifphy_cfg['bond_mode'] = bonddic['bond_mode']
                ifphy_cfg['bond_xmit_hash_policy'] = bonddic['bond_xmit_hash_policy']
                ifphy_cfg_total_render.append(ifphy_cfg)
            else:
                continue

    if not ifphy_cfg_total_render:
        LOG.error("Phy render failed")
        return False, []

    return True, ifphy_cfg_total_render


def apply_bond_hw(link_info, network_info, ifphy_cfg_total):
    iface_cfg_total = []
    iface_cfg_info_total = []
    index = 0

    for linkdic in link_info:
        iface_cfg_info_total += linkdic.values()
    for linkdic in link_info:
        if linkdic.get('type', None) == 'bond' and\
                linkdic.get('ethernet_mac_address', None) and\
                linkdic.get('bond_links', None) and\
                linkdic.get('id', None):
            bond_links = linkdic.get('bond_links', None)
            ethernet_mac_address = linkdic.get('ethernet_mac_address', None)
            if len(bond_links) < 1 or not mac_hw(ethernet_mac_address):
                LOG.error("Bond info error %s: %s" % (linkdic.get('id', None), " ".join(bond_links)))
                return False, []

            for bond_link in bond_links:
                if bond_link not in iface_cfg_info_total:
                    LOG.error("Bond info error %s: %s" % (linkdic.get('id', None), " ".join(bond_links)))
                    return False, []

            iface_cfg = {}
            bond_name = "%s%s" % ('bond', index)
            iface_cfg['auto'] = bond_name

            for networkdic in network_info:
                if networkdic.get('link', None) == linkdic.get('id', None):
                    if networkdic.get('type', None) == 'ipv4':
                        boot_proto = 'static'
                        iface_cfg['iface'] = "%s %s %s" % (bond_name, 'inet', boot_proto)
                        iface_cfg['address'] = networkdic.get('ip_address', None)
                        iface_cfg['netmask'] = networkdic.get('netmask', None)

                    else:
                        boot_proto = 'dhcp'
                        iface_cfg['iface'] = "%s %s %s" % (bond_name, 'inet', boot_proto)
                        iface_cfg['gateway'] = networkdic.get('gateway', None)
                else:
                    continue

            iface_cfg['hwaddress'] = ethernet_mac_address
            iface_cfg['bond-slaves'] = 'none'
            iface_cfg['bond_miimon'] = str(linkdic.get('bond_miimon', None))
            iface_cfg['bond_mode'] = linkdic.get('bond_mode', None)
            iface_cfg['bond_xmit_hash_policy'] = linkdic.get('bond_xmit_hash_policy', None)

            if linkdic.get('mtu', None):
                iface_cfg['mtu'] = str(linkdic.get('mtu', None))
            else:
                iface_cfg['mtu'] = ''
            iface_cfg['bond_link'] = bond_links
            iface_cfg['id'] = linkdic.get('id', None)
            index += 1
            iface_cfg_total.append(iface_cfg)

    ret, ifphy_cfg_total = render_phy_config_hw(iface_cfg_total, ifphy_cfg_total)
    if not ret:
        LOG.error("render ifphy_cfg failed")
    LOG.info("render ifphy_cfg success")

    return True, iface_cfg_total, ifphy_cfg_total


def apply_vlanif_hw(link_info, bond_info, network_info):
    viface_cfg_total = []
    for linkdic in link_info:
        if linkdic.get('type', None) == 'vlan' and\
            linkdic.get('ethernet_mac_address', None) and\
            linkdic.get('vlan_link', None) and\
            linkdic.get('vlan_id', None) and\
                linkdic.get('vlan_mac_address', None):
            vlan_id = linkdic.get('vlan_id', None)

            try:
                if int(vlan_id) < 1 or int(vlan_id) > 4096:
                    LOG.error("Vlan id %s is invalid for vlan link %s " %
                              (vlan_id, linkdic.get('id')))
                    return False, []
            except:
                LOG.error("Vlan id %s is not Interger for vlan link %s " %
                          (vlan_id, linkdic.get('id')))
                return False, []
            vlan_mac_address = linkdic.get('vlan_mac_address')
            ethernet_mac_address = linkdic.get('ethernet_mac_address')
            if not mac_hw(vlan_mac_address) or not mac_hw(ethernet_mac_address):
                LOG.error("MAC address  id %s is Invalid for vlan link %s" %
                          (vlan_mac_address, linkdic.get('id')))
                return False, []

            index = 0
            for bonddic in bond_info:
                if bonddic.get('id', None) == linkdic.get('vlan_link', None):
                    vlan_name = "%s.%s" % (bonddic.get('auto', None), vlan_id)
                    viface_cfg = {}
                    viface_cfg['auto'] = vlan_name
                    for networkdic in network_info:
                        if networkdic.get('link', None) == linkdic.get('id', None):
                            if networkdic.get('type', None) == 'ipv4':
                                boot_proto = 'static'
                                viface_cfg['iface'] = "%s %s %s" % (vlan_name, 'inet', boot_proto)
                                viface_cfg['address'] = networkdic.get('ip_address', None)
                                viface_cfg['netmask'] = networkdic.get('netmask', None)

                            else:
                                boot_proto = 'dhcp'
                                viface_cfg['iface'] = "%s %s %s" % (vlan_name, 'inet', boot_proto)
                                viface_cfg['gateway'] = networkdic.get('gateway', None)
                            viface_cfg['hwaddress'] = vlan_mac_address
                            if linkdic.get('mtu', None):
                                viface_cfg['mtu'] = str(linkdic.get('mtu', None))
                            else:
                                viface_cfg['mtu'] = ''
                            viface_cfg['vlan-raw-device'] = "%s%s" % ('bond', index)
                            viface_cfg['vlan_id'] = vlan_id

                            viface_cfg_total.append(viface_cfg)
                        else:
                            continue
                else:
                    continue
                index += 1

    return True, viface_cfg_total


def modprobe_bonding_hw():
    cmd = 'lsmod |grep bonding'
    (status, output) = subprocess.getstatusoutput(cmd)
    if status:
        cmd = 'modprobe bonding'
        (status, output) = subprocess.getstatusoutput(cmd)
        if status:
            LOG.error("modprobe bonding error, because %s" % output)
            return False
    return True


def modprobe_vlan_hw():
    cmd = 'lsmod |grep 8021q'
    (status, output) = subprocess.getstatusoutput(cmd)
    if status:
        cmd = 'modprobe 8021q'
        (status, output) = subprocess.getstatusoutput(cmd)
        if status:
            LOG.error("modprobe vlan error, because %s" % output)
            return False
    return True


def render_80_persistent_rules_hw(ifphy_cfg_total):
    cmd = "ip link |grep ether| awk '{print $2}'"
    persistant_file = "/etc/udev/rules.d/80-persistent-net.rules"

    mac_bond0 = []
    renames = []
    for ifphy_cfg in ifphy_cfg_total:
        mac = ifphy_cfg.get('hwaddress')
        name = ifphy_cfg.get('auto')
        if not mac:
            continue
        mac_bond0.append(mac)
        renames.append([mac, name])

    (status, output) = subprocess.getstatusoutput(cmd)
    LOG.info("get phy mac status is %s,output is %s" % (status, output))
    if status == 0:
        mac_infos = list(set(output.split('\n')).difference(set(mac_bond0)))
    if mac_infos:
        index = 2
        for mac in mac_infos:
            name = "eth%s" % index
            renames.append([mac, name])
            index += 1
    try:
        if os.path.exists(persistant_file):
            LOG.info("80-persistent-net file existed.")
            return True
        LOG.warning("80-persistent-net file does't exist,try to create a new one.")
        os.mknod(persistant_file)

    except Exception as e:
        LOG.error("Can't open file %s:%s" % (persistant_file, e))
        raise IOError
        return False

    render = Render()
    contents = []
    for macaddr, name in renames:
        content = render.generate_udev_rule_hw(name, macaddr)
        contents.append(content)
    try:
        per_file = open(persistant_file, 'w+')
    except Exception as e:
        LOG.error("Can't open file %s:%s" % (persistant_file, e))
        return False

    try:
        for conf in contents:
            per_file.write(conf)
    except Exception as e:
        LOG.error("Can't write file %s:%s" % (persistant_file, e))
        return False
    finally:
        per_file.close()
    os.chmod(persistant_file, 0o644)

    try:
        _rename_interfaces_hw(renames)
    except Exception as e:
        LOG.error("rename interfaces err: %" % e)
    return True


def render_network_config_hw(ifphy_cfg_total):
    persistant_file = "/etc/udev/rules.d/70-persistent-net.rules"
    if not ifphy_cfg_total:
        return False
    renames = []
    for ifphy_cfg in ifphy_cfg_total:
        mac = ifphy_cfg.get('hwaddress', None)
        name = ifphy_cfg.get('auto', None)
        if not mac:
            continue
        renames.append([mac, name])
    render = Render()
    contents = []
    for macaddr, name in renames:
        content = render.generate_udev_rule_hw(name, macaddr)
        contents.append(content)
    try:
        per_file = open(persistant_file, 'w+')
    except Exception as e:
        LOG.error("Can't open file %s:%s" % (persistant_file, e))
        return False

    try:
        for conf in contents:
            per_file.write(conf)
    except Exception as e:
        LOG.error("Can't write file %s:%s" % (persistant_file, e))
        return False
    finally:
        per_file.close()
    os.chmod(persistant_file, 0o644)

    if config_get("NETWORK_CONFIG", "enable_bms_udev_rules", "True") == "True":
        try:
            ret = render_80_persistent_rules_hw(ifphy_cfg_total)
            if not ret:
                LOG.error("render_80_persistent file failed.")
        except Exception as e:
            LOG.error("render_80_persistent file failed: %s", e)
    return True


class Render():
    def compose_udev_equality_hw(self, key, value):
        assert key == key.upper()
        return '%s=="%s"' % (key, value)

    def compose_udev_attr_equality_hw(self, attribute, value):
        assert attribute == attribute.lower()
        return 'ATTR{%s}=="%s"' % (attribute, value)

    def compose_udev_setting_hw(self, key, value):
        assert key == key.upper()
        return '%s="%s"' % (key, value)

    def generate_udev_rule_hw(self,interface, mac):
        rule = ', '.join([
            self.compose_udev_equality_hw('SUBSYSTEM', 'net'),
            self.compose_udev_equality_hw('ACTION', 'add'),
            self.compose_udev_equality_hw('DRIVERS', '?*'),
            self.compose_udev_attr_equality_hw('address', mac),
            self.compose_udev_setting_hw('NAME', interface),
        ])
        return '%s\n' % rule


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
            LOG.debug("Unable to read openstack versions from %s due to: "
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


def bring_up_interface_hw(phy_cfg_total, bond_cfg_total, viface_cfg_total):

    LOG.info("bring up phy start")
    for phy_cfg in phy_cfg_total:
        cmd = 'ifup ' + phy_cfg["auto"]
        subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        LOG.info("bring up phy begin")

    LOG.info("bring up bond start")
    for bond_cfg in bond_cfg_total:
        (status, output) = subprocess.getstatusoutput('/sbin/ifup ' + bond_cfg["auto"])
        if status != 0 or re.search(REGEX, output):
            LOG.error("Can't ifup interface %s,try again" % (bond_cfg["auto"]))
            (status, output) = subprocess.getstatusoutput('/bin/ps ax|grep dhclient|grep -v grep|grep '
			                                            + bond_cfg["auto"])
            if status == 0:
                dhclient_infos = output.split('\n')
                for dhclient_info in dhclient_infos:
                    subprocess.getstatusoutput('/bin/kill -s 9 ' + dhclient_info.split('?')[0])
            (status, output) = subprocess.getstatusoutput('/sbin/ifup '+ bond_cfg["auto"])
            LOG.info("bring up bond status is %s,output is %s" % (status, output))
        time.sleep(10)
    LOG.info("bring up bond finish")

    for viface_cfg in viface_cfg_total:
        (status, output) = subprocess.getstatusoutput('/sbin/ifup ' + viface_cfg["auto"])
        if status != 0 or re.search(REGEX, output):
            LOG.error("Can't ifup interface %s,try again" % (viface_cfg["auto"]))
            (status, output) = subprocess.getstatusoutput('/bin/ps ax|grep dhclient|grep -v grep|'
                                                        'grep '+viface_cfg["auto"])
            if status == 0 and output:
                dhclient_infos = output.split('\n')
                for dhclient_info in dhclient_infos:
                    subprocess.getstatusoutput('kill -s 9 ' + dhclient_info.split('?')[0])
            (status, output) = subprocess.getstatusoutput('/sbin/ifup ' + viface_cfg["auto"])
            LOG.info("bring up bond vif status is %s,output is %s" % (status,output))

        cmd = 'ip link set dev ' + viface_cfg["auto"] + ' mtu ' + viface_cfg["mtu"]
        (status, output) = subprocess.getstatusoutput(cmd)
        LOG.info("ip link set mtu . status,output=(%s,%s)" % (status, output))

        time.sleep(10)
    LOG.info("bring up bond vif finish")

    (status, output) = subprocess.getstatusoutput('sysctl -w net.ipv4.conf.all.rp_filter=2')
    LOG.info("sysctl rp_filter status is %s, output is %s" % (status, output))

    return True


class UrlError(IOError):
    def __init__(self, cause, code=None, headers=None, url=None):
        IOError.__init__(self, str(cause))
        self.cause = cause
        self.code = code
        self.headers = headers
        if self.headers is None:
            self.headers = {}
        self.url = url


def readurl(url, timeout=None, retries=0, sec_between=1,
            check_status=True):

    manual_tries = 1
    if retries:
        manual_tries = max(int(retries) + 1, 1)

    if sec_between is None:
        sec_between = -1

    excps = []
    for i in range(0, manual_tries):
        try:
            LOG.debug("[%s/%s] open '%s' ", i,
                      manual_tries, url)
            r = requests.get(url, timeout=timeout)
            if check_status:
                r.raise_for_status()
            LOG.debug("Read from %s (%s, %sb) after %s attempts", url,
                      r.status_code, len(r.content), (i + 1))
            return r
        except exceptions.RequestException as e:
            if (isinstance(e, (exceptions.HTTPError)) and
               hasattr(e, 'response') and
               hasattr(e.response, 'status_code')):
                excps.append(UrlError(e, code=e.response.status_code,
                                      headers=e.response.headers,
                                      url=url))
            else:
                excps.append(UrlError(e, url=url))
            if i + 1 < manual_tries and sec_between > 0:
                LOG.debug("Please wait %s seconds while we wait to try again",
                          sec_between)
                time.sleep(sec_between)
    if excps:
        raise excps[-1]
    return None


def get_meta_json_hw(timeout=5, retries=5):
    try:
        metadata_url = 'http://169.254.169.254/openstack/latest/meta_data.json'
        resp = readurl(url=metadata_url,
                       timeout=timeout,
                       retries=retries)
        metadata = resp.json()

    except Exception as e:
        LOG.error("Get metadata from metadata server %s failed. Error: %s", metadata_url, e)
        return False, None

    return True, metadata


def handle_hostname_hw(meta_json):
    hostname = meta_json.get('hostname', None).split('.')[0]
    if not hostname:
        LOG.error("Get hostname' info failed")
        return False, None
    return True, hostname


def apply_hostname_hw(hostname):
    if not hostname:
        LOG.error("Not found hostname' info")
        return False, None
    hostname_cfg = {}
    hostname_cfg['HOSTNAME'] = hostname
    if not hostname_cfg:
        LOG.error("hostname apply failed")
        return False, []
    return True, hostname_cfg


def write_hostname_hw(hostname_cfg):
    path = HOSTNAMECONFPATH
    try:
        hostname_file = open(path, 'w+')
    except:
        LOG.error("Open file Error:%s" % path)
        raise IOError
        return False

    try:
        hostname_file.write(hostname_cfg['HOSTNAME'] + '\n')
    except:
        LOG.error("Write phy conf Error:%s,%s" % ('HOSTNAME', hostname_cfg['HOSTNAME']))
        raise IOError
        return False
    finally:
        hostname_file.close()
        LOG.info("Write file %s Done" % (path))

    cmd = 'hostname %s' % hostname_cfg['HOSTNAME']
    (status, output) = subprocess.getstatusoutput(cmd)
    if status:
        LOG.error("Failed to set hostname, because %s" % output)
        return False

    return True


def write_hosts_hw(hostname_cfg):
    try:
        cmd = ('sed' + ' -i' + ' 1s/localhost/' + hostname_cfg['HOSTNAME'] + '/' + ' /etc/hosts')
        (status, output) = subprocess.getstatusoutput(cmd)
        if status:
            LOG.error("Failed to set hosts,because:%s", output)
            return False

    except Exception as e:
        LOG.error("Open file Error:%s:%s" % (path, e))
        raise IOError
        return False

    return True


def process_metadata():
    ret, meta_json = get_meta_json_hw(TIME_OUT, RETRY_NUM)
    if not ret:
        LOG.error("Get meta_json failed, metadata json is %s", meta_json)
        return False
    LOG.info("Get meta_json susess, metadata json is %s", meta_json)

    ret, hostname = handle_hostname_hw(meta_json)
    if not ret:
        LOG.error("Handle_hostname failed, hostname is %s", hostname)
        return False
    LOG.info("Handle_hostname success, hostname is %s", hostname)

    ret, hostname_cfg = apply_hostname_hw(hostname)
    if not ret:
        LOG.error("Apply hostname information failed")
        return False
    LOG.info("Apply hostname information success")

    ret = write_hostname_hw(hostname_cfg)
    if not ret:
        LOG.error("Write hostname config failed")
        return False
    LOG.info("Write hostname config success")

    ret = write_hosts_hw(hostname_cfg)
    if not ret:
        LOG.error("Write hosts config failed")
        return False
    LOG.info("Write hosts config success")

    return True


def get_dhcpclient_identifier_hw():
    (status, output) = subprocess.getstatusoutput("ip link show ib0 | grep infiniband | grep -v grep | awk  '{print$2}' ")
    if not status:
        if len(output) == LEN_LINK_ADDR:
            guid = output[36:]
        else:
            LOG.error("the length of link_address is not corret" )
            return False, None
    else:
        LOG.error("get link_address failed,because: %s" % output)
        return False, None
    dhcp_client_id = DHCLIENT_ID_PREFIX + guid
    return True, dhcp_client_id


def write_dhclient_conf_hw(dhclient_id):
    path = DHCPCLIENTCONFPATH
    try:
        if not os.path.exists(DHCPCLIENTCONFPATH):
            LOG.warning("dhclient config file does't exist,try to create a new one.")
            os.mknod(DHCPCLIENTCONFPATH)

        dhclient_file = file(path, 'w+')
    except:
        LOG.error("Open file Error:%s" % path)
        raise IOError
        return False

    try:
        dhclient_file.write('interface "ib0" { ' + '\n' + 'send dhcp-client-identifier ' + dhclient_id + ';' + '\n' + '}')
    except:
        LOG.error("Write dhclient conf Error:%s,%s" % ('dhcp-client-identifier', dhclient_id))
        raise IOError
        return False

    finally:
        dhclient_file.close()
        LOG.info("Write file %s Done" % (path))

    (status, output) = subprocess.getstatusoutput('dhclient -cf ' + path + ' ib0')

    if status:
        LOG.error("Failed to allocate ip for ib0,because:%s", output)
        return False

    return True


def set_ib_interface_hw():
    ret, dhcpclient_id = get_dhcpclient_identifier_hw()
    if not ret:
        LOG.error("Get dhcpclient_id failed, dhcpclient_id is %s", dhcpclient_id)
        return False
    LOG.info("Get dhcpclient_id success, dhcpclient_id is %s", dhcpclient_id)

    ret = write_dhclient_conf_hw(dhcpclient_id)
    if not ret:
        LOG.error("Write dhclient config failed")
        return False
    LOG.info("Write dhclient config success")

    return True


def process_network_hw():
    ret, network_json = get_network_json_hw()
    if not ret:
        LOG.error("Get network_json failed, network json is %s", network_json)
        return False
    LOG.info("Get network_json success , network json is %s", network_json)

    ret, serlist = handle_services_hw(network_json)
    if not ret:
        LOG.error("Handle_services failed, service list is %s", serlist)
        #return False
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

    ret, ifphy_cfg_total = apply_phy_hw(links, netlist)
    if not ret:
        LOG.error("Apply phy information failed")
        return False
    LOG.info("Apply phy information success")

    try:
        ret = apply_network_config_names_hw(ifphy_cfg_total)
        if not ret:
            LOG.error("Rename interfaces failed")
            return False
    except Exception as e:
        LOG.error("Rename interfaces failed:%s" % e)
    LOG.info("Rename interfaces success")

    ret, ifbond_cfg_total, ifphy_cfg_total = apply_bond_hw(links, netlist, ifphy_cfg_total)
    if not ret:
        LOG.error("Apply bond failed")
        return False
    LOG.info("Apply bond success")

    ret, ifvif_cfg_total = apply_vlanif_hw(links, ifbond_cfg_total, netlist)
    if not ret:
        LOG.error("Apply vlan failed")
        return False
    LOG.info("Apply vlan success")

    ret = write_phy_conf_hw(ifphy_cfg_total)
    if not ret:
        LOG.error("Write network config failed")
        return False
    LOG.info("Write network config success")

    ret = write_bond_conf_hw(ifbond_cfg_total)
    if not ret:
        LOG.error("Write bond config failed")
        return False
    LOG.info("Write bond config success")

    ret = write_vlanif_conf_hw(ifvif_cfg_total)
    if not ret:
        LOG.error("Write vlan config failed")
        return False
    LOG.info("Write vlan config success")

    ret = render_network_config_hw(ifphy_cfg_total)
    if not ret:
        LOG.error("Render network config failed")
        return False
    LOG.info("Render network config success")

    ret = modprobe_bonding_hw()
    if not ret:
        LOG.error("Modprobe bond driver failed")
        return False
    LOG.info("Modprobe bond driver success")

    ret = modprobe_vlan_hw()
    if not ret:
        LOG.error("Modprobe vlan driver failed")
        return False
    LOG.info("Modprobe vlan driver success")

    ret = bring_up_interface_hw(ifphy_cfg_total, ifbond_cfg_total, ifvif_cfg_total)
    if not ret:
        LOG.error("Bring up interface failed")
        return False
    LOG.info("Bring up interface success")

    return True


def main():

    try:
        if config_get("NETWORK_CONFIG", "enable_bms_network", "True") == "True":
            ret = process_network_hw()
            if not ret:
                LOG.error("process network failed")
            else:
                LOG.info("process network success")

        if config_get("METADATA", "enable_preserve_hostname", "False") == "False":
            ret = process_metadata()
            if not ret:
                LOG.error("process metadata failed")
            else:
                LOG.info("process metadata success")

        ret = set_ib_interface_hw()
        if not ret:
            LOG.error("set ib interface failed")
        LOG.info("set ib interface success")

    except Exception as e:
        LOG.error("configure bms  failed:%s" % e)
    LOG.info("configure bms  success.")


if __name__ == "__main__":
    sys.exit(main())
