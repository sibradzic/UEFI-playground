#!/usr/bin/env python3

#
# This sript is supposed to be able to check and fix "Vendor Hash File" found
# on some recent Lenovo ThinkPad UEFI ROMs. Vendor Hash File is special UEFI
# data module consisting a table of sha256 hashes of some of the FFSv2 UEFI
# volumes found within the same UEFI ROM image.
#
# Ealry in the UEFI boot process the actual sha256 hashes of FFSv2 volumes are
# being compared with values in the Vendor Hash File, and in case some manual
# changes in actual volumes the hashes will mismatch, resulting in boot failure
# (on a particular ThinkPad that I've seen this problem, turning the machine on
# results in black screen and a weird 'error code' melody being played)
#
# For latest version check https://github.com/sibradzic/UEFI-playground
#

import argparse
import binascii
import ctypes
import hashlib
import os
import stat
import sys
import urllib.request
from glob import glob
from shutil import rmtree
from zipfile import ZipFile

VENDOR_NAMEID = 'Phoenix hash file'
VENDOR_UUID = '389CC6F2-1EA8-467B-AB8A-78E769AE2A15'
GITHUB_PREFIX = 'https://github.com/LongSoft/UEFITool/releases/download/'
UEFITools_PLATFORM = 'linux_x86_64'
binaries = {
    'UEFIExtract': {
        'rel': 'NE_A57',
        'md5':  '7907c0416206183dc6e94944c05c07bb'
    },
    'UEFIReplace': {
        'rel': '0.28.0',
        'md5':  'a816ee512d76d5556761fc8749a29267'
    }
}


# Helper that returns a hash of a binary file
def file_hash(binfile, algo):
    hashfunc = getattr(hashlib, algo)
    h = hashfunc()
    with open(binfile, 'rb') as file:
        file = open(binfile, 'rb')
        while True:
            chunk = file.read(h.block_size)
            if not chunk:
                break
            h.update(chunk)

    return h.hexdigest()


# Helper for fetching UEFITools binaries
def get_binary(name, release, md5):
    full_url = GITHUB_PREFIX + release.lstrip('NE_') + '/' + name + '_' + \
               release + '_' + UEFITools_PLATFORM + '.zip'
    print('Downloading', full_url)
    urllib.request.urlretrieve(full_url, name + '.zip')
    print('Extracting', name + '.zip ...')
    zip = ZipFile(name + '.zip')
    zip.extractall()
    if file_hash(name, 'md5') == md5:
        os.chmod(name, stat.S_IRWXU)
        os.remove(name + '.zip')
    else:
        print(name, 'md5 sum does not match', md5)
        sys.exit(2)


parser = argparse.ArgumentParser(description='Lenovo ROM shenannigans')
parser.add_argument('inputrom', help='Input ROM file')
args = parser.parse_args()

# Get UEFITool binaries (unless they are already present in the working dir)
for binary in binaries:
    if not os.path.exists(binary):
        get_binary(binary, binaries[binary]['rel'], binaries[binary]['md5'])

# Complete extract of an input ROM file
print('Extracting', args.inputrom, 'into', args.inputrom + '.dump ...')
os.system('./UEFIExtract ' + args.inputrom + ' all')

print('Calculating sha256 hashes of FFSv2 folumes ...')
ffsv2_vols = {}
with open(args.inputrom + '.report.txt') as report:
    for line in report:
        if 'FFSv2' in line and 'N/A' not in line:
            entries = line.strip().split('|')
            baseaddr = entries[2].strip().lstrip('0')
            vol_uuid = entries[5].split('- ')[-1]
            glob_path_prefix = args.inputrom + '.dump/**/*' + vol_uuid
            all_dirs = glob(glob_path_prefix, recursive=True)
            match_ffsv2dir = None
            for ffsv2dir in all_dirs:
                with open(ffsv2dir + '/info.txt') as info:
                    for ln in info:
                        if 'Base' in ln:
                            base = ln.strip().split(': ')[-1].rstrip('h')
                            if base == baseaddr:
                                match_ffsv2dir = ffsv2dir
            if match_ffsv2dir:
                with open(match_ffsv2dir + '/header.bin', 'rb') as header, \
                        open(match_ffsv2dir + '/body.bin', 'rb') as body, \
                        open(match_ffsv2dir + '/full.bin', 'wb') as target:
                    target.write(header.read())
                    target.write(body.read())
                ffsv2sha256 = file_hash(match_ffsv2dir + '/full.bin', 'sha256')
                ffsv2_vols[baseaddr] = ffsv2sha256

vendor_path = glob(args.inputrom + '.dump/**/*' + VENDOR_NAMEID + '/',
                   recursive=True)[0]
vendor_hashfile = vendor_path + 'body.bin'

if vendor_hashfile:
    with open(vendor_hashfile, mode='rb') as file:
        hash_body_bytes = file.read()


# Classes defining C structure data in vendor hash table
class hash_header(ctypes.Structure):
    _fields_ = [
        ("signature", ctypes.c_char * 8),
        ("length",    ctypes.c_uint32)
    ]


headerbytes = bytearray(hash_body_bytes[:12])
header = hash_header.from_buffer(headerbytes)


class hash_record(ctypes.Structure):
    _fields_ = [
        ("hash",   ctypes.c_byte * 32),
        ("offset", ctypes.c_uint32),
        ("size",   ctypes.c_uint32)
    ]


class hash_struct(ctypes.Structure):
    _fields_ = [
        ("header",  hash_header),
        ("records", hash_record * header.length)
    ]


rwbytes = bytearray(hash_body_bytes)
hashes = hash_struct.from_buffer(rwbytes)

if hashes.header.signature == b'$HASHTBL':
    print(('Found valid vendor hash table with {} '
           'entries:').format(hashes.header.length))

fix_needed = False
for record in hashes.records:
    vendor_hash = str(binascii.hexlify(record.hash), 'utf-8')
    offset, size = record.offset, record.size
    hex_base = '{:X}'.format(offset)
    hex_size = '{:X}'.format(size)

    if hex_base in ffsv2_vols:
        real_hash = ffsv2_vols[hex_base]
        if real_hash == vendor_hash:
            print('FFSv2 volume @ {}h hash256 OK'.format(hex_base))
        else:
            print(('FFSv2 volume @ {}h hash256 mismatch! Overriding from '
                   '{} to {}').format(hex_base, vendor_hash, real_hash))
            hash_buff = bytearray(binascii.unhexlify(real_hash))
            record.hash = (ctypes.c_byte * 32).from_buffer(hash_buff)
            fix_needed = True

if fix_needed:
    with open(vendor_path + '/header.bin', 'rb') as header, \
         open('vendor_modified.bin', 'wb') as target:
        target.write(header.read())
        target.write(hashes)
    print('Replacing vendor hash module')
    os.system('./UEFIReplace ' + args.inputrom + ' ' + VENDOR_UUID +
              ' 01 vendor_modified.bin -asis')
    print('Fixed ROM image written as', args.inputrom + '.patched')

# cleanup
rmtree(args.inputrom + '.dump')
try:
    os.remove(args.inputrom + '.report.txt')
    os.remove('vendor_modified.bin')
except OSError:
    pass
