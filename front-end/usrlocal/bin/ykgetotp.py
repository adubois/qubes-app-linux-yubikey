#!/usr/bin/python
import struct
import time
import sys
import subprocess

infile_path = sys.argv[1]

#long int, long int, unsigned short, unsigned short, unsigned int
FORMAT = 'llHHI'
EVENT_SIZE = struct.calcsize(FORMAT)

#open file in binary mode
in_file = open(infile_path, "rb")

event = in_file.read(EVENT_SIZE)
key_map = {18: 'e', 19: 'r', 20: 't', 22: 'u', 23: 'i', 32: 'd', 33: 'f', 34: 'g', 35: 'h', 36: 'j', 37: 'k', 38: 'l', 46: 'c', 47: 'v', 48: 'b', 49: 'n'}
yubikey_otp = ""

while event:
    (tv_sec, tv_usec, type, code, value) = struct.unpack(FORMAT, event)

    if type == 1 and value == 1:
        if code == 28:
#            subprocess.call(["/usr/lib/qubes/qrexec_client_vm", "dom0", "qubes.2fa", "/bin/echo", yubikey_otp])
            f = open('/home/user/.yubikey','w')
            f.write(yubikey_otp[-32:])
            f.close
            print(yubikey_otp)
            yubikey_otp = ""
            break
        else:
            yubikey_otp = yubikey_otp + key_map[code]

    event = in_file.read(EVENT_SIZE)

in_file.close()
