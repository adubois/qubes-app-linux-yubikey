#!/bin/bash

qvm-run --pass-io yubikey 'cat /home/user/yubikey/qubes-app-linux-yubikey/.libs/pam_qubes_yubico.so' > pam_qubes_yubikey.so
qvm-run --pass-io yubikey 'cat /home/user/yubikey/yubico-c/.libs/libyubikey.so.0.1.6' > libyubikey.so.0.1.6

sudo /bin/install pam_qubes_yubikey.so /lib64/security/pam_qubes_yubikey.so
sudo /bin/install libyubikey.so.0.1.6 /usr/lib64/libyubikey.so.0.1.6
sudo rm /usr/lib64/libyubikey.so.0
sudo ln -s /usr/lib64/libyubikey.so.0.1.6 /usr/lib64/libyubikey.so.0

PATH="/sbin:/bin:/usr/sbin:/usr/bin:/sbin" ldconfig -n /lib64/security
PATH="/sbin:/bin:/usr/sbin:/usr/bin:/sbin" ldconfig -n /usr/lib64
