#!/bin/bash

XID=$(xinput | sed -n '/Yubico/s/^.*id=\([0-9]*\).*$/\1/Ip')
YKNODE=`xinput --list-props $XID | grep Node | awk -F'"' '{print $2}'`

echo Make sure that you have your Yubikey plugged into your USB port.
echo If this is the case you should get the dev input to which your
echo Yubikey is connected to below:
echo Yubikey_Node=$YKNODE
echo edit /rw/config/udev/rules.d/99-qubes-usb-yubikey.rules
echo and replace /dev/input/eventX with the Yubikey_Node value
