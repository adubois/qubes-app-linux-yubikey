qubes-app-linux-yubikey
=======================

Module for Qubes OS to integrate Yubikey authentication through a USB VM


Description
-----------

The Qubes Yubikey provides an easy way to integrate the Yubikey into your
existing Qubes user authentication in order to mitigate the risk of having
someone or something snooping on your keyboard while you type your password.

It has been designed to be used with a USB AppVM to protect against USB based
attacks.

http://www.yubico.com
http://www.qubes-os.org


Introduction
------------

Qubes Yubikey is composed of a front-end which capture the Yubikey OTP, of a
back-end which makes it available for consuption in dom0 and of a PAM Module
which validates the OTP. A password can also be configured to be part of your
credentials and mitigate the risk of getting your Yubikey lost or stolen.

To protect Dom0 from attacks via USB, a USB AppVM capturing all the PCI devices
on which USB controllers are connected must be configured (with possibly the
exception of the controller managing your keyboard and touchpad if you have such
hardware and no other USB devices are/can be connected to this USB controller).


Passing the OTP from the USB VM to dom0:
----------------------------------------

The Qubes Yubikey front-end has been designed to be installed in a USB AppVM.
After configuration, it will detect when you insert a Yubikey in your USB port.
You then have to press the Yubikey button once. The OTP is captured by the Qubes
Yubikey front-end. When you remove the Yubikey from the USB port, the Qubes
Yubikey front-end detects this event and transmit via qrexec the OTP to Dom0.
This behavior is to prevent you from forgetting your Yubikey in the USB port.

The Qubes Yubikey back-end just take the OTP and store it in a file in Dom0.


Usage
-----

The Qubes Yubikey PAM module, will request for a yubikey OTP and a Password.

Insert the Yubikey, press the button and remove the key, then, if you have
configured it, type your Yubikey associated password and hit enter.

If the OTP validation fails, the Qubes yubikey PAM module assumes that the USB
AppVM is compromised and will not accept further Yubikey authentication until
you clean the system up.

You can however still authenticate with your original Unix password from a
location where snooping is not a risk.


Qubes Yubikey PAM module logic
------------------------------

First the PAM module will parse the password and make it available to other PAM
modules.
If the password is correct, the OTP will be read from the file the back-end
wrote. The OTP is then decrypted; its CRC checked; validation will be done to
ensure that the OTP was generated as the first button press after insertion in
the USB port and that the counter is the next consecutive value only (to prevent
replay attacks).


Installation
------------

You can install the package from Qubes repository.

First create a brand new USB AppVM. It is important that this VM is clean as
you are going to use it initially to configure your Yubikey and set its AES
symetric key.

On this new USB AppVM (not its template) install the Qubes Yubikey front-end:
------
  $ sudo yum install qubes-app-linux-yubikey-front-end
------

This package will install:
- The Yubikey personalisation package to allow you to configure the Yubikey.
  This package will NOT be persisted after a reboot of the USB Ap-VM, which is
  the desired behaviour as the USB AppVM may become compromised in the future.
- The Qubes Yubikey front-end in /rw to ensure persistance after reboot of the
  USB AppVM.

On dom0 install the Qubes Yubikey back-end and PAM module:
------
  $ sudo yum install qubes-app-linux-yubikey-back-end
------


Qubes Yubikey front-end configuration
-------------------------------------

Once you have installed the Qubes Yubikey front-end package on a new USB VM...

The USB port you will use to connect the USB VM is configured to point to an
input device. In order to easily identify it,
- Insert the Yubikey in the port you will use in the future to authenticate
- type the following
------
/usr/local/bin/ykinput.sh
------
Replace the device value in the following file:
------
vi /rw/config/udev/rules.d/99-qubes-usb-yubikey.rules


Qubes Yubikey back-end configuration
------------------------------------

TODO


Qubes Yubikey PAM Module Configuration
--------------------------------------

You will need to configure the Qubes Yubikey PAM module for the login and xscreensaver programs. In /etc/pam.d/, edit xscreensaver by adding the following line as the first line:

------
  auth sufficient pam_qubes_yubikey.so alwaysok pwd=mypassword aeskey=1234567890ABCDEF1234567890ABCDEF
------

Supported PAM module parameters are:

  "pwd":            The password used to authenticate in conjunction to the
                    Yubikey OTP.

  "aeskey":         Your Yubikey key symetric AES key.

  "debug":          to enable debug output to stdout.

  "alwaysok":       to enable all authentication attempts to succeed
                    (aka presentation mode).

  "try_first_pass": Try to use the credentials passed by a previous PAM module
                    first. If the password is empty prompt the user to enter it.

  "use_first_pass": Use the credentials passed by a previous PAM module. If the
                    password is empty reject the authentication.

  "last_login_path": Path to the file last_login which store if the module has
                     detected a potentional compromise of the USB AppVM, the
                     last OTP and the last counter against which authentication
                     was successful.
                     Default is /var/yubikey/last_login

  "otp_path":        Path to the file where the Qubes Yubikey back-end writes
                     the OTP received from the USB AppVM and where the Qubes
                     Yubikey PAM module reads it.
                     Default is /var/yubikey/yubikey.otp

If you are using "debug" you may find it useful to create a
world-writable log file:
------
  touch /var/run/pam-debug.log
  chmod go+w /var/run/pam-debug.log
------


Feedback
--------

If you want to discuss anything related to Qubes Yubikey,
please e-mail the mailing list qubes-devel@googlegroups.com.


Source code
-----------

The development community is co-ordinated via Qubes's Git repository :

https://git.qubes-os.org/REPO/qubes-app-linux-yubikey/

The project is licensed under a BSD license.  See the file COPYING for
exact wording.  For any copyright year range specified as YYYY-ZZZZ in
this package note that the range specifies every single year in that
closed interval.


Build dependancies
------------------

Qubes Yubikey has dependancies on libyubikey (yubikey.h, libyubikey.so) and
pam-devel (security/pam_appl.h, libpam.so) installed.

Get libyubikey from

  http://opensource.yubico.com/yubico-c/


Preparing the build
-------------------

You may check out the sources using Git with the following command:
------
   $ git clone git@git.qubes-os.org:REPO/qubes-app-linux-yubikey/qubes-app-linux-yubikey.git qubes-app-linux-yubikey
------

This will create a directory 'qubes-app-linux-yubikey'.

Autoconf, automake and libtool must be installed to create a compilable source
tree.

Generate the build system using:
------
   $ cd qubes-app-linux-yubikey
   $ autoreconf --install
------


Building
--------

The build system uses Autoconf, to set up the build system run:
------
  ./configure
------

Then build the code, run the self-test and install the binaries:
------
  make check
  sudo make install
------

