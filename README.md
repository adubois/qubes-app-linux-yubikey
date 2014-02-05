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

The Qubes Yubikey PAM module, will request for a Yubikey OTP and a Password.

Insert the Yubikey, press the button and remove the key. This will intercept the
OTP in the USB VM and transmit it to Dom0. Then, type your Yubikey associated
password and hit enter.

If the password and OTP you entered are correct, you will be authenticated
successfully.

If the authentication fails, you can try to retype the password and press enter
as you may have done a typo.

Do not generate a new OTP as you would expose yourself to hold and play attacks.
The attacker could retain the first OTP until you issued a second one, at
which time the attacker can send the first one, holding the next valid token
for the next time you are away. This type of attacks would however only succeed
if you typed a wrong password while the USB VM decided to hold your OTP.

Once you have typed the correct password, if the authentication fails, it is
assumed that the USB VM is compromised and the authentication method locks
itself out.

It is assumed that if you are not able to authenticate successfully following a
Single Yubikey Insert/KeyPress/Remove you will not leave your laptop unattended.
You will go to a secure location to authenticate with your Unix password, delete
the USB VM, create a new one and re-install the Qubes PAM Yubikey front-end as
well as re-configure the PAM Yubikey module in Dom0.

It is important to be aware that side channel attacks for exemple by sampling
the USB port power current draw during OTP generation may be able to compromise
the AES key stored in your Yubikey as well as the power-up counter.
However this type of attack has so far not been publicly demonstrated.


Qubes Yubikey PAM module logic
------------------------------

First the PAM module will parse the password and make it available to other PAM
modules.
If the password is correct, the OTP will be read from the file the back-end
wrote. The OTP is then decrypted; its CRC checked; validation will be done to
ensure that the OTP was generated as the first button press after insertion in
the USB port and that the counter is the next consecutive value only.


Installation
------------

You can install the package from Qubes repository.

First create a brand new USB AppVM. It is important that this VM is clean as
you are going to use it initially to configure your Yubikey and set its AES
symetric key.

On this new USB AppVM install the Yubico personalisation package:
  $ sudo yum install ykpers
This package will install the Yubikey personalisation package to allow you to
configure the Yubikey.
This package will NOT be persisted after a reboot of the USB Ap-VM, which is
the desired behaviour as the USB AppVM may become compromised in the future.

Once personalisation is done, you can destroy the USB VM and create a new one
(not mandatory but recommended to mitigate against potential personalisation
stalled data).

you can then install in the USB VM's template the following:
  $ sudo yum install qubes-yubikey-vm

And on dom0 install the Qubes Yubikey back-end and PAM modules:
  $ sudo yum install qubes-yubikey-dom0


Qubes Yubikey personalisation
-----------------------------

Please refer to the ykpers module personalization module. it is recommended
that the AES key you select is generated from a random source you trust.


Qubes Yubikey front-end configuration
-------------------------------------

The USB port you will use to connect the Yubikey is configured to point to an
input device. In order to easily identify it:
- Insert the Yubikey in the port you will use in the future to authenticate and
  type:
  $ /usr/local/bin/ykinput.sh

And follow the instructions displayed on the screen to configure the Qubes
Yubikey front-end..


Qubes Yubikey back-end configuration
------------------------------------

TODO


Qubes Yubikey PAM Module Configuration
--------------------------------------

You will need to configure the Qubes Yubikey PAM module for the xscreensaver
programs. In /etc/pam.d/, edit xscreensaver by adding the following line as the first line:
  auth sufficient pam_qubes_yubikey.so pwd=mypassword aeskey=1234567890ABCDEF1234567890ABCDEF

To prevent from locking yourself out, You may want to try first to play with
setup (a program which require elevated privileges but that does not lock input
if you are not able to authenticate) and edit /etc/pam.d/setup. The following
may be the first line you may want to configure:
  auth sufficient pam_qubes-yubikey.so alwaysok debug pwd=mypassword aeskey=1234567890ABCDEF1234567890ABCDEF

Supported PAM module parameters are:

  "pwd":            The password used to authenticate in conjunction to the
                    Yubikey OTP. It is highly recommended that no correlation
                    exist between this password and the Unix system password.

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

If you are using "debug" you may find it useful to create a world-writable log
file:
  touch /var/run/pam-debug.log
  chmod go+w /var/run/pam-debug.log


Configuring last_login
----------------------

last_login stores the state of the last authentication if the form:
0:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:123:

The first value is:
- 0 when the OTP authentication method is not compromised.
- 1 when the OTP authentication method is compromised and locked.

The second value is the last OTP.

The third value is the last counter.


Feedback
--------

If you want to discuss anything related to Qubes Yubikey,
please e-mail the mailing list qubes-devel@googlegroups.com.


Source code
-----------

The development community is co-ordinated via Qubes's Git repository :

https://github.com/adubois/qubes-app-linux-yubikey.git

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

Please note that AES encryption/decryption is hard coded in this library. This
imply that a review of this code is recommended, particularly in the field of
side channel attacks (CPU L2 cache, power drain).


Preparing the build
-------------------

You may check out the sources using Git with the following command:
   $ mkdir ~/yubikey
   $ cd ~/yubikey
   $ git clone https://github.com/adubois/qubes-app-linux-yubikey.git

This will create a directory 'qubes-app-linux-yubikey'.

Autoconf, automake and libtool must be installed to create a compilable source
tree.

Generate the build system using:
   $ cd qubes-app-linux-yubikey
   $ autoreconf --install


Building
--------

The build system uses Autoconf, to set up the build system run:
  ./configure

Then build the code, run the self-test and install the binaries:
  make check


Post build installation
-----------------------

The front-end and back-end folders contains the files to be installed in the
USB VM and Dom0 respectively.

From Dom0, you can pull the libraries and install them by calling pull_lib.sh
