qubes-app-linux-yubikey
=======================

Qubes Yubikey is a package offering to support Yubikey hardware 2 factor authentication through
a usbVM and a Dom0 PAM module.


Description
-----------

This package provides an easy way to integrate Yubikey hardware authentication
into your existing Qubes user authentication in order to mitigate the risk of
having someone or something snooping on your keyboard while you type your password.

It has been designed to be used with a USB AppVM to protect against USB based
attacks.

https://www.yubico.com/
https://www.qubes-os.org/


Introduction
------------

Qubes Yubikey is composed of a front-end which capture the Yubikey OTP,
of a back-end which makes the Yubikey OTP available for consuption in dom0 and of a
PAM Module which provide either 2 factors authentication by validating the Yubikey OTP
and a password, or single factor authentication as a backup to mitigate the risk of
loosing your Yubikey.

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
Yubikey front-end detects this event and transmit via the Qubes OS protocol qrexec
the OTP to Dom0. This behavior is to prevent you from forgetting your Yubikey in
the USB port.

The Qubes Yubikey back-end just take the OTP and store it in a file in Dom0.


Usage
-----

The Qubes Yubikey PAM module, will request for a Yubikey OTP and a Password.

First insert the Yubikey, press the button only once and remove the key. The
removal of the key will trigger the transmission of the OTP to Dom0.
Then, type your Yubikey associated password and hit enter.

If the password and OTP you entered are correct, you will be authenticated
successfully.

If the authentication fails, you can try to retype the password and press enter
as you may have done a typo.

Note: Do not generate a second OTP as you would expose yourself to hold and play
attacks. In this case the attacker would compromise your USB VM and retain the first
OTP until you issued a second one, at which time the attacker can send the first OTP,
holding the next valid one for when you are away. The attacker would also need to
learn your password either via a camera, a microphone or a motion detector.

Once you have typed the correct password, if the authentication fails, it is
assumed that the USB VM may be compromised and the OTP authentication method
locks itself out.

If you are not able to authenticate successfully following a Single Yubikey
Insert/KeyPress/Remove you must not leave your laptop unattended as a valid OTP
may have been held in the USB VM.
You must go to a secure location to authenticate with your Unix backup password.
Then check the value of last_login's first character.
If 0 check the password you set in the xscreensaver PAM configuration.
If the password is the one you typed you need to delete and recreate the USB VM
and re-install the front-end.
If 1 you will also need to 

Note that side channel attacks by sampling the USB port power current draw
directly or indirectly during OTP generation may be able to compromise the AES
(symetric) key stored in your Yubikey as well as the power-up counter.
This type of attacks have been demonstrated on USB hardware, however as of Feb 2014
such attack as not been publicly demonstrated on Yubikey.


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

The aim is that you will be able to install the package from Qubes repository.

Note: For the moment please refer to the section `Preparing the build` to prepare,
compile and install the package. The follow information is not yet application as
a rpm package is not yet defined.

First create a brand new USB AppVM. It is important that this VM is clean as
you are going to use it initially to configure your Yubikey and set its AES
symetric key.

On this new USB AppVM install the Yubico personalisation package:

~~~
sudo yum install ykpers
~~~

This package will install the Yubikey personalisation package to allow you to
configure the Yubikey.
This package will NOT be persisted after a reboot of the USB Ap-VM, which is
the desired behaviour as the USB AppVM may become compromised in the future.

Once personalisation is done, you can destroy the USB VM and create a new one
(not mandatory but recommended to mitigate against potential personalisation
stalled data).

you can then install in the USB VM's template the following:

~~~
sudo dnf install qubes-yubikey-vm
~~~

And on dom0 install the Qubes Yubikey back-end and PAM modules:

~~~
sudo dnf install qubes-yubikey-dom0
~~~


Preparing the build
-------------------

Create a new AppVM (a DispVM is sufficient if you only want to build and install and
don't want to hack into the project).

Launch a terminal in this VM and install the following:

~~~
sudo yum install pam-devel gettext-devel git libtool libyubikey libyubikey-devel -y
sudo yum group install "Development Tools" 
git clone https://github.com/adubois/qubes-app-linux-yubikey.git
~~~

This will create a directory 'qubes-app-linux-yubikey'.

Generate the build system using:

~~~
cd qubes-app-linux-yubikey
libtoolize --install
autoreconf --install
~~~


Building
--------

The build system uses Autoconf, to set it up run:

~~~
./configure
~~~

Finally build the code, run the self-test and package the binaries:

~~~
make check
~~~

Post build installation
-----------------------

The front-end and back-end folders contains the files to be installed in the
USB VM and Dom0 respectively.

From Dom0, you can pull the libraries and install them by calling pull_lib.sh


Qubes Yubikey personalisation
-----------------------------

Please refer to the ykpers module documentation. it is recommended that the AES
key you select is generated from a random source you trust.


Qubes Yubikey front-end configuration
-------------------------------------

No configuration required.


Qubes Yubikey back-end configuration
------------------------------------

No configuration required.


Qubes Yubikey PAM Module Configuration
--------------------------------------

You will need to configure the Qubes Yubikey PAM module for the xscreensaver
programs. In /etc/pam.d/, edit xscreensaver by adding the following line as the
first line:
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

~~~
touch /var/run/pam-debug.log
chmod go+w /var/run/pam-debug.log
~~~


Configuring last_login
----------------------

last_login stores the state of the last authentication if the form:
0:123:

The first value is:
- 0 when the OTP authentication method is not compromised.
- 1 when the OTP authentication method is compromised and locked.
Re-setting this value to 0 should only be done during initial configuration
with a new trusted USB VM.

The second value is the last Yubikey power-up counter.


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


Dependancies
------------

Qubes Yubikey has dependancies on libyubikey (yubikey.h, libyubikey.so) and
pam-devel (security/pam_appl.h, libpam.so) installed.

Get libyubikey from

  http://opensource.yubico.com/yubico-c/

It is also available in Fedora repository, so you can install it with:

~~~
yum install libyubikey libyubikey-devel
~~~

Please note that AES encryption/decryption is hard coded in this library. This
imply that a review of this code is recommended, particularly in the field of
side channel attacks (CPU L2 cache, power drain).
