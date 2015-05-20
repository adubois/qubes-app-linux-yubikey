Name:		qubes-yubikey-vm
Version:	%(cat version)
Release:	1%{?dist}
Summary:	Yubikey plugin for Qubes, VM package

Group:		System Environment/Libraries
License:	GPL
URL:		https://github.com/adubois/qubes-app-linux-yubikey

Requires:	qubes-core-vm

%define _builddir %(pwd)

%description
Module for Qubes OS to integrate Yubikey authentication through a USB VM

%prep
# we operate on the current directory, so no need to unpack anything
# symlink is to generate useful debuginfo packages
rm -f %{name}-%{version}
ln -sf . %{name}-%{version}
%setup -T -D

%build

%install
install -d $RPM_BUILD_ROOT/usr/lib/yubikey
install front-end/usrlocal/lib/yubikey/*.py $RPM_BUILD_ROOT/usr/lib/yubikey/

install -d $RPM_BUILD_ROOT%{_udevrulesdir}
sed -e 's:/local::g' front-end/config/udev/rules.d/99-qubes-usb-yubikey.rules > $RPM_BUILD_ROOT%{_udevrulesdir}/99-qubes-usb-yubikey.rules
chmod 644 $RPM_BUILD_ROOT%{_udevrulesdir}/99-qubes-usb-yubikey.rules

%clean
rm -rf $RPM_BUILD_ROOT

%files
%doc README.md COPYING AUTHORS
/usr/lib/yubikey/ykgetotp.py*
/usr/lib/yubikey/ykputotp.py*
%{_udevrulesdir}/99-qubes-usb-yubikey.rules

%changelog

