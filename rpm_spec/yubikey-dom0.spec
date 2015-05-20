Name:		qubes-yubikey-dom0
Version:	%(cat version)
Release:	1%{?dist}
Summary:	Yubikey plugin for Qubes, dom0 package

Group:		System Environment/Libraries
License:	GPL
URL:		https://github.com/adubois/qubes-app-linux-yubikey

BuildRequires:	libyubikey-devel
BuildRequires:	libtool
BuildRequires:	pam-devel
Requires:	 libyubikey

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
libtoolize -i
autoreconf -i
%configure --libdir=/%{_lib} \
           --with-pam-dir=/%{_lib}/security/
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
rm -f $RPM_BUILD_ROOT/%{_lib}/security/pam_qubes_yubico.la

%clean
rm -rf $RPM_BUILD_ROOT

%files
%doc NEWS README.md COPYING AUTHORS
/%{_lib}/security/pam_qubes_yubico.so
%{_mandir}/man8/pam_qubes_yubico.8.gz


%changelog

