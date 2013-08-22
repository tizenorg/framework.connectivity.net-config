Name:       net-config
Summary:    TIZEN Network Configuration Module
Version:    0.1.90_27
Release:    1
Group:      System/Network
License:    Apache License Version 2.0
Source0:    %{name}-%{version}.tar.gz

BuildRequires:  cmake
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(dbus-glib-1)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(vconf)
BuildRequires:  pkgconfig(wifi-direct)
BuildRequires:  pkgconfig(tapi)
BuildRequires:  pkgconfig(syspopup-caller)
Requires(post): /usr/bin/vconftool
Requires:         systemd
Requires(post):   systemd
Requires(preun):  systemd
Requires(postun): systemd

%description
TIZEN Network Configuration Module

%prep
%setup -q


%build
cmake . -DCMAKE_INSTALL_PREFIX=%{_prefix}

make %{?_smp_mflags}


%install
%make_install

mkdir -p %{buildroot}%{_datadir}/dbus-1/services
cp resources/usr/share/dbus-1/services/net.netconfig.service %{buildroot}%{_datadir}/dbus-1/services/net.netconfig.service
mkdir -p %{buildroot}%{_sysconfdir}/dbus-1/system.d
cp resources/etc/dbus-1/system.d/net-config.conf %{buildroot}%{_sysconfdir}/dbus-1/system.d/net-config.conf
mkdir -p %{buildroot}/opt/etc
cp resources/opt/etc/resolv.conf %{buildroot}/opt/etc/resolv.conf
mkdir -p %{buildroot}%{_sysconfdir}/rc.d/init.d
cp resources/etc/rc.d/init.d/net-config %{buildroot}%{_sysconfdir}/rc.d/init.d/net-config
mkdir -p %{buildroot}%{_sysconfdir}/rc.d/rc3.d
ln -s ../init.d/net-config %{buildroot}%{_sysconfdir}/rc.d/rc3.d/S60net-config
mkdir -p %{buildroot}%{_sysconfdir}/rc.d/rc5.d
ln -s ../init.d/net-config %{buildroot}%{_sysconfdir}/rc.d/rc5.d/S60net-config

# Systemd service file
mkdir -p %{buildroot}%{_libdir}/systemd/system/
cp resources/usr/lib/systemd/system/net-config.service %{buildroot}%{_libdir}/systemd/system/net-config.service
mkdir -p %{buildroot}%{_libdir}/systemd/system/network.target.wants/
ln -s ../net-config.service %{buildroot}%{_libdir}/systemd/system/network.target.wants/net-config.service

#License
mkdir -p %{buildroot}%{_datadir}/license
cp LICENSE.APLv2 %{buildroot}%{_datadir}/license/net-config

#Rule file
mkdir -p %{buildroot}/opt/etc/smack/accesses.d
cp net-config.rule %{buildroot}/opt/etc/smack/accesses.d

%post

vconftool set -t int memory/dnet/state 0 -i
vconftool set -t int memory/wifi/state 0 -i
vconftool set -t int memory/wifi/transfer_state 0 -i
vconftool set -t int memory/wifi/strength 0 -i
vconftool set -t int memory/wifi/bgscan_mode 0 -i

vconftool set -t int memory/dnet/wifi 0 -i
vconftool set -t int memory/dnet/network_config 0 -i
vconftool set -t int memory/dnet/status 0 -i
vconftool set -t string memory/dnet/ip "" -i
vconftool set -t string memory/dnet/proxy "" -i

vconftool set -t string memory/wifi/connected_ap_name "" -i

vconftool set -t string db/wifi/bssid_address ""

#Default Call Statistics
vconftool set -t int db/dnet/statistics/cellular/totalsnt "0"
vconftool set -t int db/dnet/statistics/cellular/totalrcv "0"
vconftool set -t int db/dnet/statistics/cellular/lastsnt "0"
vconftool set -t int db/dnet/statistics/cellular/lastrcv "0"
vconftool set -t int db/dnet/statistics/wifi/totalsnt "0"
vconftool set -t int db/dnet/statistics/wifi/totalrcv "0"
vconftool set -t int db/dnet/statistics/wifi/lastsnt "0"
vconftool set -t int db/dnet/statistics/wifi/lastrcv "0"

vconftool set -t int file/private/wifi/last_power_state "0"

systemctl daemon-reload
if [ "$1" == "1" ]; then
    systemctl restart net-config.service
fi

%preun
if [ "$1" == "0" ]; then
    systemctl stop net-config.service
fi

%postun
systemctl daemon-reload
if [ "$1" == "1" ]; then
    systemctl restart net-config.service
fi

%files
%manifest net-config.manifest
/opt/etc/smack/accesses.d/net-config.rule
%{_sbindir}/*
%attr(644,root,root) /opt/etc/resolv.conf
%{_datadir}/dbus-1/services/*
%{_sysconfdir}/dbus-1/system.d/*
%{_sysconfdir}/rc.d/init.d/net-config
%{_sysconfdir}/rc.d/rc3.d/S60net-config
%{_sysconfdir}/rc.d/rc5.d/S60net-config
%{_libdir}/systemd/system/net-config.service
%{_libdir}/systemd/system/network.target.wants/net-config.service
%{_datadir}/license/net-config
