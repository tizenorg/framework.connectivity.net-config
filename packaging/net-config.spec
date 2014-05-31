Name:       net-config
Summary:    TIZEN Network Configuration Module
Version:    0.1.90_27
Release:    1
Group:      System/Network
License:    Apache License Version 2.0
Source0:    %{name}-%{version}.tar.gz

%if %{_repository} == "wearable"
BuildRequires:	cmake
BuildRequires:	pkgconfig(dlog)
BuildRequires:	pkgconfig(tapi)
BuildRequires:	pkgconfig(vconf)
BuildRequires:	pkgconfig(appsvc)
BuildRequires:	pkgconfig(glib-2.0)
BuildRequires:	pkgconfig(dbus-glib-1)
BuildRequires:	pkgconfig(notification)
BuildRequires:	pkgconfig(alarm-service)
BuildRequires:	pkgconfig(syspopup-caller)
BuildRequires:  pkgconfig(capi-appfw-application)
Requires:		sed
Requires:		systemd
Requires:		vconf
Requires(post):		systemd
Requires(post):		vconf
Requires(preun):	systemd
Requires(postun):	systemd
%else
BuildRequires:  cmake
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(dbus-glib-1)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(vconf)
BuildRequires:  pkgconfig(wifi-direct)
BuildRequires:  pkgconfig(tapi)
BuildRequires:  pkgconfig(syspopup-caller)
Requires(post): /usr/bin/vconftool
BuildRequires:    pkgconfig(libsystemd-daemon)
%{?systemd_requires}
%endif

%description
TIZEN Network Configuration Module

%prep
%setup -q

%build
%if %{_repository} == "wearable"
cd wearable
%cmake -DCMAKE_INSTALL_PREFIX=%{_prefix} \
%if 0%{?sec_product_feature_wlan_concurrent_mode} == 1
	-DWLAN_CONCURRENT_MODE=1 \
%endif

make %{?_smp_mflags}
%else
cd mobile
cmake . -DCMAKE_INSTALL_PREFIX=%{_prefix}

make %{?_smp_mflags}
%endif

%install
%if %{_repository} == "wearable"
cd wearable
%make_install

#Systemd service file
mkdir -p %{buildroot}%{_libdir}/systemd/system/
cp resources/usr/lib/systemd/system/net-config.service %{buildroot}%{_libdir}/systemd/system/net-config.service
mkdir -p %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants/
ln -s ../net-config.service %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants/net-config.service

mkdir -p %{buildroot}%{_datadir}/dbus-1/services/
cp resources/usr/share/dbus-1/services/net.netconfig.service %{buildroot}%{_datadir}/dbus-1/services/net.netconfig.service

mkdir -p %{buildroot}%{_sysconfdir}/
cp resources/etc/resolv.conf %{buildroot}%{_sysconfdir}/resolv.conf

mkdir -p %{buildroot}%{_sysconfdir}/wifi/
cp resources/etc/wifi/ccode.conf %{buildroot}%{_sysconfdir}/wifi/ccode.conf

mkdir -p %{buildroot}%{_sbindir}/
cp resources/usr/sbin/net-config.service %{buildroot}%{_sbindir}/net-config.service

mkdir -p %{buildroot}/opt/dbspace
sqlite3 %{buildroot}/opt/dbspace/.wifi_offload.db < resources/usr/share/wifi_offloading.sql

#DBus DAC (net-config.manifest enables DBus SMACK)
#mkdir -p %{buildroot}%{_sysconfdir}/dbus-1/system.d
#cp resources/etc/dbus-1/system.d/net-config.conf %{buildroot}%{_sysconfdir}/dbus-1/system.d/net-config.conf

#log dump
mkdir -p %{buildroot}/opt/etc/dump.d/module.d
cp resources/opt/etc/dump.d/module.d/network_log_dump.sh %{buildroot}/opt/etc/dump.d/module.d/network_log_dump.sh

#License
mkdir -p %{buildroot}%{_datadir}/license
cp LICENSE %{buildroot}%{_datadir}/license/net-config
cat LICENSE-FLORA >> %{buildroot}%{_datadir}/license/net-config
%else
cd mobile
%make_install

mkdir -p %{buildroot}%{_datadir}/dbus-1/services
cp resources/usr/share/dbus-1/services/net.netconfig.service %{buildroot}%{_datadir}/dbus-1/services/net.netconfig.service
mkdir -p %{buildroot}%{_sysconfdir}/dbus-1/system.d
cp resources/etc/dbus-1/system.d/net-config.conf %{buildroot}%{_sysconfdir}/dbus-1/system.d/net-config.conf
mkdir -p %{buildroot}/opt/etc
cp resources/opt/etc/resolv.conf %{buildroot}/opt/etc/resolv.conf

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
%endif

%post
%if %{_repository} == "wearable"
vconftool set -t int memory/dnet/state 0 -i -s system::vconf_network
vconftool set -t int memory/wifi/state 0 -i -s system::vconf_network
vconftool set -t int memory/wifi/transfer_state 0 -i -s system::vconf_network
vconftool set -t int memory/wifi/strength 0 -i -s system::vconf_network

vconftool set -t int memory/dnet/cellular 0 -i -s system::vconf_network
vconftool set -t int memory/dnet/wifi 0 -i -s system::vconf_network
vconftool set -t int memory/dnet/network_config 0 -i -s system::vconf_network
vconftool set -t int memory/dnet/status 0 -i -s system::vconf_network
vconftool set -t string memory/dnet/ip "" -i -s system::vconf_network
vconftool set -t string memory/dnet/proxy "" -i -s system::vconf_network

vconftool set -t string memory/wifi/connected_ap_name "" -i -s system::vconf_network

vconftool set -t string db/wifi/bssid_address "" -s system::vconf_network

#Default Call Statistics
vconftool set -t int db/dnet/statistics/cellular/totalsnt 0 -s system::vconf_network
vconftool set -t int db/dnet/statistics/cellular/totalrcv 0 -s system::vconf_network
vconftool set -t int db/dnet/statistics/cellular/lastsnt 0 -s system::vconf_network
vconftool set -t int db/dnet/statistics/cellular/lastrcv 0 -s system::vconf_network
vconftool set -t int db/dnet/statistics/wifi/totalsnt 0 -s system::vconf_network
vconftool set -t int db/dnet/statistics/wifi/totalrcv 0 -s system::vconf_network
vconftool set -t int db/dnet/statistics/wifi/lastsnt 0 -s system::vconf_network
vconftool set -t int db/dnet/statistics/wifi/lastrcv 0 -s system::vconf_network

#Wi-Fi last power state
vconftool set -t int file/private/wifi/last_power_state 0 -s system::vconf_network

#Wi-Fi power state due to airplane mode
vconftool set -t int file/private/wifi/wifi_off_by_airplane 0 -s system::vconf_network

#Wi-Fi power state due to restricted mode
vconftool set -t int file/private/wifi/wifi_off_by_restricted 0 -s system::vconf_network

#Wi-Fi power state due to emergency mode
vconftool set -t int file/private/wifi/wifi_off_by_emergency 0 -s system::vconf_network

#Wi-Fi sleep policy
vconftool set -t int file/private/wifi/sleep_policy 0 -g 6519 -s system::vconf_setting

#systemctl daemon-reload
#systemctl restart net-config.service

%else
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
%endif

%if %{_repository} == "wearable"
%preun
#systemctl stop net-config.service

%postun
#systemctl daemon-reload
%else
%preun
if [ "$1" == "0" ]; then
    systemctl stop net-config.service
fi

%postun
systemctl daemon-reload
if [ "$1" == "1" ]; then
    systemctl restart net-config.service
fi
%endif

%files
%if %{_repository} == "wearable"
%manifest wearable/net-config.manifest
%attr(500,root,root) %{_sbindir}/*
%attr(644,root,root) %{_sysconfdir}/resolv.conf
%attr(400,root,root) %{_sysconfdir}/wifi/ccode.conf
%attr(644,root,root) %{_datadir}/dbus-1/services/*
#DBus DAC
#%attr(644,root,root) %{_sysconfdir}/dbus-1/system.d/*
%attr(644,root,root) %{_libdir}/systemd/system/net-config.service
%attr(644,root,root) %{_libdir}/systemd/system/multi-user.target.wants/net-config.service
%{_datadir}/license/net-config
%attr(660,root,root) /opt/dbspace/.wifi_offload.db
%attr(664,root,root) /opt/dbspace/.wifi_offload.db-journal
%attr(544,root,root) /opt/etc/dump.d/module.d/network_log_dump.sh
%else
%manifest mobile/net-config.manifest
/opt/etc/smack/accesses.d/net-config.rule
%{_sbindir}/*
%attr(644,root,root) /opt/etc/resolv.conf
%{_datadir}/dbus-1/services/*
%{_sysconfdir}/dbus-1/system.d/*
%{_libdir}/systemd/system/net-config.service
%{_libdir}/systemd/system/network.target.wants/net-config.service
%{_datadir}/license/net-config
%endif
