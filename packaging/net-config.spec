Name:		net-config
Summary:	TIZEN Network Configuration service
Version:	1.0.79
Release:	1
Group:		System/Network
License:	Apache-2.0
Source0:	%{name}-%{version}.tar.gz
BuildRequires:	pkgconfig(dlog)
BuildRequires:	pkgconfig(tapi)
BuildRequires:	pkgconfig(vconf)
BuildRequires:	pkgconfig(appsvc)
BuildRequires:	pkgconfig(journal)
BuildRequires:	pkgconfig(glib-2.0)
BuildRequires:	pkgconfig(dbus-glib-1)
BuildRequires:	pkgconfig(notification)
BuildRequires:	pkgconfig(alarm-service)
BuildRequires:	pkgconfig(syspopup-caller)
BuildRequires:	pkgconfig(capi-system-info)
BuildRequires:	pkgconfig(capi-appfw-application)
BuildRequires:	pkgconfig(capi-network-wifi-direct)
BuildRequires:	cmake
BuildRequires:	model-build-features
Requires:		vconf
Requires:		connman
Requires:		systemd
Requires:		/bin/cp
Requires:		/bin/mv
Requires:		/bin/rm
Requires:		/bin/cat
Requires:		/bin/sed
Requires:		/bin/tar
Requires:		/bin/mkdir
Requires:		/bin/touch
Requires:		/sbin/route
Requires:		/bin/netstat
Requires:		/sbin/ifconfig
Requires:		/usr/bin/xargs
Requires:		/usr/bin/vconftool
Requires(post):		systemd
Requires(post):		vconf
Requires(preun):	systemd
Requires(postun):	systemd

%description
TIZEN Network Configuration service

%prep
%setup -q

%build
cmake -DCMAKE_INSTALL_PREFIX=%{_prefix} \
	-DTIZEN_WLAN_PASSPOINT=1 \
%if 0%{?model_build_feature_wlan_concurrent_mode}
	-DWLAN_CONCURRENT_MODE=1 \
%endif
%if ! 0%{?model_build_feature_wlan_p2p_disable}
	-DTIZEN_P2P_ENABLE=1 \
%endif
%if ! 0%{?model_build_feature_network_tethering_disable}
	-DTIZEN_TETHERING_ENABLE=1 \
%endif
%if 0%{?model_build_feature_wlan_wearable} == 1
	-DTIZEN_WEARABLE=1 \
%endif
	.

make %{?_smp_mflags}


%install
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
mkdir -p %{buildroot}/opt/etc/dump.d/module.d/
cp resources/opt/etc/dump.d/module.d/network_log_dump.sh %{buildroot}/opt/etc/dump.d/module.d/network_log_dump.sh
mkdir -p %{buildroot}/opt/var/lib/net-config/
cp resources/opt/etc/dump.d/module.d/network_log_dump.sh %{buildroot}/opt/var/lib/net-config/network_log_dump.sh

%if 0%{?model_build_feature_wlan_wearable} == 1
#softreset scripts
mkdir -p %{buildroot}/usr/system/RestoreDir/softreset_prepare
cp resources/usr/system/RestoreDir/softreset_prepare/network_reset_pre.sh %{buildroot}/usr/system/RestoreDir/softreset_prepare/network_reset_pre.sh

mkdir -p %{buildroot}/usr/system/RestoreDir/softreset_post
cp resources/usr/system/RestoreDir/softreset_post/network_reset_post.sh %{buildroot}/usr/system/RestoreDir/softreset_post/network_reset_post.sh
%endif

#License
mkdir -p %{buildroot}%{_datadir}/license
cp LICENSE %{buildroot}%{_datadir}/license/net-config

%post

vconftool set -t int memory/dnet/state 0 -i -f -s system::vconf_network
vconftool set -t int memory/wifi/state 0 -i -f -s system::vconf_network
vconftool set -t int memory/wifi/transfer_state 0 -i -f -s system::vconf_network
vconftool set -t int memory/wifi/strength 0 -i -f -s system::vconf_network

vconftool set -t int memory/dnet/cellular 0 -i -f -s system::vconf_network
vconftool set -t int memory/dnet/wifi 0 -i -f -s system::vconf_network
vconftool set -t int memory/dnet/network_config 0 -i -f -s system::vconf_network
vconftool set -t int memory/dnet/status 0 -i -f -s system::vconf_network
vconftool set -t string memory/dnet/ip "" -i -f -s system::vconf_network
vconftool set -t string memory/dnet/proxy "" -i -f -s system::vconf_network

vconftool set -t string memory/wifi/connected_ap_name "" -i -f -s system::vconf_network

vconftool set -t string db/wifi/bssid_address "" -f -s system::vconf_network

#Default Call Statistics
vconftool set -t int db/dnet/statistics/cellular/totalsnt 0 -f -s system::vconf_network
vconftool set -t int db/dnet/statistics/cellular/totalrcv 0 -f -s system::vconf_network
vconftool set -t int db/dnet/statistics/cellular/lastsnt 0 -f -s system::vconf_network
vconftool set -t int db/dnet/statistics/cellular/lastrcv 0 -f -s system::vconf_network
vconftool set -t int db/dnet/statistics/wifi/totalsnt 0 -f -s system::vconf_network
vconftool set -t int db/dnet/statistics/wifi/totalrcv 0 -f -s system::vconf_network
vconftool set -t int db/dnet/statistics/wifi/lastsnt 0 -f -s system::vconf_network
vconftool set -t int db/dnet/statistics/wifi/lastrcv 0 -f -s system::vconf_network

#Wi-Fi last power state
vconftool set -t int file/private/wifi/last_power_state 0 -f -s system::vconf_network

#Wi-Fi power state due to airplane mode
vconftool set -t int file/private/wifi/wifi_off_by_airplane 0 -f -s system::vconf_network

#Wi-Fi power state due to restricted mode
vconftool set -t int file/private/wifi/wifi_off_by_restricted 0 -f -s system::vconf_network

#Wi-Fi power state due to emergency mode
vconftool set -t int file/private/wifi/wifi_off_by_emergency 0 -f -s system::vconf_network

#Wi-Fi sleep policy
vconftool set -t int file/private/wifi/sleep_policy 0 -g 6519 -f -s system::vconf_setting

%if 0%{?model_build_feature_wlan_wearable} == 1
#Wearable use Wi-Fi
vconftool set -t int db/private/wifi/wearable_wifi_use 1 -g 6519 -f -s net-config
%endif

#Network logs
mkdir -p /opt/usr/data/network
chmod 755 /opt/usr/data/network

#systemctl daemon-reload
#systemctl restart net-config.service

%preun
#systemctl stop net-config.service

%postun
#systemctl daemon-reload


%files
%manifest net-config.manifest
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
%attr(500,root,root) /opt/etc/dump.d/module.d/network_log_dump.sh
%attr(500,root,root) /opt/var/lib/net-config/network_log_dump.sh

%if 0%{?model_build_feature_wlan_wearable} == 1
%attr(700,root,root) /usr/system/RestoreDir/softreset_prepare/network_reset_pre.sh
%attr(700,root,root) /usr/system/RestoreDir/softreset_post/network_reset_post.sh
%endif
