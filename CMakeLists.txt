CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(net-config C)
SET(PACKAGE ${PROJECT_NAME})
SET(PREFIX ${CMAKE_INSTALL_PREFIX})
SET(BINDIR "${PREFIX}/sbin")
SET(DATADIR "${PREFIX}/share")
SET(LIBDIR "${PREFIX}/lib")
SET(INTERFACES "${CMAKE_SOURCE_DIR}/interfaces")

SET(SRCS
	src/main.c
	src/wifi.c
	src/neterror.c
	src/wifi-eap.c
	src/wifi-wps.c
	src/wifi-agent.c
	src/wifi-power.c
	src/wifi-state.c
	src/cellular-state.c
	src/wifi-passpoint.c
	src/utils/log.c
	src/utils/util.c
	src/dbus/netdbus.c
	src/network-clock.c
	src/network-state.c
	src/network-monitor.c
	src/wifi-firmware.c
	src/wifi-indicator.c
	src/signal-handler.c
	src/wifi-ssid-scan.c
	src/utils/emulator.c
	src/wifi-eap-config.c
	src/network-statistics.c
	src/dbus/netsupplicant.c
	src/wifi-background-scan.c
	src/wifi-tel-intf.c
	src/wifi-config.c
	src/clatd-handler.c
	)

IF("${CMAKE_BUILD_TYPE}" STREQUAL "")
	SET(CMAKE_BUILD_TYPE "Release")
ENDIF("${CMAKE_BUILD_TYPE}" STREQUAL "")
MESSAGE("Build type: ${CMAKE_BUILD_TYPE}")

IF(TIZEN_WLAN_PASSPOINT)
	ADD_DEFINITIONS(-DTIZEN_WLAN_PASSPOINT)
ENDIF(TIZEN_WLAN_PASSPOINT)

IF(TIZEN_WLAN_USE_P2P_INTERFACE)
	ADD_DEFINITIONS(-DTIZEN_WLAN_USE_P2P_INTERFACE)
ENDIF(TIZEN_WLAN_USE_P2P_INTERFACE)

IF(TIZEN_P2P_ENABLE)
	ADD_DEFINITIONS(-DTIZEN_P2P_ENABLE)
	SET(P2P_REQUIRED_PKGS "capi-network-wifi-direct")
ENDIF(TIZEN_P2P_ENABLE)

IF(TIZEN_TETHERING_ENABLE)
	ADD_DEFINITIONS(-DTIZEN_TETHERING_ENABLE)
ENDIF(TIZEN_TETHERING_ENABLE)

IF(TIZEN_CAPTIVE_PORTAL)
	ADD_DEFINITIONS(-DTIZEN_CAPTIVE_PORTAL)
	SET(SRCS ${SRCS} src/utils/network-accessibility.c)
ENDIF(TIZEN_CAPTIVE_PORTAL)

IF(TIZEN_TV)
       ADD_DEFINITIONS(-DTIZEN_TV)
ENDIF(TIZEN_TV)

IF(TIZEN_WEARABLE)
	ADD_DEFINITIONS(-DTIZEN_WEARABLE)
	SET(WEARABLE_REQUIRED_PKGS "weconn")
ENDIF(TIZEN_WEARABLE)

ADD_DEFINITIONS(-DTIZEN_TELEPHONY_ENABLE)

IF(TIZEN_DEBUG_DISABLE)
	ADD_DEFINITIONS(-DTIZEN_DEBUG_DISABLE)
	SET(SRCS ${SRCS} src/wifi-dump.c)
ENDIF(TIZEN_DEBUG_DISABLE)

INCLUDE(FindPkgConfig)
PKG_CHECK_MODULES(pkgs REQUIRED
	dlog
	tapi
	vconf
	bundle
	gio-2.0
	glib-2.0
	gio-unix-2.0
	eventsystem
	alarm-service
	syspopup-caller
	capi-system-info
	capi-appfw-application
	${P2P_REQUIRED_PKGS}
	${WEARABLE_REQUIRED_PKGS}
	)

FOREACH(flag ${pkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -Wall -fvisibility=hidden")
SET(EXTRA_CXXFLAGS "${EXTRA_CXXFLAGS} -Wall -Werror -fvisibility=hidden -fvisibility-inlines-hidden")
SET(CMAKE_C_FLAGS "-I${CMAKE_SOURCE_DIR} -I${CMAKE_SOURCE_DIR}/include ${CMAKE_C_FLAGS} ${EXTRA_CFLAGS} -fPIE")
SET(CMAKE_C_FLAGS_DEBUG "-O0 -g -fPIE")
SET(CMAKE_C_FLAGS_RELEASE "-O2 -fPIE")

IF(WLAN_CONCURRENT_MODE)
	ADD_DEFINITIONS(-DWLAN_CONCURRENT_MODE)
ENDIF(WLAN_CONCURRENT_MODE)

FIND_PROGRAM(UNAME NAMES uname)
EXEC_PROGRAM("${UNAME}" ARGS "-m"
OUTPUT_VARIABLE "ARCH")
IF("${ARCH}" STREQUAL "arm")
	ADD_DEFINITIONS("-DTARGET_ARM")
	MESSAGE("add -DTARGET_ARM")
ENDIF("${ARCH}" STREQUAL "arm")

ADD_DEFINITIONS("-DPACKAGE=\"${PACKAGE}\"")
ADD_DEFINITIONS("-DPREFIX=\"${PREFIX}\"")

SET(CMAKE_EXE_LINKER_FLAGS "-Wl,--as-needed")

ADD_CUSTOM_COMMAND(
	WORKING_DIRECTORY
	OUTPUT ${CMAKE_SOURCE_DIR}/generated-code.c
	COMMAND gdbus-codegen --interface-prefix net.netconfig.
			--generate-c-code generated-code
			--c-generate-object-manager
			--generate-docbook generated-code-docs
			${INTERFACES}/netconfig-iface-network-state.xml ${INTERFACES}/netconfig-iface-network-statistics.xml ${INTERFACES}/netconfig-iface-wifi.xml
			COMMENT "Generating GDBus .c/.h")

ADD_EXECUTABLE(${PROJECT_NAME} ${SRCS} ${CMAKE_SOURCE_DIR}/generated-code.c)

TARGET_LINK_LIBRARIES(${PROJECT_NAME} ${pkgs_LDFLAGS} ${PCAP_LIB})

INSTALL(TARGETS ${PROJECT_NAME} DESTINATION ${BINDIR})
