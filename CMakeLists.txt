CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(net-config C)
SET(PACKAGE ${PROJECT_NAME})
SET(PREFIX ${CMAKE_INSTALL_PREFIX})
SET(BINDIR "${PREFIX}/sbin")
SET(DATADIR "${PREFIX}/share")
SET(LIBDIR "${PREFIX}/lib")

SET(SRCS
	src/main.c
	src/wifi.c
	src/neterror.c
	src/wifi-eap.c
	src/wifi-wps.c
	src/wifi-agent.c
	src/wifi-ccode.c
	src/wifi-power.c
	src/wifi-state.c
	src/cellular-state.c
	src/wifi-passpoint.c
	src/utils/log.c
	src/utils/util.c
	src/dbus/netdbus.c
	src/network-clock.c
	src/network-state.c
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
	)

IF("${CMAKE_BUILD_TYPE}" STREQUAL "")
	SET(CMAKE_BUILD_TYPE "Release")
ENDIF("${CMAKE_BUILD_TYPE}" STREQUAL "")
MESSAGE("Build type: ${CMAKE_BUILD_TYPE}")

IF(TIZEN_WLAN_PASSPOINT)
	ADD_DEFINITIONS(-DTIZEN_WLAN_PASSPOINT)
ENDIF(TIZEN_WLAN_PASSPOINT)

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


#IF(TIZEN_MOBILE)
#	ADD_DEFINITIONS(-DTIZEN_MOBILE)
#ENDIF(TIZEN_MOBILE)
IF(TIZEN_WEARABLE)
	ADD_DEFINITIONS(-DTIZEN_WEARABLE)
ENDIF(TIZEN_WEARABLE)

INCLUDE(FindPkgConfig)
PKG_CHECK_MODULES(pkgs REQUIRED
	dlog
	tapi
	vconf
	journal
	gio-2.0
	glib-2.0
	dbus-glib-1
	notification
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

SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -Wall -Werror -fvisibility=hidden")
SET(EXTRA_CXXFLAGS "${EXTRA_CXXFLAGS} -Wall -Werror -fvisibility=hidden -fvisibility-inlines-hidden")
SET(CMAKE_C_FLAGS "-I${CMAKE_SOURCE_DIR}/include ${CMAKE_C_FLAGS} ${EXTRA_CFLAGS}")
SET(CMAKE_C_FLAGS_DEBUG "-O0 -g")
SET(CMAKE_C_FLAGS_RELEASE "-O2")

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

ADD_EXECUTABLE(${PROJECT_NAME} ${SRCS})
TARGET_LINK_LIBRARIES(${PROJECT_NAME} ${pkgs_LDFLAGS} ${PCAP_LIB})

ADD_CUSTOM_TARGET(netconfig-iface-network-state-glue.h
	COMMAND dbus-binding-tool --mode=glib-server --prefix=netconfig_iface_network_state
	--output=${CMAKE_SOURCE_DIR}/include/netconfig-iface-network-state-glue.h
	${CMAKE_SOURCE_DIR}/interfaces/netconfig-iface-network-state.xml
	DEPENDS ${CMAKE_SOURCE_DIR}/interfaces/netconfig-iface-network-state.xml
)
ADD_CUSTOM_TARGET(netconfig-iface-network-statistics-glue.h
	COMMAND dbus-binding-tool --mode=glib-server --prefix=netconfig_iface_network_statistics
	--output=${CMAKE_SOURCE_DIR}/include/netconfig-iface-network-statistics-glue.h
	${CMAKE_SOURCE_DIR}/interfaces/netconfig-iface-network-statistics.xml
	DEPENDS ${CMAKE_SOURCE_DIR}/interfaces/netconfig-iface-network-statistics.xml
)
ADD_CUSTOM_TARGET(netconfig-iface-wifi-glue.h
	COMMAND dbus-binding-tool --mode=glib-server --prefix=netconfig_iface_wifi
	--output=${CMAKE_SOURCE_DIR}/include/netconfig-iface-wifi-glue.h
	${CMAKE_SOURCE_DIR}/interfaces/netconfig-iface-wifi.xml
	DEPENDS ${CMAKE_SOURCE_DIR}/interfaces/netconfig-iface-wifi.xml
)

ADD_DEPENDENCIES(${PROJECT_NAME} netconfig-iface-network-state-glue.h)
ADD_DEPENDENCIES(${PROJECT_NAME} netconfig-iface-network-statistics-glue.h)
ADD_DEPENDENCIES(${PROJECT_NAME} netconfig-iface-wifi-glue.h)

INSTALL(TARGETS ${PROJECT_NAME} DESTINATION ${BINDIR})
