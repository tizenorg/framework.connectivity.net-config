CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(net-config C)
SET(PACKAGE ${PROJECT_NAME})
SET(PREFIX ${CMAKE_INSTALL_PREFIX})
SET(BINDIR "${PREFIX}/sbin")
SET(DATADIR "${PREFIX}/share")
SET(LIBDIR "${PREFIX}/lib")

SET(SRCS
	src/main.c
	src/neterror.c
	src/wifi.c
	src/wifi-power.c
	src/wifi-state.c
	src/wifi-eap.c
	src/network-clock.c
	src/network-state.c
	src/network-statistics.c
	src/wifi-indicator.c
	src/signal-handler.c
	src/wifi-ssid-scan.c
	src/wifi-background-scan.c
	src/wifi-agent.c
	src/wifi-eap-config.c
	src/dbus/netdbus.c
	src/dbus/netsupplicant.c
	src/utils/util.c
	src/utils/emulator.c
	)

IF("${CMAKE_BUILD_TYPE}" STREQUAL "")
	SET(CMAKE_BUILD_TYPE "Release")
ENDIF("${CMAKE_BUILD_TYPE}" STREQUAL "")
MESSAGE("Build type: ${CMAKE_BUILD_TYPE}")

INCLUDE(FindPkgConfig)
PKG_CHECK_MODULES(pkgs REQUIRED
	glib-2.0
	dbus-glib-1
	dlog
	vconf
	wifi-direct
	tapi
	syspopup-caller
	libsystemd-daemon)

FOREACH(flag ${pkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -fvisibility=hidden -Wall")
SET(CMAKE_C_FLAGS "-I${CMAKE_SOURCE_DIR}/include ${CMAKE_C_FLAGS} ${EXTRA_CFLAGS}")
SET(CMAKE_C_FLAGS_DEBUG "-O0 -g")
SET(CMAKE_C_FLAGS_RELEASE "-O2")

FIND_PROGRAM(UNAME NAMES uname)
EXEC_PROGRAM("${UNAME}" ARGS "-m"
OUTPUT_VARIABLE "ARCH")
IF("${ARCH}" STREQUAL "arm")
	ADD_DEFINITIONS("-DEMBEDDED_TARGET")
	MESSAGE("add -DEMBEDDED_TARGET")
ENDIF("${ARCH}" STREQUAL "arm")

ADD_DEFINITIONS("-DPACKAGE=\"${PACKAGE}\"")
ADD_DEFINITIONS("-DPREFIX=\"${PREFIX}\"")

SET(CMAKE_EXE_LINKER_FLAGS "-Wl,--as-needed")

ADD_EXECUTABLE(${PROJECT_NAME} ${SRCS})
TARGET_LINK_LIBRARIES(${PROJECT_NAME} ${pkgs_LDFLAGS})

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
