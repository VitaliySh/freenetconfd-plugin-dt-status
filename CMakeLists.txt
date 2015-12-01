CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
SET(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/build/modules")

PROJECT(freenetconfd-plugins)

FILE(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/build)

SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/lib)

SET(SOURCES
	src/status.c
	src/config.c
	src/config.h
)

ADD_LIBRARY(freenetconfd-plugin-status MODULE ${SOURCES})
SET_TARGET_PROPERTIES(freenetconfd-plugin-status PROPERTIES OUTPUT_NAME freenetconfd-plugin-status PREFIX "")

FIND_PACKAGE(LIBUBOX REQUIRED)
INCLUDE_DIRECTORIES(${LIBUBOX_INCLUDE_DIR})
TARGET_LINK_LIBRARIES(freenetconfd-plugin-status ${LIBUBOX_LIBRARIES})

TARGET_LINK_LIBRARIES(freenetconfd-plugin-status json-c)

INSTALL(
	TARGETS
		freenetconfd-plugin-status
	LIBRARY DESTINATION lib/freenetconfd/
)

INSTALL(
	FILES
		yang/status@2015-12-1.yang
	DESTINATION etc/yang/
)
