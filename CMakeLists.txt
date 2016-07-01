cmake_minimum_required(VERSION 2.8)

PROJECT(usign C)
ADD_DEFINITIONS(-O2 -Wall -Werror --std=gnu99 -g3 -Wmissing-declarations)

SET(SOURCES ed25519.c edsign.c f25519.c fprime.c sha512.c main.c)

SET(LIBS)
IF(USE_LIBUBOX)
  ADD_DEFINITIONS(-DUSE_LIBUBOX)
  SET(LIBS ubox)
  FIND_PATH(ubox_include_dir libubox/utils.h)
  INCLUDE_DIRECTORIES(${ubox_include_dir})
ELSE()
  SET(SOURCES ${SOURCES} base64.c)
ENDIF()

ADD_EXECUTABLE(usign ${SOURCES})
TARGET_LINK_LIBRARIES(usign ${LIBS})

INSTALL(TARGETS usign
	RUNTIME DESTINATION bin
)
