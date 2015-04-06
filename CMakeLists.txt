cmake_minimum_required(VERSION 2.8)

PROJECT(usign C)
ADD_DEFINITIONS(-O2 -Wall -Werror --std=gnu99 -g3 -Wmissing-declarations)

SET(SOURCES ed25519.c edsign.c f25519.c fprime.c sha512.c base64.c main.c)
ADD_EXECUTABLE(usign ${SOURCES})

INSTALL(TARGETS usign
	RUNTIME DESTINATION bin
)
