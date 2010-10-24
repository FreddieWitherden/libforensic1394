CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

PROJECT(libforensic1394)

# Current version of the library
SET(FORENSIC1394_VERSION_MAJOR 0)
SET(FORENSIC1394_VERSION_MINOR 3)
SET(FORENSIC1394_VERSION_PATCH 0)

# Overall version given as <major>.<minor>.<patch>
SET(FORENSIC1394_VERSION "${FORENSIC1394_VERSION_MAJOR}.${FORENSIC1394_VERSION_MINOR}.${FORENSIC1394_VERSION_PATCH}")

# This should be updated when the ABI is changed
SET(FORENSIC1394_SOVERSION 2)

INCLUDE(CheckIncludeFile)
INCLUDE(CheckCSourceCompiles)
INCLUDE(TestBigEndian)

INCLUDE_DIRECTORIES(./src)

IF(CMAKE_COMPILER_IS_GNUCC)
    # The more warnings the better
    ADD_DEFINITIONS(-g -pipe -Werror -fsigned-char -Wall)

    CHECK_C_SOURCE_COMPILES("
        #if ((defined(__GNUC__)) && (__GNUC__ >= 4))
        int main(int argc, char **argv) { int is_gcc4 = 1; return 0; }
        #else
        #error This is not gcc4.
        #endif
    " FORENSIC1394_IS_GCC4)

    IF(FORENSIC1394_IS_GCC4 AND NOT WIN32)
        # Hide all symbols by default (implicit on Windows)
        ADD_DEFINITIONS(-fvisibility=hidden)
    ENDIF()
ENDIF()

# Someday...
IF(MSVC)
    ADD_DEFINITIONS(-D_CRT_SECURE_NO_WARNINGS=1)
ENDIF()

# Determine the endianess of the system
TEST_BIG_ENDIAN(FORENSIC1394_BIG_ENDIAN)

IF(FORENSIC1394_BIG_ENDIAN)
	ADD_DEFINITIONS(-DFORENSIC1394_BIG_ENDIAN)
ELSE()
	ADD_DEFINITIONS(-DFORENSIC1394_LITTLE_ENDIAN)
ENDIF()

# Common source to all builds
SET(FORENSIC1394_SRCS
    src/forensic1394.h
    src/common.h
    src/common.c
    src/csr.h
    src/csr.c)

# Linux / Juju stack (others may be added later)
IF("${CMAKE_SYSTEM}" MATCHES "Linux")
    # Look for the firewire-core header
    CHECK_INCLUDE_FILE(linux/firewire-cdev.h FORENSIC1394_HAS_FWCORE)

    IF(NOT FORENSIC1394_HAS_FWCORE)
        MESSAGE(FATAL "linux/firewire-cdev.h not found!")
    ENDIF()

    LIST(APPEND FORENSIC1394_SRCS src/linux/juju.c)
# Mac OS X / IOKit
ELSEIF(APPLE)
    # Ensure we link to IOKit for firewire access
    LIST(APPEND OTHER_LDFLAGS "-framework CoreFoundation -framework IOKit")

    LIST(APPEND FORENSIC1394_SRCS src/macosx/iokit.c)
# Windows or BSD; currently unsupported
ELSE()
    MESSAGE(FATAL "Currently only Mac OS X and GNU/Linux are supported!")
ENDIF()

OPTION(FORENSIC1394_BUILD_STATIC "Build static library" TRUE)
IF(FORENSIC1394_BUILD_STATIC)
    ADD_LIBRARY(forensic1394-static STATIC ${FORENSIC1394_SRCS})
    SET_TARGET_PROPERTIES(forensic1394-static PROPERTIES OUTPUT_NAME "forensic1394")
    SET(FORENSIC1394_LIB_TARGET forensic1394-static)
    LIST(APPEND FORENSIC1394_INSTALL_TARGETS ";forensic1394-static")
ENDIF()

OPTION(FORENSIC1394_BUILD_SHARED "Build shared library" TRUE)
IF(FORENSIC1394_BUILD_SHARED)
    ADD_LIBRARY(forensic1394 SHARED ${FORENSIC1394_SRCS})
    SET_TARGET_PROPERTIES(forensic1394 PROPERTIES VERSION ${FORENSIC1394_VERSION})
    SET_TARGET_PROPERTIES(forensic1394 PROPERTIES SOVERSION ${FORENSIC1394_SOVERSION})
    TARGET_LINK_LIBRARIES(forensic1394 ${OPTIONAL_LIBRARY_LIBS} ${OTHER_LDFLAGS})
    SET(FORENSIC1394_LIB_TARGET forensic1394)
    LIST(APPEND FORENSIC1394_INSTALL_TARGETS ";forensic1394")
ENDIF()

# Must build either a shared or static library
IF(NOT FORENSIC1394_BUILD_SHARED AND NOT FORENSIC1394_BUILD_STATIC)
    MESSAGE(FATAL "Both shared and static libraries are disabled!")
ENDIF()

# From CMake FAQ
IF(FORENSIC1394_BUILD_SHARED AND FORENSIC1394_BUILD_STATIC)
    SET_TARGET_PROPERTIES(forensic1394 PROPERTIES CLEAN_DIRECT_OUTPUT 1)
    SET_TARGET_PROPERTIES(forensic1394-static PROPERTIES CLEAN_DIRECT_OUTPUT 1)
ENDIF()

INSTALL(TARGETS ${FORENSIC1394_INSTALL_TARGETS}
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib)
INSTALL(FILES src/forensic1394.h DESTINATION include)

# Documentation
FIND_PACKAGE(Doxygen)
IF(DOXYGEN_FOUND)
    ADD_CUSTOM_TARGET(docs ${DOXYGEN_EXECUTABLE} COMMENT "Building documentation")
ELSE()
    MESSAGE(STATUS "Doxygen not found. You won't be able to build documentation.")
ENDIF()

# CPack package generation (must be set before we include CPack)
SET(CPACK_PACKAGE_VENDOR "Freddie Witherden")
SET(CPACK_PACKAGE_VERSION_MAJOR ${FORENSIC1394_VERSION_MAJOR})
SET(CPACK_PACKAGE_VERSION_MINOR ${FORENSIC1394_VERSION_MINOR})
SET(CPACK_PACKAGE_VERSION_PATCH ${FORENSIC1394_VERSION_PATCH})

# We only want TGZ packages by default
SET(CPACK_GENERATOR TGZ)

# See if we can build DEB/RPM packages
FIND_PROGRAM(FORENSIC1394_HAVE_DPKG dpkg)
FIND_PROGRAM(FORENSIC1394_HAVE_RPMBUILD rpmbuild)

IF(FORENSIC1394_HAVE_DPKG)
    MESSAGE(STATUS "Dpkg found. Enabling Debian packages.")
    LIST(APPEND CPACK_GENERATOR DEB)

    # Debian packages really should have a valid maintainer
    IF(NOT CPACK_DEBIAN_PACKAGE_MAINTAINER)
        MESSAGE(STATUS "CPACK_DEBIAN_PACKAGE_MAINTAINER is not set. "
                       "Defaulting to \"Unknown\"")
        SET(CPACK_DEBIAN_PACKAGE_MAINTAINER "Unknown")
    ENDIF()
ENDIF()

IF(FORENSIC1394_HAVE_RPMBUILD)
    MESSAGE(STATUS "Rpmbuild found. Enabling RPM packages.")
    LIST(APPEND CPACK_GENERATOR RPM)
ENDIF()

INCLUDE(CPack)
