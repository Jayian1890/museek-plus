project(museekd CXX)

# Find ZLib
find_package(ZLIB REQUIRED)
include_directories(${ZLIB_INCLUDE_DIR})

# Find LibXml2
find_package(LibXml2 REQUIRED)
include_directories(${LIBXML2_INCLUDE_DIR})
add_definitions(${LIBXML2_DEFINITIONS})

# Check for some OS specific libraries
set(OS_LIBRARIES "")
if(WIN32 AND NOT CYGWIN)
    set(OS_LIBRARIES ${OS_LIBRARIES} ole32 shell32)
endif()

# Select some source files. Separate library sources from the standalone main.
set(MUSEEKD_LIB_SOURCES
    codesetmanager.cpp  ifacemanager.cpp     peermanager.cpp
    configmanager.cpp   ifacesocket.cpp      peersocket.cpp
    servermanager.cpp
    downloadmanager.cpp messageprocessor.cpp sharesdatabase.cpp
    downloadsocket.cpp  museekd.cpp          ticketsocket.cpp
    handshakesocket.cpp networkmessage.cpp   usersocket.cpp
    uploadmanager.cpp   uploadsocket.cpp     searchmanager.cpp
    distributedsocket.cpp
    )

# Build the museekd library (for embedding into the GUI)
add_library(museekd_lib STATIC ${MUSEEKD_LIB_SOURCES})

# Link the museekd library to some libraries and propagate to consumers
target_link_libraries(
    museekd_lib
    PUBLIC
    Mucipher
    Muhelp
    ${NEWNET_LIBRARIES}
    ${ZLIB_LIBRARIES}
    ${LIBXML2_LIBRARIES}
    ${ICONV_LIBRARIES}
    ${OS_LIBRARIES}
    )

# Build the standalone museekd binary (keeps original behavior)
set(MUSEEKD_MAIN_SOURCES main.cpp)
add_executable(museekd ${MUSEEKD_MAIN_SOURCES})
# Link standalone binary to the library
target_link_libraries(museekd PRIVATE museekd_lib)

# Install the museekd binary to the 'bin' directory.
install(
    TARGETS museekd
    DESTINATION bin
    )

install(
    FILES "museekd.1"
    DESTINATION "${CMAKE_INSTALL_MANDIR}/man1"
    )
install(
    FILES "config.xml.tmpl"
    DESTINATION ${CMAKE_INSTALL_DATADIR}/museek/museekd
    )
message("--> Museek Daemon (museekd) will be installed.")
