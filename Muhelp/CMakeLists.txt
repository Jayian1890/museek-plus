project(Muhelp CXX)

include(FindPkgConfig REQUIRED)

pkg_search_module(LIBXMLPP REQUIRED "libxml++-2.6")

add_definitions(${LIBXMLPP_CFLAGS})
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

include_directories(${CMAKE_CURRENT_BUILD_DIR})

set(MUHELP_SOURCES
    Codec.cc
    DirEntry.cc
    Muconf.cc
    )

add_library(Muhelp STATIC ${MUHELP_SOURCES})

# Export libxml++ include dirs to consumers
if(LIBXMLPP_INCLUDE_DIRS)
    target_include_directories(Muhelp PUBLIC ${LIBXMLPP_INCLUDE_DIRS})
endif()

# Export libxml++ library dirs to consumers (so linker can find xml++)
if(LIBXMLPP_LIBRARY_DIRS)
    target_link_directories(Muhelp PUBLIC ${LIBXMLPP_LIBRARY_DIRS})
endif()

# Link the Muhelp library to some libraries and propagate them to consumers
# so final executables that link Muhelp get the required libs.
target_link_libraries(
    Muhelp
    PUBLIC
    NewNet
    ${LIBXML2_LIBRARIES}
    ${LIBXMLPP_LIBRARIES}
    )
