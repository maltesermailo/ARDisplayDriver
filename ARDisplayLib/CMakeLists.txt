# CMakeList.txt: CMake-Projekt für "ARDisplayLib". Schließen Sie die Quelle ein, und definieren Sie
# projektspezifische Logik hier.
#
set(CMAKE_LINK_FULLPATH ON)
# Fügen Sie der ausführbaren Datei dieses Projekts eine Quelle hinzu.
if(APPLE)
    set(OS_SOURCES "")
elseif(UNIX)
    set(OS_SOURCES "")
elseif(WIN32)
    set(OS_SOURCES "win/Windows.cpp")
endif()

add_library (ARDisplayLib SHARED ${OS_SOURCES} "common/Library.cpp" "ARDisplayLib.h" "Internals.h" "common/Discovery.cpp")

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET ARDisplayLib PROPERTY CXX_STANDARD 20)
endif()

# Platform-specific settings
if(WIN32)
    target_compile_definitions(ARDisplayLib PRIVATE ARDISPLAYLIB_EXPORTS)
elseif(APPLE)
    set_target_properties(ARDisplayLib PROPERTIES
        INSTALL_NAME_DIR "@rpath"
    )
endif()

find_package(PkgConfig REQUIRED)
find_package(OpenSSL REQUIRED)

pkg_check_modules(GSTREAMER REQUIRED gstreamer-1.0 gstreamer-app-1.0 gstreamer-rtp-1.0 gstreamer-rtsp-1.0 gstreamer-rtsp-server-1.0 gstreamer-sdp-1.0 gstreamer-video-1.0 gstreamer-net-1.0)
pkg_check_modules(GSTREAMER_BASE REQUIRED gstreamer-base-1.0)
pkg_check_modules(GLIB REQUIRED glib-2.0 gobject-2.0)
pkg_check_modules(GIO REQUIRED gio-2.0)

# Add include directories and libraries
include_directories(${GSTREAMER_INCLUDE_DIRS} ${GSTREAMER_BASE_INCLUDE_DIRS} ${GIO_INCLUDE_DIRS} ${GLIB_INCLUDE_DIRS})
link_directories(${GSTREAMER_LIBRARY_DIRS} ${GSTREAMER_BASE_LIBRARY_DIRS})

if(WIN32)
    target_link_options(ARDisplayLib PRIVATE "/LIBPATH:${GSTREAMER_LIBRARY_DIRS}")
    # Link GStreamer libraries
    target_link_libraries(ARDisplayLib
        ${GSTREAMER_LIBRARIES}
        ${GSTREAMER_BASE_LIBRARIES}
        ${GLIB_LIBRARIES}
        ${GIO_LIBRARIES}
        OpenSSL::SSL OpenSSL::Crypto
        ws2_32
    )
else()
    # Link GStreamer libraries
    target_link_libraries(ARDisplayLib
        ${GSTREAMER_LIBRARIES}
        ${GSTREAMER_BASE_LIBRARIES}
        ${GLIB_LIBRARIES}
        ${GIO_LIBRARIES}
        OpenSSL::SSL OpenSSL::Crypto
    )
endif()

# Add NVENC support
#set(NVENC_SDK_PATH "/path/to/NVIDIA_SDK/Video_Codec_SDK_12.0")
#include_directories(${NVENC_SDK_PATH}/Interface)
#if(WIN32)
#    target_link_libraries(ARDisplayLib "${NVENC_SDK_PATH}/Lib/Win64/nvencodeapi.lib")
#elseif(UNIX)
#    target_link_libraries(ARDisplayLib "${NVENC_SDK_PATH}/Lib/Linux/x64/libnvidia-encode.so")
#endif()


# Installation rules
include(GNUInstallDirs)
install(TARGETS ARDisplayLib
    EXPORT ARDisplayLibTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(EXPORT ARDisplayLibTargets
    FILE ARDisplayLib.cmake
    NAMESPACE MyLibrary::
    DESTINATION ${CMAKE_INSTALL_DATADIR}/MyLibrary/cmake
)

# TODO: Fügen Sie bei Bedarf Tests hinzu, und installieren Sie Ziele.
