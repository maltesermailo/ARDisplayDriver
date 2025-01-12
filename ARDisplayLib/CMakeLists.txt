# CMakeList.txt: CMake-Projekt für "ARDisplayLib". Schließen Sie die Quelle ein, und definieren Sie
# projektspezifische Logik hier.
#

# Fügen Sie der ausführbaren Datei dieses Projekts eine Quelle hinzu.
add_library (ARDisplayLib SHARED "ARDisplayLib.cpp" "ARDisplayLib.h")

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET ARDisplayLib PROPERTY CXX_STANDARD 20)
endif()

# Platform-specific settings
if(WIN32)
    target_compile_definitions(ARDisplayLib PRIVATE ARDISPLAY_EXPORTS)
elseif(APPLE)
    set_target_properties(ARDisplayLib PROPERTIES
        INSTALL_NAME_DIR "@rpath"
    )
endif()

find_package(PkgConfig REQUIRED)

pkg_check_modules(GSTREAMER REQUIRED gstreamer-1.0)
pkg_check_modules(GSTREAMER_BASE REQUIRED gstreamer-base-1.0)

# Add include directories and libraries
include_directories(${GSTREAMER_INCLUDE_DIRS} ${GSTREAMER_BASE_INCLUDE_DIRS})
link_directories(${GSTREAMER_LIBRARY_DIRS} ${GSTREAMER_BASE_LIBRARY_DIRS})

# Link GStreamer libraries
target_link_libraries(my_library
    ${GSTREAMER_LIBRARIES}
    ${GSTREAMER_BASE_LIBRARIES}
)

# Add NVENC support
set(NVENC_SDK_PATH "/path/to/NVIDIA_SDK/Video_Codec_SDK_12.0")
include_directories(${NVENC_SDK_PATH}/Interface)
if(WIN32)
    target_link_libraries(my_library "${NVENC_SDK_PATH}/Lib/Win64/nvencodeapi.lib")
elseif(UNIX)
    target_link_libraries(my_library "${NVENC_SDK_PATH}/Lib/Linux/x64/libnvidia-encode.so")
endif()

# Add H.265 support (libx265)
pkg_check_modules(X265 REQUIRED x265)
include_directories(${X265_INCLUDE_DIRS})
link_directories(${X265_LIBRARY_DIRS})
target_link_libraries(my_library ${X265_LIBRARIES})


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
