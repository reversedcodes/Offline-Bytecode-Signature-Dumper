cmake_minimum_required(VERSION 3.16)

project(Offline-Bytecode-Signature-Dumper
    VERSION 0.1.0
    LANGUAGES C
)

include(FetchContent)

if(NOT TARGET miniz)
    FetchContent_Declare(miniz
        GIT_REPOSITORY https://github.com/richgel999/miniz.git
        GIT_TAG 3.1.2
        GIT_SHALLOW TRUE
    )
    FetchContent_MakeAvailable(miniz)
endif()

if(NOT TARGET jni2hook AND NOT TARGET jni2hook::jni2hook)
    set(JNI2HOOK_BUILD_TESTS OFF)
    set(JNI2HOOK_BUILD_EXAMPLES OFF)
    set(JNI2HOOK_INSTALL OFF)

    get_filename_component(OBSD_LOCAL_JNI2HOOK
        "${CMAKE_CURRENT_LIST_DIR}/../../external/jni2hook"
        ABSOLUTE
    )

    if(EXISTS "${OBSD_LOCAL_JNI2HOOK}/CMakeLists.txt")
        add_subdirectory(
            "${OBSD_LOCAL_JNI2HOOK}"
            "${CMAKE_CURRENT_BINARY_DIR}/jni2hook"
            EXCLUDE_FROM_ALL
        )
    else()
        FetchContent_Declare(jni2hook
            GIT_REPOSITORY https://github.com/reversedcodes/jni2hook.git
            GIT_TAG 1.1-Beta
            GIT_SHALLOW TRUE
        )
        FetchContent_MakeAvailable(jni2hook)
    endif()
endif()

if(TARGET jni2hook::jni2hook)
    set(OBSD_JNI2HOOK_TARGET jni2hook::jni2hook)
elseif(TARGET jni2hook)
    set(OBSD_JNI2HOOK_TARGET jni2hook)
else()
    message(FATAL_ERROR "jni2hook target is unavailable")
endif()

add_executable(Offline-Bytecode-Signature-Dumper
    src/Main.c
)

target_compile_features(Offline-Bytecode-Signature-Dumper PRIVATE c_std_11)

target_link_libraries(Offline-Bytecode-Signature-Dumper PRIVATE
    ${OBSD_JNI2HOOK_TARGET}
    miniz
)

if(MSVC)
    target_compile_options(Offline-Bytecode-Signature-Dumper PRIVATE /W4)
else()
    target_compile_options(Offline-Bytecode-Signature-Dumper PRIVATE
        -Wall
        -Wextra
        -Wpedantic
    )
endif()
