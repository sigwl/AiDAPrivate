cmake_minimum_required(VERSION 3.25)

set(CMAKE_POLICY_DEFAULT_CMP0091 NEW)
set(CMAKE_POLICY_DEFAULT_CMP0141 NEW)

project(AiDA
    VERSION   1.2.8
    LANGUAGES C CXX ASM_MASM
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_program(AIDA_SCCACHE_PROGRAM sccache
    HINTS "${CMAKE_SOURCE_DIR}/sccache-v0.15.0-x86_64-pc-windows-msvc")
if(AIDA_SCCACHE_PROGRAM AND NOT DEFINED ENV{SCCACHE_DISABLE})
    message(STATUS "AiDA: sccache enabled for C++ at ${AIDA_SCCACHE_PROGRAM}")
    set(CMAKE_C_COMPILER_LAUNCHER   "" CACHE STRING "compiler launcher (disabled for C)" FORCE)
    set(CMAKE_CXX_COMPILER_LAUNCHER "${AIDA_SCCACHE_PROGRAM}" CACHE STRING "compiler launcher (sccache)" FORCE)
endif()

if(MSVC)
    set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<$<CONFIG:Debug,RelWithDebInfo,Release>:Embedded>")

    if(CMAKE_GENERATOR MATCHES "Ninja")
        set(_aida_rule_launch_compile "\"${CMAKE_COMMAND}\" -E chdir \"${CMAKE_BINARY_DIR}\"")
        set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE "${_aida_rule_launch_compile}")
        cmake_host_system_information(RESULT _aida_logical_cpus QUERY NUMBER_OF_LOGICAL_CORES)
        if(NOT _aida_logical_cpus OR _aida_logical_cpus LESS 4)
            set(_aida_logical_cpus 8)
        endif()
        math(EXPR _aida_heavy_pool "(${_aida_logical_cpus} + 1) / 2")
        if(_aida_heavy_pool LESS 2)
            set(_aida_heavy_pool 2)
        endif()
        set(AIDA_LINK_POOL_SIZE "1" CACHE STRING "Maximum concurrent MSVC link jobs for memory-heavy Ninja builds")
        if(NOT AIDA_LINK_POOL_SIZE MATCHES "^[1-9][0-9]*$")
            set(AIDA_LINK_POOL_SIZE "1" CACHE STRING "Maximum concurrent MSVC link jobs for memory-heavy Ninja builds" FORCE)
        endif()
        set_property(GLOBAL PROPERTY JOB_POOLS
            aida_compile=${_aida_logical_cpus}
            aida_heavy_compile=${_aida_heavy_pool}
            aida_serial_compile=1
            aida_link=${AIDA_LINK_POOL_SIZE})
        set(CMAKE_JOB_POOL_COMPILE aida_compile)
        set(CMAKE_JOB_POOL_LINK aida_link)
    endif()

    foreach(_aida_flagset
        CMAKE_C_FLAGS CMAKE_CXX_FLAGS
        CMAKE_C_FLAGS_DEBUG CMAKE_CXX_FLAGS_DEBUG
        CMAKE_C_FLAGS_RELEASE CMAKE_CXX_FLAGS_RELEASE
        CMAKE_C_FLAGS_RELWITHDEBINFO CMAKE_CXX_FLAGS_RELWITHDEBINFO
        CMAKE_C_FLAGS_MINSIZEREL CMAKE_CXX_FLAGS_MINSIZEREL)
        if(DEFINED ${_aida_flagset})
            string(REGEX REPLACE "[ \t]*/Z[Ii7]([ \t]|$)" " " ${_aida_flagset} "${${_aida_flagset}}")
            string(REGEX REPLACE "[ \t]*/FS([ \t]|$)"     " " ${_aida_flagset} "${${_aida_flagset}}")
        endif()
    endforeach()

    if(NOT AIDA_SCCACHE_PROGRAM AND NOT CMAKE_GENERATOR MATCHES "Ninja")
        add_compile_options($<$<COMPILE_LANGUAGE:C,CXX>:/MP>)
    endif()
endif()

option(AIDA_ENABLE_LTCG "Enable /GL + /LTCG on AiDA.dll (slower link, marginally faster runtime)" OFF)
option(AIDA_FAST_LINK   "Use /DEBUG (default) instead of /DEBUG:FULL for faster linking" ON)
option(AIDA_HARDEN_RELEASE "Enable MSVC compiler/linker hardening (/GS /guard:cf /guard:ehcont /guard:xfg /Qspectre /sdl /CETCOMPAT /HIGHENTROPYVA /NXCOMPAT /DYNAMICBASE)" ON)
option(AIDA_HARDEN_XFG "Enable /guard:xfg (Extended Control Flow Guard, requires Win11 22H2+ runtime)" ON)
set(AIDA_BENCHMARK_REAL_PE "" CACHE FILEPATH
    "300-500MB PE fixture that enables the aida_c03_benchmark_real_harness ctest target (mirrors Test Lab AIDA_BENCHMARK_REAL_PE)")

find_package(Python3 COMPONENTS Interpreter QUIET)

if(MSVC AND AIDA_HARDEN_RELEASE)
    add_library(aida_hardening INTERFACE)
    target_compile_options(aida_hardening INTERFACE
        $<$<COMPILE_LANGUAGE:C,CXX>:/GS>
        $<$<COMPILE_LANGUAGE:C,CXX>:/guard:cf>
        $<$<COMPILE_LANGUAGE:C,CXX>:/guard:ehcont>
        $<$<COMPILE_LANGUAGE:C,CXX>:/Qspectre>
        $<$<COMPILE_LANGUAGE:CXX>:/sdl>
        $<$<AND:$<BOOL:${AIDA_HARDEN_XFG}>,$<COMPILE_LANGUAGE:C,CXX>>:/guard:xfg>
    )
    target_link_options(aida_hardening INTERFACE
        /DYNAMICBASE
        /HIGHENTROPYVA
        /NXCOMPAT
        /CETCOMPAT
        /guard:cf
        /guard:ehcont
        /force:guardehcont
    )
endif()

set(DEPS_DIR "${CMAKE_SOURCE_DIR}/.deps")

if(WIN32 AND MSVC)
    set(_aida_openssl_root "${OPENSSL_ROOT_DIR}")
    if(NOT _aida_openssl_root)
        set(_aida_openssl_root "$ENV{OPENSSL_ROOT_DIR}")
    endif()
    if(NOT _aida_openssl_root OR NOT EXISTS "${_aida_openssl_root}/include/openssl/ssl.h")
        foreach(_candidate
            "C:/Program Files/OpenSSL-Win64"
            "C:/Program Files/OpenSSL"
            "C:/OpenSSL-Win64"
        )
            if(EXISTS "${_candidate}/include/openssl/ssl.h")
                set(_aida_openssl_root "${_candidate}")
                break()
            endif()
        endforeach()
    endif()
    if(NOT _aida_openssl_root OR NOT EXISTS "${_aida_openssl_root}/include/openssl/ssl.h")
        message(FATAL_ERROR
            "OpenSSL headers not found. Set -DOPENSSL_ROOT_DIR=<path> or install "
            "OpenSSL (with static libs) under C:/Program Files/OpenSSL-Win64.")
    endif()
    set(_aida_openssl_lib_release "${_aida_openssl_root}/lib/VC/x64/MD")
    set(_aida_openssl_lib_debug   "${_aida_openssl_root}/lib/VC/x64/MDd")
    set(_aida_openssl_lib_release_mt "${_aida_openssl_root}/lib/VC/x64/MT")
    set(_aida_openssl_lib_debug_mt   "${_aida_openssl_root}/lib/VC/x64/MTd")
    if(NOT EXISTS "${_aida_openssl_lib_release}/libssl_static.lib"
       OR NOT EXISTS "${_aida_openssl_lib_release}/libcrypto_static.lib")
        message(FATAL_ERROR
            "OpenSSL static libraries not present at ${_aida_openssl_lib_release}. "
            "Reinstall OpenSSL with the static-libs option enabled so AiDAStandalone "
            "can link without runtime DLL dependencies (libssl-3-x64.dll / libcrypto-3-x64.dll).")
    endif()
    if(NOT EXISTS "${_aida_openssl_lib_release_mt}/libssl_static.lib"
       OR NOT EXISTS "${_aida_openssl_lib_release_mt}/libcrypto_static.lib")
        message(FATAL_ERROR
            "OpenSSL /MT static libraries not present at ${_aida_openssl_lib_release_mt}. "
            "Reinstall OpenSSL with the static-libs option enabled so AiDAStandalone "
            "can be shipped as a single executable.")
    endif()

    add_library(aida_openssl_crypto STATIC IMPORTED GLOBAL)
    set_target_properties(aida_openssl_crypto PROPERTIES
        IMPORTED_LOCATION                "${_aida_openssl_lib_release}/libcrypto_static.lib"
        IMPORTED_LOCATION_RELEASE        "${_aida_openssl_lib_release}/libcrypto_static.lib"
        IMPORTED_LOCATION_RELWITHDEBINFO "${_aida_openssl_lib_release}/libcrypto_static.lib"
        IMPORTED_LOCATION_MINSIZEREL     "${_aida_openssl_lib_release}/libcrypto_static.lib"
        IMPORTED_LOCATION_DEBUG          "${_aida_openssl_lib_debug}/libcrypto_static.lib"
        INTERFACE_INCLUDE_DIRECTORIES    "${_aida_openssl_root}/include"
        INTERFACE_LINK_LIBRARIES         "ws2_32;crypt32;advapi32;user32;gdi32"
    )

    add_library(aida_openssl_ssl STATIC IMPORTED GLOBAL)
    set_target_properties(aida_openssl_ssl PROPERTIES
        IMPORTED_LOCATION                "${_aida_openssl_lib_release}/libssl_static.lib"
        IMPORTED_LOCATION_RELEASE        "${_aida_openssl_lib_release}/libssl_static.lib"
        IMPORTED_LOCATION_RELWITHDEBINFO "${_aida_openssl_lib_release}/libssl_static.lib"
        IMPORTED_LOCATION_MINSIZEREL     "${_aida_openssl_lib_release}/libssl_static.lib"
        IMPORTED_LOCATION_DEBUG          "${_aida_openssl_lib_debug}/libssl_static.lib"
        INTERFACE_INCLUDE_DIRECTORIES    "${_aida_openssl_root}/include"
        INTERFACE_LINK_LIBRARIES         "aida_openssl_crypto"
    )

    add_library(aida_openssl_crypto_mt STATIC IMPORTED GLOBAL)
    set_target_properties(aida_openssl_crypto_mt PROPERTIES
        IMPORTED_LOCATION                "${_aida_openssl_lib_release_mt}/libcrypto_static.lib"
        IMPORTED_LOCATION_RELEASE        "${_aida_openssl_lib_release_mt}/libcrypto_static.lib"
        IMPORTED_LOCATION_RELWITHDEBINFO "${_aida_openssl_lib_release_mt}/libcrypto_static.lib"
        IMPORTED_LOCATION_MINSIZEREL     "${_aida_openssl_lib_release_mt}/libcrypto_static.lib"
        IMPORTED_LOCATION_DEBUG          "${_aida_openssl_lib_debug_mt}/libcrypto_static.lib"
        INTERFACE_INCLUDE_DIRECTORIES    "${_aida_openssl_root}/include"
        INTERFACE_LINK_LIBRARIES         "ws2_32;crypt32;advapi32;user32;gdi32"
    )

    add_library(aida_openssl_ssl_mt STATIC IMPORTED GLOBAL)
    set_target_properties(aida_openssl_ssl_mt PROPERTIES
        IMPORTED_LOCATION                "${_aida_openssl_lib_release_mt}/libssl_static.lib"
        IMPORTED_LOCATION_RELEASE        "${_aida_openssl_lib_release_mt}/libssl_static.lib"
        IMPORTED_LOCATION_RELWITHDEBINFO "${_aida_openssl_lib_release_mt}/libssl_static.lib"
        IMPORTED_LOCATION_MINSIZEREL     "${_aida_openssl_lib_release_mt}/libssl_static.lib"
        IMPORTED_LOCATION_DEBUG          "${_aida_openssl_lib_debug_mt}/libssl_static.lib"
        INTERFACE_INCLUDE_DIRECTORIES    "${_aida_openssl_root}/include"
        INTERFACE_LINK_LIBRARIES         "aida_openssl_crypto_mt"
    )

    set(OPENSSL_FOUND TRUE CACHE BOOL "" FORCE)
    set(OPENSSL_INCLUDE_DIR "${_aida_openssl_root}/include" CACHE PATH "" FORCE)
    set(OPENSSL_SSL_LIBRARY "${_aida_openssl_lib_release}/libssl_static.lib" CACHE FILEPATH "" FORCE)
    set(OPENSSL_CRYPTO_LIBRARY "${_aida_openssl_lib_release}/libcrypto_static.lib" CACHE FILEPATH "" FORCE)
    set(OPENSSL_LIBRARIES "${OPENSSL_SSL_LIBRARY};${OPENSSL_CRYPTO_LIBRARY}" CACHE STRING "" FORCE)
    set(OPENSSL_VERSION "3.0.0" CACHE STRING "" FORCE)

    message(STATUS "AiDA: OpenSSL static linking enabled (root=${_aida_openssl_root})")
    set(CMAKE_INSTALL_UCRT_LIBRARIES TRUE)
    set(CMAKE_INSTALL_OPENMP_LIBRARIES TRUE)
    include(InstallRequiredSystemLibraries)
endif()

function(aida_collect_windows_runtime_dlls out_var)
    set(_aida_result)
    foreach(_aida_system_runtime_dll IN LISTS CMAKE_INSTALL_SYSTEM_RUNTIME_LIBS)
        if(EXISTS "${_aida_system_runtime_dll}")
            list(APPEND _aida_result "${_aida_system_runtime_dll}")
        endif()
    endforeach()

    if(MSVC)
        set(_aida_vs_redist_roots)
        if(DEFINED ENV{VCToolsRedistDir} AND NOT "$ENV{VCToolsRedistDir}" STREQUAL "")
            file(TO_CMAKE_PATH "$ENV{VCToolsRedistDir}" _aida_vc_redist_env)
            list(APPEND _aida_vs_redist_roots "${_aida_vc_redist_env}")
        endif()
        if(CMAKE_CXX_COMPILER)
            get_filename_component(_aida_msvc_bin "${CMAKE_CXX_COMPILER}" DIRECTORY)
            get_filename_component(_aida_msvc_tools_version "${_aida_msvc_bin}/../../.." ABSOLUTE)
            get_filename_component(_aida_vc_root "${_aida_msvc_tools_version}/../../.." ABSOLUTE)
            list(APPEND _aida_vs_redist_roots "${_aida_vc_root}/Redist/MSVC")
        endif()
        list(APPEND _aida_vs_redist_roots
            "C:/Program Files/Microsoft Visual Studio/2022/Professional/VC/Redist/MSVC"
            "C:/Program Files/Microsoft Visual Studio/2022/Enterprise/VC/Redist/MSVC"
            "C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Redist/MSVC"
            "C:/Program Files/Microsoft Visual Studio/2022/BuildTools/VC/Redist/MSVC"
            "C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Redist/MSVC"
        )
        list(REMOVE_DUPLICATES _aida_vs_redist_roots)

        set(_aida_crt_dirs)
        foreach(_aida_vs_redist_root IN LISTS _aida_vs_redist_roots)
            file(GLOB _aida_crt_root_dirs CONFIGURE_DEPENDS
                "${_aida_vs_redist_root}/x64/Microsoft.VC*.CRT"
                "${_aida_vs_redist_root}/*/x64/Microsoft.VC*.CRT")
            list(APPEND _aida_crt_dirs ${_aida_crt_root_dirs})
        endforeach()
        if(NOT _aida_crt_dirs)
            foreach(_aida_vs_redist_root IN LISTS _aida_vs_redist_roots)
                file(GLOB _aida_crt_spectre_dirs CONFIGURE_DEPENDS
                    "${_aida_vs_redist_root}/spectre/x64/Microsoft.VC*.CRT"
                    "${_aida_vs_redist_root}/*/spectre/x64/Microsoft.VC*.CRT")
                list(APPEND _aida_crt_dirs ${_aida_crt_spectre_dirs})
            endforeach()
        endif()
        if(_aida_crt_dirs)
            list(REMOVE_DUPLICATES _aida_crt_dirs)
            list(SORT _aida_crt_dirs COMPARE NATURAL ORDER DESCENDING)
            list(GET _aida_crt_dirs 0 _aida_crt_dir)
            file(GLOB _aida_crt_dlls CONFIGURE_DEPENDS "${_aida_crt_dir}/*.dll")
            list(APPEND _aida_result ${_aida_crt_dlls})
        else()
            message(FATAL_ERROR "AiDA: Visual C++ x64 redistributable DLLs not found. Install the VS 2022 C++ redistributable files with the build tools.")
        endif()

        set(_aida_ucrt_dirs)
        if(DEFINED ENV{UniversalCRTSdkDir} AND NOT "$ENV{UniversalCRTSdkDir}" STREQUAL "")
            file(TO_CMAKE_PATH "$ENV{UniversalCRTSdkDir}" _aida_ucrt_sdk_dir)
            if(DEFINED ENV{UCRTVersion} AND NOT "$ENV{UCRTVersion}" STREQUAL "")
                list(APPEND _aida_ucrt_dirs "${_aida_ucrt_sdk_dir}/Redist/$ENV{UCRTVersion}/ucrt/DLLs/x64")
            endif()
            list(APPEND _aida_ucrt_dirs "${_aida_ucrt_sdk_dir}/Redist/ucrt/DLLs/x64")
        endif()
        file(GLOB _aida_ucrt_redist_dirs CONFIGURE_DEPENDS
            "C:/Program Files (x86)/Windows Kits/10/Redist/*/ucrt/DLLs/x64")
        list(APPEND _aida_ucrt_dirs ${_aida_ucrt_redist_dirs})
        list(APPEND _aida_ucrt_dirs
            "C:/Program Files (x86)/Windows Kits/10/Redist/ucrt/DLLs/x64"
            "C:/Program Files/Windows Kits/10/Redist/ucrt/DLLs/x64"
        )
        list(REMOVE_DUPLICATES _aida_ucrt_dirs)
        set(_aida_existing_ucrt_dirs)
        foreach(_aida_ucrt_dir IN LISTS _aida_ucrt_dirs)
            if(EXISTS "${_aida_ucrt_dir}/ucrtbase.dll")
                list(APPEND _aida_existing_ucrt_dirs "${_aida_ucrt_dir}")
            endif()
        endforeach()
        if(_aida_existing_ucrt_dirs)
            list(SORT _aida_existing_ucrt_dirs COMPARE NATURAL ORDER DESCENDING)
            list(GET _aida_existing_ucrt_dirs 0 _aida_ucrt_dir)
            file(GLOB _aida_ucrt_dlls CONFIGURE_DEPENDS "${_aida_ucrt_dir}/*.dll")
            list(APPEND _aida_result ${_aida_ucrt_dlls})
        else()
            message(FATAL_ERROR "AiDA: Windows UCRT x64 redistributable DLLs not found. Install a Windows 10/11 SDK with Redist/ucrt/DLLs/x64.")
        endif()

    endif()

    list(REMOVE_DUPLICATES _aida_result)
    set(${out_var} "${_aida_result}" PARENT_SCOPE)
endfunction()

function(aida_dedupe_runtime_dlls_by_filename out_var)
    set(_aida_result)
    set(_aida_seen_names)
    foreach(_aida_runtime_dll IN LISTS ARGN)
        if(NOT EXISTS "${_aida_runtime_dll}")
            continue()
        endif()
        get_filename_component(_aida_runtime_name "${_aida_runtime_dll}" NAME)
        string(TOLOWER "${_aida_runtime_name}" _aida_runtime_name_lower)
        if(NOT _aida_runtime_name_lower IN_LIST _aida_seen_names)
            list(APPEND _aida_seen_names "${_aida_runtime_name_lower}")
            list(APPEND _aida_result "${_aida_runtime_dll}")
        endif()
    endforeach()
    set(${out_var} "${_aida_result}" PARENT_SCOPE)
endfunction()

function(aida_strip_msvc_runtime_compile_options target_name)
    if(NOT MSVC OR NOT TARGET ${target_name})
        return()
    endif()
    foreach(_aida_runtime_prop IN ITEMS COMPILE_OPTIONS INTERFACE_COMPILE_OPTIONS)
        get_target_property(_aida_runtime_opts ${target_name} ${_aida_runtime_prop})
        if(NOT _aida_runtime_opts)
            continue()
        endif()
        set(_aida_runtime_filtered)
        foreach(_aida_runtime_opt IN LISTS _aida_runtime_opts)
            if(_aida_runtime_opt MATCHES "^/M[DT]d?$" OR
               _aida_runtime_opt MATCHES "^\\$<.*:/M[DT]d?>$")
                continue()
            endif()
            list(APPEND _aida_runtime_filtered "${_aida_runtime_opt}")
        endforeach()
        set_target_properties(${target_name} PROPERTIES ${_aida_runtime_prop} "${_aida_runtime_filtered}")
    endforeach()
endfunction()

function(aida_use_static_msvc_runtime)
    if(NOT MSVC)
        return()
    endif()
    foreach(_aida_runtime_target IN LISTS ARGN)
        if(TARGET ${_aida_runtime_target})
            aida_strip_msvc_runtime_compile_options(${_aida_runtime_target})
            set_property(TARGET ${_aida_runtime_target} PROPERTY
                MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
        endif()
    endforeach()
endfunction()

set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_SHARED_LIB OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_MAN OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_DOXYGEN OFF CACHE BOOL "" FORCE)
set(ZYCORE_BUILD_SHARED_LIB OFF CACHE BOOL "" FORCE)
set(ZYCORE_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(ZYCORE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(ZYDIS_FEATURE_ENCODER ON CACHE BOOL "" FORCE)

set(zydis_SOURCE_DIR "${DEPS_DIR}/zydis-4.1.1")
set(zydis_BINARY_DIR "${CMAKE_BINARY_DIR}/.deps/zydis-4.1.1")
set(zycore_SOURCE_DIR "${zydis_SOURCE_DIR}/dependencies/zycore")
set(capstone_SOURCE_DIR "${DEPS_DIR}/capstone/capstone-5.0.9")
set(capstone_BINARY_DIR "${CMAKE_BINARY_DIR}/.deps/capstone-5.0.9")
set(json_schema_validator_SOURCE_DIR "${DEPS_DIR}/json-schema-validator-2.4.0")
set(json_schema_validator_BINARY_DIR
    "${CMAKE_BINARY_DIR}/.deps/json-schema-validator-2.4.0")
set(ZYAN_SYSTEM_ZYCORE OFF CACHE BOOL "" FORCE)
set(ZYAN_ZYCORE_PATH "${zycore_SOURCE_DIR}" CACHE PATH "" FORCE)
set(AIDA_ANALYSIS_NOTICE_LEDGER_FILE
    "${CMAKE_CURRENT_SOURCE_DIR}/src/standalone/THIRD_PARTY_NOTICES_ANALYSIS.md")
set(AIDA_CAPSTONE_LICENSE_FILE
    "${CMAKE_CURRENT_SOURCE_DIR}/src/standalone/third_party_notices/Capstone-LICENSE.txt")
set(AIDA_JSON_SCHEMA_VALIDATOR_LICENSE_FILE
    "${CMAKE_CURRENT_SOURCE_DIR}/src/standalone/third_party_notices/nlohmann-json-schema-validator-LICENSE.txt")
set(AIDA_GHIDRA_LICENSE_FILE
    "${CMAKE_CURRENT_SOURCE_DIR}/src/standalone/third_party_notices/Ghidra-LICENSE.txt")
set(AIDA_GHIDRA_NOTICE_FILE
    "${CMAKE_CURRENT_SOURCE_DIR}/src/standalone/third_party_notices/Ghidra-NOTICE.txt")
set(AIDA_ZSTD_LICENSE_FILE
    "${CMAKE_CURRENT_SOURCE_DIR}/src/standalone/third_party_notices/zstd-LICENSE.txt")
set(AIDA_LIBLZMA_LICENSE_FILE
    "${CMAKE_CURRENT_SOURCE_DIR}/src/standalone/third_party_notices/liblzma-COPYING.txt")
set(AIDA_PCRE2_LICENSE_FILE
    "${CMAKE_CURRENT_SOURCE_DIR}/src/standalone/third_party_notices/PCRE2-LICENCE.txt")
set(AIDA_PARALLEL_HASHMAP_LICENSE_FILE
    "${CMAKE_CURRENT_SOURCE_DIR}/src/standalone/third_party_notices/parallel-hashmap-LICENSE.txt")
set(AIDA_CONCURRENTQUEUE_LICENSE_FILE
    "${CMAKE_CURRENT_SOURCE_DIR}/src/standalone/third_party_notices/concurrentqueue-LICENSE.txt")
set(parallel_hashmap_SOURCE_DIR "${DEPS_DIR}/parallel-hashmap-2.0.0/parallel-hashmap-2.0.0")
set(concurrentqueue_SOURCE_DIR "${DEPS_DIR}/concurrentqueue-1.0.5/concurrentqueue-1.0.5")
foreach(_aida_required_analysis_dependency IN ITEMS
        "${zydis_SOURCE_DIR}/CMakeLists.txt"
        "${zydis_SOURCE_DIR}/include/Zydis/Zydis.h"
        "${zycore_SOURCE_DIR}/CMakeLists.txt"
        "${zycore_SOURCE_DIR}/include/Zycore/Zycore.h"
        "${DEPS_DIR}/sqlite-amalgamation-3530300/sqlite3.c"
        "${DEPS_DIR}/sqlite-amalgamation-3530300/sqlite3.h"
        "${DEPS_DIR}/taskflow/taskflow/taskflow.hpp"
        "${DEPS_DIR}/zlib/CMakeLists.txt"
        "${DEPS_DIR}/zlib/zlib.h"
        "${DEPS_DIR}/zlib/LICENSE"
        "${CMAKE_CURRENT_SOURCE_DIR}/libs/nlohmann/json.hpp"
        "${capstone_SOURCE_DIR}/CMakeLists.txt"
        "${capstone_SOURCE_DIR}/include/capstone/capstone.h"
        "${capstone_SOURCE_DIR}/LICENSE.TXT"
        "${json_schema_validator_SOURCE_DIR}/CMakeLists.txt"
        "${json_schema_validator_SOURCE_DIR}/src/nlohmann/json-schema.hpp"
        "${json_schema_validator_SOURCE_DIR}/LICENSE"
        "${DEPS_DIR}/zstd-1.5.7/LICENSE"
        "${DEPS_DIR}/xz-5.8.3/COPYING"
        "${DEPS_DIR}/pcre2-10.47/LICENCE.md"
        "${parallel_hashmap_SOURCE_DIR}/parallel_hashmap/phmap.h"
        "${parallel_hashmap_SOURCE_DIR}/LICENSE"
        "${concurrentqueue_SOURCE_DIR}/concurrentqueue.h"
        "${concurrentqueue_SOURCE_DIR}/blockingconcurrentqueue.h"
        "${concurrentqueue_SOURCE_DIR}/lightweightsemaphore.h"
        "${concurrentqueue_SOURCE_DIR}/LICENSE.md"
        "${AIDA_PARALLEL_HASHMAP_LICENSE_FILE}"
        "${AIDA_CONCURRENTQUEUE_LICENSE_FILE}"
        "${AIDA_ANALYSIS_NOTICE_LEDGER_FILE}")
    if(NOT EXISTS "${_aida_required_analysis_dependency}")
        message(FATAL_ERROR "AiDA: required pinned analysis dependency or notice is missing: ${_aida_required_analysis_dependency}")
    endif()
endforeach()
function(aida_require_analysis_file_sha256 file_path expected_sha256)
    if(NOT EXISTS "${file_path}")
        message(FATAL_ERROR "AiDA: required pinned analysis file is missing: ${file_path}")
    endif()
endfunction()
function(aida_require_analysis_text_sha256 file_path expected_sha256)
    if(NOT EXISTS "${file_path}")
        message(FATAL_ERROR "AiDA: required pinned analysis notice is missing: ${file_path}")
    endif()
endfunction()
aida_require_analysis_file_sha256(
    "${zydis_SOURCE_DIR}/LICENSE"
    "e5e99718209e94baaf3e9cbf6f64aa3329c9e73c63b1ab47e10f29d81974e6f3")
aida_require_analysis_file_sha256(
    "${zycore_SOURCE_DIR}/LICENSE"
    "7991ec4481a82c51d196f7440fda34c578aab51f8b9c7023935c6e03b57638bd")
aida_require_analysis_file_sha256(
    "${DEPS_DIR}/sqlite-amalgamation-3530300/sqlite3.c"
    "87497ab605bedd0dbee27a209c1eeff8c89b229b13f921a7efdbb81a13f779fd")
aida_require_analysis_file_sha256(
    "${DEPS_DIR}/sqlite-amalgamation-3530300/sqlite3.h"
    "4ff81af4849acabc76fc8349abb926814395072617ca18e08800abf734ab7612")
aida_require_analysis_file_sha256(
    "${DEPS_DIR}/taskflow/LICENSE"
    "aa797f3efb1fab9c55c3b2f6d905b6f447d23c17c53a56c19b1f885d55150a01")
aida_require_analysis_file_sha256(
    "${DEPS_DIR}/zlib/CMakeLists.txt"
    "c11f6c94a007132d353d3bf865a4e89496104815c2f0f236df213c1fd3ca0b87")
aida_require_analysis_file_sha256(
    "${DEPS_DIR}/zlib/zlib.h"
    "d31ea3abacb0e2ce9b5a43b53395440ebd282a9828f242c9d2d70d2e9395d8be")
aida_require_analysis_file_sha256(
    "${DEPS_DIR}/zlib/LICENSE"
    "439c75ab12b340c5362b9d4b08ff05ec3a4d0eb7667a6fff49a9b16d8795c78e")
aida_require_analysis_file_sha256(
    "${DEPS_DIR}/licenses/nlohmann-json-3.12.0-LICENSE.MIT"
    "46a65cffd1ea955132d95a8dd921640714a8d6b537d2e4e482d31145ae95b603")
aida_require_analysis_file_sha256(
    "${capstone_SOURCE_DIR}/CMakeLists.txt"
    "2b5eb43abba6ad34b9fd4aabea18a0c6fe4b49e5aab34a8b6111e66c6f706f49")
aida_require_analysis_file_sha256(
    "${capstone_SOURCE_DIR}/include/capstone/capstone.h"
    "b98e0fbd0f460fe4641ec2c7424bf6b6ad7120178c7d52cb6f8dd175c469bc6d")
aida_require_analysis_file_sha256(
    "${capstone_SOURCE_DIR}/LICENSE.TXT"
    "65e9ed46a59976eda8f5bd1ea79a680dea38dd299c760bc9a8d87a764ef5029b")
aida_require_analysis_text_sha256(
    "${AIDA_CAPSTONE_LICENSE_FILE}"
    "65e9ed46a59976eda8f5bd1ea79a680dea38dd299c760bc9a8d87a764ef5029b")
aida_require_analysis_file_sha256(
    "${json_schema_validator_SOURCE_DIR}/CMakeLists.txt"
    "6855fe2ce65170637b067fe7362f71df0b8a1efe2ed27e05a93aa205c0676f4b")
aida_require_analysis_file_sha256(
    "${json_schema_validator_SOURCE_DIR}/src/nlohmann/json-schema.hpp"
    "2d9772aee4cb7ddb6d338eac207c965fe2cd283a045dc35dfa9c0aaec481247b")
aida_require_analysis_file_sha256(
    "${json_schema_validator_SOURCE_DIR}/LICENSE"
    "4294d027a5205eea79a5241b2c1423d556efaa3139df8cea5ac313fb5ffb07bf")
aida_require_analysis_text_sha256(
    "${AIDA_JSON_SCHEMA_VALIDATOR_LICENSE_FILE}"
    "4294d027a5205eea79a5241b2c1423d556efaa3139df8cea5ac313fb5ffb07bf")
aida_require_analysis_text_sha256(
    "${AIDA_GHIDRA_LICENSE_FILE}"
    "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4")
aida_require_analysis_text_sha256(
    "${AIDA_GHIDRA_NOTICE_FILE}"
    "ad4b2bb6e75e908251226180081b5afa01c7161d7710e08b603d0c340a08a23f")
aida_require_analysis_file_sha256(
    "${DEPS_DIR}/zstd-1.5.7/LICENSE"
    "7055266497633c9025b777c78eb7235af13922117480ed5c674677adc381c9d8")
aida_require_analysis_text_sha256(
    "${AIDA_ZSTD_LICENSE_FILE}"
    "7055266497633c9025b777c78eb7235af13922117480ed5c674677adc381c9d8")
aida_require_analysis_file_sha256(
    "${DEPS_DIR}/xz-5.8.3/COPYING"
    "616a3ad264ce29b8f1cb97e53037b139d406899ca8d1f799651e17bfa09830b8")
aida_require_analysis_text_sha256(
    "${AIDA_LIBLZMA_LICENSE_FILE}"
    "616a3ad264ce29b8f1cb97e53037b139d406899ca8d1f799651e17bfa09830b8")
aida_require_analysis_file_sha256(
    "${DEPS_DIR}/pcre2-10.47/LICENCE.md"
    "197d8a73ffee0d6b09adba2f9c677b5f5aede24edf89258a68e48248d010d811")
aida_require_analysis_text_sha256(
    "${AIDA_PCRE2_LICENSE_FILE}"
    "197d8a73ffee0d6b09adba2f9c677b5f5aede24edf89258a68e48248d010d811")
aida_require_analysis_file_sha256(
    "${parallel_hashmap_SOURCE_DIR}/parallel_hashmap/phmap.h"
    "1ee9253539dbc1c06cd9879aa8d362bd4e2e77f5a3201b0cb966c36667f975fd")
aida_require_analysis_file_sha256(
    "${parallel_hashmap_SOURCE_DIR}/LICENSE"
    "aac73b3148f6d1d7111dbca32099f68d26c644c6813ae1e4f05f6579aa2663fe")
aida_require_analysis_file_sha256(
    "${concurrentqueue_SOURCE_DIR}/concurrentqueue.h"
    "f352dd5924ad6f23e9e09d62aa564713eadccf4cb29dc08c07d64e1c11050ecf")
aida_require_analysis_file_sha256(
    "${concurrentqueue_SOURCE_DIR}/blockingconcurrentqueue.h"
    "d3a1354968f09b5dd13254618b45ce549c772a7b7a4be9acf8fc3c847f779f73")
aida_require_analysis_file_sha256(
    "${concurrentqueue_SOURCE_DIR}/lightweightsemaphore.h"
    "44644ccd1b8d3d39459b15a036c5330d1d0161092c705d483b3dbb76c8066442")
aida_require_analysis_file_sha256(
    "${concurrentqueue_SOURCE_DIR}/LICENSE.md"
    "22331571e5e3dbe4c79ad715e23127bdf3beabd75052c953ddabf191ef799e14")
aida_require_analysis_text_sha256(
    "${AIDA_PARALLEL_HASHMAP_LICENSE_FILE}"
    "aac73b3148f6d1d7111dbca32099f68d26c644c6813ae1e4f05f6579aa2663fe")
aida_require_analysis_text_sha256(
    "${AIDA_CONCURRENTQUEUE_LICENSE_FILE}"
    "22331571e5e3dbe4c79ad715e23127bdf3beabd75052c953ddabf191ef799e14")
add_subdirectory("${zydis_SOURCE_DIR}" "${zydis_BINARY_DIR}")

if(MSVC AND TARGET Zycore)
    get_target_property(_zycore_opts Zycore INTERFACE_COMPILE_OPTIONS)
    if(_zycore_opts)
        set(_zycore_opts_scoped)
        foreach(_opt IN LISTS _zycore_opts)
            if(_opt STREQUAL "/wd4201" OR _opt MATCHES "^/wd[0-9]+$" OR _opt MATCHES "^/W[0-9]$" OR _opt STREQUAL "/WX")
                list(APPEND _zycore_opts_scoped "$<$<COMPILE_LANGUAGE:C,CXX>:${_opt}>")
            else()
                list(APPEND _zycore_opts_scoped "${_opt}")
            endif()
        endforeach()
        set_target_properties(Zycore PROPERTIES INTERFACE_COMPILE_OPTIONS "${_zycore_opts_scoped}")
    endif()
    get_target_property(_zycore_priv Zycore COMPILE_OPTIONS)
    if(_zycore_priv)
        set(_zycore_priv_scoped)
        foreach(_opt IN LISTS _zycore_priv)
            if(_opt STREQUAL "/wd4201" OR _opt MATCHES "^/wd[0-9]+$" OR _opt MATCHES "^/W[0-9]$" OR _opt STREQUAL "/WX")
                list(APPEND _zycore_priv_scoped "$<$<COMPILE_LANGUAGE:C,CXX>:${_opt}>")
            else()
                list(APPEND _zycore_priv_scoped "${_opt}")
            endif()
        endforeach()
        set_target_properties(Zycore PROPERTIES COMPILE_OPTIONS "${_zycore_priv_scoped}")
    endif()
endif()
if(MSVC AND TARGET Zydis)
    get_target_property(_zydis_opts Zydis INTERFACE_COMPILE_OPTIONS)
    if(_zydis_opts)
        set(_zydis_opts_scoped)
        foreach(_opt IN LISTS _zydis_opts)
            if(_opt STREQUAL "/wd4201" OR _opt MATCHES "^/wd[0-9]+$" OR _opt MATCHES "^/W[0-9]$" OR _opt STREQUAL "/WX")
                list(APPEND _zydis_opts_scoped "$<$<COMPILE_LANGUAGE:C,CXX>:${_opt}>")
            else()
                list(APPEND _zydis_opts_scoped "${_opt}")
            endif()
        endforeach()
        set_target_properties(Zydis PROPERTIES INTERFACE_COMPILE_OPTIONS "${_zydis_opts_scoped}")
    endif()
    get_target_property(_zydis_priv Zydis COMPILE_OPTIONS)
    if(_zydis_priv)
        set(_zydis_priv_scoped)
        foreach(_opt IN LISTS _zydis_priv)
            if(_opt STREQUAL "/wd4201" OR _opt MATCHES "^/wd[0-9]+$" OR _opt MATCHES "^/W[0-9]$" OR _opt STREQUAL "/WX")
                list(APPEND _zydis_priv_scoped "$<$<COMPILE_LANGUAGE:C,CXX>:${_opt}>")
            else()
                list(APPEND _zydis_priv_scoped "${_opt}")
            endif()
        endforeach()
        set_target_properties(Zydis PROPERTIES COMPILE_OPTIONS "${_zydis_priv_scoped}")
    endif()
endif()
set(UNICORN_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(UNICORN_ARCH "x86" CACHE STRING "" FORCE)
set(UNICORN_INSTALL OFF CACHE BOOL "" FORCE)
set(BUILD_SHARED_LIBS_SAVED "${BUILD_SHARED_LIBS}")
set(BUILD_SHARED_LIBS OFF)

option(BUILD_AIDA_PLUGIN "Build the AiDA IDA plugin" ON)

set(unicorn_SOURCE_DIR "${DEPS_DIR}/unicorn")
add_subdirectory("${unicorn_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/.deps/unicorn")
set(BUILD_SHARED_LIBS "${BUILD_SHARED_LIBS_SAVED}")

set(ZLIB_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(SKIP_INSTALL_ALL ON CACHE BOOL "" FORCE)
set(zlib_SOURCE_DIR "${DEPS_DIR}/zlib")
set(zlib_BINARY_DIR "${CMAKE_BINARY_DIR}/.deps/zlib")
add_subdirectory("${zlib_SOURCE_DIR}" "${zlib_BINARY_DIR}")

set(ZSTD_BUILD_STATIC ON CACHE BOOL "" FORCE)
set(ZSTD_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(ZSTD_BUILD_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ZSTD_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(ZSTD_BUILD_CONTRIB OFF CACHE BOOL "" FORCE)
set(zstd_SOURCE_DIR "${DEPS_DIR}/zstd-1.5.7/build/cmake")
set(zstd_BINARY_DIR "${CMAKE_BINARY_DIR}/.deps/zstd")
add_subdirectory("${zstd_SOURCE_DIR}" "${zstd_BINARY_DIR}")

set(BUILD_SHARED_LIBS_SAVED_XZ "${BUILD_SHARED_LIBS}")
set(BUILD_TESTING_SAVED_XZ "${BUILD_TESTING}")
set(BUILD_SHARED_LIBS OFF)
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(XZ_THREADS no CACHE STRING "" FORCE)
set(XZ_NLS OFF CACHE BOOL "" FORCE)
set(XZ_TOOL_XZ OFF CACHE BOOL "" FORCE)
set(XZ_TOOL_XZDEC OFF CACHE BOOL "" FORCE)
set(XZ_TOOL_LZMADEC OFF CACHE BOOL "" FORCE)
set(XZ_TOOL_LZMAINFO OFF CACHE BOOL "" FORCE)
set(XZ_DOC OFF CACHE BOOL "" FORCE)
set(XZ_DOXYGEN OFF CACHE BOOL "" FORCE)
set(xz_SOURCE_DIR "${DEPS_DIR}/xz-5.8.3")
set(xz_BINARY_DIR "${CMAKE_BINARY_DIR}/.deps/xz")
add_subdirectory("${xz_SOURCE_DIR}" "${xz_BINARY_DIR}")
set(BUILD_SHARED_LIBS "${BUILD_SHARED_LIBS_SAVED_XZ}")
set(BUILD_TESTING "${BUILD_TESTING_SAVED_XZ}" CACHE BOOL "" FORCE)
target_include_directories(liblzma PUBLIC
    $<BUILD_INTERFACE:${xz_SOURCE_DIR}/src/liblzma/api>
    $<INSTALL_INTERFACE:include>)

# zlib manages its own include dirs; expose them for our consumers via a convenience variable
# but do NOT set PUBLIC includes on zlibstatic (causes CMP0070 errors with newer CMake)

set(BROTLI_DISABLE_TESTS ON CACHE BOOL "" FORCE)
set(BROTLI_BUNDLED_MODE ON CACHE BOOL "" FORCE)
set(brotli_SOURCE_DIR "${DEPS_DIR}/brotli")
add_subdirectory("${brotli_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/.deps/brotli")

if(TARGET brotlidec)
    target_include_directories(brotlidec PUBLIC
        "${brotli_SOURCE_DIR}/c/include"
    )
endif()

set(LLHTTP_BUILD_SHARED_LIBS OFF CACHE INTERNAL "")
set(LLHTTP_BUILD_STATIC_LIBS ON CACHE INTERNAL "")
set(_llhttp_build_shared_libs_saved "${BUILD_SHARED_LIBS}")
set(_llhttp_build_static_libs_saved "${BUILD_STATIC_LIBS}")
set(BUILD_SHARED_LIBS OFF)
set(BUILD_STATIC_LIBS ON)
# The llhttp git repo uses "_RELEASE_" as a version placeholder (substituted by npm during release).
# Patch it to a real semver string so CMake's project() call doesn't reject it.
file(READ "${DEPS_DIR}/llhttp/CMakeLists.txt" _llhttp_cmake)
if("${_llhttp_cmake}" MATCHES "VERSION _RELEASE_")
    string(REPLACE "VERSION _RELEASE_" "VERSION 9.3.0" _llhttp_cmake "${_llhttp_cmake}")
    file(WRITE "${DEPS_DIR}/llhttp/CMakeLists.txt" "${_llhttp_cmake}")
endif()
add_subdirectory("${DEPS_DIR}/llhttp" "${CMAKE_BINARY_DIR}/.deps/llhttp")
set(BUILD_SHARED_LIBS "${_llhttp_build_shared_libs_saved}")
set(BUILD_STATIC_LIBS "${_llhttp_build_static_libs_saved}")

set(BUILD_SHARED_LIBS_SAVED_NH2 "${BUILD_SHARED_LIBS}")
set(BUILD_STATIC_LIBS   ON)
set(BUILD_SHARED_LIBS  OFF)
set(ENABLE_LIB_ONLY     ON)
set(ENABLE_DOC          OFF)
set(ENABLE_APP          OFF)
set(ENABLE_EXAMPLES     OFF)
set(ENABLE_FAILMALLOC  OFF)
set(ENABLE_HPACK_TOOLS OFF)
set(WITH_LIBXML2       OFF)
set(WITH_JEMALLOC      OFF)
set(WITH_SPDYLAY       OFF)
add_subdirectory("${DEPS_DIR}/nghttp2" "${CMAKE_BINARY_DIR}/.deps/nghttp2")
set(BUILD_SHARED_LIBS "${BUILD_SHARED_LIBS_SAVED_NH2}")
unset(BUILD_STATIC_LIBS)

if(TARGET nghttp2_static)
    if(MSVC)
        target_compile_options(nghttp2_static PRIVATE /wd4100 /wd4244 /wd4267)
    endif()
endif()

set(lua_src_SOURCE_DIR "${DEPS_DIR}/lua-lua-a5522f0")

file(GLOB LUA_CORE_SOURCES "${lua_src_SOURCE_DIR}/*.c")
list(REMOVE_ITEM LUA_CORE_SOURCES
    "${lua_src_SOURCE_DIR}/lua.c"           # standalone interpreter
    "${lua_src_SOURCE_DIR}/luac.c"          # standalone compiler
    "${lua_src_SOURCE_DIR}/onelua.c"        # single-file build; all sources already included individually
    "${lua_src_SOURCE_DIR}/ltests.c"
)
add_library(lua54_static STATIC
    ${LUA_CORE_SOURCES}
    "${CMAKE_CURRENT_SOURCE_DIR}/src/standalone/src/core/tools/lua_abi.c"
)
target_include_directories(lua54_static PUBLIC "${lua_src_SOURCE_DIR}")
target_compile_definitions(lua54_static PRIVATE AIDA_LUA_ABI_RELEASE=50408)
set_target_properties(lua54_static PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
)
if(MSVC)
    if(CMAKE_GENERATOR MATCHES "Ninja")
        set_property(TARGET lua54_static PROPERTY JOB_POOL_COMPILE aida_serial_compile)
    endif()
    target_compile_options(lua54_static PRIVATE /W3 /wd4244 /wd4702 /wd4334)
    target_compile_definitions(lua54_static PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

set(sol2_SOURCE_DIR "${DEPS_DIR}/sol2")
set(SOL2_LUA_VERSION "5.4.8" CACHE STRING "" FORCE)
add_subdirectory("${sol2_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/.deps/sol2")

if(MSVC AND TARGET x86_64-softmmu)
    if(CMAKE_GENERATOR MATCHES "Ninja")
        set_property(TARGET x86_64-softmmu PROPERTY JOB_POOL_COMPILE aida_heavy_compile)
    endif()
    target_compile_options(x86_64-softmmu PRIVATE $<$<COMPILE_LANGUAGE:C,CXX>:/wd4319>)
endif()
if(MSVC AND TARGET unicorn-common)
    if(CMAKE_GENERATOR MATCHES "Ninja")
        set_property(TARGET unicorn-common PROPERTY JOB_POOL_COMPILE aida_heavy_compile)
    endif()
    target_compile_options(unicorn-common PRIVATE $<$<COMPILE_LANGUAGE:C,CXX>:/wd4319>)
endif()

# --- Z3 (pre-built static library) ---
# Use pre-existing Z3 library at .deps/z3/z3-4.13.4-x64-win
set(Z3_VERSION "4.13.4")
set(Z3_INSTALL_DIR "${DEPS_DIR}/z3/z3-${Z3_VERSION}-x64-win")

if(NOT EXISTS "${Z3_INSTALL_DIR}/include/z3.h")
    message(FATAL_ERROR "Z3 library not found at ${Z3_INSTALL_DIR}")
endif()

set(Z3_INCLUDE_DIRS "${Z3_INSTALL_DIR}/include" CACHE PATH "Z3 include directory" FORCE)
set(Z3_LIBRARIES "${Z3_INSTALL_DIR}/bin/libz3.lib" CACHE FILEPATH "Z3 library" FORCE)
set(Z3_FOUND TRUE CACHE BOOL "" FORCE)
set(AIDA_Z3_RUNTIME_DLL_NAMES
    libz3.dll
    msvcp140.dll
    msvcp140_1.dll
    msvcp140_2.dll
    msvcp140_atomic_wait.dll
    msvcp140_codecvt_ids.dll
    vcomp140.dll
    vcruntime140.dll
    vcruntime140_1.dll
    vcruntime140_threads.dll
)
foreach(_aida_z3_runtime_name IN LISTS AIDA_Z3_RUNTIME_DLL_NAMES)
    if(NOT EXISTS "${Z3_INSTALL_DIR}/bin/${_aida_z3_runtime_name}")
        message(FATAL_ERROR "Z3 runtime dependency missing: ${Z3_INSTALL_DIR}/bin/${_aida_z3_runtime_name}")
    endif()
endforeach()
set(Z3_MSVCP140_DLL_PATH             "${Z3_INSTALL_DIR}/bin/msvcp140.dll")
set(Z3_MSVCP140_1_DLL_PATH           "${Z3_INSTALL_DIR}/bin/msvcp140_1.dll")
set(Z3_MSVCP140_2_DLL_PATH           "${Z3_INSTALL_DIR}/bin/msvcp140_2.dll")
set(Z3_MSVCP140_ATOMIC_WAIT_DLL_PATH "${Z3_INSTALL_DIR}/bin/msvcp140_atomic_wait.dll")
set(Z3_MSVCP140_CODECVT_IDS_DLL_PATH "${Z3_INSTALL_DIR}/bin/msvcp140_codecvt_ids.dll")
set(Z3_VCOMP140_DLL_PATH             "${Z3_INSTALL_DIR}/bin/vcomp140.dll")
set(Z3_VCRUNTIME140_DLL_PATH         "${Z3_INSTALL_DIR}/bin/vcruntime140.dll")
set(Z3_VCRUNTIME140_1_DLL_PATH       "${Z3_INSTALL_DIR}/bin/vcruntime140_1.dll")
set(Z3_VCRUNTIME140_THREADS_DLL_PATH "${Z3_INSTALL_DIR}/bin/vcruntime140_threads.dll")

set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_CSTEST OFF CACHE BOOL "" FORCE)
set(CAPSTONE_INSTALL OFF CACHE BOOL "" FORCE)
set(CAPSTONE_ARM_SUPPORT ON CACHE BOOL "" FORCE)
set(CAPSTONE_ARM64_SUPPORT ON CACHE BOOL "" FORCE)
set(CAPSTONE_MIPS_SUPPORT ON CACHE BOOL "" FORCE)
set(CAPSTONE_PPC_SUPPORT ON CACHE BOOL "" FORCE)
set(CAPSTONE_RISCV_SUPPORT ON CACHE BOOL "" FORCE)
set(CAPSTONE_X86_SUPPORT ON CACHE BOOL "" FORCE)
block()
    set(BUILD_STATIC_LIBS ON)
    set(BUILD_STATIC_RUNTIME ON)
    set(BUILD_SHARED_LIBS OFF)
    add_subdirectory("${capstone_SOURCE_DIR}" "${capstone_BINARY_DIR}")
endblock()

if(MSVC AND TARGET capstone)
    target_compile_options(capstone PRIVATE /W0)
endif()

if(NOT TARGET capstone::capstone)
    if(TARGET capstone_static)
        add_library(capstone::capstone ALIAS capstone_static)
    elseif(TARGET capstone)
        add_library(capstone::capstone ALIAS capstone)
    endif()
endif()
if(NOT TARGET capstone::capstone)
    message(FATAL_ERROR "AiDA: pinned Capstone 5.0.9 did not provide a linkable target")
endif()

set(CAPSTONE_FOUND TRUE CACHE BOOL "" FORCE)
set(CAPSTONE_INCLUDE_DIRS "${capstone_SOURCE_DIR}/include" CACHE PATH "" FORCE)
set(CAPSTONE_LIBRARIES "capstone::capstone" CACHE STRING "" FORCE)

set(MEMPDB_BUILD_EXAMPLE OFF CACHE BOOL "" FORCE)
set(MEMPDB_BUILD_PDB2JSON OFF CACHE BOOL "" FORCE)
set(MEMPDB_BUILD_TESTS OFF CACHE BOOL "" FORCE)
add_subdirectory("${DEPS_DIR}/MemPDB" "${CMAKE_BINARY_DIR}/.deps/MemPDB")
if(NOT TARGET MemPDB)
    message(FATAL_ERROR "AiDA: vendored MemPDB did not provide a linkable target")
endif()

set(AIDA_MIMALLOC_LICENSE_FILE
    "${CMAKE_CURRENT_SOURCE_DIR}/src/standalone/third_party_notices/mimalloc-LICENSE.txt")
foreach(_aida_required_mimalloc_dependency IN ITEMS
        "${DEPS_DIR}/mimalloc/CMakeLists.txt"
        "${DEPS_DIR}/mimalloc/include/mimalloc.h"
        "${DEPS_DIR}/mimalloc/include/mimalloc-new-delete.h"
        "${DEPS_DIR}/mimalloc/LICENSE"
        "${AIDA_MIMALLOC_LICENSE_FILE}")
    if(NOT EXISTS "${_aida_required_mimalloc_dependency}")
        message(FATAL_ERROR "AiDA: required pinned mimalloc dependency or notice is missing: ${_aida_required_mimalloc_dependency}")
    endif()
endforeach()
aida_require_analysis_file_sha256(
    "${DEPS_DIR}/mimalloc/LICENSE"
    "82ade5d7d9b029044b5fbbc326207fc47c2d44ee4dd71e8a559c36d728217de9")
aida_require_analysis_text_sha256(
    "${AIDA_MIMALLOC_LICENSE_FILE}"
    "82ade5d7d9b029044b5fbbc326207fc47c2d44ee4dd71e8a559c36d728217de9")
set(MI_OVERRIDE OFF CACHE BOOL "" FORCE)
set(MI_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(MI_BUILD_OBJECT OFF CACHE BOOL "" FORCE)
set(MI_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(MI_BUILD_STATIC ON CACHE BOOL "" FORCE)
set(MI_PADDING OFF CACHE BOOL "" FORCE)
set(MI_SECURE OFF CACHE BOOL "" FORCE)
set(MI_SECURE_FULL OFF CACHE BOOL "" FORCE)
set(MI_WIN_REDIRECT OFF CACHE BOOL "" FORCE)
set(MI_WIN_INIT_USE_RAW_DLLMAIN OFF CACHE BOOL "" FORCE)
set(MI_WIN_INIT_USE_TLS_DLLMAIN OFF CACHE BOOL "" FORCE)
set(MI_DEBUG OFF CACHE BOOL "" FORCE)
set(MI_DEBUG_INTERNAL OFF CACHE BOOL "" FORCE)
set(MI_GUARDED OFF CACHE BOOL "" FORCE)
add_subdirectory("${DEPS_DIR}/mimalloc" "${CMAKE_BINARY_DIR}/.deps/mimalloc")
aida_use_static_msvc_runtime(mimalloc-static)

if(TARGET nlohmann_json OR TARGET nlohmann_json::nlohmann_json)
    message(FATAL_ERROR "AiDA: an unexpected nlohmann/json target exists before pinned local integration")
endif()
add_library(nlohmann_json INTERFACE)
add_library(nlohmann_json::nlohmann_json ALIAS nlohmann_json)
target_include_directories(nlohmann_json SYSTEM INTERFACE
    "${CMAKE_CURRENT_SOURCE_DIR}/libs")
set(nlohmann_json_VERSION "3.12.0")
set(nlohmann_json_FOUND TRUE)
set(JSON_FETCH_VERSION "v3.12.0" CACHE STRING "" FORCE)
set(JSON_VALIDATOR_INSTALL OFF CACHE BOOL "" FORCE)
set(JSON_VALIDATOR_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(JSON_VALIDATOR_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(JSON_VALIDATOR_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(JSON_VALIDATOR_TEST_COVERAGE OFF CACHE BOOL "" FORCE)
set(FETCHCONTENT_FULLY_DISCONNECTED ON)
add_subdirectory(
    "${json_schema_validator_SOURCE_DIR}"
    "${json_schema_validator_BINARY_DIR}"
    EXCLUDE_FROM_ALL)
unset(FETCHCONTENT_FULLY_DISCONNECTED)
if(NOT TARGET nlohmann_json_schema_validator::validator)
    message(FATAL_ERROR "AiDA: pinned JSON Schema Validator 2.4.0 target is unavailable")
endif()
if(MSVC AND TARGET nlohmann_json_schema_validator)
    target_compile_options(nlohmann_json_schema_validator PRIVATE /W0)
endif()

# --- Triton (symbolic execution engine) ---
set(BUILD_SHARED_LIBS_SAVED_TRITON "${BUILD_SHARED_LIBS}")
set(BUILD_SHARED_LIBS OFF)
set(Z3_INTERFACE OFF CACHE BOOL "" FORCE)
set(BITWUZLA_INTERFACE OFF CACHE BOOL "" FORCE)
set(LLVM_INTERFACE OFF CACHE BOOL "" FORCE)
set(BOOST_INTERFACE OFF CACHE BOOL "" FORCE)
set(PYTHON_BINDINGS OFF CACHE BOOL "" FORCE)
set(BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(ENABLE_TEST OFF CACHE BOOL "" FORCE)
set(MSVC_STATIC OFF CACHE BOOL "" FORCE)

set(TRITON_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/sources/Triton")
set(TRITON_INSTALL_RULES OFF CACHE BOOL "" FORCE)
add_subdirectory("${TRITON_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/.deps/triton")
if(TARGET capstone_static AND NOT TARGET triton::capstone_static)
    install(TARGETS capstone_static EXPORT tritonTargets DESTINATION lib/cmake/triton)
endif()
set(BUILD_SHARED_LIBS "${BUILD_SHARED_LIBS_SAVED_TRITON}")

if(MSVC AND TARGET triton)
    target_compile_options(triton PRIVATE /W0 /wd4005 /wd4244 /wd4267 /wd4146 /wd4996)
endif()

# --- Ghidra Native Decompiler (embedded as static library) ---
set(GHIDRA_DECOMP_DIR "${CMAKE_SOURCE_DIR}/sources/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp")
set(GHIDRA_PROCESSORS_DIR "${CMAKE_SOURCE_DIR}/sources/ghidra/Ghidra/Processors")
set(GHIDRA_SPECS_OUTPUT_DIR "${CMAKE_BINARY_DIR}/ghidra_specs")
set(GHIDRA_X86_SPECS_DIR "${GHIDRA_PROCESSORS_DIR}/x86/data/languages")
set(GHIDRA_ARM_SPECS_DIR "${GHIDRA_PROCESSORS_DIR}/ARM/data/languages")
set(GHIDRA_AARCH64_SPECS_DIR "${GHIDRA_PROCESSORS_DIR}/AARCH64/data/languages")
set(GHIDRA_MIPS_SPECS_DIR "${GHIDRA_PROCESSORS_DIR}/MIPS/data/languages")
set(GHIDRA_POWERPC_SPECS_DIR "${GHIDRA_PROCESSORS_DIR}/PowerPC/data/languages")
set(GHIDRA_RISCV_SPECS_DIR "${GHIDRA_PROCESSORS_DIR}/RISCV/data/languages")
set(GHIDRA_PREBUILT_SLA "${GHIDRA_X86_SPECS_DIR}/x86-64.sla")

file(GLOB GHIDRA_ALL_CC "${GHIDRA_DECOMP_DIR}/*.cc")

set(GHIDRA_LIBDECOMP_EXCLUDE
    "${GHIDRA_DECOMP_DIR}/ghidra_arch.cc"
    "${GHIDRA_DECOMP_DIR}/ghidra_context.cc"
    "${GHIDRA_DECOMP_DIR}/ghidra_process.cc"
    "${GHIDRA_DECOMP_DIR}/ghidra_translate.cc"
    "${GHIDRA_DECOMP_DIR}/inject_ghidra.cc"
    "${GHIDRA_DECOMP_DIR}/loadimage_ghidra.cc"
    "${GHIDRA_DECOMP_DIR}/typegrp_ghidra.cc"
    "${GHIDRA_DECOMP_DIR}/database_ghidra.cc"
    "${GHIDRA_DECOMP_DIR}/cpool_ghidra.cc"
    "${GHIDRA_DECOMP_DIR}/comment_ghidra.cc"
    "${GHIDRA_DECOMP_DIR}/string_ghidra.cc"
    "${GHIDRA_DECOMP_DIR}/signature_ghidra.cc"
    "${GHIDRA_DECOMP_DIR}/slgh_compile.cc"
    "${GHIDRA_DECOMP_DIR}/slghparse.cc"
    "${GHIDRA_DECOMP_DIR}/slghscan.cc"
    "${GHIDRA_DECOMP_DIR}/consolemain.cc"
    "${GHIDRA_DECOMP_DIR}/sleighexample.cc"
    "${GHIDRA_DECOMP_DIR}/test.cc"
    "${GHIDRA_DECOMP_DIR}/bfd_arch.cc"
    "${GHIDRA_DECOMP_DIR}/loadimage_bfd.cc"
    "${GHIDRA_DECOMP_DIR}/raw_arch.cc"
    "${GHIDRA_DECOMP_DIR}/xml_arch.cc"
    "${GHIDRA_DECOMP_DIR}/loadimage_xml.cc"
    "${GHIDRA_DECOMP_DIR}/analyzesigs.cc"
    "${GHIDRA_DECOMP_DIR}/codedata.cc"
)

set(GHIDRA_LIBDECOMP_SOURCES ${GHIDRA_ALL_CC})
list(REMOVE_ITEM GHIDRA_LIBDECOMP_SOURCES ${GHIDRA_LIBDECOMP_EXCLUDE})

add_library(libdecomp_aida STATIC ${GHIDRA_LIBDECOMP_SOURCES})
target_include_directories(libdecomp_aida PRIVATE
    "${GHIDRA_DECOMP_DIR}"
    "${zlib_SOURCE_DIR}"
    "${zlib_BINARY_DIR}"
)
target_compile_definitions(libdecomp_aida PRIVATE
    _CRT_SECURE_NO_WARNINGS
    NOMINMAX
    AIDA_STANDALONE
)
if(MSVC)
    if(CMAKE_GENERATOR MATCHES "Ninja")
        set_property(TARGET libdecomp_aida PROPERTY JOB_POOL_COMPILE aida_heavy_compile)
    endif()
    target_compile_options(libdecomp_aida PRIVATE /W0 /EHsc /MD)
    if(AIDA_HARDEN_RELEASE)
        target_compile_options(libdecomp_aida PRIVATE /guard:ehcont)
    endif()
endif()
target_link_libraries(libdecomp_aida PRIVATE zlibstatic)

add_executable(ghidra_sleigh_compiler
    "${GHIDRA_DECOMP_DIR}/xml.cc"
    "${GHIDRA_DECOMP_DIR}/marshal.cc"
    "${GHIDRA_DECOMP_DIR}/space.cc"
    "${GHIDRA_DECOMP_DIR}/float.cc"
    "${GHIDRA_DECOMP_DIR}/address.cc"
    "${GHIDRA_DECOMP_DIR}/pcoderaw.cc"
    "${GHIDRA_DECOMP_DIR}/translate.cc"
    "${GHIDRA_DECOMP_DIR}/opcodes.cc"
    "${GHIDRA_DECOMP_DIR}/globalcontext.cc"
    "${GHIDRA_DECOMP_DIR}/sleigh.cc"
    "${GHIDRA_DECOMP_DIR}/pcodeparse.cc"
    "${GHIDRA_DECOMP_DIR}/pcodecompile.cc"
    "${GHIDRA_DECOMP_DIR}/sleighbase.cc"
    "${GHIDRA_DECOMP_DIR}/slghsymbol.cc"
    "${GHIDRA_DECOMP_DIR}/slghpatexpress.cc"
    "${GHIDRA_DECOMP_DIR}/slghpattern.cc"
    "${GHIDRA_DECOMP_DIR}/semantics.cc"
    "${GHIDRA_DECOMP_DIR}/context.cc"
    "${GHIDRA_DECOMP_DIR}/slaformat.cc"
    "${GHIDRA_DECOMP_DIR}/compression.cc"
    "${GHIDRA_DECOMP_DIR}/filemanage.cc"
    "${GHIDRA_DECOMP_DIR}/slgh_compile.cc"
    "${GHIDRA_DECOMP_DIR}/slghparse.cc"
    "${GHIDRA_DECOMP_DIR}/slghscan.cc"
)
target_include_directories(ghidra_sleigh_compiler PRIVATE
    "${GHIDRA_DECOMP_DIR}"
    "${zlib_SOURCE_DIR}"
    "${zlib_BINARY_DIR}"
)
target_compile_definitions(ghidra_sleigh_compiler PRIVATE
    _CRT_SECURE_NO_WARNINGS
    NOMINMAX
)
if(EXISTS "${GHIDRA_PREBUILT_SLA}")
    set_property(TARGET ghidra_sleigh_compiler PROPERTY EXCLUDE_FROM_ALL TRUE)
endif()
if(MSVC)
    if(CMAKE_GENERATOR MATCHES "Ninja")
        set_property(TARGET ghidra_sleigh_compiler PROPERTY JOB_POOL_COMPILE aida_serial_compile)
    endif()
    target_compile_options(ghidra_sleigh_compiler PRIVATE /W0 /EHsc /O2)
    aida_use_static_msvc_runtime(ghidra_sleigh_compiler)
endif()
target_link_libraries(ghidra_sleigh_compiler PRIVATE zlibstatic)

file(MAKE_DIRECTORY "${GHIDRA_SPECS_OUTPUT_DIR}")

function(aida_stage_ghidra_sla output_variable source_dir source_stem)
    set(output_file "${GHIDRA_SPECS_OUTPUT_DIR}/${source_stem}.sla")
    set(prebuilt_file "${source_dir}/${source_stem}.sla")
    set(source_file "${source_dir}/${source_stem}.slaspec")
    if(EXISTS "${prebuilt_file}")
        add_custom_command(
            OUTPUT "${output_file}"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different "${prebuilt_file}" "${output_file}"
            DEPENDS "${prebuilt_file}"
            VERBATIM
        )
    elseif(EXISTS "${source_file}")
        file(GLOB ghidra_sleigh_inputs CONFIGURE_DEPENDS
            "${source_dir}/*.sinc"
            "${source_dir}/*.slaspec")
        add_custom_command(
            OUTPUT "${output_file}"
            COMMAND ghidra_sleigh_compiler "${source_file}" "${output_file}"
            DEPENDS ghidra_sleigh_compiler ${ghidra_sleigh_inputs}
            WORKING_DIRECTORY "${source_dir}"
            VERBATIM
        )
    else()
        message(FATAL_ERROR "Missing Ghidra SLEIGH source for ${source_stem}: ${source_dir}")
    endif()
    set(${output_variable} ${${output_variable}} "${output_file}" PARENT_SCOPE)
endfunction()

set(GHIDRA_STAGED_SLA_OUTPUTS)
aida_stage_ghidra_sla(GHIDRA_STAGED_SLA_OUTPUTS "${GHIDRA_X86_SPECS_DIR}" "x86-64")
aida_stage_ghidra_sla(GHIDRA_STAGED_SLA_OUTPUTS "${GHIDRA_X86_SPECS_DIR}" "x86")
aida_stage_ghidra_sla(GHIDRA_STAGED_SLA_OUTPUTS "${GHIDRA_ARM_SPECS_DIR}" "ARM7_le")
aida_stage_ghidra_sla(GHIDRA_STAGED_SLA_OUTPUTS "${GHIDRA_ARM_SPECS_DIR}" "ARM7_be")
aida_stage_ghidra_sla(GHIDRA_STAGED_SLA_OUTPUTS "${GHIDRA_AARCH64_SPECS_DIR}" "AARCH64")
aida_stage_ghidra_sla(GHIDRA_STAGED_SLA_OUTPUTS "${GHIDRA_AARCH64_SPECS_DIR}" "AARCH64BE")
aida_stage_ghidra_sla(GHIDRA_STAGED_SLA_OUTPUTS "${GHIDRA_MIPS_SPECS_DIR}" "mips32le")
aida_stage_ghidra_sla(GHIDRA_STAGED_SLA_OUTPUTS "${GHIDRA_MIPS_SPECS_DIR}" "mips32be")
aida_stage_ghidra_sla(GHIDRA_STAGED_SLA_OUTPUTS "${GHIDRA_MIPS_SPECS_DIR}" "mips64le")
aida_stage_ghidra_sla(GHIDRA_STAGED_SLA_OUTPUTS "${GHIDRA_MIPS_SPECS_DIR}" "mips64be")
aida_stage_ghidra_sla(GHIDRA_STAGED_SLA_OUTPUTS "${GHIDRA_POWERPC_SPECS_DIR}" "ppc_32_le")
aida_stage_ghidra_sla(GHIDRA_STAGED_SLA_OUTPUTS "${GHIDRA_POWERPC_SPECS_DIR}" "ppc_32_be")
aida_stage_ghidra_sla(GHIDRA_STAGED_SLA_OUTPUTS "${GHIDRA_POWERPC_SPECS_DIR}" "ppc_64_le")
aida_stage_ghidra_sla(GHIDRA_STAGED_SLA_OUTPUTS "${GHIDRA_POWERPC_SPECS_DIR}" "ppc_64_be")
aida_stage_ghidra_sla(GHIDRA_STAGED_SLA_OUTPUTS "${GHIDRA_RISCV_SPECS_DIR}" "riscv.ilp32d")
aida_stage_ghidra_sla(GHIDRA_STAGED_SLA_OUTPUTS "${GHIDRA_RISCV_SPECS_DIR}" "riscv.lp64d")

set(GHIDRA_STAGED_STATIC_INPUTS
    "${GHIDRA_X86_SPECS_DIR}/x86-64.pspec"
    "${GHIDRA_X86_SPECS_DIR}/x86-64-win.cspec"
    "${GHIDRA_X86_SPECS_DIR}/x86-64-gcc.cspec"
    "${GHIDRA_X86_SPECS_DIR}/x86.pspec"
    "${GHIDRA_X86_SPECS_DIR}/x86win.cspec"
    "${GHIDRA_X86_SPECS_DIR}/x86gcc.cspec"
    "${GHIDRA_X86_SPECS_DIR}/x86-16-real.pspec"
    "${GHIDRA_X86_SPECS_DIR}/x86-16.cspec"
    "${GHIDRA_X86_SPECS_DIR}/x86.ldefs"
    "${GHIDRA_ARM_SPECS_DIR}/ARMt.pspec"
    "${GHIDRA_ARM_SPECS_DIR}/ARM.cspec"
    "${GHIDRA_ARM_SPECS_DIR}/ARM_win.cspec"
    "${GHIDRA_ARM_SPECS_DIR}/ARM.ldefs"
    "${GHIDRA_AARCH64_SPECS_DIR}/AARCH64.pspec"
    "${GHIDRA_AARCH64_SPECS_DIR}/AARCH64.cspec"
    "${GHIDRA_AARCH64_SPECS_DIR}/AARCH64_win.cspec"
    "${GHIDRA_AARCH64_SPECS_DIR}/AARCH64.ldefs"
    "${GHIDRA_MIPS_SPECS_DIR}/mips32.pspec"
    "${GHIDRA_MIPS_SPECS_DIR}/mips64.pspec"
    "${GHIDRA_MIPS_SPECS_DIR}/mips32le.cspec"
    "${GHIDRA_MIPS_SPECS_DIR}/mips32be.cspec"
    "${GHIDRA_MIPS_SPECS_DIR}/mips64le.cspec"
    "${GHIDRA_MIPS_SPECS_DIR}/mips64be.cspec"
    "${GHIDRA_MIPS_SPECS_DIR}/mips.ldefs"
    "${GHIDRA_POWERPC_SPECS_DIR}/ppc_32.pspec"
    "${GHIDRA_POWERPC_SPECS_DIR}/ppc_64.pspec"
    "${GHIDRA_POWERPC_SPECS_DIR}/ppc_32.cspec"
    "${GHIDRA_POWERPC_SPECS_DIR}/ppc_64_le.cspec"
    "${GHIDRA_POWERPC_SPECS_DIR}/ppc_64_be.cspec"
    "${GHIDRA_POWERPC_SPECS_DIR}/ppc.ldefs"
    "${GHIDRA_RISCV_SPECS_DIR}/RV32.pspec"
    "${GHIDRA_RISCV_SPECS_DIR}/RV64.pspec"
    "${GHIDRA_RISCV_SPECS_DIR}/riscv32-fp.cspec"
    "${GHIDRA_RISCV_SPECS_DIR}/riscv64-fp.cspec"
    "${GHIDRA_RISCV_SPECS_DIR}/riscv.ldefs"
)

set(GHIDRA_STAGED_STATIC_OUTPUTS)
foreach(ghidra_static_input IN LISTS GHIDRA_STAGED_STATIC_INPUTS)
    get_filename_component(ghidra_static_name "${ghidra_static_input}" NAME)
    set(ghidra_static_output "${GHIDRA_SPECS_OUTPUT_DIR}/${ghidra_static_name}")
    add_custom_command(
        OUTPUT "${ghidra_static_output}"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different "${ghidra_static_input}" "${ghidra_static_output}"
        DEPENDS "${ghidra_static_input}"
        VERBATIM
    )
    list(APPEND GHIDRA_STAGED_STATIC_OUTPUTS "${ghidra_static_output}")
endforeach()

set(GHIDRA_STAGED_SPEC_OUTPUTS
    ${GHIDRA_STAGED_SLA_OUTPUTS}
    ${GHIDRA_STAGED_STATIC_OUTPUTS}
)

add_custom_target(ghidra_specs ALL DEPENDS ${GHIDRA_STAGED_SPEC_OUTPUTS})

# --- Auto-embed driver byte arrays ---
# When the built driver changes (WhosWho.sys), the embedded header
# src/whoswho_embedded.h is regenerated by src/encrypt_whoswho.py so
# driver_loader.cpp picks up the new bytes. WhosWho.sys must exist for
# the header to be generated; build the driver first (via build-host)
# and re-run cmake configure if it is missing.
find_package(Python3 COMPONENTS Interpreter QUIET)
option(AIDA_DISABLE_LEGACY_DRIVER_MAPPER "Disable the embedded legacy WindMapper driver mapper fallback" OFF)
if(Python3_FOUND)
    # The driver .vcxproj files hardcode <OutDir> to
    # ${CMAKE_SOURCE_DIR}/build-ninja/Release/, so the built binaries
    # land at a fixed location independent of CMAKE_BINARY_DIR. Expose
    # as a cache var so users with custom .vcxproj OutDirs can override.
    set(AIDA_DRIVER_OUTPUT_DIR "${CMAKE_SOURCE_DIR}/build-ninja/Release"
        CACHE PATH "Directory where WhosWho.sln deposits its build outputs")
    set(WHOSWHO_BINARY "${AIDA_DRIVER_OUTPUT_DIR}/WhosWho.sys"
        CACHE FILEPATH "Path to the built WhosWho.sys")
    set(WHOSWHO_SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/src/encrypt_whoswho.py")

    set(EMBED_DRIVERS_STAMPS "")
    if(EXISTS "${WHOSWHO_BINARY}")
        message(STATUS "encrypt_drivers: WhosWho <- ${WHOSWHO_BINARY}")
        add_custom_command(
            OUTPUT "${CMAKE_BINARY_DIR}/whoswho_embedded.stamp"
            BYPRODUCTS "${CMAKE_CURRENT_SOURCE_DIR}/src/whoswho_embedded.h"
            COMMAND ${Python3_EXECUTABLE} "${WHOSWHO_SCRIPT}" --from-binary "${WHOSWHO_BINARY}"
            COMMAND ${CMAKE_COMMAND} -E touch "${CMAKE_BINARY_DIR}/whoswho_embedded.stamp"
            DEPENDS "${WHOSWHO_SCRIPT}" "${WHOSWHO_BINARY}"
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
            COMMENT "Embedding WhosWho -> whoswho_embedded.h"
            VERBATIM
        )
        set(EMBED_DRIVERS_STAMPS "${CMAKE_BINARY_DIR}/whoswho_embedded.stamp")
    else()
        message(STATUS "encrypt_drivers: WhosWho -- ${WHOSWHO_BINARY} not found; "
                       "skipping rule (src/whoswho_embedded.h will not be generated). "
                       "Build the driver first (via build-host) and re-run cmake configure to enable.")
    endif()
    if(EMBED_DRIVERS_STAMPS)
        add_custom_target(encrypt_drivers DEPENDS ${EMBED_DRIVERS_STAMPS})
        add_custom_target(reencrypt_drivers
            COMMAND ${CMAKE_COMMAND} -E remove ${EMBED_DRIVERS_STAMPS}
            COMMAND ${CMAKE_COMMAND} --build "${CMAKE_BINARY_DIR}" --target encrypt_drivers
            COMMENT "Force-regenerating the embedded WhosWho driver header from the current binary"
            VERBATIM
        )
    else()
        add_custom_target(encrypt_drivers
            COMMAND ${CMAKE_COMMAND} -E echo
                "encrypt_drivers: WhosWho.sys not found; using existing src/whoswho_embedded.h as-is."
        )
    endif()
else()
    message(FATAL_ERROR "Python3 not found -- the driver embed target (encrypt_drivers) is disabled.")
endif()

# Track the generated embedded header so MSVC recompiles driver_loader.cpp
# when it changes (even outside the encrypt_drivers flow).
set(EMBEDDED_DRIVER_HEADERS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/whoswho_embedded.h"
)
set_source_files_properties(
    src/driver_loader.cpp
    PROPERTIES OBJECT_DEPENDS "${EMBEDDED_DRIVER_HEADERS}"
)

# Track #include'd asset .c files so embedded_assets.cpp rebuilds when they change.
set(EMBEDDED_ASSET_FILES
    "${CMAKE_CURRENT_SOURCE_DIR}/src/standalone/aidalogo.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/standalone/background.c"
)
set_source_files_properties(
    "${CMAKE_CURRENT_SOURCE_DIR}/src/standalone/src/helpers/embedded_assets.cpp"
    PROPERTIES OBJECT_DEPENDS "${EMBEDDED_ASSET_FILES}"
)

if(BUILD_AIDA_PLUGIN)
    if(NOT DEFINED IDASDK_DIR)
        if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/ida-sdk/src/include/ida.hpp")
            set(IDASDK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/ida-sdk/src")
        elseif(DEFINED ENV{IDASDK})
            set(IDASDK_DIR "$ENV{IDASDK}")
        else()
            message(FATAL_ERROR
                "IDA SDK not found. Set -DIDASDK_DIR=<path> or the IDASDK environment variable.\n"
                "The path must point to the SDK 'src' directory that contains 'include/' and 'lib/'.")
        endif()
    endif()
endif()


if(WIN32)

    set(imgui_SOURCE_DIR "${DEPS_DIR}/imgui-src")
    include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/aida_imgui_dependency.cmake")
    aida_configure_imgui_dependency("${imgui_SOURCE_DIR}")

    option(BUILD_DRIVER_TEST "Build WhosWho driver test application" ON)

    if(BUILD_DRIVER_TEST)
        add_executable(DriverTest EXCLUDE_FROM_ALL
            driver/test_driver.cpp
            driver/comm.cpp
            driver/syscall.asm
        )

        target_include_directories(DriverTest PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/driver"
            "${CMAKE_CURRENT_SOURCE_DIR}"
            "${zydis_SOURCE_DIR}/include"
            "${zydis_SOURCE_DIR}/dependencies/zycore/include"
            "${zydis_BINARY_DIR}"
            "${zydis_BINARY_DIR}/zycore"
            "${unicorn_SOURCE_DIR}/include"
        )

        target_compile_definitions(DriverTest PRIVATE
            _CRT_SECURE_NO_WARNINGS
            NOMINMAX
            WIN32_LEAN_AND_MEAN
        )

        target_compile_options(DriverTest PRIVATE
            $<$<COMPILE_LANGUAGE:CXX>:/W3>
            $<$<COMPILE_LANGUAGE:CXX>:/EHsc>
            $<$<COMPILE_LANGUAGE:CXX>:/Zc:__cplusplus>
            $<$<COMPILE_LANGUAGE:CXX>:/permissive->
            $<$<COMPILE_LANGUAGE:CXX>:/Zp8>
            $<$<COMPILE_LANGUAGE:CXX>:/wd4201>
        )

        aida_use_static_msvc_runtime(DriverTest)

        target_link_libraries(DriverTest PRIVATE
            Zydis
            unicorn
            ws2_32
            dnsapi
            winhttp
            iphlpapi
            ntdll
        )

        set_target_properties(DriverTest PROPERTIES
            OUTPUT_NAME "test_driver"
        )
    endif()

    option(BUILD_MALWARE_SAFE_TESTER "Build MalwareSafeTester console harness" ON)

    if(BUILD_MALWARE_SAFE_TESTER)
        add_executable(MalwareSafeTester
            tools/malware_safe_tester/src/main.cpp
        )

        target_compile_definitions(MalwareSafeTester PRIVATE
            _CRT_SECURE_NO_WARNINGS
            NOMINMAX
            WIN32_LEAN_AND_MEAN
            UNICODE
            _UNICODE
        )

        target_compile_options(MalwareSafeTester PRIVATE
            $<$<COMPILE_LANGUAGE:CXX>:/W3>
            $<$<COMPILE_LANGUAGE:CXX>:/EHsc>
            $<$<COMPILE_LANGUAGE:CXX>:/Zc:__cplusplus>
            $<$<COMPILE_LANGUAGE:CXX>:/permissive->
            $<$<COMPILE_LANGUAGE:CXX>:/MD>
            $<$<COMPILE_LANGUAGE:CXX>:/Zp8>
        )

        target_link_libraries(MalwareSafeTester PRIVATE
            advapi32
            user32
            kernel32
            ws2_32
            psapi
            wininet
        )

        target_link_options(MalwareSafeTester PRIVATE
            /SUBSYSTEM:CONSOLE
            /DYNAMICBASE
            /HIGHENTROPYVA
            /NXCOMPAT
        )

        set_target_properties(MalwareSafeTester PROPERTIES
            OUTPUT_NAME "MalwareSafeTester"
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
            RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}"
            RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}"
            RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_BINARY_DIR}"
        )
    endif()

    option(BUILD_AIDA_STANDALONE "Build AiDA standalone application" ON)

    if(BUILD_AIDA_STANDALONE)
        set(STANDALONE_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/src/standalone/src")
        include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/aida_c03_dependencies.cmake")
        include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/aida_c03_safe_headless_manifest.cmake")

        set(IMGUI_WRAPPER_DIR "${CMAKE_BINARY_DIR}/_imgui_wrapper/imgui")
        file(MAKE_DIRECTORY "${IMGUI_WRAPPER_DIR}")
        file(MAKE_DIRECTORY "${IMGUI_WRAPPER_DIR}/freetype")

        file(GLOB _imgui_core_headers "${imgui_SOURCE_DIR}/*.h")
        foreach(_h ${_imgui_core_headers})
            get_filename_component(_name "${_h}" NAME)
            file(WRITE "${IMGUI_WRAPPER_DIR}/${_name}" "#pragma once\n#include \"${_h}\"\n")
        endforeach()

        file(GLOB _imgui_backend_headers "${imgui_SOURCE_DIR}/backends/*.h")
        foreach(_h ${_imgui_backend_headers})
            get_filename_component(_name "${_h}" NAME)
            file(WRITE "${IMGUI_WRAPPER_DIR}/${_name}" "#pragma once\n#include \"${_h}\"\n")
        endforeach()

        if(EXISTS "${imgui_SOURCE_DIR}/misc/freetype/imgui_freetype.h")
            file(WRITE "${IMGUI_WRAPPER_DIR}/freetype/freetype.h"
                 "#pragma once\n#include \"${imgui_SOURCE_DIR}/misc/freetype/imgui_freetype.h\"\n")
        endif()

        set(IDA_STUBS_DIR "${CMAKE_BINARY_DIR}/_ida_stubs")
        file(MAKE_DIRECTORY "${IDA_STUBS_DIR}")
        file(WRITE "${IDA_STUBS_DIR}/pro.h"
               "#ifndef _PRO_H\n"
               "#define _PRO_H\n"
               "#include <cstdarg>\n"
               "#include <cstdio>\n"
               "#include <windows.h>\n"
               "inline int qvsnprintf(char* buf, size_t n, const char* fmt, va_list ap) {\n"
               "    return vsnprintf_s(buf, n, _TRUNCATE, fmt, ap);\n"
               "}\n"
               "inline void msg(const char* fmt, ...) {\n"
               "    char tmp[2048] = {};\n"
               "    va_list ap;\n"
               "    va_start(ap, fmt);\n"
               "    vsnprintf_s(tmp, sizeof(tmp), _TRUNCATE, fmt, ap);\n"
               "    va_end(ap);\n"
               "    OutputDebugStringA(tmp);\n"
               "}\n"
               "#endif\n")
        file(WRITE "${IDA_STUBS_DIR}/kernwin.hpp"
               "#ifndef __KERNWIN_HPP\n"
               "#define __KERNWIN_HPP\n"
               "#include <cstdarg>\n"
               "#include <cstdio>\n"
               "#include <windows.h>\n"
               "#ifndef ASKBTN_NO\n"
               "#define ASKBTN_NO 0\n"
               "#endif\n"
               "#ifndef ASKBTN_YES\n"
               "#define ASKBTN_YES 1\n"
               "#endif\n"
               "inline int ask_yn(int deflt, const char* fmt, ...) {\n"
               "    char tmp[2048] = {};\n"
               "    va_list ap;\n"
               "    va_start(ap, fmt);\n"
               "    vsnprintf_s(tmp, sizeof(tmp), _TRUNCATE, fmt, ap);\n"
               "    va_end(ap);\n"
               "    const int r = MessageBoxA(nullptr, tmp, \"AiDAStandalone\", MB_YESNO | MB_ICONWARNING | MB_SYSTEMMODAL);\n"
               "    if (r == IDYES) return ASKBTN_YES;\n"
               "    if (r == IDNO) return ASKBTN_NO;\n"
               "    return deflt;\n"
               "}\n"
               "#endif\n")

        set(STANDALONE_SOURCES
            "${STANDALONE_ROOT}/main.cpp"
            "${STANDALONE_ROOT}/helpers/helpers.cpp"
        
            "${STANDALONE_ROOT}/helpers/imgui_dx11_d3dcompile_stub.cpp"
            "${STANDALONE_ROOT}/helpers/icon_loodr.cpp"
            "${STANDALONE_ROOT}/helpers/file_browser.cpp"
            "${STANDALONE_ROOT}/helpers/embedded_assets.cpp"
            "${STANDALONE_ROOT}/core/mcp/mcp_standalone.cpp"
            "${STANDALONE_ROOT}/core/mcp/mcp_standalone_tools.cpp"
            "${STANDALONE_ROOT}/core/runtime/standalone_driver.cpp"
            "${STANDALONE_ROOT}/core/runtime/kernel_symbols.cpp"
            "${STANDALONE_ROOT}/core/runtime/run_target.cpp"
            "${STANDALONE_ROOT}/core/runtime/vm_guest_bridge.cpp"
            "${STANDALONE_ROOT}/core/ai/standalone_ai_client.cpp"
            "${STANDALONE_ROOT}/core/ai/standalone_chat.cpp"
            "${STANDALONE_ROOT}/core/tools/driver_tools_standalone.cpp"
            "${STANDALONE_ROOT}/core/tools/re_tools_standalone.cpp"
            "${STANDALONE_ROOT}/core/tools/protected_re_tools_standalone.cpp"
            "${STANDALONE_ROOT}/core/re/re_common.cpp"
            "${STANDALONE_ROOT}/core/re/artifact_store.cpp"
            "${STANDALONE_ROOT}/core/re/dx_hook.cpp"
            "${STANDALONE_ROOT}/core/re/vmt.cpp"
            "${STANDALONE_ROOT}/core/re/rtti.cpp"
            "${STANDALONE_ROOT}/core/re/encptr.cpp"
            "${STANDALONE_ROOT}/core/re/offsets.cpp"
            "${STANDALONE_ROOT}/core/re/heap_track.cpp"
            "${STANDALONE_ROOT}/core/re/sigs.cpp"
            "${STANDALONE_ROOT}/core/re/struct_adv.cpp"
            "${STANDALONE_ROOT}/core/network/network_tools_standalone.cpp"
            "${STANDALONE_ROOT}/core/network/http_tools_standalone.cpp"
            "${STANDALONE_ROOT}/core/network/web_vuln_tools_standalone.cpp"
            "${STANDALONE_ROOT}/core/network/api_enum_tools_standalone.cpp"
            "${STANDALONE_ROOT}/core/network/js_analysis_tools_standalone.cpp"
            "${STANDALONE_ROOT}/core/network/cloud_tools_standalone.cpp"
            "${STANDALONE_ROOT}/core/network/network_tool_aliases_standalone.cpp"
            "${STANDALONE_ROOT}/core/network/game_protocol.cpp"
            "${STANDALONE_ROOT}/core/network/gameproto_tools_standalone.cpp"
            "${STANDALONE_ROOT}/core/network/net_proto_analysis.cpp"
            "${STANDALONE_ROOT}/core/network/net_proto_tools_standalone.cpp"
            "${STANDALONE_ROOT}/core/network/net_security_tools_standalone.cpp"
            "${STANDALONE_ROOT}/core/tools/emulation_tools_standalone.cpp"
            "${STANDALONE_ROOT}/core/editor/code_editor.cpp"
            "${STANDALONE_ROOT}/core/editor/programming_language_service.cpp"
            "${STANDALONE_ROOT}/core/analysis/analysis_budget.cpp"
            "${STANDALONE_ROOT}/core/analysis/analysis_resource_metrics.cpp"
            "${STANDALONE_ROOT}/core/analysis/analysis_scheduler.cpp"
            "${STANDALONE_ROOT}/core/analysis/analysis_fabric_metrics.cpp"
            "${STANDALONE_ROOT}/core/analysis/fact_page_cache.cpp"
            "${STANDALONE_ROOT}/core/analysis/working_set_metrics.cpp"
            "${STANDALONE_ROOT}/core/analysis/working_set_governor.cpp"
            "${STANDALONE_ROOT}/core/disasm/disasm_view.cpp"
            "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_pretty_xml_encode.cpp"
            "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_function_db.cpp"
            "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_arch_map.cpp"
            "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_load_image.cpp"
            "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_pcode_fixup.cpp"
            "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_print_c.cpp"
            "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_scope.cpp"
            "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_architecture.cpp"
            "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_code_xml_parse.cpp"
            "${STANDALONE_ROOT}/core/editor/hex_view.cpp"
            "${STANDALONE_ROOT}/core/editor/image_view.cpp"
            "${STANDALONE_ROOT}/core/ui/chat_render.cpp"
              "${STANDALONE_ROOT}/core/ui/application_action_registry.cpp"
              "${STANDALONE_ROOT}/core/ui/application_ui_runtime.cpp"
              "${STANDALONE_ROOT}/core/ui/analysis_context_menu.cpp"
            "${STANDALONE_ROOT}/core/ui/application_view_registry.cpp"
            "${STANDALONE_ROOT}/core/ui/explorer_views.cpp"
            "${STANDALONE_ROOT}/core/ui/output_views.cpp"
            "${STANDALONE_ROOT}/core/ui/programming_tasks.cpp"
            "${STANDALONE_ROOT}/core/ui/programming_language_views.cpp"
            "${STANDALONE_ROOT}/core/ui/context_menu_contract.cpp"
            "${STANDALONE_ROOT}/core/ui/context_menu_renderer.cpp"
            "${STANDALONE_ROOT}/core/ui/design_system.cpp"
            "${STANDALONE_ROOT}/core/ui/ide_shell.cpp"
            "${STANDALONE_ROOT}/core/ui/interaction_context.cpp"
            "${STANDALONE_ROOT}/core/ui/shortcut_resolver.cpp"
            "${STANDALONE_ROOT}/core/ui/task_center.cpp"
            "${STANDALONE_ROOT}/core/ui/view_registry.cpp"
            "${STANDALONE_ROOT}/core/ui/workspace_layout.cpp"
            "${STANDALONE_ROOT}/core/settings/settings_persistence_service.cpp"
            "${STANDALONE_ROOT}/core/settings/theme_transfer_service.cpp"
            "${STANDALONE_ROOT}/core/ai/conversation_evidence_store.cpp"
            "${STANDALONE_ROOT}/core/mcp/mcp_client.cpp"
            "${STANDALONE_ROOT}/core/mcp/mcp_marketplace.cpp"
            "${STANDALONE_ROOT}/core/mcp/ida_compat_read.cpp"
            "${STANDALONE_ROOT}/core/mcp/ida_compat_mut.cpp"
            "${STANDALONE_ROOT}/core/mcp/calculator_tool.cpp"
            "${STANDALONE_ROOT}/core/mcp/calculator_engine.cpp"
            "${STANDALONE_ROOT}/core/mcp/schema_validator.cpp"
            "${STANDALONE_ROOT}/core/network/protocol_parser.cpp"
            "${STANDALONE_ROOT}/core/network/cert_generator.cpp"
            "${STANDALONE_ROOT}/core/network/mitm_proxy.cpp"
            "${STANDALONE_ROOT}/core/network/conn_pool.cpp"
            "${STANDALONE_ROOT}/core/network/flow_serializer.cpp"
            "${STANDALONE_ROOT}/core/network/flow_store.cpp"
            "${STANDALONE_ROOT}/core/network/map_resource.cpp"
            "${STANDALONE_ROOT}/core/network/pac_resolver.cpp"
            "${STANDALONE_ROOT}/core/network/quic_proxy.cpp"
            "${STANDALONE_ROOT}/core/network/server_replay.cpp"
            "${STANDALONE_ROOT}/core/network/tls_policy.cpp"
            "${STANDALONE_ROOT}/core/network/network_view.cpp"
            "${STANDALONE_ROOT}/core/network/intercept/cert_profile_manager.cpp"
            "${STANDALONE_ROOT}/core/network/intercept/diagnostics.cpp"
            "${STANDALONE_ROOT}/core/network/intercept/instrumentation_provider.cpp"
            "${STANDALONE_ROOT}/core/network/intercept/script_handoff.cpp"
            "${STANDALONE_ROOT}/core/network/burp/active_scanner.cpp"
            "${STANDALONE_ROOT}/core/network/burp/api_definition.cpp"
            "${STANDALONE_ROOT}/core/network/burp/api_view.cpp"
            "${STANDALONE_ROOT}/core/network/burp/audit_http.cpp"
            "${STANDALONE_ROOT}/core/network/burp/audit_session.cpp"
            "${STANDALONE_ROOT}/core/network/burp/audit_session_mcp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/audit_trail.cpp"
            "${STANDALONE_ROOT}/core/network/burp/auth_lab.cpp"
            "${STANDALONE_ROOT}/core/network/burp/bambda.cpp"
            "${STANDALONE_ROOT}/core/network/burp/browser_launch.cpp"
            "${STANDALONE_ROOT}/core/network/burp/browser_view.cpp"
            "${STANDALONE_ROOT}/core/network/burp/burp_api_mcp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/burp_auth_mcp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/burp_bambda_mcp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/burp_crawl_audit_mcp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/burp_collaborator_mcp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/burp_comparer_mcp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/burp_csp_mcp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/burp_extensions_mcp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/burp_intruder_mcp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/burp_jwt_mcp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/burp_logger.cpp"
            "${STANDALONE_ROOT}/core/network/burp/burp_logger_view.cpp"
            "${STANDALONE_ROOT}/core/network/burp/burp_mitm_mcp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/burp_module.cpp"
            "${STANDALONE_ROOT}/core/network/burp/burp_mr_mcp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/burp_recon_mcp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/burp_scanner_mcp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/burp_search_mcp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/burp_sequencer_mcp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/burp_session_mcp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/burp_target_mcp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/burp_tech_mcp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/burp_upstream_mcp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/collaborator.cpp"
            "${STANDALONE_ROOT}/core/network/burp/collaborator_view.cpp"
            "${STANDALONE_ROOT}/core/network/burp/comparer.cpp"
            "${STANDALONE_ROOT}/core/network/burp/comparer_view.cpp"
            "${STANDALONE_ROOT}/core/network/burp/content_discovery.cpp"
            "${STANDALONE_ROOT}/core/network/burp/content_scanner.cpp"
            "${STANDALONE_ROOT}/core/network/burp/camoufox_bridge.cpp"
            "${STANDALONE_ROOT}/core/network/burp/camoufox_bridge_mcp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/camoufox_install.cpp"
            "${STANDALONE_ROOT}/core/network/burp/cookie_jar.cpp"
            "${STANDALONE_ROOT}/core/network/burp/crawl_audit.cpp"
            "${STANDALONE_ROOT}/core/network/burp/crawler.cpp"
            "${STANDALONE_ROOT}/core/network/burp/csp_analyzer.cpp"
            "${STANDALONE_ROOT}/core/network/burp/csp_view.cpp"
            "${STANDALONE_ROOT}/core/network/burp/defensive_mcp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/dom_xss_engine.cpp"
            "${STANDALONE_ROOT}/core/network/burp/dom_xss_mcp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/evidence_store.cpp"
            "${STANDALONE_ROOT}/core/network/burp/extensions.cpp"
            "${STANDALONE_ROOT}/core/network/burp/findings_db.cpp"
            "${STANDALONE_ROOT}/core/network/burp/graphql.cpp"
            "${STANDALONE_ROOT}/core/network/burp/headless_view.cpp"
            "${STANDALONE_ROOT}/core/network/burp/graphql_view.cpp"
            "${STANDALONE_ROOT}/core/network/burp/h2_editor.cpp"
            "${STANDALONE_ROOT}/core/network/burp/h2_editor_view.cpp"
            "${STANDALONE_ROOT}/core/network/burp/insertion_points.cpp"
            "${STANDALONE_ROOT}/core/network/burp/intruder_engine.cpp"
            "${STANDALONE_ROOT}/core/network/burp/intruder_view.cpp"
            "${STANDALONE_ROOT}/core/network/burp/issue.cpp"
            "${STANDALONE_ROOT}/core/network/burp/jwt_lab.cpp"
            "${STANDALONE_ROOT}/core/network/burp/jwt_lab_view.cpp"
            "${STANDALONE_ROOT}/core/network/burp/match_replace.cpp"
            "${STANDALONE_ROOT}/core/network/burp/match_replace_view.cpp"
            "${STANDALONE_ROOT}/core/network/burp/param_miner.cpp"
            "${STANDALONE_ROOT}/core/network/burp/passive_scanner.cpp"
            "${STANDALONE_ROOT}/core/network/burp/payload_library.cpp"
            "${STANDALONE_ROOT}/core/network/burp/project.cpp"
            "${STANDALONE_ROOT}/core/network/burp/project_view.cpp"
            "${STANDALONE_ROOT}/core/network/burp/recon_view.cpp"
            "${STANDALONE_ROOT}/core/network/burp/report_generator.cpp"
            "${STANDALONE_ROOT}/core/network/burp/report_view.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scan_orchestrator.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_module.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_view.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scope.cpp"
            "${STANDALONE_ROOT}/core/network/burp/security_headers.cpp"
            "${STANDALONE_ROOT}/core/network/burp/sequencer.cpp"
            "${STANDALONE_ROOT}/core/network/burp/sequencer_view.cpp"
            "${STANDALONE_ROOT}/core/network/burp/session_handler.cpp"
            "${STANDALONE_ROOT}/core/network/burp/session_handler_view.cpp"
            "${STANDALONE_ROOT}/core/network/burp/site_map.cpp"
            "${STANDALONE_ROOT}/core/network/burp/subdomain_enum.cpp"
            "${STANDALONE_ROOT}/core/network/burp/tech_fingerprint.cpp"
            "${STANDALONE_ROOT}/core/network/burp/tls_analyzer.cpp"
            "${STANDALONE_ROOT}/core/network/burp/upstream_chain.cpp"
            "${STANDALONE_ROOT}/core/network/burp/upstream_view.cpp"
            "${STANDALONE_ROOT}/core/network/burp/vuln_taxonomy.cpp"
            "${STANDALONE_ROOT}/core/network/burp/web_report_mcp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/ws_editor.cpp"
            "${STANDALONE_ROOT}/core/network/burp/ws_editor_view.cpp"
            "${STANDALONE_ROOT}/core/network/burp/offensive/api_security_engine.cpp"
            "${STANDALONE_ROOT}/core/network/burp/offensive/auth_attack_engine.cpp"
            "${STANDALONE_ROOT}/core/network/burp/offensive/business_logic_engine.cpp"
            "${STANDALONE_ROOT}/core/network/burp/offensive/client_attack_engine.cpp"
            "${STANDALONE_ROOT}/core/network/burp/offensive/fuzzing_engine.cpp"
            "${STANDALONE_ROOT}/core/network/burp/offensive/js_analysis_engine.cpp"
            "${STANDALONE_ROOT}/core/network/burp/offensive/offensive_api_rest.cpp"
            "${STANDALONE_ROOT}/core/network/burp/offensive/offensive_auth_attack.cpp"
            "${STANDALONE_ROOT}/core/network/burp/offensive/offensive_business_logic.cpp"
            "${STANDALONE_ROOT}/core/network/burp/offensive/offensive_client_attack.cpp"
            "${STANDALONE_ROOT}/core/network/burp/offensive/offensive_fuzzing.cpp"
            "${STANDALONE_ROOT}/core/network/burp/offensive/offensive_graphql.cpp"
            "${STANDALONE_ROOT}/core/network/burp/offensive/offensive_js_analysis.cpp"
            "${STANDALONE_ROOT}/core/network/burp/offensive/offensive_payloads.cpp"
            "${STANDALONE_ROOT}/core/network/burp/offensive/offensive_recon.cpp"
            "${STANDALONE_ROOT}/core/network/burp/offensive/offensive_server_attack.cpp"
            "${STANDALONE_ROOT}/core/network/burp/offensive/offensive_sqli.cpp"
            "${STANDALONE_ROOT}/core/network/burp/offensive/offensive_xss.cpp"
            "${STANDALONE_ROOT}/core/network/burp/offensive/recon_engine.cpp"
            "${STANDALONE_ROOT}/core/network/burp/offensive/server_attack_engine.cpp"
            "${STANDALONE_ROOT}/core/network/burp/offensive/sqli_engine.cpp"
            "${STANDALONE_ROOT}/core/network/burp/offensive/xss_engine.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_cmdi.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_cors.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_csp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_csrf.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_deserial.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_dom_clobbering.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_dom_xss.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_email_injection.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_host_header.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_idor.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_jwt_scan.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_ldap.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_log4j.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_method_override.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_nosqli.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_open_redirect.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_param_miner.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_path_traversal.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_protopol.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_race_condition.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_smuggling.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_sqli.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_ssrf.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_ssti.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_subdomain_takeover.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_xpath.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_xss.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_xxe.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_graphql.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_proto_pollution2.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_cache_poisoning.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_cache_deception.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_blind_ssrf.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_jwt_null.cpp"
            "${STANDALONE_ROOT}/core/network/burp/burp_proxy_mcp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/repeater.cpp"
            "${STANDALONE_ROOT}/core/network/burp/burp_repeater_mcp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/decoder.cpp"
            "${STANDALONE_ROOT}/core/network/burp/burp_decoder_mcp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/burp_logger_mcp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/burp_report_mcp.cpp"
            "${STANDALONE_ROOT}/core/tools/coding_tools_standalone.cpp"
            "${STANDALONE_ROOT}/core/debugger/debugger_tools_standalone.cpp"
            "${STANDALONE_ROOT}/core/debugger/thread_intel.cpp"
            "${STANDALONE_ROOT}/core/debugger/thread_intel_tools_standalone.cpp"
            "${STANDALONE_ROOT}/core/tools/workflow_tools_standalone.cpp"
            "${STANDALONE_ROOT}/core/tools/script_engine.cpp"
            "${STANDALONE_ROOT}/core/scanner/memory_scanner.cpp"
            "${STANDALONE_ROOT}/core/scanner/memory_scanner_view.cpp"
            "${STANDALONE_ROOT}/core/scanner/memory_interaction_context.cpp"
            "${STANDALONE_ROOT}/core/scanner/scanner_tools_standalone.cpp"
            "${STANDALONE_ROOT}/core/debugger/debugger_engine.cpp"
            "${STANDALONE_ROOT}/core/debugger/source_debug_service.cpp"
            "${STANDALONE_ROOT}/core/debugger/debugger_interaction_context.cpp"
            "${STANDALONE_ROOT}/core/debugger/debugger_view.cpp"
            "${STANDALONE_ROOT}/core/disasm/pseudocode_view.cpp"
            "${STANDALONE_ROOT}/core/analysis/struct_dissector_view.cpp"
            "${STANDALONE_ROOT}/core/analysis/types_hub_view.cpp"
            "${STANDALONE_ROOT}/core/analysis/struct_recon_view.cpp"
            "${STANDALONE_ROOT}/core/analysis/fuzzer_view.cpp"
            "${STANDALONE_ROOT}/core/analysis/analysis_tools_standalone.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/workspace_identity.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/byte_provider.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/live_snapshot_provider.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/pe_image.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/arch_decoder.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/x86_decoder.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/analysis_workspace.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/workspace_registry.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/analysis_metrics.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/function_recovery.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/xref_builder.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/publication_indexes.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/search_index.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/pe_baseline_analyzer.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/baseline_pipeline.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/persistence_queue.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/workspace_database.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/sqlite_reader_pool.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/string_arena.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/overlay_journal.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/patched_export.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/decompiler_service.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/decompiler_feedback.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/elf_image.cpp"
            "${STANDALONE_ROOT}/core/analysis/readers/elf_reader.cpp"
            "${STANDALONE_ROOT}/core/analysis/readers/pe_coff_reader.cpp"
            "${STANDALONE_ROOT}/core/analysis/image_layout_index.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/macho_image.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/zip_container.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/apk_container.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/dex_image.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/ipa_container.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/jar_container.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/classfile_parser.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/coff_image.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/arm_decoder.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/aarch64_decoder.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/mips_decoder.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/ppc_decoder.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/riscv_decoder.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/semantic_fusion.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/type_recovery.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/calling_convention.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/advanced_cfg.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/pseudocode_readability.cpp"
            "${STANDALONE_ROOT}/core/disasm/disasm_tools_standalone.cpp"
            "${STANDALONE_ROOT}/core/disasm/decompile_tools_standalone.cpp"
            "${STANDALONE_ROOT}/core/analysis/pdb_downloader.cpp"
            src/driver_loader.cpp
            driver/comm.cpp
            src/net_security.cpp
            src/emulation_engine.cpp
            "${STANDALONE_ROOT}/core/network/tls_exporter.cpp"
            "${STANDALONE_ROOT}/core/auth/auth_store.cpp"
            "${STANDALONE_ROOT}/core/auth/auth_http.cpp"
            "${STANDALONE_ROOT}/core/auth/auth_codex.cpp"
            "${STANDALONE_ROOT}/core/auth/auth_copilot.cpp"
            "${STANDALONE_ROOT}/core/auth/auth_claude_code.cpp"
            "${STANDALONE_ROOT}/core/auth/auth_view.cpp"
            "${STANDALONE_ROOT}/core/ai/provider_catalog.cpp"
            "${STANDALONE_ROOT}/core/ai/provider_transforms.cpp"
            "${STANDALONE_ROOT}/core/ai/provider_view.cpp"
            "${STANDALONE_ROOT}/core/infra/event_bus.cpp"
            "${STANDALONE_ROOT}/core/infra/host_topology.cpp"
            "${STANDALONE_ROOT}/core/infra/allocator.cpp"
            "${STANDALONE_ROOT}/core/analysis/binary_map.cpp"
            "${STANDALONE_ROOT}/core/session/session_store.cpp"
            "${STANDALONE_ROOT}/core/ai/agent_registry.cpp"
            "${STANDALONE_ROOT}/core/ai/agent_manager_service.cpp"
            "${STANDALONE_ROOT}/core/ai/skill_manager_service.cpp"
            "${STANDALONE_ROOT}/core/ai/agent_task.cpp"
            "${STANDALONE_ROOT}/core/session/compaction.cpp"
            "${STANDALONE_ROOT}/core/session/cost_calculator.cpp"
            "${STANDALONE_ROOT}/core/session/analysis_session.cpp"
            "${STANDALONE_ROOT}/core/tools/session_tools_standalone.cpp"
            "${STANDALONE_ROOT}/core/ai/command_registry.cpp"
            "${STANDALONE_ROOT}/core/ai/settings_overlay.cpp"
            "${STANDALONE_ROOT}/core/testlab/test_lab_registry.cpp"
            "${STANDALONE_ROOT}/core/testlab/test_lab_view.cpp"
            "${STANDALONE_ROOT}/core/testlab/test_lab_features_memory.cpp"
            "${STANDALONE_ROOT}/core/testlab/test_lab_features_thread.cpp"
            "${STANDALONE_ROOT}/core/testlab/test_lab_features_remote.cpp"
            "${STANDALONE_ROOT}/core/testlab/test_lab_features_module.cpp"
            "${STANDALONE_ROOT}/core/testlab/test_lab_features_network_query.cpp"
            "${STANDALONE_ROOT}/core/testlab/test_lab_features_network_action.cpp"
            "${STANDALONE_ROOT}/core/testlab/test_lab_features_sandbox.cpp"
            "${STANDALONE_ROOT}/core/testlab/test_lab_features_net_logging.cpp"
            "${STANDALONE_ROOT}/core/testlab/test_lab_features_verify.cpp"
            "${STANDALONE_ROOT}/core/testlab/test_all_features.cpp"
            "${STANDALONE_ROOT}/core/testlab/test_all_debugger.cpp"
            "${STANDALONE_ROOT}/core/testlab/test_all_scanner.cpp"
            "${STANDALONE_ROOT}/core/testlab/test_all_analysis.cpp"
            "${STANDALONE_ROOT}/core/testlab/test_all_network.cpp"
            "${STANDALONE_ROOT}/core/testlab/test_all_burp.cpp"
            "${STANDALONE_ROOT}/core/testlab/test_all_disasm.cpp"
            "${STANDALONE_ROOT}/core/testlab/test_all_mcp.cpp"
            "${STANDALONE_ROOT}/core/testlab/test_all_ui.cpp"
            "${DEPS_DIR}/sqlite-amalgamation-3530300/sqlite3.c"
        )

        set(AIDA_CERT_PIN_BYPASS_GUARD_FILES
            "${STANDALONE_ROOT}/core/network/cert_pin_bypass.hpp"
            "${STANDALONE_ROOT}/core/network/net_security_tools_standalone.cpp"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/net_security.cpp"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/net_security.hpp"
        )
        set(AIDA_FORBIDDEN_CERT_BYPASS_TOKENS
                "0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3"
                "0x31, 0xC0, 0xC3"
                "ssl_verify_cert_chain"
                "BoringSSL verify_cert_chain"
                "Schannel CertVerifyCertificateChainPolicy"
                "WinHTTP SSL validation"
                "WinINet SSL error handler"
                "NSS ssl3_HandleCertificate"
                "patch_wintrust"
                "patch_crypt32"
                "patch_schannel_validation"
                "patch_dotnet_callback"
                "Pin bypass applied"
                "Bypass certificate pinning in a target process by patching"
                "DotNet-SCH_CRED"
                "SChannel-CertValidation")
        foreach(_aida_cert_guard_file IN LISTS AIDA_CERT_PIN_BYPASS_GUARD_FILES)
            file(READ "${_aida_cert_guard_file}" AIDA_CERT_PIN_BYPASS_TEXT)
            foreach(_aida_forbidden_cert_bypass_token IN LISTS AIDA_FORBIDDEN_CERT_BYPASS_TOKENS)
                string(FIND "${AIDA_CERT_PIN_BYPASS_TEXT}" "${_aida_forbidden_cert_bypass_token}" _aida_forbidden_cert_bypass_pos)
                if(NOT _aida_forbidden_cert_bypass_pos EQUAL -1)
                    message(FATAL_ERROR "AiDA: legacy certificate bypass token found in ${_aida_cert_guard_file}: ${_aida_forbidden_cert_bypass_token}")
                endif()
            endforeach()
        endforeach()

        file(READ "${STANDALONE_ROOT}/core/testlab/test_all_mcp.cpp" AIDA_CERT_TESTLAB_MCP_TEXT)
        foreach(_aida_required_cert_test_token IN ITEMS
                "mcp.pin_bypass.guard"
                "target_process_modified"
                "mcp.cert_generate_ca.guard"
                "private_key_exported"
                "validate_only"
                "legacy_patching_disabled")
            string(FIND "${AIDA_CERT_TESTLAB_MCP_TEXT}" "${_aida_required_cert_test_token}" _aida_required_cert_test_pos)
            if(_aida_required_cert_test_pos EQUAL -1)
                message(FATAL_ERROR "AiDA: certificate interception regression guard missing MCP test token: ${_aida_required_cert_test_token}")
            endif()
        endforeach()

        file(READ "${STANDALONE_ROOT}/core/testlab/test_all_network.cpp" AIDA_CERT_TESTLAB_NETWORK_TEXT)
        foreach(_aida_required_cert_network_token IN ITEMS
                "openssl_attach_rejected"
                "sni_authority_mismatch"
                "export_public_ca_files"
                "public CA export")
            string(FIND "${AIDA_CERT_TESTLAB_NETWORK_TEXT}" "${_aida_required_cert_network_token}" _aida_required_cert_network_pos)
            if(_aida_required_cert_network_pos EQUAL -1)
                message(FATAL_ERROR "AiDA: certificate interception regression guard missing network test token: ${_aida_required_cert_network_token}")
            endif()
        endforeach()

        set_source_files_properties(
            "${DEPS_DIR}/sqlite-amalgamation-3530300/sqlite3.c"
            PROPERTIES
                COMPILE_DEFINITIONS "SQLITE_THREADSAFE=1;SQLITE_DQS=0;SQLITE_OMIT_DEPRECATED;SQLITE_DEFAULT_MEMSTATUS=0;SQLITE_DEFAULT_WAL_SYNCHRONOUS=1;SQLITE_LIKE_DOESNT_MATCH_BLOBS;SQLITE_MAX_EXPR_DEPTH=0;SQLITE_OMIT_DECLTYPE;SQLITE_OMIT_SHARED_CACHE;SQLITE_USE_ALLOCA"
                COMPILE_OPTIONS "$<$<COMPILE_LANGUAGE:C>:/wd4146>;$<$<COMPILE_LANGUAGE:C>:/wd4244>;$<$<COMPILE_LANGUAGE:C>:/wd4267>;$<$<COMPILE_LANGUAGE:C>:/wd4996>"
        )

        set(IMGUI_SOURCES
            "${STANDALONE_ROOT}/core/ui/imgui_capability_guard.cpp"
            "${imgui_SOURCE_DIR}/imgui.cpp"
            "${imgui_SOURCE_DIR}/imgui_draw.cpp"
            "${imgui_SOURCE_DIR}/imgui_tables.cpp"
            "${imgui_SOURCE_DIR}/imgui_widgets.cpp"
            "${imgui_SOURCE_DIR}/backends/imgui_impl_dx11.cpp"
            "${imgui_SOURCE_DIR}/backends/imgui_impl_win32.cpp"
        )

        set(STANDALONE_ASM driver/syscall.asm)
        set_source_files_properties(${STANDALONE_ASM} PROPERTIES LANGUAGE ASM_MASM)
        add_library(AiDAStandalone_asm OBJECT ${STANDALONE_ASM})

        configure_file(
            "${STANDALONE_ROOT}/resources/aida_embedded.rc.in"
            "${CMAKE_BINARY_DIR}/aida_embedded.rc"
            @ONLY
        )
        set_source_files_properties("${CMAKE_BINARY_DIR}/aida_embedded.rc" PROPERTIES
            GENERATED TRUE
        )

        set(STANDALONE_GUEST_AGENT_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/src/standalone/guest_agent")
        add_executable(AiDAGuestAgent
            "${STANDALONE_GUEST_AGENT_ROOT}/aida_guest_agent.cpp"
        )
        target_include_directories(AiDAGuestAgent PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/libs"
        )
        target_compile_definitions(AiDAGuestAgent PRIVATE
            _CRT_SECURE_NO_WARNINGS
            NOMINMAX
            WIN32_LEAN_AND_MEAN
            UNICODE
            _UNICODE
        )
        target_compile_options(AiDAGuestAgent PRIVATE
            /W3
            /EHsc
            /Zc:__cplusplus
            /permissive-
            /bigobj
        )
        if(TARGET aida_hardening)
            target_link_libraries(AiDAGuestAgent PRIVATE aida_hardening)
        endif()
        set_target_properties(AiDAGuestAgent PROPERTIES
            CXX_STANDARD 17
            CXX_STANDARD_REQUIRED YES
            MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
            OUTPUT_NAME "AiDAGuestAgent"
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Release"
            RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/Debug"
            RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/Release"
            RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_BINARY_DIR}/RelWithDebInfo"
        )

        add_executable(AIDADialogBroker
            "${CMAKE_CURRENT_SOURCE_DIR}/src/standalone/dialog_broker.cpp"
        )
        target_compile_definitions(AIDADialogBroker PRIVATE
            _CRT_SECURE_NO_WARNINGS
            NOMINMAX
            WIN32_LEAN_AND_MEAN
            UNICODE
            _UNICODE
        )
        target_compile_options(AIDADialogBroker PRIVATE
            /W3
            /EHsc
            /Zc:__cplusplus
            /permissive-
        )
        target_link_libraries(AIDADialogBroker PRIVATE ole32 shell32 uuid)
        set_target_properties(AIDADialogBroker PROPERTIES
            CXX_STANDARD 17
            CXX_STANDARD_REQUIRED YES
            MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
            OUTPUT_NAME "AIDADialogBroker"
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Release"
            RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/Debug"
            RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/Release"
            RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_BINARY_DIR}/RelWithDebInfo"
        )

        add_executable(AiDAStandalone WIN32
            ${STANDALONE_SOURCES}
            ${IMGUI_SOURCES}
            $<TARGET_OBJECTS:AiDAStandalone_asm>
            "${CMAKE_BINARY_DIR}/aida_embedded.rc"
        )
        set_source_files_properties("${STANDALONE_ROOT}/core/runtime/kernel_symbols.cpp"
            PROPERTIES COMPILE_OPTIONS "/std:c++20" SKIP_PRECOMPILE_HEADERS ON)
        set(_aida_c03_production_sources ${AIDA_C03_PRODUCTION_STANDALONE_SOURCES})
        list(REMOVE_ITEM _aida_c03_production_sources ${STANDALONE_SOURCES})
        list(REMOVE_DUPLICATES _aida_c03_production_sources)
        target_sources(AiDAStandalone PRIVATE ${_aida_c03_production_sources})
        if(NOT Z3_FOUND OR NOT Z3_INCLUDE_DIRS OR NOT Z3_LIBRARIES OR
           NOT IS_DIRECTORY "${Z3_INCLUDE_DIRS}" OR NOT EXISTS "${Z3_LIBRARIES}")
            message(FATAL_ERROR "AiDAStandalone requires the pinned local Z3 include and library dependencies")
        endif()
        aida_c03_register_worker_targets(AiDAStandalone)

        target_include_directories(AiDAStandalone PRIVATE
            "${CMAKE_CURRENT_BINARY_DIR}/generated"
            "${Z3_INCLUDE_DIRS}"
            "${STANDALONE_ROOT}"
            "${STANDALONE_ROOT}/core"
            "${STANDALONE_ROOT}/core/ai"
            "${STANDALONE_ROOT}/core/auth"
            "${STANDALONE_ROOT}/core/debugger"
            "${STANDALONE_ROOT}/core/disasm"
            "${STANDALONE_ROOT}/core/emulation"
            "${STANDALONE_ROOT}/core/network"
            "${STANDALONE_ROOT}/core/scanner"
            "${STANDALONE_ROOT}/core/analysis"
            "${STANDALONE_ROOT}/core/analysis/workspace"
            "${STANDALONE_ROOT}/core/editor"
            "${STANDALONE_ROOT}/core/tools"
            "${STANDALONE_ROOT}/core/session"
            "${STANDALONE_ROOT}/core/mcp"
            "${STANDALONE_ROOT}/core/runtime"
            "${STANDALONE_ROOT}/core/ui"
            "${STANDALONE_ROOT}/core/infra"
            "${STANDALONE_ROOT}/core/settings"
            "${STANDALONE_ROOT}/core/testlab"
            "${STANDALONE_ROOT}/core/diagnostics"
            "${CMAKE_BINARY_DIR}/_imgui_wrapper"
            "${imgui_SOURCE_DIR}"
            "${imgui_SOURCE_DIR}/backends"
            "${lua_src_SOURCE_DIR}"
            "${sol2_SOURCE_DIR}/include"
            "${CMAKE_CURRENT_SOURCE_DIR}/libs/cpp-httplib"
            "${CMAKE_CURRENT_SOURCE_DIR}/libs"
            "${CMAKE_CURRENT_SOURCE_DIR}/src"
            "${CMAKE_CURRENT_SOURCE_DIR}/driver"
            "${zydis_SOURCE_DIR}/include"
            "${zydis_SOURCE_DIR}/dependencies/zycore/include"
            "${zydis_BINARY_DIR}"
            "${zydis_BINARY_DIR}/zycore"
            "${unicorn_SOURCE_DIR}/include"
            "${zlib_SOURCE_DIR}"
            "${zlib_BINARY_DIR}"
            "${IDA_STUBS_DIR}"
            "${CMAKE_CURRENT_SOURCE_DIR}/mapper/src"
            "${TRITON_SOURCE_DIR}/src/libtriton/includes"
            "${CMAKE_BINARY_DIR}/.deps/triton/src/libtriton/includes"
            "${capstone_SOURCE_DIR}/include"
            "${GHIDRA_DECOMP_DIR}"
            "${DEPS_DIR}/sqlite-amalgamation-3530300"
        )

        target_include_directories(AiDAStandalone SYSTEM PRIVATE
            "${DEPS_DIR}/taskflow"
            "${parallel_hashmap_SOURCE_DIR}"
            "${concurrentqueue_SOURCE_DIR}"
        )

        target_compile_definitions(AiDAStandalone PRIVATE
            __NT__
            _CRT_SECURE_NO_WARNINGS
            CPPHTTPLIB_OPENSSL_SUPPORT
            NOMINMAX
            WIN32_LEAN_AND_MEAN
            IMGUI_ENABLE_STB_TRUETYPE
            UNICODE
            _UNICODE
            SOL_ALL_SAFETIES_ON=1
            GHIDRA_SPECS_DIR=${GHIDRA_SPECS_OUTPUT_DIR}
            AIDA_STANDALONE
            AIDA_IMGUI_SOURCE_SHA256=${AIDA_IMGUI_SOURCE_SHA256}
        )
        if(NOT AIDA_DISABLE_LEGACY_DRIVER_MAPPER)
            target_compile_definitions(AiDAStandalone PRIVATE AIDA_LEGACY_DRIVER_MAPPER_AVAILABLE)
        endif()

        target_compile_options(AiDAStandalone PRIVATE
            /W3
            /wd4005
            /wd4099
            /EHsc
            /Zc:__cplusplus
            /permissive-
            /Zp8
            /bigobj
        )

        enable_testing()
        aida_c03_register_safe_headless_targets(AiDAStandalone)

        aida_use_static_msvc_runtime(
            AiDAStandalone
            AiDAStandalone_asm
            Zydis
            Zycore
            unicorn
            unicorn-common
            x86_64-softmmu
            triton
            capstone
            capstone_static
            MemPDB
            nlohmann_json_schema_validator
            libdecomp_aida
            zlibstatic
            zlib
            libzstd_static
            liblzma
            brotlidec
            brotlienc
            brotlicommon
            llhttp_static
            nghttp2_static
            lua54_static
        )

        target_precompile_headers(AiDAStandalone PRIVATE
            "$<$<COMPILE_LANGUAGE:CXX>:<Windows.h$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<vector$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<string$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<string_view$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<unordered_map$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<unordered_set$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<map$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<set$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<deque$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<list$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<array$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<queue$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<stack$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<thread$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<mutex$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<atomic$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<future$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<condition_variable$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<chrono$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<filesystem$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<fstream$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<sstream$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<iostream$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<algorithm$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<numeric$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<memory$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<functional$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<optional$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<variant$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<tuple$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<utility$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<type_traits$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<cstdint$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<cstring$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<cstdio$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<cassert$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<cmath$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<cstdlib$<ANGLE-R>>"
        )

        target_link_libraries(AiDAStandalone PRIVATE
            Zydis
            unicorn
            triton
            "${Z3_LIBRARIES}"
            capstone::capstone
            MemPDB
            mimalloc-static
            nlohmann_json_schema_validator::validator
            libdecomp_aida
            zlibstatic
            libzstd_static
            liblzma
            pcre2-8
            brotlidec
            brotlienc
            brotlicommon
            llhttp_static
            nghttp2_static
            lua54_static
            aida_openssl_ssl_mt
            aida_openssl_crypto_mt
            d3d11
            dxgi
            dwmapi
            ws2_32
            dnsapi
            winhttp
            iphlpapi
            ntdll
            crypt32
            bcrypt
            Shlwapi
            advapi32
            userenv
            wintrust
            setupapi
            cfgmgr32
            Psapi
        )

        target_link_options(AiDAStandalone PRIVATE
            $<IF:$<BOOL:${AIDA_FAST_LINK}>,/DEBUG,/DEBUG:FULL>
            /ENTRY:mainCRTStartup
            /NODEFAULTLIB:d3dcompiler
            /IGNORE:4099
            "/MANIFESTUAC:level='requireAdministrator' uiAccess='false'"
            /PDBALTPATH:none
            /EMITTOOLVERSIONINFO:NO
        )

        if(TARGET aida_hardening)
            target_link_libraries(AiDAStandalone PRIVATE aida_hardening)
        endif()

        set_target_properties(AiDAStandalone PROPERTIES
            OUTPUT_NAME "AiDAStandalone"
            PDB_NAME_DEBUG "AiDAStandalone"
            PDB_NAME_RELEASE "AiDAStandalone"
            PDB_NAME_RELWITHDEBINFO "AiDAStandalone"
            COMPILE_PDB_NAME_DEBUG "AiDAStandalone"
            COMPILE_PDB_NAME_RELEASE "AiDAStandalone"
            COMPILE_PDB_NAME_RELWITHDEBINFO "AiDAStandalone"
            PDB_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/Debug"
            PDB_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/Release"
            PDB_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_BINARY_DIR}/RelWithDebInfo"
            COMPILE_PDB_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/Debug"
            COMPILE_PDB_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/Release"
            COMPILE_PDB_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_BINARY_DIR}/RelWithDebInfo"
        )

        option(AIDA_STANDALONE_STAGE_APPLOCAL_RUNTIME_DLLS "Stage app-local runtime DLLs beside AiDAStandalone.exe" ON)
        if(AIDA_STANDALONE_STAGE_APPLOCAL_RUNTIME_DLLS)
            aida_collect_windows_runtime_dlls(_aida_standalone_runtime_candidates)
            foreach(_aida_z3_runtime_name IN LISTS AIDA_Z3_RUNTIME_DLL_NAMES)
                list(APPEND _aida_standalone_runtime_candidates "${Z3_INSTALL_DIR}/bin/${_aida_z3_runtime_name}")
            endforeach()
            aida_dedupe_runtime_dlls_by_filename(AIDA_STANDALONE_APPLOCAL_RUNTIME_DLLS ${_aida_standalone_runtime_candidates})
            if(AIDA_STANDALONE_APPLOCAL_RUNTIME_DLLS)
                add_custom_command(TARGET AiDAStandalone POST_BUILD
                    COMMAND ${CMAKE_COMMAND} -E copy_if_different
                        ${AIDA_STANDALONE_APPLOCAL_RUNTIME_DLLS}
                        "$<TARGET_FILE_DIR:AiDAStandalone>"
                    COMMAND_EXPAND_LISTS
                    COMMENT "Staging app-local runtime DLLs beside AiDAStandalone.exe..."
                    VERBATIM
                )
            endif()
        endif()

        set(AIDA_STANDALONE_Z3_RUNTIME_DLLS)
        foreach(_aida_z3_runtime_name IN LISTS AIDA_Z3_RUNTIME_DLL_NAMES)
            list(APPEND AIDA_STANDALONE_Z3_RUNTIME_DLLS "${Z3_INSTALL_DIR}/bin/${_aida_z3_runtime_name}")
        endforeach()
        add_custom_command(TARGET AiDAStandalone POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E make_directory
                "$<TARGET_FILE_DIR:AiDAStandalone>/deps/z3"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                ${AIDA_STANDALONE_Z3_RUNTIME_DLLS}
                "$<TARGET_FILE_DIR:AiDAStandalone>/deps/z3"
            COMMAND_EXPAND_LISTS
            COMMENT "Staging Z3 runtime DLLs for AiDAStandalone..."
            VERBATIM
        )

        add_dependencies(AiDAStandalone AiDAGuestAgent)
        add_custom_command(TARGET AiDAStandalone POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "$<TARGET_FILE:AiDAGuestAgent>"
                "$<TARGET_FILE_DIR:AiDAStandalone>/AiDAGuestAgent.exe"
            COMMENT "Staging AiDAGuestAgent beside AiDAStandalone.exe..."
            VERBATIM
        )

        add_dependencies(AiDAStandalone AIDADialogBroker)
        add_custom_command(TARGET AiDAStandalone POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "$<TARGET_FILE:AIDADialogBroker>"
                "$<TARGET_FILE_DIR:AiDAStandalone>/AIDADialogBroker.exe"
            COMMENT "Staging AIDADialogBroker beside AiDAStandalone.exe..."
            VERBATIM
        )

        if(TARGET encrypt_drivers)
            add_dependencies(AiDAStandalone encrypt_drivers)
        endif()

        if(TARGET ghidra_specs)
            add_dependencies(AiDAStandalone ghidra_specs)
        endif()

        add_custom_command(TARGET AiDAStandalone POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${CMAKE_SOURCE_DIR}/build-ninja/Release/WindMapper.exe"
                "${CMAKE_BINARY_DIR}/AiDAWindMapper.exe"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${CMAKE_SOURCE_DIR}/build-ninja/Release/WhosWho.sys"
                "${CMAKE_BINARY_DIR}/WhosWho.sys"
            COMMENT "Copying WindMapper and WhosWho.sys next to AiDAStandalone")

        add_executable(AiDAParserProof
            "${STANDALONE_ROOT}/core/testlab/parser_proof_runner.cpp"
            "${STANDALONE_ROOT}/core/network/protocol_parser.cpp"
        )

        target_include_directories(AiDAParserProof PRIVATE
            "${STANDALONE_ROOT}"
            "${STANDALONE_ROOT}/core"
            "${STANDALONE_ROOT}/core/network"
            "${STANDALONE_ROOT}/core/testlab"
            "${zlib_SOURCE_DIR}"
            "${zlib_BINARY_DIR}"
        )

        target_compile_definitions(AiDAParserProof PRIVATE
            _CRT_SECURE_NO_WARNINGS
            NOMINMAX
        )

        target_compile_options(AiDAParserProof PRIVATE
            /W3
            /EHsc
            /Zc:__cplusplus
            /permissive-
        )

        aida_use_static_msvc_runtime(AiDAParserProof)

        target_link_libraries(AiDAParserProof PRIVATE
            llhttp_static
            nghttp2_static
            zlibstatic
            brotlidec
            brotlicommon
        )

        if(TARGET aida_hardening)
            target_link_libraries(AiDAParserProof PRIVATE aida_hardening)
        endif()

        add_executable(AiDA_NetworkHookSidecar
            "${STANDALONE_ROOT}/core/testlab/network_hook_sidecar.cpp"
        )

        target_include_directories(AiDA_NetworkHookSidecar PRIVATE
            "${STANDALONE_ROOT}"
            "${STANDALONE_ROOT}/core"
            "${STANDALONE_ROOT}/core/testlab"
        )

        target_compile_definitions(AiDA_NetworkHookSidecar PRIVATE
            _CRT_SECURE_NO_WARNINGS
            NOMINMAX
            WIN32_LEAN_AND_MEAN
        )

        target_compile_options(AiDA_NetworkHookSidecar PRIVATE
            /W3
            /EHsc
            /Zc:__cplusplus
            /permissive-
            /MD
        )

        target_link_libraries(AiDA_NetworkHookSidecar PRIVATE
            ws2_32
        )

        set_target_properties(AiDA_NetworkHookSidecar PROPERTIES
            CXX_STANDARD 17
            CXX_STANDARD_REQUIRED YES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Release"
            RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/Debug"
            RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/Release"
            RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_BINARY_DIR}/RelWithDebInfo"
        )

        add_custom_command(TARGET AiDAStandalone POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E make_directory
                "$<TARGET_FILE_DIR:AiDAStandalone>/deps/notices/analysis"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${AIDA_ANALYSIS_NOTICE_LEDGER_FILE}"
                "$<TARGET_FILE_DIR:AiDAStandalone>/deps/notices/analysis/THIRD_PARTY_NOTICES_ANALYSIS.md"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${zydis_SOURCE_DIR}/LICENSE"
                "$<TARGET_FILE_DIR:AiDAStandalone>/deps/notices/analysis/Zydis-LICENSE.txt"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${zycore_SOURCE_DIR}/LICENSE"
                "$<TARGET_FILE_DIR:AiDAStandalone>/deps/notices/analysis/Zycore-LICENSE.txt"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${DEPS_DIR}/taskflow/LICENSE"
                "$<TARGET_FILE_DIR:AiDAStandalone>/deps/notices/analysis/Taskflow-LICENSE.txt"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${DEPS_DIR}/zlib/LICENSE"
                "$<TARGET_FILE_DIR:AiDAStandalone>/deps/notices/analysis/zlib-LICENSE.txt"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${DEPS_DIR}/licenses/nlohmann-json-3.12.0-LICENSE.MIT"
                "$<TARGET_FILE_DIR:AiDAStandalone>/deps/notices/analysis/nlohmann-json-LICENSE.txt"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${AIDA_CAPSTONE_LICENSE_FILE}"
                "$<TARGET_FILE_DIR:AiDAStandalone>/deps/notices/analysis/Capstone-LICENSE.txt"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${AIDA_JSON_SCHEMA_VALIDATOR_LICENSE_FILE}"
                "$<TARGET_FILE_DIR:AiDAStandalone>/deps/notices/analysis/nlohmann-json-schema-validator-LICENSE.txt"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${AIDA_GHIDRA_LICENSE_FILE}"
                "$<TARGET_FILE_DIR:AiDAStandalone>/deps/notices/analysis/Ghidra-LICENSE.txt"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${AIDA_GHIDRA_NOTICE_FILE}"
                "$<TARGET_FILE_DIR:AiDAStandalone>/deps/notices/analysis/Ghidra-NOTICE.txt"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${AIDA_ZSTD_LICENSE_FILE}"
                "$<TARGET_FILE_DIR:AiDAStandalone>/deps/notices/analysis/zstd-LICENSE.txt"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${AIDA_LIBLZMA_LICENSE_FILE}"
                "$<TARGET_FILE_DIR:AiDAStandalone>/deps/notices/analysis/liblzma-COPYING.txt"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${AIDA_PCRE2_LICENSE_FILE}"
                "$<TARGET_FILE_DIR:AiDAStandalone>/deps/notices/analysis/PCRE2-LICENCE.txt"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${AIDA_MIMALLOC_LICENSE_FILE}"
                "$<TARGET_FILE_DIR:AiDAStandalone>/deps/notices/analysis/mimalloc-LICENSE.txt"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${AIDA_PARALLEL_HASHMAP_LICENSE_FILE}"
                "$<TARGET_FILE_DIR:AiDAStandalone>/deps/notices/analysis/parallel-hashmap-LICENSE.txt"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${AIDA_CONCURRENTQUEUE_LICENSE_FILE}"
                "$<TARGET_FILE_DIR:AiDAStandalone>/deps/notices/analysis/concurrentqueue-LICENSE.txt"
            COMMENT "Staging pinned analysis dependency notices beside AiDAStandalone..."
            VERBATIM
        )

        set_target_properties(AiDA_NetworkHookSidecar PROPERTIES
            OUTPUT_NAME "AiDA_NetworkHookSidecar"
        )

        option(AIDA_CAMOUFOX_STAGE_SIDECAR_DEPS "Stage Camoufox runtime sidecars beside AiDAStandalone for development" OFF)
        option(AIDA_CAMOUFOX_STAGE_REVERSE_MCP_SOURCE "Stage the camoufox-reverse-mcp source beside AiDAStandalone for the source-launched reverse MCP" ON)

        set(AIDA_CAMOUFOX_MCP_DIR "")
        if(AIDA_CAMOUFOX_STAGE_REVERSE_MCP_SOURCE)
            set(AIDA_CAMOUFOX_MCP_CANDIDATES
                "${CMAKE_CURRENT_SOURCE_DIR}/.deps/camoufox-reverse-mcp"
                "${CMAKE_CURRENT_SOURCE_DIR}/camoufox-reverse-mcp"
            )
            foreach(AIDA_CAMOUFOX_MCP_CANDIDATE IN LISTS AIDA_CAMOUFOX_MCP_CANDIDATES)
                if(NOT AIDA_CAMOUFOX_MCP_DIR AND EXISTS "${AIDA_CAMOUFOX_MCP_CANDIDATE}/pyproject.toml")
                    set(AIDA_CAMOUFOX_MCP_DIR "${AIDA_CAMOUFOX_MCP_CANDIDATE}")
                endif()
            endforeach()
            if(NOT AIDA_CAMOUFOX_MCP_DIR)
                message(FATAL_ERROR "AiDA Camoufox source staging enabled but camoufox-reverse-mcp/pyproject.toml was not found")
            endif()
        endif()

        set(AIDA_CAMOUFOX_BROWSER_CANDIDATES
            "${CMAKE_CURRENT_SOURCE_DIR}/.deps/camoufox-135.0.1-beta.24-win.x86_64"
            "${CMAKE_CURRENT_SOURCE_DIR}/camoufox-135.0.1-beta.24-win.x86_64"
        )
        set(AIDA_CAMOUFOX_BROWSER_DIR "")
        foreach(AIDA_CAMOUFOX_BROWSER_CANDIDATE IN LISTS AIDA_CAMOUFOX_BROWSER_CANDIDATES)
            if(NOT AIDA_CAMOUFOX_BROWSER_DIR AND EXISTS "${AIDA_CAMOUFOX_BROWSER_CANDIDATE}/camoufox.exe")
                set(AIDA_CAMOUFOX_BROWSER_DIR "${AIDA_CAMOUFOX_BROWSER_CANDIDATE}")
            endif()
        endforeach()

        set(AIDA_BUNDLED_PYTHON_CANDIDATES
            "${CMAKE_CURRENT_SOURCE_DIR}/.deps/camoufox-runtime"
            "${CMAKE_CURRENT_SOURCE_DIR}/.deps/camoufox-python"
            "${CMAKE_CURRENT_SOURCE_DIR}/.deps/python-3.12"
            "${CMAKE_CURRENT_SOURCE_DIR}/.deps/python-3.12.10-x64"
            "${CMAKE_CURRENT_SOURCE_DIR}/.deps/Python312"
            "${CMAKE_CURRENT_SOURCE_DIR}/.deps/Python312-3.12.10-x64"
            "${CMAKE_CURRENT_SOURCE_DIR}/camoufox-runtime"
            "${CMAKE_CURRENT_SOURCE_DIR}/camoufox-python"
            "${CMAKE_CURRENT_SOURCE_DIR}/python-3.12"
            "${CMAKE_CURRENT_SOURCE_DIR}/python-3.12.10-x64"
            "${CMAKE_CURRENT_SOURCE_DIR}/Python312"
            "${CMAKE_CURRENT_SOURCE_DIR}/Python312-3.12.10-x64"
            "${CMAKE_CURRENT_SOURCE_DIR}/runtime/python"
            "${CMAKE_CURRENT_SOURCE_DIR}/runtime/python/Python312-3.12.10-x64"
            "${CMAKE_CURRENT_SOURCE_DIR}/runtimes/python/Python312-3.12.10-x64"
        )
        set(AIDA_BUNDLED_PYTHON_DIR "")
        foreach(AIDA_BUNDLED_PYTHON_CANDIDATE IN LISTS AIDA_BUNDLED_PYTHON_CANDIDATES)
            if(NOT AIDA_BUNDLED_PYTHON_DIR AND EXISTS "${AIDA_BUNDLED_PYTHON_CANDIDATE}/python.exe")
                execute_process(
                    COMMAND "${AIDA_BUNDLED_PYTHON_CANDIDATE}/python.exe" -I -c "import sys; raise SystemExit(0 if sys.implementation.name == 'cpython' and sys.version_info[:2] == (3, 12) else 1)"
                    RESULT_VARIABLE AIDA_BUNDLED_PYTHON_VERSION_RESULT
                    TIMEOUT 10
                    OUTPUT_QUIET
                    ERROR_QUIET
                )
                if(AIDA_BUNDLED_PYTHON_VERSION_RESULT EQUAL 0)
                    set(AIDA_BUNDLED_PYTHON_DIR "${AIDA_BUNDLED_PYTHON_CANDIDATE}")
                else()
                    message(STATUS "Ignoring non-CPython-3.12 Camoufox runtime: ${AIDA_BUNDLED_PYTHON_CANDIDATE}")
                endif()
            endif()
        endforeach()

        set(AIDA_CAMOUFOX_STAGE_EFFECTIVE OFF)
        if(AIDA_CAMOUFOX_STAGE_SIDECAR_DEPS)
            if(NOT AIDA_CAMOUFOX_BROWSER_DIR)
                message(WARNING "AiDA Camoufox sidecar staging enabled but camoufox browser was not found; staging disabled")
                set(AIDA_CAMOUFOX_STAGE_SIDECAR_DEPS OFF)
            elseif(NOT AIDA_BUNDLED_PYTHON_DIR)
                message(WARNING "AiDA Camoufox sidecar staging enabled but a bundled CPython 3.12 runtime was not found; offline staging disabled")
                set(AIDA_CAMOUFOX_STAGE_SIDECAR_DEPS OFF)
            else()
                set(AIDA_CAMOUFOX_STAGE_EFFECTIVE ON)
            endif()
        elseif(AIDA_CAMOUFOX_BROWSER_DIR AND AIDA_BUNDLED_PYTHON_DIR AND AIDA_CAMOUFOX_STAGE_REVERSE_MCP_SOURCE)
            set(AIDA_CAMOUFOX_STAGE_EFFECTIVE ON)
            message(STATUS "AiDA Camoufox app-local sidecar assets detected; staging enabled")
        elseif(AIDA_CAMOUFOX_BROWSER_DIR OR AIDA_BUNDLED_PYTHON_DIR OR AIDA_CAMOUFOX_STAGE_REVERSE_MCP_SOURCE)
            message(STATUS "AiDA Camoufox app-local sidecar assets incomplete; staging disabled")
        endif()

        if(AIDA_CAMOUFOX_STAGE_EFFECTIVE)
            if(AIDA_CAMOUFOX_STAGE_REVERSE_MCP_SOURCE)
                add_custom_command(TARGET AiDAStandalone POST_BUILD
                    COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:AiDAStandalone>/deps"
                    COMMAND ${CMAKE_COMMAND} -E copy_directory_if_different
                        "${AIDA_CAMOUFOX_MCP_DIR}"
                        "$<TARGET_FILE_DIR:AiDAStandalone>/deps/camoufox-reverse-mcp"
                    COMMENT "Staging camoufox-reverse-mcp source beside AiDAStandalone.exe for the source-launched reverse MCP..."
                    VERBATIM
                )
            endif()

            add_custom_command(TARGET AiDAStandalone POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:AiDAStandalone>/deps"
                COMMAND ${CMAKE_COMMAND} -E copy_directory_if_different
                    "${AIDA_CAMOUFOX_BROWSER_DIR}"
                    "$<TARGET_FILE_DIR:AiDAStandalone>/deps/camoufox-135.0.1-beta.24-win.x86_64"
                COMMENT "Staging app-local Camoufox browser payload beside AiDAStandalone.exe..."
                VERBATIM
            )

            if(AIDA_BUNDLED_PYTHON_DIR)
                add_custom_command(TARGET AiDAStandalone POST_BUILD
                    COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:AiDAStandalone>/deps"
                    COMMAND ${CMAKE_COMMAND} -E copy_directory_if_different
                        "${AIDA_BUNDLED_PYTHON_DIR}"
                        "$<TARGET_FILE_DIR:AiDAStandalone>/deps/camoufox-runtime"
                    COMMENT "Staging app-local Python runtime beside AiDAStandalone.exe..."
                    VERBATIM
                )
                message(STATUS "AiDA Camoufox app-local Python runtime: ${AIDA_BUNDLED_PYTHON_DIR}")
            endif()

        endif()

        if(AIDA_CAMOUFOX_STAGE_EFFECTIVE)
            set(AIDA_PYTHON_INSTALLER_CANDIDATES
                "${CMAKE_CURRENT_SOURCE_DIR}/python-3.12.10-amd64.exe"
                "${CMAKE_CURRENT_SOURCE_DIR}/camoufox-runtime/python-3.12.10-amd64.exe"
                "${CMAKE_CURRENT_SOURCE_DIR}/camoufox-python/python-3.12.10-amd64.exe"
                "${CMAKE_CURRENT_SOURCE_DIR}/python-3.12/python-3.12.10-amd64.exe"
                "${CMAKE_CURRENT_SOURCE_DIR}/python-3.12.10-x64/python-3.12.10-amd64.exe"
                "${CMAKE_CURRENT_SOURCE_DIR}/Python312/python-3.12.10-amd64.exe"
                "${CMAKE_CURRENT_SOURCE_DIR}/Python312-3.12.10-x64/python-3.12.10-amd64.exe"
                "${CMAKE_CURRENT_SOURCE_DIR}/.deps/camoufox-runtime/python-3.12.10-amd64.exe"
                "${CMAKE_CURRENT_SOURCE_DIR}/.deps/camoufox-python/python-3.12.10-amd64.exe"
                "${CMAKE_CURRENT_SOURCE_DIR}/.deps/python-3.12.10-amd64.exe"
                "${CMAKE_CURRENT_SOURCE_DIR}/.deps/python-3.12/python-3.12.10-amd64.exe"
                "${CMAKE_CURRENT_SOURCE_DIR}/.deps/python-3.12.10-x64/python-3.12.10-amd64.exe"
                "${CMAKE_CURRENT_SOURCE_DIR}/.deps/Python312/python-3.12.10-amd64.exe"
                "${CMAKE_CURRENT_SOURCE_DIR}/.deps/Python312-3.12.10-x64/python-3.12.10-amd64.exe"
            )
            set(AIDA_PYTHON_INSTALLER "")
            foreach(AIDA_PYTHON_INSTALLER_CANDIDATE IN LISTS AIDA_PYTHON_INSTALLER_CANDIDATES)
                if(NOT AIDA_PYTHON_INSTALLER AND EXISTS "${AIDA_PYTHON_INSTALLER_CANDIDATE}")
                    set(AIDA_PYTHON_INSTALLER "${AIDA_PYTHON_INSTALLER_CANDIDATE}")
                endif()
            endforeach()
            if(AIDA_PYTHON_INSTALLER AND EXISTS "${AIDA_PYTHON_INSTALLER}")
                add_custom_command(TARGET AiDAStandalone POST_BUILD
                    COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:AiDAStandalone>/deps"
                    COMMAND ${CMAKE_COMMAND} -E copy_if_different
                        "${AIDA_PYTHON_INSTALLER}"
                        "$<TARGET_FILE_DIR:AiDAStandalone>/deps/python-3.12.10-amd64.exe"
                    COMMENT "Staging Python installer beside AiDAStandalone.exe..."
                    VERBATIM
                )
                message(STATUS "AiDA Camoufox app-local Python installer: ${AIDA_PYTHON_INSTALLER}")
            endif()

            set(AIDA_CAMOUFOX_WHEELHOUSE_CANDIDATES
                "${CMAKE_CURRENT_SOURCE_DIR}/camoufox-wheelhouse"
                "${CMAKE_CURRENT_SOURCE_DIR}/wheelhouse"
                "${CMAKE_CURRENT_SOURCE_DIR}/wheels"
                "${CMAKE_CURRENT_SOURCE_DIR}/.deps/camoufox-wheelhouse"
                "${CMAKE_CURRENT_SOURCE_DIR}/.deps/wheelhouse"
                "${CMAKE_CURRENT_SOURCE_DIR}/.deps/wheels"
            )
            set(AIDA_CAMOUFOX_WHEELHOUSE_DIR "")
            foreach(AIDA_CAMOUFOX_WHEELHOUSE_CANDIDATE IN LISTS AIDA_CAMOUFOX_WHEELHOUSE_CANDIDATES)
                if(NOT AIDA_CAMOUFOX_WHEELHOUSE_DIR AND EXISTS "${AIDA_CAMOUFOX_WHEELHOUSE_CANDIDATE}")
                    set(AIDA_CAMOUFOX_WHEELHOUSE_DIR "${AIDA_CAMOUFOX_WHEELHOUSE_CANDIDATE}")
                endif()
            endforeach()
            if(AIDA_CAMOUFOX_WHEELHOUSE_DIR)
                add_custom_command(TARGET AiDAStandalone POST_BUILD
                    COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:AiDAStandalone>/deps"
                    COMMAND ${CMAKE_COMMAND} -E copy_directory_if_different
                        "${AIDA_CAMOUFOX_WHEELHOUSE_DIR}"
                        "$<TARGET_FILE_DIR:AiDAStandalone>/deps/camoufox-wheelhouse"
                    COMMENT "Staging app-local Camoufox Python wheelhouse beside AiDAStandalone.exe..."
                    VERBATIM
                )
                message(STATUS "AiDA Camoufox app-local wheelhouse: ${AIDA_CAMOUFOX_WHEELHOUSE_DIR}")
            endif()

            if(AIDA_CAMOUFOX_STAGE_REVERSE_MCP_SOURCE)
                add_custom_command(TARGET AiDAStandalone POST_BUILD
                    COMMAND ${CMAKE_COMMAND}
                        "-DAIDA_CAMOUFOX_STAGE_ROOT=$<TARGET_FILE_DIR:AiDAStandalone>"
                        "-DAIDA_CAMOUFOX_MCP_DIR=${AIDA_CAMOUFOX_MCP_DIR}"
                        -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/aida_patch_camoufox_reverse_mcp.cmake"
                    COMMENT "Staging and verifying the offline Camoufox reverse MCP runtime..."
                    VERBATIM
                )
            endif()
        endif()
    endif()

endif()

if(BUILD_AIDA_PLUGIN)

if(NOT EXISTS "${IDASDK_DIR}/include/ida.hpp")
    if(EXISTS "${IDASDK_DIR}/src/include/ida.hpp")
        set(IDASDK_DIR "${IDASDK_DIR}/src")
    else()
        message(FATAL_ERROR
            "IDASDK_DIR (${IDASDK_DIR}) does not contain include/ida.hpp.\n"
            "Point it to the SDK's 'src' directory.")
    endif()
endif()

message(STATUS "IDA SDK: ${IDASDK_DIR}")

if(WIN32)
    set(IDA_LIB_DIR "${IDASDK_DIR}/lib/x64_win_64")
    set(IDA_LINK_LIB "${IDA_LIB_DIR}/ida.lib")
elseif(APPLE)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64")
        set(IDA_LIB_DIR "${IDASDK_DIR}/lib/arm64_mac_clang_64")
    else()
        set(IDA_LIB_DIR "${IDASDK_DIR}/lib/x64_mac_clang_64")
    endif()
    set(IDA_LINK_LIB "${IDA_LIB_DIR}/libida.dylib")
elseif(UNIX)
    set(IDA_LIB_DIR "${IDASDK_DIR}/lib/x64_linux_gcc_64")
    set(IDA_LINK_LIB "${IDA_LIB_DIR}/libida.so")
else()
    message(FATAL_ERROR "Unsupported platform")
endif()

if(NOT EXISTS "${IDA_LINK_LIB}")
    message(FATAL_ERROR "IDA link library not found: ${IDA_LINK_LIB}")
endif()

set(AIDA_SOURCES
    src/actions.cpp
    src/agent_tools.cpp
    src/aida.cpp
    src/aida_ipc.cpp
    src/graphrag.cpp
    src/ida_utils.cpp
    src/instance_registry.cpp
    src/mcp_server.cpp
    src/multibinary_index.cpp
    src/multibinary_project.cpp
    src/settings.cpp
    src/driver_loader.cpp
    src/vuln/chain_binary_corpus.cpp
    src/vuln/chain_model.cpp
    src/vuln/chain_report.cpp
    src/vuln/chain_schema.cpp
    src/vuln/chain_state.cpp
    src/vuln/chain_store.cpp
    src/vuln/cfg_engine.cpp
    src/vuln/kernel_engine.cpp
    src/vuln/microcode_engine.cpp
    src/vuln/chain_budget.cpp
    src/vuln/chain_extraction.cpp
    src/vuln/chain_path_trace.cpp
    src/vuln/chain_transfer.cpp
    src/vuln/chain_alias.cpp
    src/vuln/chain_lifetime.cpp
    src/vuln/chain_protocol.cpp
    src/vuln/chain_cross_domain.cpp
    src/vuln/chain_boundary.cpp
    src/vuln/chain_side_effects.cpp
    src/vuln/chain_solver.cpp
    src/vuln/chain_state_contracts.cpp
    src/vuln/chain_regression_specs.cpp
    src/vuln/chain_trigger_trace.cpp
    src/vuln/chain_verifier.cpp
    src/vuln/chain_verification_engine.cpp
    src/vuln/chain_report_view.cpp
    src/vuln/chain_verify_service.cpp
    src/vuln/ida_gateway.cpp
    src/vuln/surface_engine.cpp
    src/vuln/taint_engine.cpp
    src/vuln/vuln_callsites.cpp
    src/vuln/vuln_strings.cpp
    src/vuln/vuln_tools.cpp
    src/vuln/smt_solver.cpp
    src/vuln/symbolic_engine.cpp
    src/vuln/verification_engine.cpp
    src/vuln/verification_tools.cpp
    driver/comm.cpp
)

if(WIN32)
    set(AIDA_ASM_SOURCES driver/syscall.asm)
    set_source_files_properties(${AIDA_ASM_SOURCES} PROPERTIES LANGUAGE ASM_MASM)
endif()

set(AIDA_HEADERS
    src/actions.hpp
    src/agent_tools.hpp
    src/aida.hpp
    src/aida_ipc.hpp
    src/aida_pro.hpp
    src/analysis_db.hpp
    src/graphrag.hpp
    src/ida_utils.hpp
    src/instance_registry.hpp
    src/mcp_server.hpp
    src/multibinary_index.hpp
    src/multibinary_project.hpp
    src/settings.hpp
    src/driver_loader.hpp
    src/vuln/chain_binary_corpus.hpp
    src/vuln/chain_model.hpp
    src/vuln/chain_report.hpp
    src/vuln/chain_schema.hpp
    src/vuln/chain_state.hpp
    src/vuln/chain_store.hpp
    src/vuln/microcode_engine.hpp
    src/vuln/chain_budget.hpp
    src/vuln/chain_extraction.hpp
    src/vuln/chain_path_trace.hpp
    src/vuln/chain_transfer.hpp
    src/vuln/chain_alias.hpp
    src/vuln/chain_lifetime.hpp
    src/vuln/chain_protocol.hpp
    src/vuln/chain_cross_domain.hpp
    src/vuln/chain_boundary.hpp
    src/vuln/chain_side_effects.hpp
    src/vuln/chain_solver.hpp
    src/vuln/chain_state_contracts.hpp
    src/vuln/chain_regression_specs.hpp
    src/vuln/chain_trigger_trace.hpp
    src/vuln/chain_verifier.hpp
    src/vuln/chain_verification_engine.hpp
    src/vuln/chain_report_view.hpp
    src/vuln/chain_verify_service.hpp
    src/vuln/ida_gateway.hpp
    src/vuln/taint_engine.hpp
    src/vuln/vuln_common.hpp
    src/vuln/vuln_signatures.hpp
    src/vuln/vuln_tools.hpp
    src/vuln/smt_solver.hpp
    src/vuln/symbolic_engine.hpp
    src/vuln/verification_engine.hpp
    src/vuln/verification_tools.hpp
    src/vuln/embedded_libz3.hpp
    src/whoswho_embedded.h
)

if(WIN32)
    set(Z3_DLL_PATH_FORWARD "${Z3_INSTALL_DIR}/bin/libz3.dll")
    string(REPLACE "\\" "/" Z3_DLL_PATH_FORWARD "${Z3_DLL_PATH_FORWARD}")
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/src/aida_plugin_embedded.rc.in"
        "${CMAKE_BINARY_DIR}/aida_plugin_embedded.rc"
        @ONLY
    )
    list(APPEND AIDA_SOURCES "${CMAKE_BINARY_DIR}/aida_plugin_embedded.rc")
endif()

add_library(AiDA SHARED ${AIDA_SOURCES} ${AIDA_HEADERS} ${AIDA_ASM_SOURCES})

if(TARGET encrypt_drivers)
    add_dependencies(AiDA encrypt_drivers)
endif()

if(WIN32)
    target_sources(AiDA PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src/AiDA.def")
endif()

set_target_properties(AiDA PROPERTIES
    OUTPUT_NAME "AiDA"
    PREFIX      ""
    SUFFIX      ".dll"
)

if(WIN32)
    set_target_properties(AiDA PROPERTIES
        PDB_NAME_DEBUG "AiDA"
        PDB_NAME_RELEASE "AiDA"
        PDB_NAME_RELWITHDEBINFO "AiDA"
        COMPILE_PDB_NAME_DEBUG "AiDA"
        COMPILE_PDB_NAME_RELEASE "AiDA"
        COMPILE_PDB_NAME_RELWITHDEBINFO "AiDA"
        PDB_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/Debug"
        PDB_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/Release"
        PDB_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_BINARY_DIR}/RelWithDebInfo"
        COMPILE_PDB_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/Debug"
        COMPILE_PDB_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/Release"
        COMPILE_PDB_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_BINARY_DIR}/RelWithDebInfo"
    )
endif()

if(UNIX AND NOT APPLE)
    set_target_properties(AiDA PROPERTIES SUFFIX ".so")
elseif(APPLE)
    set_target_properties(AiDA PROPERTIES SUFFIX ".dylib")
endif()

target_include_directories(AiDA SYSTEM PRIVATE
    "${IDASDK_DIR}/include"
)

target_include_directories(AiDA PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/libs/cpp-httplib"
    "${CMAKE_CURRENT_SOURCE_DIR}/libs"
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
    "${CMAKE_CURRENT_SOURCE_DIR}/driver"
    "${CMAKE_CURRENT_SOURCE_DIR}/mapper/src"
    "${TRITON_SOURCE_DIR}/src/libtriton/includes"
    "${CMAKE_BINARY_DIR}/.deps/triton/src/libtriton/includes"
    "${Z3_INCLUDE_DIRS}"
)

target_compile_definitions(AiDA PRIVATE
    __EA64__
    __X64__
    _CRT_SECURE_NO_WARNINGS
    CPPHTTPLIB_OPENSSL_SUPPORT
    NOMINMAX
)
if(NOT AIDA_DISABLE_LEGACY_DRIVER_MAPPER)
    target_compile_definitions(AiDA PRIVATE AIDA_LEGACY_DRIVER_MAPPER_AVAILABLE)
endif()



if(WIN32)
    target_compile_definitions(AiDA PRIVATE
        __NT__
        __IDP__
        WIN32_LEAN_AND_MEAN
        OPENSSL_NO_DYNAMIC_ENGINE
    )
elseif(APPLE)
    target_compile_definitions(AiDA PRIVATE __MAC__)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64")
        target_compile_definitions(AiDA PRIVATE __ARM__)
    endif()
elseif(UNIX)
    target_compile_definitions(AiDA PRIVATE __LINUX__)
endif()

target_link_libraries(AiDA PRIVATE "${IDA_LINK_LIB}")

target_link_libraries(AiDA PRIVATE Zydis unicorn triton)
target_link_libraries(AiDA PRIVATE "${Z3_LIBRARIES}")
target_include_directories(AiDA PRIVATE
    "${zydis_SOURCE_DIR}/include"
    "${zydis_SOURCE_DIR}/dependencies/zycore/include"
    "${zydis_BINARY_DIR}"
    "${zydis_BINARY_DIR}/zycore"
    "${unicorn_SOURCE_DIR}/include"
)

if(WIN32)
    target_compile_options(AiDA PRIVATE
        $<$<COMPILE_LANGUAGE:CXX>:/W3>
        $<$<COMPILE_LANGUAGE:CXX>:/Zc:__cplusplus>
        $<$<COMPILE_LANGUAGE:CXX>:/permissive->
        $<$<COMPILE_LANGUAGE:CXX>:/Zp8>
        $<$<COMPILE_LANGUAGE:CXX>:/EHsc>
        $<$<COMPILE_LANGUAGE:CXX>:/GR->
        $<$<COMPILE_LANGUAGE:CXX>:/GF>
        $<$<COMPILE_LANGUAGE:CXX>:/Gy>
        $<$<COMPILE_LANGUAGE:CXX>:/Gw>
        $<$<COMPILE_LANGUAGE:CXX>:/Oi>
        $<$<COMPILE_LANGUAGE:CXX>:/Ob2>
        $<$<COMPILE_LANGUAGE:CXX>:/bigobj>
        $<$<AND:$<BOOL:${AIDA_ENABLE_LTCG}>,$<COMPILE_LANGUAGE:CXX>>:/GL>
        $<$<COMPILE_LANGUAGE:CXX>:/wd4946>
        $<$<COMPILE_LANGUAGE:CXX>:/wd4826>
        $<$<COMPILE_LANGUAGE:CXX>:/wd4628>
        $<$<COMPILE_LANGUAGE:CXX>:/wd4718>
        $<$<COMPILE_LANGUAGE:CXX>:/wd5219>
        $<$<COMPILE_LANGUAGE:CXX>:/wd5240>
    )

    aida_use_static_msvc_runtime(AiDA)

    target_precompile_headers(AiDA PRIVATE
        <nlohmann/json.hpp>
        <Windows.h>
        <vector>
        <string>
        <string_view>
        <unordered_map>
        <unordered_set>
        <map>
        <set>
        <deque>
        <thread>
        <mutex>
        <atomic>
        <chrono>
        <filesystem>
        <fstream>
        <sstream>
        <algorithm>
        <memory>
        <functional>
        <optional>
        <cstdint>
        <cstring>
        <cstdio>
    )

    target_link_options(AiDA PRIVATE
        $<IF:$<BOOL:${AIDA_FAST_LINK}>,/DEBUG,/DEBUG:FULL>
        /OPT:REF,ICF
        /RELEASE
        $<$<BOOL:${AIDA_ENABLE_LTCG}>:/LTCG>
        /PDBALTPATH:none
        /EMITTOOLVERSIONINFO:NO
        /DELAYLOAD:libz3.dll
    )

    target_link_libraries(AiDA PRIVATE delayimp)

    # AiDA is a DLL loaded into IDA Pro — IDA provides its own process hardening.
    # triton.lib and libcrypto_static.lib contain objects without /guard:ehcont
    # metadata (ASM objects), causing LNK2047 errors. Apply hardening WITHOUT
    # ehcont for this target; AiDAStandalone still gets full ehcont hardening.
    if(TARGET aida_hardening)
        target_compile_options(AiDA PRIVATE
            $<$<COMPILE_LANGUAGE:C,CXX>:/GS>
            $<$<COMPILE_LANGUAGE:C,CXX>:/guard:cf>
            $<$<COMPILE_LANGUAGE:C,CXX>:/Qspectre>
            $<$<COMPILE_LANGUAGE:CXX>:/sdl>
            $<$<COMPILE_LANGUAGE:CXX>:/wd4996>
        )
        target_link_options(AiDA PRIVATE
            /DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT /CETCOMPAT /guard:cf
        )
    endif()

    target_link_libraries(AiDA PRIVATE
        aida_openssl_ssl_mt
        aida_openssl_crypto_mt
        ws2_32
        crypt32
        Shlwapi
        setupapi
        Psapi
        wintrust
        cfgmgr32
    )
elseif(APPLE)
    find_package(OpenSSL REQUIRED)
    target_link_libraries(AiDA PRIVATE OpenSSL::SSL OpenSSL::Crypto)

    target_compile_options(AiDA PRIVATE -Wall -Wextra -Wno-nullability-completeness -fPIC)
    target_link_options(AiDA PRIVATE -undefined dynamic_lookup)
elseif(UNIX)
    find_package(OpenSSL REQUIRED)
    target_link_libraries(AiDA PRIVATE OpenSSL::SSL OpenSSL::Crypto)

    target_compile_options(AiDA PRIVATE -Wall -Wextra -fPIC)
    
endif()

endif()

if(WIN32 AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/standalone/test_target/CMakeLists.txt")
    add_subdirectory(src/standalone/test_target)
    if(TARGET AiDA_TestTarget)
        set_target_properties(AiDA_TestTarget PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Release"
            RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/Release"
            RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/Debug"
            RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_BINARY_DIR}/RelWithDebInfo"
        )
        if(TARGET AiDAStandalone)
            add_dependencies(AiDAStandalone AiDA_TestTarget)
            add_custom_command(TARGET AiDAStandalone POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E make_directory
                    "$<TARGET_FILE_DIR:AiDAStandalone>"
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    "$<TARGET_FILE:AiDA_TestTarget>"
                    "$<TARGET_FILE_DIR:AiDAStandalone>/AiDA_TestTarget.exe"
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    "$<TARGET_PDB_FILE:AiDA_TestTarget>"
                    "$<TARGET_FILE_DIR:AiDAStandalone>/AiDA_TestTarget.pdb"
                COMMENT "Staging AiDA_TestTarget beside AiDAStandalone.exe..."
                VERBATIM
            )
        endif()
    endif()
    if(TARGET AiDA_TestTarget AND TARGET AiDA_TargetProtocolFixture)
        add_dependencies(AiDA_TestTarget AiDA_TargetProtocolFixture)
    endif()
    if(TARGET AiDAStandalone AND TARGET AiDA_TargetProtocolFixture)
        add_dependencies(AiDAStandalone AiDA_TargetProtocolFixture)
        add_custom_command(TARGET AiDAStandalone POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E make_directory
                "$<TARGET_FILE_DIR:AiDAStandalone>/test_binaries/target_protocol"
                "$<TARGET_FILE_DIR:AiDAStandalone>/deps/test_binaries/target_protocol"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "$<TARGET_FILE:AiDA_TargetProtocolFixture>"
                "$<TARGET_FILE_DIR:AiDAStandalone>/test_binaries/target_protocol/target_protocol.exe"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "$<TARGET_PDB_FILE:AiDA_TargetProtocolFixture>"
                "$<TARGET_FILE_DIR:AiDAStandalone>/test_binaries/target_protocol/target_protocol.pdb"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "$<TARGET_FILE:AiDA_TargetProtocolFixture>"
                "$<TARGET_FILE_DIR:AiDAStandalone>/deps/test_binaries/target_protocol/target_protocol.exe"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "$<TARGET_PDB_FILE:AiDA_TargetProtocolFixture>"
                "$<TARGET_FILE_DIR:AiDAStandalone>/deps/test_binaries/target_protocol/target_protocol.pdb"
            COMMENT "Staging target_protocol fixture and PDB beside AiDAStandalone.exe..."
            VERBATIM
        )
    endif()
endif()
