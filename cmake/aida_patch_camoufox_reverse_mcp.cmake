if(NOT DEFINED AIDA_CAMOUFOX_STAGE_ROOT OR NOT AIDA_CAMOUFOX_STAGE_ROOT)
    message(FATAL_ERROR "AIDA_CAMOUFOX_STAGE_ROOT is required")
endif()
if(NOT DEFINED AIDA_CAMOUFOX_MCP_DIR OR NOT AIDA_CAMOUFOX_MCP_DIR)
    message(FATAL_ERROR "AIDA_CAMOUFOX_MCP_DIR is required")
endif()

set(AIDA_CAMOUFOX_REPO_MCP_ROOT "${AIDA_CAMOUFOX_MCP_DIR}/src/camoufox_reverse_mcp")
set(AIDA_CAMOUFOX_STAGE_MCP_ROOTS
    "${AIDA_CAMOUFOX_STAGE_ROOT}/deps/camoufox-reverse-mcp/src/camoufox_reverse_mcp"
    "${AIDA_CAMOUFOX_STAGE_ROOT}/deps/camoufox-runtime/Lib/site-packages/camoufox_reverse_mcp"
)
set(AIDA_CAMOUFOX_RUNTIME_PACKAGE_ROOT "${AIDA_CAMOUFOX_STAGE_ROOT}/deps/camoufox-runtime/Lib/site-packages/camoufox_reverse_mcp")
message(STATUS "[AIDA-CAMOUFOX] stage_begin root=${AIDA_CAMOUFOX_STAGE_ROOT} repo=${AIDA_CAMOUFOX_REPO_MCP_ROOT}")
if(NOT EXISTS "${AIDA_CAMOUFOX_REPO_MCP_ROOT}/__init__.py")
    message(FATAL_ERROR "Camoufox reverse-MCP package source is missing: ${AIDA_CAMOUFOX_REPO_MCP_ROOT}")
endif()
foreach(AIDA_CAMOUFOX_STAGE_MCP_ROOT IN LISTS AIDA_CAMOUFOX_STAGE_MCP_ROOTS)
    if(EXISTS "${AIDA_CAMOUFOX_STAGE_MCP_ROOT}")
        set(AIDA_CAMOUFOX_STAGE_PACKAGE_EXISTS TRUE)
    else()
        set(AIDA_CAMOUFOX_STAGE_PACKAGE_EXISTS FALSE)
    endif()
    message(STATUS "[AIDA-CAMOUFOX] stage_package_begin root=${AIDA_CAMOUFOX_STAGE_MCP_ROOT} exists=${AIDA_CAMOUFOX_STAGE_PACKAGE_EXISTS}")
    get_filename_component(AIDA_CAMOUFOX_STAGE_MCP_PARENT "${AIDA_CAMOUFOX_STAGE_MCP_ROOT}" DIRECTORY)
    set(AIDA_CAMOUFOX_STAGE_MCP_TEMP "${AIDA_CAMOUFOX_STAGE_MCP_ROOT}.staging")
    file(REMOVE_RECURSE "${AIDA_CAMOUFOX_STAGE_MCP_TEMP}")
    file(MAKE_DIRECTORY "${AIDA_CAMOUFOX_STAGE_MCP_PARENT}")
    file(COPY "${AIDA_CAMOUFOX_REPO_MCP_ROOT}/" DESTINATION "${AIDA_CAMOUFOX_STAGE_MCP_TEMP}")
    if(NOT EXISTS "${AIDA_CAMOUFOX_STAGE_MCP_TEMP}/__init__.py" OR NOT EXISTS "${AIDA_CAMOUFOX_STAGE_MCP_TEMP}/__main__.py")
        file(REMOVE_RECURSE "${AIDA_CAMOUFOX_STAGE_MCP_TEMP}")
        message(FATAL_ERROR "Camoufox reverse-MCP temporary package staging failed: ${AIDA_CAMOUFOX_STAGE_MCP_TEMP}")
    endif()
    file(REMOVE_RECURSE "${AIDA_CAMOUFOX_STAGE_MCP_ROOT}")
    file(RENAME "${AIDA_CAMOUFOX_STAGE_MCP_TEMP}" "${AIDA_CAMOUFOX_STAGE_MCP_ROOT}")
    message(STATUS "[AIDA-CAMOUFOX] stage_package_complete root=${AIDA_CAMOUFOX_STAGE_MCP_ROOT}")
endforeach()
if(NOT EXISTS "${AIDA_CAMOUFOX_RUNTIME_PACKAGE_ROOT}/__init__.py")
    message(FATAL_ERROR "Camoufox reverse-MCP package was not staged into the bundled runtime: ${AIDA_CAMOUFOX_RUNTIME_PACKAGE_ROOT}")
endif()
if(NOT EXISTS "${AIDA_CAMOUFOX_RUNTIME_PACKAGE_ROOT}/__main__.py")
    message(FATAL_ERROR "Camoufox reverse-MCP package entry point was not staged into the bundled runtime: ${AIDA_CAMOUFOX_RUNTIME_PACKAGE_ROOT}")
endif()
file(READ "${AIDA_CAMOUFOX_RUNTIME_PACKAGE_ROOT}/__main__.py" AIDA_CAMOUFOX_RUNTIME_MAIN_CONTENT)
foreach(AIDA_CAMOUFOX_RUNTIME_CONTRACT_MARKER IN ITEMS
    "--aida-contract-check"
    "AIDA_CAMOUFOX_RUNTIME_CONTRACT_OK"
    "AIDA_INITIATOR_CONTRACT_V2"
    "initiator_params")
    string(FIND "${AIDA_CAMOUFOX_RUNTIME_MAIN_CONTENT}" "${AIDA_CAMOUFOX_RUNTIME_CONTRACT_MARKER}" AIDA_CAMOUFOX_RUNTIME_CONTRACT_MARKER_POS)
    if(AIDA_CAMOUFOX_RUNTIME_CONTRACT_MARKER_POS EQUAL -1)
        message(FATAL_ERROR "Bundled Camoufox reverse-MCP entry point is missing contract marker ${AIDA_CAMOUFOX_RUNTIME_CONTRACT_MARKER}: ${AIDA_CAMOUFOX_RUNTIME_PACKAGE_ROOT}/__main__.py")
    endif()
endforeach()
set(AIDA_CAMOUFOX_SOURCE_SYNC_FILES
    "browser.py"
    "__main__.py"
    "_playwright_patch.py"
    "tools/navigation.py"
    "tools/script_analysis.py"
    "tools/network.py"
    "tools/debugging.py"
    "tools/hooking.py"
    "tools/environment.py"
    "tools/storage.py"
)

set(AIDA_CAMOUFOX_REQUIRED_REVERSE_TOOLS
    "launch_browser"
    "close_browser"
    "list_pages"
    "new_page"
    "select_page"
    "close_page"
    "evaluate_js"
    "navigate"
    "diagnose_bloxflip_matrix"
    "get_page_info"
    "network_capture"
    "list_network_requests"
    "get_network_request"
    "scripts"
)

set(AIDA_CAMOUFOX_REPO_BROWSER_PATH "${AIDA_CAMOUFOX_REPO_MCP_ROOT}/browser.py")
set(AIDA_CAMOUFOX_REPO_MAIN_PATH "${AIDA_CAMOUFOX_REPO_MCP_ROOT}/__main__.py")
set(AIDA_CAMOUFOX_REPO_PLAYWRIGHT_PATCH_PATH "${AIDA_CAMOUFOX_REPO_MCP_ROOT}/_playwright_patch.py")
set(AIDA_CAMOUFOX_REPO_NAV_PATH "${AIDA_CAMOUFOX_REPO_MCP_ROOT}/tools/navigation.py")
set(AIDA_CAMOUFOX_REPO_SCRIPT_PATH "${AIDA_CAMOUFOX_REPO_MCP_ROOT}/tools/script_analysis.py")
set(AIDA_CAMOUFOX_REPO_NETWORK_PATH "${AIDA_CAMOUFOX_REPO_MCP_ROOT}/tools/network.py")
set(AIDA_CAMOUFOX_REPO_DEBUGGING_PATH "${AIDA_CAMOUFOX_REPO_MCP_ROOT}/tools/debugging.py")
set(AIDA_CAMOUFOX_REPO_STORAGE_PATH "${AIDA_CAMOUFOX_REPO_MCP_ROOT}/tools/storage.py")
set(AIDA_CAMOUFOX_REPO_MULTIPAGE_SOURCE_READY FALSE)
if(EXISTS "${AIDA_CAMOUFOX_REPO_BROWSER_PATH}" AND EXISTS "${AIDA_CAMOUFOX_REPO_NAV_PATH}")
    if(NOT EXISTS "${AIDA_CAMOUFOX_REPO_MAIN_PATH}")
        message(WARNING "Root Camoufox reverse-MCP main source is missing: ${AIDA_CAMOUFOX_REPO_MAIN_PATH}")
    endif()
    if(NOT EXISTS "${AIDA_CAMOUFOX_REPO_PLAYWRIGHT_PATCH_PATH}")
        message(WARNING "Root Camoufox reverse-MCP Playwright patch source is missing: ${AIDA_CAMOUFOX_REPO_PLAYWRIGHT_PATCH_PATH}")
    endif()
    if(NOT EXISTS "${AIDA_CAMOUFOX_REPO_NETWORK_PATH}")
        message(WARNING "Root Camoufox reverse-MCP network source is missing: ${AIDA_CAMOUFOX_REPO_NETWORK_PATH}")
    endif()
    if(NOT EXISTS "${AIDA_CAMOUFOX_REPO_SCRIPT_PATH}")
        message(WARNING "Root Camoufox reverse-MCP script source is missing: ${AIDA_CAMOUFOX_REPO_SCRIPT_PATH}")
    endif()
    file(READ "${AIDA_CAMOUFOX_REPO_BROWSER_PATH}" AIDA_CAMOUFOX_REPO_BROWSER_CONTENT)
    file(READ "${AIDA_CAMOUFOX_REPO_MAIN_PATH}" AIDA_CAMOUFOX_REPO_MAIN_CONTENT)
    file(READ "${AIDA_CAMOUFOX_REPO_PLAYWRIGHT_PATCH_PATH}" AIDA_CAMOUFOX_REPO_PLAYWRIGHT_PATCH_CONTENT)
    file(READ "${AIDA_CAMOUFOX_REPO_NAV_PATH}" AIDA_CAMOUFOX_REPO_NAV_CONTENT)
    file(READ "${AIDA_CAMOUFOX_REPO_SCRIPT_PATH}" AIDA_CAMOUFOX_REPO_SCRIPT_CONTENT)
    file(READ "${AIDA_CAMOUFOX_REPO_NETWORK_PATH}" AIDA_CAMOUFOX_REPO_NETWORK_CONTENT)
    if(EXISTS "${AIDA_CAMOUFOX_REPO_DEBUGGING_PATH}")
        file(READ "${AIDA_CAMOUFOX_REPO_DEBUGGING_PATH}" AIDA_CAMOUFOX_REPO_DEBUGGING_CONTENT)
    else()
        set(AIDA_CAMOUFOX_REPO_DEBUGGING_CONTENT "")
    endif()
    if(EXISTS "${AIDA_CAMOUFOX_REPO_STORAGE_PATH}")
        file(READ "${AIDA_CAMOUFOX_REPO_STORAGE_PATH}" AIDA_CAMOUFOX_REPO_STORAGE_CONTENT)
    else()
        set(AIDA_CAMOUFOX_REPO_STORAGE_CONTENT "")
    endif()
    string(REPLACE "\r\n" "\n" AIDA_CAMOUFOX_REPO_BROWSER_CONTENT "${AIDA_CAMOUFOX_REPO_BROWSER_CONTENT}")
    string(REPLACE "\r" "\n" AIDA_CAMOUFOX_REPO_BROWSER_CONTENT "${AIDA_CAMOUFOX_REPO_BROWSER_CONTENT}")
    string(REPLACE "\r\n" "\n" AIDA_CAMOUFOX_REPO_MAIN_CONTENT "${AIDA_CAMOUFOX_REPO_MAIN_CONTENT}")
    string(REPLACE "\r" "\n" AIDA_CAMOUFOX_REPO_MAIN_CONTENT "${AIDA_CAMOUFOX_REPO_MAIN_CONTENT}")
    string(REPLACE "\r\n" "\n" AIDA_CAMOUFOX_REPO_PLAYWRIGHT_PATCH_CONTENT "${AIDA_CAMOUFOX_REPO_PLAYWRIGHT_PATCH_CONTENT}")
    string(REPLACE "\r" "\n" AIDA_CAMOUFOX_REPO_PLAYWRIGHT_PATCH_CONTENT "${AIDA_CAMOUFOX_REPO_PLAYWRIGHT_PATCH_CONTENT}")
    string(REPLACE "\r\n" "\n" AIDA_CAMOUFOX_REPO_NAV_CONTENT "${AIDA_CAMOUFOX_REPO_NAV_CONTENT}")
    string(REPLACE "\r" "\n" AIDA_CAMOUFOX_REPO_NAV_CONTENT "${AIDA_CAMOUFOX_REPO_NAV_CONTENT}")
    string(REPLACE "\r\n" "\n" AIDA_CAMOUFOX_REPO_SCRIPT_CONTENT "${AIDA_CAMOUFOX_REPO_SCRIPT_CONTENT}")
    string(REPLACE "\r" "\n" AIDA_CAMOUFOX_REPO_SCRIPT_CONTENT "${AIDA_CAMOUFOX_REPO_SCRIPT_CONTENT}")
    string(REPLACE "\r\n" "\n" AIDA_CAMOUFOX_REPO_NETWORK_CONTENT "${AIDA_CAMOUFOX_REPO_NETWORK_CONTENT}")
    string(REPLACE "\r" "\n" AIDA_CAMOUFOX_REPO_NETWORK_CONTENT "${AIDA_CAMOUFOX_REPO_NETWORK_CONTENT}")
    string(REPLACE "\r\n" "\n" AIDA_CAMOUFOX_REPO_DEBUGGING_CONTENT "${AIDA_CAMOUFOX_REPO_DEBUGGING_CONTENT}")
    string(REPLACE "\r" "\n" AIDA_CAMOUFOX_REPO_DEBUGGING_CONTENT "${AIDA_CAMOUFOX_REPO_DEBUGGING_CONTENT}")
    string(REPLACE "\r\n" "\n" AIDA_CAMOUFOX_REPO_STORAGE_CONTENT "${AIDA_CAMOUFOX_REPO_STORAGE_CONTENT}")
    string(REPLACE "\r" "\n" AIDA_CAMOUFOX_REPO_STORAGE_CONTENT "${AIDA_CAMOUFOX_REPO_STORAGE_CONTENT}")
    set(AIDA_CAMOUFOX_REPO_TOOL_CONTENT "${AIDA_CAMOUFOX_REPO_NAV_CONTENT}\n${AIDA_CAMOUFOX_REPO_SCRIPT_CONTENT}\n${AIDA_CAMOUFOX_REPO_NETWORK_CONTENT}\n${AIDA_CAMOUFOX_REPO_DEBUGGING_CONTENT}")
    foreach(AIDA_CAMOUFOX_REQUIRED_REVERSE_TOOL IN LISTS AIDA_CAMOUFOX_REQUIRED_REVERSE_TOOLS)
        string(FIND "${AIDA_CAMOUFOX_REPO_TOOL_CONTENT}" "async def ${AIDA_CAMOUFOX_REQUIRED_REVERSE_TOOL}(" AIDA_CAMOUFOX_REQUIRED_TOOL_POS)
        if(AIDA_CAMOUFOX_REQUIRED_TOOL_POS EQUAL -1)
            message(WARNING "Root Camoufox reverse-MCP source is missing required tool ${AIDA_CAMOUFOX_REQUIRED_REVERSE_TOOL}: ${AIDA_CAMOUFOX_REPO_MCP_ROOT}")
        endif()
    endforeach()
    foreach(AIDA_CAMOUFOX_REQUIRED_BROWSER_MARKER IN ITEMS
        "self._aida_multipage_patch = 4"
        "async def list_pages"
        "async def new_page"
        "async def select_page"
        "async def close_page"
        "async def resolve_page"
        "async def page_envelope"
        "def _mark_page_terminal"
        "AIDA_CAMOUFOX_FAST_VISIBLE_FALLBACK"
        "aida_camoufox_bridge_20260620_crash_diag_1"
        "aida_launch_budget_policy_v1"
        "aida_resolve_launch_budget_policy"
        "aida_validate_launch_budget_policy"
        "aida_retry_launch_timeout_ms"
        "aida_bridge_patch_active"
        "aida_launch_policy_resolved"
        "context_close_event"
        "cmdline_sha256"
        "subprocess_diagnostics_installed"
        "stdout_capture"
        "stderr_capture"
        "exit_ts_ms"
        "diagnostic_original_style_bundled"
        "_registered_page_records"
        "page_recovery_created"
        "resolve_page_default_recovery_begin"
        "browser_page_id_unavailable"
        "def _launch_error_summary"
        "last_launch_failure_payload"
        "launch_new_page_task_result"
        "privacy_verify_exception"
        "page_closed_during_launch"
        "requestfinished"
        "requestfinished_event"
        "websocket_event"
        "response_body_length")
        string(FIND "${AIDA_CAMOUFOX_REPO_BROWSER_CONTENT}" "${AIDA_CAMOUFOX_REQUIRED_BROWSER_MARKER}" AIDA_CAMOUFOX_REQUIRED_BROWSER_MARKER_POS)
        if(AIDA_CAMOUFOX_REQUIRED_BROWSER_MARKER_POS EQUAL -1)
            message(WARNING "Root Camoufox reverse-MCP browser source is missing required marker ${AIDA_CAMOUFOX_REQUIRED_BROWSER_MARKER}: ${AIDA_CAMOUFOX_REPO_BROWSER_PATH}")
        endif()
    endforeach()
    foreach(AIDA_CAMOUFOX_REQUIRED_MAIN_MARKER IN ITEMS
        "_aida_apply_playwright_pageerror_patch"
        "patch_playwright_pageerror"
        "aida_launch_budget_policy_v1"
        "launch_budget_policy_marker_present"
        "launch_budget_retry_contract_ok"
        "playwright_patch=playwright_patch")
        string(FIND "${AIDA_CAMOUFOX_REPO_MAIN_CONTENT}" "${AIDA_CAMOUFOX_REQUIRED_MAIN_MARKER}" AIDA_CAMOUFOX_REQUIRED_MAIN_MARKER_POS)
        if(AIDA_CAMOUFOX_REQUIRED_MAIN_MARKER_POS EQUAL -1)
            message(WARNING "Root Camoufox reverse-MCP main source is missing required marker ${AIDA_CAMOUFOX_REQUIRED_MAIN_MARKER}: ${AIDA_CAMOUFOX_REPO_MAIN_PATH}")
        endif()
    endforeach()
    foreach(AIDA_CAMOUFOX_REQUIRED_PLAYWRIGHT_PATCH_MARKER IN ITEMS
        "AIDA_PLAYWRIGHT_PAGEERROR_PATCH_ID"
        "aida_playwright_pageerror_location_patch_20260620_1"
        "patch_playwright_pageerror"
        "coreBundle.js"
        "pageError.location.url"
        "pageError.location?.url ?? ''"
        "pageError.location.lineNumber"
        "pageError.location?.lineNumber ?? 0"
        "pageError.location.columnNumber"
        "pageError.location?.columnNumber ?? 0")
        string(FIND "${AIDA_CAMOUFOX_REPO_PLAYWRIGHT_PATCH_CONTENT}" "${AIDA_CAMOUFOX_REQUIRED_PLAYWRIGHT_PATCH_MARKER}" AIDA_CAMOUFOX_REQUIRED_PLAYWRIGHT_PATCH_MARKER_POS)
        if(AIDA_CAMOUFOX_REQUIRED_PLAYWRIGHT_PATCH_MARKER_POS EQUAL -1)
            message(WARNING "Root Camoufox reverse-MCP Playwright patch source is missing required marker ${AIDA_CAMOUFOX_REQUIRED_PLAYWRIGHT_PATCH_MARKER}: ${AIDA_CAMOUFOX_REPO_PLAYWRIGHT_PATCH_PATH}")
        endif()
    endforeach()
    foreach(AIDA_CAMOUFOX_REQUIRED_NAV_MARKER IN ITEMS
        "diagnostic_navigation_goto_begin"
        "diagnostic_navigation_goto_exception"
        "bloxflip_navigation_state"
        "navigation_lifecycle_degraded"
        "first_failure_phase"
        "diagnose_bloxflip_matrix"
        "launch_browser_tool_exception"
        "browser_manager.last_launch_failure_payload"
        "bridge_attempt_id"
        "original_style_bundled"
        "node_exit_code"
        "camoufox_child_exits"
        "cloudflare"
        "aida_clamp_navigation_timeout_ms"
        "aida_resolve_launch_budget_policy"
        "nav_timeout_ms"
        "\"timeout_ms\": nav_timeout_ms"
        "_await_no_cancel_wait(page.evaluate(\"document.readyState\")"
        "_navigation_capture_summary"
        "\"capture_compacted\""
        "\"body_access\""
        "\"network_requests\""
        "\"network_capture\"")
        string(FIND "${AIDA_CAMOUFOX_REPO_NAV_CONTENT}" "${AIDA_CAMOUFOX_REQUIRED_NAV_MARKER}" AIDA_CAMOUFOX_REQUIRED_NAV_MARKER_POS)
        if(AIDA_CAMOUFOX_REQUIRED_NAV_MARKER_POS EQUAL -1)
            message(WARNING "Root Camoufox reverse-MCP navigation source is missing required marker ${AIDA_CAMOUFOX_REQUIRED_NAV_MARKER}: ${AIDA_CAMOUFOX_REPO_NAV_PATH}")
        endif()
    endforeach()
    foreach(AIDA_CAMOUFOX_REQUIRED_SCRIPT_MARKER IN ITEMS
        "async def scripts("
        "async def _script_error"
        "\"scripts\""
        "\"count\""
        "scripts_error"
        "requested_page_id")
        string(FIND "${AIDA_CAMOUFOX_REPO_SCRIPT_CONTENT}" "${AIDA_CAMOUFOX_REQUIRED_SCRIPT_MARKER}" AIDA_CAMOUFOX_REQUIRED_SCRIPT_MARKER_POS)
        if(AIDA_CAMOUFOX_REQUIRED_SCRIPT_MARKER_POS EQUAL -1)
            message(WARNING "Root Camoufox reverse-MCP script source is missing required marker ${AIDA_CAMOUFOX_REQUIRED_SCRIPT_MARKER}: ${AIDA_CAMOUFOX_REPO_SCRIPT_PATH}")
        endif()
    endforeach()
    foreach(AIDA_CAMOUFOX_REQUIRED_NETWORK_MARKER IN ITEMS
        "\"request_id\""
        "\"network_request_id\""
        "\"response_body_length\""
        "\"request_body_length\""
        "\"redirect_chain\""
        "\"websocket\""
        "\"timing\""
        "\"initiator\""
        "_NETWORK_DEFAULT_LIMIT"
        "url_prefix: str | None = None"
        "_request_matches_text_filter"
        "\"filtered_count\""
        "\"returned_count\""
        "\"has_more\"")
        string(FIND "${AIDA_CAMOUFOX_REPO_NETWORK_CONTENT}" "${AIDA_CAMOUFOX_REQUIRED_NETWORK_MARKER}" AIDA_CAMOUFOX_REQUIRED_NETWORK_MARKER_POS)
        if(AIDA_CAMOUFOX_REQUIRED_NETWORK_MARKER_POS EQUAL -1)
            message(WARNING "Root Camoufox reverse-MCP network source is missing required marker ${AIDA_CAMOUFOX_REQUIRED_NETWORK_MARKER}: ${AIDA_CAMOUFOX_REPO_NETWORK_PATH}")
        endif()
    endforeach()
    foreach(AIDA_CAMOUFOX_REQUIRED_DEBUGGING_MARKER IN ITEMS
        "timeout_ms: int = 30000"
        "_eval_with_budget"
        "evaluate_js timed out after"
        "browser_manager.resolve_page_for_operation(page_id")
        string(FIND "${AIDA_CAMOUFOX_REPO_DEBUGGING_CONTENT}" "${AIDA_CAMOUFOX_REQUIRED_DEBUGGING_MARKER}" AIDA_CAMOUFOX_REQUIRED_DEBUGGING_MARKER_POS)
        if(AIDA_CAMOUFOX_REQUIRED_DEBUGGING_MARKER_POS EQUAL -1)
            message(WARNING "Root Camoufox reverse-MCP debugging source is missing required marker ${AIDA_CAMOUFOX_REQUIRED_DEBUGGING_MARKER}: ${AIDA_CAMOUFOX_REPO_DEBUGGING_PATH}")
        endif()
    endforeach()
    foreach(AIDA_CAMOUFOX_REQUIRED_STORAGE_MARKER IN ITEMS
        "payload: dict | None = None"
        "cookie_action = str(params.get(\"action\") or action or \"get\")"
        "browser_manager.resolve_page_for_operation(page_id")
        string(FIND "${AIDA_CAMOUFOX_REPO_STORAGE_CONTENT}" "${AIDA_CAMOUFOX_REQUIRED_STORAGE_MARKER}" AIDA_CAMOUFOX_REQUIRED_STORAGE_MARKER_POS)
        if(AIDA_CAMOUFOX_REQUIRED_STORAGE_MARKER_POS EQUAL -1)
            message(WARNING "Root Camoufox reverse-MCP storage source is missing required marker ${AIDA_CAMOUFOX_REQUIRED_STORAGE_MARKER}: ${AIDA_CAMOUFOX_REPO_STORAGE_PATH}")
        endif()
    endforeach()
    set(AIDA_CAMOUFOX_REPO_MULTIPAGE_SOURCE_READY TRUE)
endif()

foreach(AIDA_CAMOUFOX_SOURCE_SYNC_FILE IN LISTS AIDA_CAMOUFOX_SOURCE_SYNC_FILES)
    set(AIDA_CAMOUFOX_SOURCE_PATH "${AIDA_CAMOUFOX_REPO_MCP_ROOT}/${AIDA_CAMOUFOX_SOURCE_SYNC_FILE}")
    if(NOT EXISTS "${AIDA_CAMOUFOX_SOURCE_PATH}")
        continue()
    endif()
    file(READ "${AIDA_CAMOUFOX_SOURCE_PATH}" AIDA_CAMOUFOX_SOURCE_SYNC_CONTENT)
    string(REPLACE "\r\n" "\n" AIDA_CAMOUFOX_SOURCE_SYNC_CONTENT "${AIDA_CAMOUFOX_SOURCE_SYNC_CONTENT}")
    string(REPLACE "\r" "\n" AIDA_CAMOUFOX_SOURCE_SYNC_CONTENT "${AIDA_CAMOUFOX_SOURCE_SYNC_CONTENT}")
    foreach(AIDA_CAMOUFOX_STAGE_MCP_ROOT IN LISTS AIDA_CAMOUFOX_STAGE_MCP_ROOTS)
        set(AIDA_CAMOUFOX_STAGE_PATH "${AIDA_CAMOUFOX_STAGE_MCP_ROOT}/${AIDA_CAMOUFOX_SOURCE_SYNC_FILE}")
        if(NOT EXISTS "${AIDA_CAMOUFOX_STAGE_PATH}")
            if(AIDA_CAMOUFOX_SOURCE_SYNC_FILE STREQUAL "_playwright_patch.py" AND EXISTS "${AIDA_CAMOUFOX_STAGE_MCP_ROOT}")
                file(WRITE "${AIDA_CAMOUFOX_STAGE_PATH}" "${AIDA_CAMOUFOX_SOURCE_SYNC_CONTENT}")
                message(STATUS "Synchronized ${AIDA_CAMOUFOX_STAGE_PATH}")
            endif()
            continue()
        endif()
        file(READ "${AIDA_CAMOUFOX_STAGE_PATH}" AIDA_CAMOUFOX_STAGE_SYNC_CONTENT)
        string(REPLACE "\r\n" "\n" AIDA_CAMOUFOX_STAGE_SYNC_CONTENT "${AIDA_CAMOUFOX_STAGE_SYNC_CONTENT}")
        string(REPLACE "\r" "\n" AIDA_CAMOUFOX_STAGE_SYNC_CONTENT "${AIDA_CAMOUFOX_STAGE_SYNC_CONTENT}")
        if(NOT AIDA_CAMOUFOX_STAGE_SYNC_CONTENT STREQUAL AIDA_CAMOUFOX_SOURCE_SYNC_CONTENT)
            file(WRITE "${AIDA_CAMOUFOX_STAGE_PATH}" "${AIDA_CAMOUFOX_SOURCE_SYNC_CONTENT}")
            message(STATUS "Synchronized ${AIDA_CAMOUFOX_STAGE_PATH}")
        endif()
    endforeach()
endforeach()

foreach(AIDA_CAMOUFOX_STAGE_MCP_ROOT IN LISTS AIDA_CAMOUFOX_STAGE_MCP_ROOTS)
    set(AIDA_CAMOUFOX_STAGE_PLAYWRIGHT_PATCH_PATH "${AIDA_CAMOUFOX_STAGE_MCP_ROOT}/_playwright_patch.py")
    if(EXISTS "${AIDA_CAMOUFOX_REPO_PLAYWRIGHT_PATCH_PATH}" AND NOT EXISTS "${AIDA_CAMOUFOX_STAGE_PLAYWRIGHT_PATCH_PATH}")
        file(COPY "${AIDA_CAMOUFOX_REPO_PLAYWRIGHT_PATCH_PATH}" DESTINATION "${AIDA_CAMOUFOX_STAGE_MCP_ROOT}")
        message(STATUS "Restored ${AIDA_CAMOUFOX_STAGE_PLAYWRIGHT_PATCH_PATH}")
    endif()
    if(NOT EXISTS "${AIDA_CAMOUFOX_STAGE_PLAYWRIGHT_PATCH_PATH}")
        message(FATAL_ERROR "[AIDA-CAMOUFOX] staged Playwright patch missing after synchronization: ${AIDA_CAMOUFOX_STAGE_PLAYWRIGHT_PATCH_PATH}")
    endif()
    message(STATUS "[AIDA-CAMOUFOX] playwright_patch_ready path=${AIDA_CAMOUFOX_STAGE_PLAYWRIGHT_PATCH_PATH}")
endforeach()

set(AIDA_CAMOUFOX_NAV_PATCH_FILES
    "${AIDA_CAMOUFOX_STAGE_ROOT}/deps/camoufox-reverse-mcp/src/camoufox_reverse_mcp/tools/navigation.py"
    "${AIDA_CAMOUFOX_STAGE_ROOT}/deps/camoufox-runtime/Lib/site-packages/camoufox_reverse_mcp/tools/navigation.py"
)

foreach(AIDA_CAMOUFOX_NAV_PATCH_FILE IN LISTS AIDA_CAMOUFOX_NAV_PATCH_FILES)
    if(NOT EXISTS "${AIDA_CAMOUFOX_NAV_PATCH_FILE}")
        continue()
    endif()
    file(READ "${AIDA_CAMOUFOX_NAV_PATCH_FILE}" AIDA_CAMOUFOX_NAV_CONTENT)
    set(AIDA_CAMOUFOX_NAV_ORIGINAL "${AIDA_CAMOUFOX_NAV_CONTENT}")
    string(REPLACE "\r\n" "\n" AIDA_CAMOUFOX_NAV_CONTENT "${AIDA_CAMOUFOX_NAV_CONTENT}")
    string(REPLACE "\r" "\n" AIDA_CAMOUFOX_NAV_CONTENT "${AIDA_CAMOUFOX_NAV_CONTENT}")

    if(NOT AIDA_CAMOUFOX_NAV_CONTENT MATCHES "AIDA_LAUNCH_DEFAULT_BUNDLED_VISIBLE_MS")
        string(REPLACE
            "from ..browser import "
            "from ..browser import AIDA_LAUNCH_DEFAULT_BUNDLED_VISIBLE_MS, "
            AIDA_CAMOUFOX_NAV_CONTENT "${AIDA_CAMOUFOX_NAV_CONTENT}")
    endif()

    string(FIND "${AIDA_CAMOUFOX_NAV_CONTENT}" "service_workers: str | None = None" AIDA_CAMOUFOX_NAV_SERVICE_WORKERS_SIG_POS)
    if(AIDA_CAMOUFOX_NAV_SERVICE_WORKERS_SIG_POS EQUAL -1)
        string(REPLACE [=[    privacy_fail_closed: bool = True,
]=]
[=[    privacy_fail_closed: bool = True,
    service_workers: str | None = None,
    block_service_workers: bool = False,
    aida_fast_visible_launch: bool | None = None,
    aida_launch_policy_marker: str | None = None,
]=]
            AIDA_CAMOUFOX_NAV_CONTENT "${AIDA_CAMOUFOX_NAV_CONTENT}")
    endif()

    string(FIND "${AIDA_CAMOUFOX_NAV_CONTENT}" "bridge_generation: int | str | None = None" AIDA_CAMOUFOX_NAV_BRIDGE_SIG_POS)
    if(AIDA_CAMOUFOX_NAV_BRIDGE_SIG_POS EQUAL -1)
        string(REPLACE [=[    user_data_dir: str | None = None,
    privacy_fail_closed: bool = True,
]=]
[=[    user_data_dir: str | None = None,
    privacy_fail_closed: bool = True,
    bridge_generation: int | str | None = None,
    bridge_session_id: str | None = None,
    bridge_attempt_id: str | None = None,
]=]
            AIDA_CAMOUFOX_NAV_CONTENT "${AIDA_CAMOUFOX_NAV_CONTENT}")
    endif()

    string(FIND "${AIDA_CAMOUFOX_NAV_CONTENT}" "config[\"service_workers\"] = str(service_workers)" AIDA_CAMOUFOX_NAV_SERVICE_WORKERS_CONFIG_POS)
    if(AIDA_CAMOUFOX_NAV_SERVICE_WORKERS_CONFIG_POS EQUAL -1)
        string(REPLACE [=[        if user_data_dir:
            config["user_data_dir"] = user_data_dir
]=]
[=[        if user_data_dir:
            config["user_data_dir"] = user_data_dir
        if service_workers is not None:
            config["service_workers"] = str(service_workers)
        if block_service_workers:
            config["block_service_workers"] = True
        if aida_fast_visible_launch is not None:
            config["aida_fast_visible_launch"] = bool(aida_fast_visible_launch)
        if aida_launch_policy_marker:
            config["aida_launch_policy_marker"] = str(aida_launch_policy_marker)
]=]
            AIDA_CAMOUFOX_NAV_CONTENT "${AIDA_CAMOUFOX_NAV_CONTENT}")
    endif()

    string(FIND "${AIDA_CAMOUFOX_NAV_CONTENT}" "config[\"bridge_generation\"] = bridge_generation" AIDA_CAMOUFOX_NAV_BRIDGE_CONFIG_POS)
    if(AIDA_CAMOUFOX_NAV_BRIDGE_CONFIG_POS EQUAL -1)
        string(REPLACE [=[        if aida_launch_policy_marker:
            config["aida_launch_policy_marker"] = str(aida_launch_policy_marker)
]=]
[=[        if aida_launch_policy_marker:
            config["aida_launch_policy_marker"] = str(aida_launch_policy_marker)
        if bridge_generation is not None:
            config["bridge_generation"] = bridge_generation
        if bridge_session_id:
            config["bridge_session_id"] = bridge_session_id
        if bridge_attempt_id:
            config["bridge_attempt_id"] = bridge_attempt_id
]=]
            AIDA_CAMOUFOX_NAV_CONTENT "${AIDA_CAMOUFOX_NAV_CONTENT}")
        string(REPLACE [=[        if user_data_dir:
            config["user_data_dir"] = user_data_dir
        if proxy:
]=]
[=[        if user_data_dir:
            config["user_data_dir"] = user_data_dir
        if bridge_generation is not None:
            config["bridge_generation"] = bridge_generation
        if bridge_session_id:
            config["bridge_session_id"] = bridge_session_id
        if bridge_attempt_id:
            config["bridge_attempt_id"] = bridge_attempt_id
        if proxy:
]=]
            AIDA_CAMOUFOX_NAV_CONTENT "${AIDA_CAMOUFOX_NAV_CONTENT}")
    endif()

    foreach(AIDA_CAMOUFOX_NAV_REQUIRED_MARKER IN ITEMS
        "service_workers: str | None = None"
        "block_service_workers: bool = False"
        "aida_fast_visible_launch: bool | None = None"
        "aida_launch_policy_marker: str | None = None"
        "bridge_generation: int | str | None = None"
        "config[\"service_workers\"] = str(service_workers)"
        "config[\"aida_fast_visible_launch\"] = bool(aida_fast_visible_launch)"
        "config[\"bridge_generation\"] = bridge_generation")
        string(FIND "${AIDA_CAMOUFOX_NAV_CONTENT}" "${AIDA_CAMOUFOX_NAV_REQUIRED_MARKER}" AIDA_CAMOUFOX_NAV_REQUIRED_MARKER_POS)
        if(AIDA_CAMOUFOX_NAV_REQUIRED_MARKER_POS EQUAL -1)
            message(WARNING "Failed to patch Camoufox navigation launch contract ${AIDA_CAMOUFOX_NAV_REQUIRED_MARKER}: ${AIDA_CAMOUFOX_NAV_PATCH_FILE}")
        endif()
    endforeach()

    if(NOT AIDA_CAMOUFOX_NAV_CONTENT STREQUAL AIDA_CAMOUFOX_NAV_ORIGINAL)
        file(WRITE "${AIDA_CAMOUFOX_NAV_PATCH_FILE}" "${AIDA_CAMOUFOX_NAV_CONTENT}")
        message(STATUS "Patched ${AIDA_CAMOUFOX_NAV_PATCH_FILE}")
    endif()
endforeach()

set(AIDA_CAMOUFOX_PATCH_FILES
    "${AIDA_CAMOUFOX_STAGE_ROOT}/deps/camoufox-reverse-mcp/src/camoufox_reverse_mcp/browser.py"
    "${AIDA_CAMOUFOX_STAGE_ROOT}/deps/camoufox-runtime/Lib/site-packages/camoufox_reverse_mcp/browser.py"
)

foreach(AIDA_CAMOUFOX_PATCH_FILE IN LISTS AIDA_CAMOUFOX_PATCH_FILES)
    if(NOT EXISTS "${AIDA_CAMOUFOX_PATCH_FILE}")
        continue()
    endif()

    file(READ "${AIDA_CAMOUFOX_PATCH_FILE}" AIDA_CAMOUFOX_CONTENT)
    set(AIDA_CAMOUFOX_ORIGINAL "${AIDA_CAMOUFOX_CONTENT}")
    string(REPLACE "\r\n" "\n" AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    string(REPLACE "\r" "\n" AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "import ctypes as _ctypes")
        string(REPLACE
            "import contextlib\n"
            "import contextlib\nimport ctypes as _ctypes\n"
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "import traceback as _traceback")
        string(REPLACE
            "import time\n"
            "import time\nimport traceback as _traceback\n"
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "AIDA_CAMOUFOX_EXECUTABLE")
        string(REPLACE
"        if cfg.get(\"block_webrtc\"):
            kwargs[\"block_webrtc\"] = True

        locale = cfg.get(\"locale\", \"auto\")"
"        kwargs[\"block_webrtc\"] = True

        executable_path = cfg.get(\"executable_path\") or __import__(\"os\").environ.get(\"AIDA_CAMOUFOX_EXECUTABLE\")
        if executable_path:
            kwargs[\"executable_path\"] = str(executable_path)

        ff_version = cfg.get(\"ff_version\")
        if ff_version is not None:
            try:
                kwargs[\"ff_version\"] = int(ff_version)
                kwargs[\"i_know_what_im_doing\"] = True
            except (TypeError, ValueError):
                pass

        locale = cfg.get(\"locale\", \"auto\")"
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    string(REPLACE
        "_os.environ.get(\"AIDA_CAMOUFOX_EXECUTABLE\")"
        "__import__(\"os\").environ.get(\"AIDA_CAMOUFOX_EXECUTABLE\")"
        AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")

    string(REPLACE
"            import json as _json
            import os as _os
            from functools import partial"
"            import json as _json
            from functools import partial"
        AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "bundled_visible_launch")
        string(REPLACE
"        os_type = cfg.get(\"os\", \"auto\")
        host_os = detect_host_os()
        if os_type == \"auto\":
            os_type = host_os
        kwargs[\"os\"] = os_type"
"        os_requested = cfg.get(\"os\", \"auto\")
        host_os = detect_host_os()
        os_type = host_os if os_requested == \"auto\" else os_requested"
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")

        string(REPLACE
"        locale = cfg.get(\"locale\", \"auto\")
        if locale == \"auto\":
            locale = detect_system_locale()
        kwargs[\"locale\"] = locale

        headless = cfg.get(\"headless\", False)
        kwargs[\"headless\"] = headless

        window_size, window_diag = _resolve_window_size(cfg)"
"        locale_requested = cfg.get(\"locale\", \"auto\")
        locale = detect_system_locale() if locale_requested == \"auto\" else locale_requested

        headless = cfg.get(\"headless\", False)
        kwargs[\"headless\"] = headless

        bundled_visible_launch = bool(executable_path) and not headless
        if not bundled_visible_launch or os_requested != \"auto\":
            kwargs[\"os\"] = os_type
        if not bundled_visible_launch or locale_requested != \"auto\":
            kwargs[\"locale\"] = locale

        window_size, window_diag = _resolve_window_size(cfg)"
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "_build_camoufox_launch_options")
        string(REPLACE
"def detect_system_locale() -> str:
    \"\"\"Best-effort detection of the host's locale (e.g. 'zh-CN').\"\"\"
    for var in (\"LANG\", \"LC_ALL\", \"LC_MESSAGES\"):
        val = _os.environ.get(var, \"\")
        if val and val not in (\"C\", \"POSIX\"):
            return val.split(\".\")[0].replace(\"_\", \"-\")
    return \"en-US\""
"def detect_system_locale() -> str:
    \"\"\"Best-effort detection of the host's locale (e.g. 'zh-CN').\"\"\"
    for var in (\"LANG\", \"LC_ALL\", \"LC_MESSAGES\"):
        val = _os.environ.get(var, \"\")
        if val and val not in (\"C\", \"POSIX\"):
            return val.split(\".\")[0].replace(\"_\", \"-\")
    return \"en-US\"


def _build_camoufox_launch_options(headless: bool, kwargs: dict[str, Any]) -> dict[str, Any]:
    from camoufox.utils import launch_options as _cfx_launch_options
    return _cfx_launch_options(headless=headless, **{
        k: v for k, v in kwargs.items() if k not in (\"headless\", \"from_options\")
    })"
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "launch_bundled_options")
        string(REPLACE
"        enable_trace = cfg.get(\"enable_trace\", False)

        if enable_trace:"
"        enable_trace = cfg.get(\"enable_trace\", False)

        from_options = None
        if executable_path:
            from_options = _build_camoufox_launch_options(headless, kwargs)
            kwargs[\"from_options\"] = from_options
            _camoufox_debug(
                \"launch_bundled_options\",
                executable_path=str(executable_path),
                from_options_has_executable=bool(from_options.get(\"executable_path\")),
                from_options_args=len(from_options.get(\"args\") or []),
                from_options_has_env=bool(from_options.get(\"env\")),
            )

        if enable_trace:"
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")

        string(REPLACE
"            from camoufox.utils import launch_options as _cfx_launch_options"
""
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")

        string(REPLACE
"            from_options = _cfx_launch_options(headless=headless, **{
                k: v for k, v in kwargs.items() if k != \"headless\"
            })"
"            if from_options is None:
                from_options = _build_camoufox_launch_options(headless, kwargs)"
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "AIDA_CAMOUFOX_DEBUG_LOG")
        string(REPLACE [=[def _camoufox_debug(event: str, **fields: Any) -> None:
    payload = {"event": event, **fields}
    try:
        print("AIDA_CAMOUFOX " + _json.dumps(payload, sort_keys=True, separators=(",", ":")), file=sys.stderr, flush=True)
    except Exception:
        pass]=]
[=[def _camoufox_debug(event_name: str = "", **fields: Any) -> None:
    safe_fields = dict(fields)
    if "event" in safe_fields:
        safe_fields["payload_event"] = safe_fields.pop("event")
    payload = {"event": event_name, **safe_fields}
    try:
        line = "AIDA_CAMOUFOX " + _json.dumps(payload, sort_keys=True, separators=(",", ":"))
        print(line, file=sys.stderr, flush=True)
        log_path = _os.environ.get("AIDA_CAMOUFOX_DEBUG_LOG", "")
        if log_path:
            with open(log_path, "a", encoding="utf-8") as fp:
                fp.write(line + "\n")
    except Exception:
        pass]=]
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    string(REPLACE
        "k: v for k, v in kwargs.items() if k not in (\"headless\", \"from_options\")"
        "k: v for k, v in kwargs.items() if k not in (\"headless\", \"from_options\", \"persistent_context\")"
        AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "_new_profile_dir")
        string(REPLACE [=[def _build_camoufox_launch_options(headless: bool, kwargs: dict[str, Any]) -> dict[str, Any]:
    from camoufox.utils import launch_options as _cfx_launch_options
    return _cfx_launch_options(headless=headless, **{
        k: v for k, v in kwargs.items() if k not in ("headless", "from_options", "persistent_context")
    })]=]
[=[def _build_camoufox_launch_options(headless: bool, kwargs: dict[str, Any]) -> dict[str, Any]:
    from camoufox.utils import launch_options as _cfx_launch_options
    return _cfx_launch_options(headless=headless, **{
        k: v for k, v in kwargs.items() if k not in ("headless", "from_options", "persistent_context")
    })


def _new_profile_dir() -> str:
    root = _os.environ.get("AIDA_CAMOUFOX_PROFILE_ROOT", "")
    if not root:
        base = _os.environ.get("LOCALAPPDATA") or _os.environ.get("TEMP") or _os.getcwd()
        root = _os.path.join(base, "AiDA", "camoufox-profiles")
    _os.makedirs(root, exist_ok=True)
    return _os.path.join(root, f"profile-{_os.getpid()}-{int(time.time() * 1000)}")]=]
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "def _write_private_profile_prefs")
        string(REPLACE [=[def _new_profile_dir() -> str:
    root = _os.environ.get("AIDA_CAMOUFOX_PROFILE_ROOT", "")
    if not root:
        base = _os.environ.get("LOCALAPPDATA") or _os.environ.get("TEMP") or _os.getcwd()
        root = _os.path.join(base, "AiDA", "camoufox-profiles")
    _os.makedirs(root, exist_ok=True)
    return _os.path.join(root, f"profile-{_os.getpid()}-{int(time.time() * 1000)}")]=]
[=[def _new_profile_dir() -> str:
    root = _os.environ.get("AIDA_CAMOUFOX_PROFILE_ROOT", "")
    if not root:
        base = _os.environ.get("LOCALAPPDATA") or _os.environ.get("TEMP") or _os.getcwd()
        root = _os.path.join(base, "AiDA", "camoufox-profiles")
    _os.makedirs(root, exist_ok=True)
    return _os.path.join(root, f"profile-{_os.getpid()}-{int(time.time() * 1000)}")


def _write_private_profile_prefs(profile_dir: str | None) -> dict[str, Any]:
    prefs = {
        "beacon.enabled": False,
        "browser.cache.disk.enable": False,
        "browser.cache.offline.enable": False,
        "browser.formfill.enable": False,
        "browser.newtabpage.activity-stream.feeds.telemetry": False,
        "browser.newtabpage.activity-stream.telemetry": False,
        "browser.sessionstore.max_tabs_undo": 0,
        "browser.sessionstore.privacy_level": 2,
        "browser.sessionstore.resume_from_crash": False,
        "browser.search.geoip.url": "",
        "browser.search.region": "US",
        "browser.search.update": False,
        "browser.search.suggest.enabled": False,
        "browser.search.separatePrivateDefault": False,
        "browser.search.separatePrivateDefault.ui.enabled": False,
        "browser.urlbar.speculativeConnect.enabled": False,
        "browser.urlbar.quicksuggest.enabled": False,
        "browser.urlbar.suggest.searches": False,
        "datareporting.healthreport.uploadEnabled": False,
        "datareporting.policy.dataSubmissionEnabled": False,
        "dom.push.enabled": False,
        "media.peerconnection.enabled": False,
        "media.peerconnection.ice.proxy_only": True,
        "media.peerconnection.ice.no_host": True,
        "media.peerconnection.ice.default_address_only": True,
        "media.peerconnection.ice.obfuscate_host_addresses": True,
        "network.cookie.lifetimePolicy": 2,
        "network.dns.disablePrefetch": True,
        "network.http.speculative-parallel-limit": 0,
        "network.predictor.enabled": False,
        "network.prefetch-next": False,
        "permissions.default.geo": 2,
        "places.history.enabled": False,
        "privacy.clearOnShutdown.cache": True,
        "privacy.clearOnShutdown.cookies": True,
        "privacy.clearOnShutdown.downloads": True,
        "privacy.clearOnShutdown.formdata": True,
        "privacy.clearOnShutdown.history": True,
        "privacy.clearOnShutdown.offlineApps": True,
        "privacy.clearOnShutdown.sessions": True,
        "privacy.sanitize.sanitizeOnShutdown": True,
        "toolkit.telemetry.enabled": False,
        "toolkit.telemetry.unified": False,
    }
    out: dict[str, Any] = {"profile_dir": profile_dir or "", "prefs": sorted(prefs.keys()), "written": False}
    if not profile_dir:
        return out
    try:
        _os.makedirs(profile_dir, exist_ok=True)
        path = _os.path.join(profile_dir, "user.js")
        try:
            with open(path, "r", encoding="utf-8") as fp:
                existing = fp.read()
        except FileNotFoundError:
            existing = ""
        keys = tuple(prefs.keys())
        lines = [
            line for line in existing.splitlines()
            if not any(line.strip().startswith(f"user_pref(\"{key}\"") for key in keys)
        ]
        rendered = []
        for key, value in prefs.items():
            if isinstance(value, bool):
                value_text = "true" if value else "false"
            else:
                value_text = _json.dumps(value)
            rendered.append(f"user_pref(\"{key}\", {value_text});")
        with open(path, "w", encoding="utf-8", newline="\n") as fp:
            if lines:
                fp.write("\n".join(lines).rstrip() + "\n")
            fp.write("\n".join(rendered) + "\n")
        out["written"] = True
        out["path"] = path
    except Exception as exc:
        out["error_type"] = type(exc).__name__
        out["error"] = _safe_text(exc, 300)
    return out


async def _verify_private_page(page: Page | None) -> dict[str, Any]:
    if page is None:
        return {"webrtc_blocked": False, "ice_probe_ok": False, "ice_candidate_leak_detected": True, "ua_policy": "camoufox_native", "error": "missing_page"}
    return await _verify_page_privacy(page, {"ua_policy": "camoufox_native", "block_webrtc": True, "privacy_fail_closed": True, "fingerprint_overrides": {}})]=]
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "def _write_private_profile_prefs")
        string(REPLACE [=[def _windows_descendant_pids(root_pid: int) -> list[int]:]=]
[=[def _write_private_profile_prefs(profile_dir: str | None) -> dict[str, Any]:
    prefs = {
        "beacon.enabled": False,
        "browser.cache.disk.enable": False,
        "browser.cache.offline.enable": False,
        "browser.formfill.enable": False,
        "browser.newtabpage.activity-stream.feeds.telemetry": False,
        "browser.newtabpage.activity-stream.telemetry": False,
        "browser.sessionstore.max_tabs_undo": 0,
        "browser.sessionstore.privacy_level": 2,
        "browser.sessionstore.resume_from_crash": False,
        "browser.search.geoip.url": "",
        "browser.search.region": "US",
        "browser.search.update": False,
        "browser.search.suggest.enabled": False,
        "browser.search.separatePrivateDefault": False,
        "browser.search.separatePrivateDefault.ui.enabled": False,
        "browser.urlbar.speculativeConnect.enabled": False,
        "browser.urlbar.quicksuggest.enabled": False,
        "browser.urlbar.suggest.searches": False,
        "datareporting.healthreport.uploadEnabled": False,
        "datareporting.policy.dataSubmissionEnabled": False,
        "dom.push.enabled": False,
        "media.peerconnection.enabled": False,
        "media.peerconnection.ice.proxy_only": True,
        "media.peerconnection.ice.no_host": True,
        "media.peerconnection.ice.default_address_only": True,
        "media.peerconnection.ice.obfuscate_host_addresses": True,
        "network.cookie.lifetimePolicy": 2,
        "network.dns.disablePrefetch": True,
        "network.http.speculative-parallel-limit": 0,
        "network.predictor.enabled": False,
        "network.prefetch-next": False,
        "permissions.default.geo": 2,
        "places.history.enabled": False,
        "privacy.clearOnShutdown.cache": True,
        "privacy.clearOnShutdown.cookies": True,
        "privacy.clearOnShutdown.downloads": True,
        "privacy.clearOnShutdown.formdata": True,
        "privacy.clearOnShutdown.history": True,
        "privacy.clearOnShutdown.offlineApps": True,
        "privacy.clearOnShutdown.sessions": True,
        "privacy.sanitize.sanitizeOnShutdown": True,
        "toolkit.telemetry.enabled": False,
        "toolkit.telemetry.unified": False,
    }
    out: dict[str, Any] = {"profile_dir": profile_dir or "", "prefs": sorted(prefs.keys()), "written": False}
    if not profile_dir:
        return out
    try:
        _os.makedirs(profile_dir, exist_ok=True)
        path = _os.path.join(profile_dir, "user.js")
        try:
            with open(path, "r", encoding="utf-8") as fp:
                existing = fp.read()
        except FileNotFoundError:
            existing = ""
        keys = tuple(prefs.keys())
        lines = [
            line for line in existing.splitlines()
            if not any(line.strip().startswith(f"user_pref(\"{key}\"") for key in keys)
        ]
        rendered = []
        for key, value in prefs.items():
            if isinstance(value, bool):
                value_text = "true" if value else "false"
            else:
                value_text = _json.dumps(value)
            rendered.append(f"user_pref(\"{key}\", {value_text});")
        with open(path, "w", encoding="utf-8", newline="\n") as fp:
            if lines:
                fp.write("\n".join(lines).rstrip() + "\n")
            fp.write("\n".join(rendered) + "\n")
        out["written"] = True
        out["path"] = path
    except Exception as exc:
        out["error_type"] = type(exc).__name__
        out["error"] = _safe_text(exc, 300)
    return out


async def _verify_private_page(page: Page | None) -> dict[str, Any]:
    if page is None:
        return {"webrtc_blocked": False, "ice_probe_ok": False, "ice_candidate_leak_detected": True, "ua_policy": "camoufox_native", "error": "missing_page"}
    return await _verify_page_privacy(page, {"ua_policy": "camoufox_native", "block_webrtc": True, "privacy_fail_closed": True, "fingerprint_overrides": {}})


def _windows_descendant_pids(root_pid: int) -> list[int]:]=]
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "media\\.peerconnection\\.enabled")
        string(REPLACE
"        \"browser.sessionstore.resume_from_crash\": False,"
"        \"browser.sessionstore.resume_from_crash\": False,
        \"media.peerconnection.enabled\": False,
        \"media.peerconnection.ice.proxy_only\": True,
        \"media.peerconnection.ice.no_host\": True,
        \"media.peerconnection.ice.default_address_only\": True,
        \"media.peerconnection.ice.obfuscate_host_addresses\": True,"
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "browser\\.cache\\.disk\\.enable")
        string(REPLACE
"        \"media.peerconnection.enabled\": False,"
"        \"beacon.enabled\": False,
        \"browser.cache.disk.enable\": False,
        \"browser.cache.offline.enable\": False,
        \"browser.formfill.enable\": False,
        \"browser.newtabpage.activity-stream.feeds.telemetry\": False,
        \"browser.newtabpage.activity-stream.telemetry\": False,
        \"browser.sessionstore.max_tabs_undo\": 0,
        \"browser.sessionstore.privacy_level\": 2,
        \"browser.sessionstore.resume_from_crash\": False,
        \"browser.search.geoip.url\": \"\",
        \"browser.search.region\": \"US\",
        \"browser.search.update\": False,
        \"browser.search.suggest.enabled\": False,
        \"browser.search.separatePrivateDefault\": False,
        \"browser.search.separatePrivateDefault.ui.enabled\": False,
        \"browser.urlbar.speculativeConnect.enabled\": False,
        \"browser.urlbar.quicksuggest.enabled\": False,
        \"browser.urlbar.suggest.searches\": False,
        \"datareporting.healthreport.uploadEnabled\": False,
        \"datareporting.policy.dataSubmissionEnabled\": False,
        \"dom.push.enabled\": False,
        \"media.peerconnection.enabled\": False,"
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
        string(REPLACE
"        \"media.peerconnection.ice.obfuscate_host_addresses\": True,"
"        \"media.peerconnection.ice.obfuscate_host_addresses\": True,
        \"network.cookie.lifetimePolicy\": 2,
        \"network.dns.disablePrefetch\": True,
        \"network.http.speculative-parallel-limit\": 0,
        \"network.predictor.enabled\": False,
        \"network.prefetch-next\": False,
        \"permissions.default.geo\": 2,
        \"places.history.enabled\": False,
        \"privacy.clearOnShutdown.cache\": True,
        \"privacy.clearOnShutdown.cookies\": True,
        \"privacy.clearOnShutdown.downloads\": True,
        \"privacy.clearOnShutdown.formdata\": True,
        \"privacy.clearOnShutdown.history\": True,
        \"privacy.clearOnShutdown.offlineApps\": True,
        \"privacy.clearOnShutdown.sessions\": True,
        \"privacy.sanitize.sanitizeOnShutdown\": True,
        \"toolkit.telemetry.enabled\": False,
        \"toolkit.telemetry.unified\": False,"
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "prefs\\[\"media\\.peerconnection\\.enabled\"\\] = False")
        string(REPLACE [=[            if isinstance(cfg.get("firefox_user_prefs"), dict):
                prefs.update(cfg["firefox_user_prefs"])
            kwargs["firefox_user_prefs"] = prefs]=]
[=[            if isinstance(cfg.get("firefox_user_prefs"), dict):
                prefs.update(cfg["firefox_user_prefs"])
            prefs["media.peerconnection.enabled"] = False
            prefs["media.peerconnection.ice.proxy_only"] = True
            prefs["media.peerconnection.ice.no_host"] = True
            prefs["media.peerconnection.ice.default_address_only"] = True
            prefs["media.peerconnection.ice.obfuscate_host_addresses"] = True
            kwargs["firefox_user_prefs"] = prefs]=]
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "prefs\\[\"browser\\.cache\\.disk\\.enable\"\\] = False")
        string(REPLACE
"            prefs[\"media.peerconnection.enabled\"] = False"
"            prefs[\"beacon.enabled\"] = False
            prefs[\"browser.cache.disk.enable\"] = False
            prefs[\"browser.cache.offline.enable\"] = False
            prefs[\"browser.formfill.enable\"] = False
            prefs[\"browser.newtabpage.activity-stream.feeds.telemetry\"] = False
            prefs[\"browser.newtabpage.activity-stream.telemetry\"] = False
            prefs[\"browser.sessionstore.max_tabs_undo\"] = 0
            prefs[\"browser.sessionstore.privacy_level\"] = 2
            prefs[\"browser.sessionstore.resume_from_crash\"] = False
            prefs[\"browser.search.geoip.url\"] = \"\"
            prefs[\"browser.search.region\"] = \"US\"
            prefs[\"browser.search.update\"] = False
            prefs[\"browser.search.suggest.enabled\"] = False
            prefs[\"browser.search.separatePrivateDefault\"] = False
            prefs[\"browser.search.separatePrivateDefault.ui.enabled\"] = False
            prefs[\"browser.urlbar.speculativeConnect.enabled\"] = False
            prefs[\"browser.urlbar.quicksuggest.enabled\"] = False
            prefs[\"browser.urlbar.suggest.searches\"] = False
            prefs[\"datareporting.healthreport.uploadEnabled\"] = False
            prefs[\"datareporting.policy.dataSubmissionEnabled\"] = False
            prefs[\"dom.push.enabled\"] = False
            prefs[\"media.peerconnection.enabled\"] = False"
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
        string(REPLACE
"            prefs[\"media.peerconnection.ice.obfuscate_host_addresses\"] = True"
"            prefs[\"media.peerconnection.ice.obfuscate_host_addresses\"] = True
            prefs[\"network.cookie.lifetimePolicy\"] = 2
            prefs[\"network.dns.disablePrefetch\"] = True
            prefs[\"network.http.speculative-parallel-limit\"] = 0
            prefs[\"network.predictor.enabled\"] = False
            prefs[\"network.prefetch-next\"] = False
            prefs[\"permissions.default.geo\"] = 2
            prefs[\"places.history.enabled\"] = False
            prefs[\"privacy.clearOnShutdown.cache\"] = True
            prefs[\"privacy.clearOnShutdown.cookies\"] = True
            prefs[\"privacy.clearOnShutdown.downloads\"] = True
            prefs[\"privacy.clearOnShutdown.formdata\"] = True
            prefs[\"privacy.clearOnShutdown.history\"] = True
            prefs[\"privacy.clearOnShutdown.offlineApps\"] = True
            prefs[\"privacy.clearOnShutdown.sessions\"] = True
            prefs[\"privacy.sanitize.sanitizeOnShutdown\"] = True
            prefs[\"toolkit.telemetry.enabled\"] = False
            prefs[\"toolkit.telemetry.unified\"] = False"
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "_profile_dir")
        string(REPLACE
            "        self._route_handlers: dict[str, Any] = {}  # 已注册的 route handler 映射"
            "        self._route_handlers: dict[str, Any] = {}  # 已注册的 route handler 映射\n        self._profile_dir: str | None = None\n        self._profile_generated = False"
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "_profile_dir")
        string(REPLACE [=[        self._persistent_scripts: list[dict] = []
        self._persistent_traces: dict[str, list] = {}]=]
[=[        self._persistent_scripts: list[dict] = []
        self._persistent_traces: dict[str, list] = {}
        self._profile_dir: str | None = None
        self._profile_generated = False]=]
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "def _profile_snapshot")
        string(REPLACE [=[def _prepare_profile_dir(profile_dir: str, generated: bool) -> tuple[str, dict[str, Any]]:
    resolved = _os.path.abspath(_os.path.expandvars(_os.path.expanduser(str(profile_dir))))
    existed = _os.path.exists(resolved)
    if generated and existed:
        _shutil.rmtree(resolved, ignore_errors=True)
        existed = False
    _os.makedirs(resolved, exist_ok=True)
    locks = _profile_lock_info(resolved)
    info = {
        "profile_dir": resolved,
        "generated": generated,
        "existed": existed,
        "locks": len(locks),
        "lock_names": [item.get("name", "") for item in locks],
    }
    return resolved, info]=]
[=[def _prepare_profile_dir(profile_dir: str, generated: bool) -> tuple[str, dict[str, Any]]:
    resolved = _os.path.abspath(_os.path.expandvars(_os.path.expanduser(str(profile_dir))))
    existed = _os.path.exists(resolved)
    if generated and existed:
        _shutil.rmtree(resolved, ignore_errors=True)
        existed = False
    _os.makedirs(resolved, exist_ok=True)
    locks = _profile_lock_info(resolved)
    info = {
        "profile_dir": resolved,
        "generated": generated,
        "existed": existed,
        "locks": len(locks),
        "lock_names": [item.get("name", "") for item in locks],
    }
    return resolved, info


def _profile_snapshot(profile_dir: str | None) -> dict[str, Any]:
    if not profile_dir:
        return {"present": False}
    out: dict[str, Any] = {"present": True, "profile_dir": str(profile_dir)}
    try:
        out["exists"] = _os.path.exists(profile_dir)
        out["locks"] = _profile_lock_info(profile_dir)
        names = ("parent.lock", ".parentlock", "lock", "compatibility.ini", "prefs.js", "sessionCheckpoints.json", "sessionstore.jsonlz4")
        files = []
        for name in names:
            path = _os.path.join(profile_dir, name)
            if _os.path.exists(path):
                item = _path_info(path)
                item["name"] = name
                files.append(item)
        out["files"] = files[:32]
        crash_dir = _os.path.join(profile_dir, "crashes")
        crashes = []
        if _os.path.isdir(crash_dir):
            for name in sorted(_os.listdir(crash_dir))[-24:]:
                crashes.append(_path_info(_os.path.join(crash_dir, name)))
        out["crashes"] = crashes
        out["descendants"] = _windows_descendant_pids(_os.getpid())[:32]
    except Exception as exc:
        out["error_type"] = type(exc).__name__
        out["error"] = _safe_text(exc, 500)
    return out]=]
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "kwargs\\[\"persistent_context\"\\]")
        string(REPLACE [=[        if not bundled_visible_launch or locale_requested != "auto":
            kwargs["locale"] = locale

        window_size, window_diag = _resolve_window_size(cfg)
        if not headless:
            kwargs["window"] = window_size]=]
[=[        if not bundled_visible_launch or locale_requested != "auto":
            kwargs["locale"] = locale

        profile_dir = None
        profile_info: dict[str, Any] = {}
        if bundled_visible_launch:
            profile_requested = bool(cfg.get("profile_dir") or cfg.get("user_data_dir") or cfg.get("persistent_context"))
            if profile_requested:
                generated_profile = not bool(cfg.get("profile_dir") or cfg.get("user_data_dir"))
                profile_dir = str(cfg.get("profile_dir") or cfg.get("user_data_dir") or _new_profile_dir())
                profile_dir, profile_info = _prepare_profile_dir(profile_dir, generated_profile)
                kwargs["persistent_context"] = True
                kwargs["user_data_dir"] = profile_dir
            else:
                profile_info = {"profile_dir": "", "generated": False, "existed": False, "locks": 0, "lock_names": [], "mode": "non_persistent"}

        window_size, window_diag = _resolve_window_size(cfg)
        if not headless:
            kwargs["window"] = window_size
        fast_probe = bool(cfg.get("aida_testlab_fast_probe") or cfg.get("testlab_fast_probe")) or str(_os.environ.get("AIDA_CAMOUFOX_TESTLAB_FAST_PROBE", "")).lower() in {"1", "true", "yes", "on"}
        launch_budget_policy = aida_resolve_launch_budget_policy(cfg.get("launch_timeout_ms"), bundled_visible_launch=bundled_visible_launch, fast_probe=fast_probe)
        launch_timeout_ms = int(launch_budget_policy["launch_timeout_ms"])]=]
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "timeout_ms=launch_timeout_ms")
        string(REPLACE [=[            enable_trace=bool(cfg.get("enable_trace")),
            window=window_diag,
        )]=]
[=[            enable_trace=bool(cfg.get("enable_trace")),
            window=window_diag,
            persistent=bool(kwargs.get("persistent_context")),
            timeout_ms=launch_timeout_ms,
        )]=]
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "profile_dir=profile_dir")
        string(REPLACE [=[                from_options_has_executable=bool(from_options.get("executable_path")),
                from_options_args=len(from_options.get("args") or []),
                from_options_has_env=bool(from_options.get("env")),
            )]=]
[=[                from_options_has_executable=bool(from_options.get("executable_path")),
                from_options_args=len(from_options.get("args") or []),
                from_options_has_env=bool(from_options.get("env")),
                persistent=bool(kwargs.get("persistent_context")),
                profile_dir=profile_dir or "",
            )]=]
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "launch_context_enter_begin")
        string(REPLACE [=[        try:
            self._cm = AsyncCamoufox(**kwargs)
            self.browser = await self._cm.__aenter__()

            ctx = self.browser.contexts[0] if self.browser.contexts else await self.browser.new_context()]=]
[=[        try:
            profile_privacy = _write_private_profile_prefs(profile_dir)
            _camoufox_debug("launch_profile_privacy", **profile_privacy)
            if profile_dir and not profile_privacy.get("written"):
                raise RuntimeError("Camoufox privacy profile preferences were not written")
            self._profile_dir = profile_dir
            self._profile_generated = bool(profile_info.get("generated"))
            self._cm = AsyncCamoufox(**kwargs)
            _camoufox_debug(
                "launch_context_enter_begin",
                persistent=bool(kwargs.get("persistent_context")),
                timeout_ms=launch_timeout_ms,
            )
            self.browser = await asyncio.wait_for(self._cm.__aenter__(), timeout=launch_timeout_ms / 1000)
            _camoufox_debug(
                "launch_context_enter_ok",
                elapsed_ms=int((time.perf_counter() - launch_started) * 1000),
                browser_type=type(self.browser).__name__,
                persistent=bool(kwargs.get("persistent_context")),
            )

            if isinstance(self.browser, BrowserContext):
                ctx = self.browser
            else:
                if self.browser.contexts:
                    ctx = self.browser.contexts[0]
                else:
                    _camoufox_debug("launch_new_context_begin")
                    ctx, _, _ = await _create_camoufox_safe_context(self.browser, {}, float(launch_budget_policy["context_create_timeout_s"]), "launch_new_context", None, launch_started)
                    _camoufox_debug("launch_new_context_ok", elapsed_ms=int((time.perf_counter() - launch_started) * 1000))]=]
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")

        string(REPLACE
            "            page = ctx.pages[0] if ctx.pages else await ctx.new_page()"
            "            if ctx.pages:\n                page = ctx.pages[0]\n            else:\n                _camoufox_debug(\"launch_new_page_begin\")\n                page = await asyncio.wait_for(ctx.new_page(), timeout=float(launch_budget_policy[\"page_create_timeout_s\"]))\n                _camoufox_debug(\"launch_new_page_ok\", elapsed_ms=int((time.perf_counter() - launch_started) * 1000))\n            privacy_info = await _verify_page_privacy(page, self._context_plan)\n            _camoufox_debug(\"launch_privacy_verified\", **privacy_info)\n            if not privacy_info.get(\"webrtc_blocked\") or not privacy_info.get(\"ice_probe_ok\") or privacy_info.get(\"ice_candidate_leak_detected\"):\n                raise RuntimeError(\"Camoufox privacy verification failed\")"
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")

        string(REPLACE [=[                error_len=len(str(exc)),
                window=window_diag,
            )
            raise]=]
[=[                error_len=len(str(exc)),
                window=window_diag,
                persistent=bool(kwargs.get("persistent_context")),
            )
            if self._cm is not None:
                try:
                    await asyncio.wait_for(self._cm.__aexit__(None, None, None), timeout=10)
                except Exception:
                    pass
            self.browser = None
            self.contexts.clear()
            self.pages.clear()
            self.active_page_name = None
            self._cm = None
            self._profile_dir = None
            self._profile_generated = False
            if profile_dir and bool(profile_info.get("generated")):
                try:
                    import shutil
                    shutil.rmtree(profile_dir, ignore_errors=True)
                except Exception:
                    pass
            raise]=]
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "launch_context_enter_wait")
        string(REPLACE [=[            self._cm = AsyncCamoufox(**kwargs)
            _camoufox_debug(
                "launch_context_enter_begin",
                persistent=bool(kwargs.get("persistent_context")),
                timeout_ms=launch_timeout_ms,
            )
            self.browser = await asyncio.wait_for(self._cm.__aenter__(), timeout=launch_timeout_ms / 1000)
            _camoufox_debug(
                "launch_context_enter_ok",
                elapsed_ms=int((time.perf_counter() - launch_started) * 1000),
                browser_type=type(self.browser).__name__,
                persistent=bool(kwargs.get("persistent_context")),
            )]=]
[=[            self._cm = AsyncCamoufox(**kwargs)
            _camoufox_debug(
                "launch_context_enter_begin",
                persistent=bool(kwargs.get("persistent_context")),
                timeout_ms=launch_timeout_ms,
                profile_snapshot=_profile_snapshot(profile_dir),
                descendants=_windows_descendant_pids(_os.getpid())[:32],
            )

            async def _aida_launch_watchdog() -> None:
                tick = 0
                while True:
                    await asyncio.sleep(5)
                    tick += 1
                    _camoufox_debug(
                        "launch_context_enter_wait",
                        tick=tick,
                        elapsed_ms=int((time.perf_counter() - launch_started) * 1000),
                        persistent=bool(kwargs.get("persistent_context")),
                        timeout_ms=launch_timeout_ms,
                        profile_snapshot=_profile_snapshot(profile_dir),
                        descendants=_windows_descendant_pids(_os.getpid())[:32],
                    )

            watchdog_task = asyncio.create_task(_aida_launch_watchdog())
            try:
                self.browser = await asyncio.wait_for(self._cm.__aenter__(), timeout=launch_timeout_ms / 1000)
            finally:
                watchdog_task.cancel()
                with contextlib.suppress(BaseException):
                    await watchdog_task
            _camoufox_debug(
                "launch_context_enter_ok",
                elapsed_ms=int((time.perf_counter() - launch_started) * 1000),
                browser_type=type(self.browser).__name__,
                persistent=bool(kwargs.get("persistent_context")),
                profile_snapshot=_profile_snapshot(profile_dir),
                descendants=_windows_descendant_pids(_os.getpid())[:32],
            )]=]
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "launch_options_build_ok")
        string(REPLACE [=[def _build_camoufox_launch_options(headless: bool, kwargs: dict[str, Any]) -> dict[str, Any]:
    from camoufox.utils import launch_options as _cfx_launch_options
    return _cfx_launch_options(headless=headless, **{
        k: v for k, v in kwargs.items() if k not in ("headless", "from_options", "persistent_context")
    })]=]
[=[def _build_camoufox_launch_options(headless: bool, kwargs: dict[str, Any]) -> dict[str, Any]:
    _launch_options_started = time.perf_counter()
    _launch_keys = sorted(str(k) for k in kwargs.keys())
    _camoufox_debug(
        "launch_options_begin",
        headless=bool(headless),
        keys=_launch_keys,
        has_executable=bool(kwargs.get("executable_path")),
        has_prefs=bool(kwargs.get("firefox_user_prefs")),
        has_user_data_dir=bool(kwargs.get("user_data_dir")),
    )
    try:
        _camoufox_debug("launch_options_import_begin")
        from camoufox.utils import launch_options as _cfx_launch_options
        _camoufox_debug(
            "launch_options_import_ok",
            elapsed_ms=int((time.perf_counter() - _launch_options_started) * 1000),
        )
    except Exception as exc:
        _camoufox_debug(
            "launch_options_import_fail",
            elapsed_ms=int((time.perf_counter() - _launch_options_started) * 1000),
            error_type=type(exc).__name__,
            error_len=len(str(exc)),
            error_summary=_safe_text(exc),
            error_traceback=_safe_text("".join(_traceback.format_exception(type(exc), exc, exc.__traceback__)), 4000),
        )
        raise
    try:
        _camoufox_debug(
            "launch_options_build_begin",
            elapsed_ms=int((time.perf_counter() - _launch_options_started) * 1000),
            key_count=len(_launch_keys),
        )
        _options = _cfx_launch_options(headless=headless, **{
            k: v for k, v in kwargs.items() if k not in ("headless", "from_options", "persistent_context")
        })
        _camoufox_debug(
            "launch_options_build_ok",
            elapsed_ms=int((time.perf_counter() - _launch_options_started) * 1000),
            option_keys=sorted(str(k) for k in _options.keys()) if isinstance(_options, dict) else [],
            from_options_has_executable=bool(_options.get("executable_path")) if isinstance(_options, dict) else False,
            from_options_args=len(_options.get("args") or []) if isinstance(_options, dict) else 0,
            from_options_has_env=bool(_options.get("env")) if isinstance(_options, dict) else False,
        )
        return _options
    except Exception as exc:
        _camoufox_debug(
            "launch_options_build_fail",
            elapsed_ms=int((time.perf_counter() - _launch_options_started) * 1000),
            error_type=type(exc).__name__,
            error_len=len(str(exc)),
            error_summary=_safe_text(exc),
            error_traceback=_safe_text("".join(_traceback.format_exception(type(exc), exc, exc.__traceback__)), 4000),
        )
        raise]=]
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
        string(REPLACE [=[def _build_camoufox_launch_options(headless: bool, kwargs: dict[str, Any]) -> dict[str, Any]:
    from camoufox.utils import launch_options as _cfx_launch_options
    return _cfx_launch_options(headless=headless, **{
        k: v for k, v in kwargs.items() if k not in ("headless", "from_options")
    })]=]
[=[def _build_camoufox_launch_options(headless: bool, kwargs: dict[str, Any]) -> dict[str, Any]:
    _launch_options_started = time.perf_counter()
    _launch_keys = sorted(str(k) for k in kwargs.keys())
    _camoufox_debug(
        "launch_options_begin",
        headless=bool(headless),
        keys=_launch_keys,
        has_executable=bool(kwargs.get("executable_path")),
        has_prefs=bool(kwargs.get("firefox_user_prefs")),
        has_user_data_dir=bool(kwargs.get("user_data_dir")),
    )
    try:
        _camoufox_debug("launch_options_import_begin")
        from camoufox.utils import launch_options as _cfx_launch_options
        _camoufox_debug(
            "launch_options_import_ok",
            elapsed_ms=int((time.perf_counter() - _launch_options_started) * 1000),
        )
    except Exception as exc:
        _camoufox_debug(
            "launch_options_import_fail",
            elapsed_ms=int((time.perf_counter() - _launch_options_started) * 1000),
            error_type=type(exc).__name__,
            error_len=len(str(exc)),
            error_summary=_safe_text(exc),
            error_traceback=_safe_text("".join(_traceback.format_exception(type(exc), exc, exc.__traceback__)), 4000),
        )
        raise
    try:
        _camoufox_debug(
            "launch_options_build_begin",
            elapsed_ms=int((time.perf_counter() - _launch_options_started) * 1000),
            key_count=len(_launch_keys),
        )
        _options = _cfx_launch_options(headless=headless, **{
            k: v for k, v in kwargs.items() if k not in ("headless", "from_options", "persistent_context")
        })
        _camoufox_debug(
            "launch_options_build_ok",
            elapsed_ms=int((time.perf_counter() - _launch_options_started) * 1000),
            option_keys=sorted(str(k) for k in _options.keys()) if isinstance(_options, dict) else [],
            from_options_has_executable=bool(_options.get("executable_path")) if isinstance(_options, dict) else False,
            from_options_args=len(_options.get("args") or []) if isinstance(_options, dict) else 0,
            from_options_has_env=bool(_options.get("env")) if isinstance(_options, dict) else False,
        )
        return _options
    except Exception as exc:
        _camoufox_debug(
            "launch_options_build_fail",
            elapsed_ms=int((time.perf_counter() - _launch_options_started) * 1000),
            error_type=type(exc).__name__,
            error_len=len(str(exc)),
            error_summary=_safe_text(exc),
            error_traceback=_safe_text("".join(_traceback.format_exception(type(exc), exc, exc.__traceback__)), 4000),
        )
        raise]=]
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
        string(REPLACE [=[def _build_camoufox_launch_options(headless: bool, kwargs: dict[str, Any]) -> dict[str, Any]:
    started = time.perf_counter()
    options_kwargs = {
        k: v for k, v in kwargs.items() if k not in ("headless", "from_options", "persistent_context")
    }
    _camoufox_debug(
        "launch_options_begin",
        headless=bool(headless),
        keys=sorted(options_kwargs.keys()),
        has_executable=bool(options_kwargs.get("executable_path")),
        has_prefs=bool(options_kwargs.get("firefox_user_prefs")),
        has_user_data_dir=bool(options_kwargs.get("user_data_dir")),
    )
    import_started = time.perf_counter()
    _camoufox_debug("launch_options_import_begin")
    from camoufox.utils import launch_options as _cfx_launch_options
    _camoufox_debug("launch_options_import_ok", elapsed_ms=int((time.perf_counter() - import_started) * 1000))
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        result = _cfx_launch_options(headless=headless, **options_kwargs)
    stdout = out.getvalue()
    if stdout:
        _camoufox_debug("launch_options_stdout", summary=_safe_text(stdout), length=len(stdout))
    _camoufox_debug(
        "launch_options_built",
        elapsed_ms=int((time.perf_counter() - started) * 1000),
        args=len(result.get("args") or []),
        env_keys=len(result.get("env") or {}),
        has_executable=bool(result.get("executable_path")),
        has_proxy=bool(result.get("proxy")),
        has_prefs=bool(result.get("firefox_user_prefs")),
    )
    return result]=]
[=[def _build_camoufox_launch_options(headless: bool, kwargs: dict[str, Any]) -> dict[str, Any]:
    _launch_options_started = time.perf_counter()
    options_kwargs = {
        k: v for k, v in kwargs.items() if k not in ("headless", "from_options", "persistent_context")
    }
    _launch_keys = sorted(str(k) for k in options_kwargs.keys())
    _camoufox_debug(
        "launch_options_begin",
        headless=bool(headless),
        keys=_launch_keys,
        has_executable=bool(options_kwargs.get("executable_path")),
        has_prefs=bool(options_kwargs.get("firefox_user_prefs")),
        has_user_data_dir=bool(options_kwargs.get("user_data_dir")),
    )
    try:
        _camoufox_debug("launch_options_import_begin")
        from camoufox.utils import launch_options as _cfx_launch_options
        _camoufox_debug(
            "launch_options_import_ok",
            elapsed_ms=int((time.perf_counter() - _launch_options_started) * 1000),
        )
    except Exception as exc:
        _camoufox_debug(
            "launch_options_import_fail",
            elapsed_ms=int((time.perf_counter() - _launch_options_started) * 1000),
            error_type=type(exc).__name__,
            error_len=len(str(exc)),
            error_summary=_safe_text(exc),
            error_traceback=_safe_text("".join(_traceback.format_exception(type(exc), exc, exc.__traceback__)), 4000),
        )
        raise
    try:
        _camoufox_debug(
            "launch_options_build_begin",
            elapsed_ms=int((time.perf_counter() - _launch_options_started) * 1000),
            key_count=len(_launch_keys),
        )
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            result = _cfx_launch_options(headless=headless, **options_kwargs)
        stdout = out.getvalue()
        if stdout:
            _camoufox_debug("launch_options_stdout", summary=_safe_text(stdout), length=len(stdout))
        _camoufox_debug(
            "launch_options_build_ok",
            elapsed_ms=int((time.perf_counter() - _launch_options_started) * 1000),
            option_keys=sorted(str(k) for k in result.keys()) if isinstance(result, dict) else [],
            from_options_has_executable=bool(result.get("executable_path")) if isinstance(result, dict) else False,
            from_options_args=len(result.get("args") or []) if isinstance(result, dict) else 0,
            from_options_has_env=bool(result.get("env")) if isinstance(result, dict) else False,
        )
        return result
    except Exception as exc:
        _camoufox_debug(
            "launch_options_build_fail",
            elapsed_ms=int((time.perf_counter() - _launch_options_started) * 1000),
            error_type=type(exc).__name__,
            error_len=len(str(exc)),
            error_summary=_safe_text(exc),
            error_traceback=_safe_text("".join(_traceback.format_exception(type(exc), exc, exc.__traceback__)), 4000),
        )
        raise]=]
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
        string(REPLACE [=[def _build_camoufox_launch_options(headless: bool, kwargs: dict[str, Any]) -> dict[str, Any]:
    from camoufox.utils import launch_options as _cfx_launch_options
    started = time.perf_counter()
    out = io.StringIO()
    options_kwargs = {
        k: v for k, v in kwargs.items() if k not in ("headless", "from_options", "persistent_context")
    }
    with contextlib.redirect_stdout(out):
        result = _cfx_launch_options(headless=headless, **options_kwargs)
    stdout = out.getvalue()
    if stdout:
        _camoufox_debug("launch_options_stdout", summary=_safe_text(stdout), length=len(stdout))
    _camoufox_debug(
        "launch_options_built",
        elapsed_ms=int((time.perf_counter() - started) * 1000),
        args=len(result.get("args") or []),
        env_keys=len(result.get("env") or {}),
        has_executable=bool(result.get("executable_path")),
        has_proxy=bool(result.get("proxy")),
        has_prefs=bool(result.get("firefox_user_prefs")),
    )
    return result]=]
[=[def _build_camoufox_launch_options(headless: bool, kwargs: dict[str, Any]) -> dict[str, Any]:
    _launch_options_started = time.perf_counter()
    options_kwargs = {
        k: v for k, v in kwargs.items() if k not in ("headless", "from_options", "persistent_context")
    }
    _launch_keys = sorted(str(k) for k in options_kwargs.keys())
    _camoufox_debug(
        "launch_options_begin",
        headless=bool(headless),
        keys=_launch_keys,
        has_executable=bool(options_kwargs.get("executable_path")),
        has_prefs=bool(options_kwargs.get("firefox_user_prefs")),
        has_user_data_dir=bool(options_kwargs.get("user_data_dir")),
    )
    try:
        _camoufox_debug("launch_options_import_begin")
        from camoufox.utils import launch_options as _cfx_launch_options
        _camoufox_debug(
            "launch_options_import_ok",
            elapsed_ms=int((time.perf_counter() - _launch_options_started) * 1000),
        )
    except Exception as exc:
        _camoufox_debug(
            "launch_options_import_fail",
            elapsed_ms=int((time.perf_counter() - _launch_options_started) * 1000),
            error_type=type(exc).__name__,
            error_len=len(str(exc)),
            error_summary=_safe_text(exc),
            error_traceback=_safe_text("".join(_traceback.format_exception(type(exc), exc, exc.__traceback__)), 4000),
        )
        raise
    try:
        _camoufox_debug(
            "launch_options_build_begin",
            elapsed_ms=int((time.perf_counter() - _launch_options_started) * 1000),
            key_count=len(_launch_keys),
        )
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            result = _cfx_launch_options(headless=headless, **options_kwargs)
        stdout = out.getvalue()
        if stdout:
            _camoufox_debug("launch_options_stdout", summary=_safe_text(stdout), length=len(stdout))
        _camoufox_debug(
            "launch_options_build_ok",
            elapsed_ms=int((time.perf_counter() - _launch_options_started) * 1000),
            option_keys=sorted(str(k) for k in result.keys()) if isinstance(result, dict) else [],
            from_options_has_executable=bool(result.get("executable_path")) if isinstance(result, dict) else False,
            from_options_args=len(result.get("args") or []) if isinstance(result, dict) else 0,
            from_options_has_env=bool(result.get("env")) if isinstance(result, dict) else False,
        )
        return result
    except Exception as exc:
        _camoufox_debug(
            "launch_options_build_fail",
            elapsed_ms=int((time.perf_counter() - _launch_options_started) * 1000),
            error_type=type(exc).__name__,
            error_len=len(str(exc)),
            error_summary=_safe_text(exc),
            error_traceback=_safe_text("".join(_traceback.format_exception(type(exc), exc, exc.__traceback__)), 4000),
        )
        raise]=]
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "launch_profile_privacy")
        string(REPLACE [=[        try:
            self._profile_dir = profile_dir]=]
[=[        try:
            profile_privacy = _write_private_profile_prefs(profile_dir)
            _camoufox_debug("launch_profile_privacy", **profile_privacy)
            if profile_dir and not profile_privacy.get("written"):
                raise RuntimeError("Camoufox privacy profile preferences were not written")
            self._profile_dir = profile_dir
            self._profile_generated = bool(profile_info.get("generated"))]=]
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "launch_privacy_verified")
        string(REPLACE [=[            if ctx.pages:
                page = ctx.pages[0]
            else:
                _camoufox_debug("launch_new_page_begin")
                page = await asyncio.wait_for(ctx.new_page(), timeout=min(max(15.0, max(5.0, launch_timeout_ms / 1000.0) * 0.75), max(5.0, launch_timeout_ms / 1000.0)))
                _camoufox_debug("launch_new_page_ok", elapsed_ms=int((time.perf_counter() - launch_started) * 1000))]=]
[=[            if ctx.pages:
                page = ctx.pages[0]
            else:
                _camoufox_debug("launch_new_page_begin")
                page = await asyncio.wait_for(ctx.new_page(), timeout=float(launch_budget_policy["page_create_timeout_s"]))
                _camoufox_debug("launch_new_page_ok", elapsed_ms=int((time.perf_counter() - launch_started) * 1000))
            privacy_info = await _verify_page_privacy(page, self._context_plan)
            _camoufox_debug("launch_privacy_verified", **privacy_info)
            if not privacy_info.get("webrtc_blocked") or not privacy_info.get("ice_probe_ok") or privacy_info.get("ice_candidate_leak_detected"):
                raise RuntimeError("Camoufox privacy verification failed")]=]
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "launch_existing_page_reuse")
        string(REPLACE [=[            launch_phase = "new_page"
            _camoufox_debug("launch_new_page_begin", timeout_s=page_create_timeout_s)
            try:
                page = await _await_no_cancel_wait(ctx.new_page(), timeout=page_create_timeout_s)
            except asyncio.TimeoutError:
                _camoufox_debug("launch_new_page_timeout", elapsed_ms=int((time.perf_counter() - launch_started) * 1000), timeout_s=page_create_timeout_s)
                raise
            _camoufox_debug("launch_new_page_ok", elapsed_ms=int((time.perf_counter() - launch_started) * 1000))]=]
[=[            launch_phase = "page_select"
            existing_pages: list[Page] = []
            try:
                existing_pages = list(ctx.pages)
            except Exception as exc:
                _camoufox_debug(
                    "launch_existing_pages_snapshot_failed",
                    elapsed_ms=int((time.perf_counter() - launch_started) * 1000),
                    error_type=type(exc).__name__,
                    error_len=len(str(exc)),
                )
            page = None
            for candidate in existing_pages:
                try:
                    if not candidate.is_closed():
                        page = candidate
                        break
                except Exception as exc:
                    _camoufox_debug(
                        "launch_existing_page_state_failed",
                        elapsed_ms=int((time.perf_counter() - launch_started) * 1000),
                        error_type=type(exc).__name__,
                        error_len=len(str(exc)),
                    )
            if page is None and persistent_context:
                page_wait_timeout_s = min(3.0, max(1.0, page_create_timeout_s * 0.10))
                _camoufox_debug(
                    "launch_existing_page_wait_begin",
                    elapsed_ms=int((time.perf_counter() - launch_started) * 1000),
                    pages_seen=len(existing_pages),
                    timeout_s=page_wait_timeout_s,
                )
                try:
                    candidate = await _await_no_cancel_wait(ctx.wait_for_event("page"), timeout=page_wait_timeout_s)
                    if candidate is not None and not candidate.is_closed():
                        page = candidate
                except asyncio.TimeoutError:
                    _camoufox_debug(
                        "launch_existing_page_wait_timeout",
                        elapsed_ms=int((time.perf_counter() - launch_started) * 1000),
                        timeout_s=page_wait_timeout_s,
                    )
                except Exception as exc:
                    _camoufox_debug(
                        "launch_existing_page_wait_failed",
                        elapsed_ms=int((time.perf_counter() - launch_started) * 1000),
                        error_type=type(exc).__name__,
                        error_len=len(str(exc)),
                        error_summary=_safe_text(exc),
                    )
            if page is not None:
                page_url = ""
                try:
                    page_url = str(page.url or "")
                except Exception:
                    pass
                _camoufox_debug(
                    "launch_existing_page_reuse",
                    elapsed_ms=int((time.perf_counter() - launch_started) * 1000),
                    pages_seen=len(existing_pages),
                    url=_safe_text(page_url, 160),
                )
            else:
                launch_phase = "new_page"
                _camoufox_debug("launch_new_page_begin", timeout_s=page_create_timeout_s)
                try:
                    page = await _await_no_cancel_wait(ctx.new_page(), timeout=page_create_timeout_s)
                except asyncio.TimeoutError:
                    _camoufox_debug("launch_new_page_timeout", elapsed_ms=int((time.perf_counter() - launch_started) * 1000), timeout_s=page_create_timeout_s)
                    raise
                _camoufox_debug("launch_new_page_ok", elapsed_ms=int((time.perf_counter() - launch_started) * 1000))
            try:
                current_pages = list(ctx.pages)
                extras_seen = 0
                extras_closed = 0
                extras_kept = 0
                for extra in current_pages:
                    if extra is page:
                        continue
                    extras_seen += 1
                    extra_url = ""
                    try:
                        extra_url = str(extra.url or "")
                    except Exception:
                        pass
                    if extra_url in {"", "about:blank", "about:newtab"}:
                        await _await_no_cancel_wait(extra.close(), timeout=5.0)
                        extras_closed += 1
                    else:
                        extras_kept += 1
                if extras_seen:
                    _camoufox_debug(
                        "launch_duplicate_pages_cleanup",
                        elapsed_ms=int((time.perf_counter() - launch_started) * 1000),
                        seen=extras_seen,
                        closed=extras_closed,
                        kept=extras_kept,
                        remaining=len(ctx.pages),
                    )
            except Exception as exc:
                _camoufox_debug(
                    "launch_duplicate_pages_cleanup_failed",
                    elapsed_ms=int((time.perf_counter() - launch_started) * 1000),
                    error_type=type(exc).__name__,
                    error_len=len(str(exc)),
                    error_summary=_safe_text(exc),
                )]=]
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    string(REPLACE [=[    started = time.perf_counter()
    pids = _windows_descendant_pids(_os.getpid())
    summary: dict[str, Any] = {"reason": reason, "count": len(pids), "pids": pids[:24], "results": []}]=]
[=[    started = time.perf_counter()
    _camoufox_debug("descendant_cleanup_scan_begin", reason=reason)
    pids = _windows_descendant_pids(_os.getpid())
    _camoufox_debug("descendant_cleanup_scan_end", reason=reason, count=len(pids), pids=pids[:24])
    summary: dict[str, Any] = {"reason": reason, "count": len(pids), "pids": pids[:24], "results": []}]=]
        AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")

    string(REPLACE [=[    summary: dict[str, Any] = {"reason": reason, "count": len(pids), "pids": pids[:24], "results": []}
    for pid in reversed(pids):]=]
[=[    summary: dict[str, Any] = {"reason": reason, "count": len(pids), "pids": pids[:24], "results": []}
    _camoufox_debug("descendant_cleanup_begin", reason=reason, count=len(pids), pids=pids[:24])
    for pid in reversed(pids):]=]
        AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")

    string(REPLACE [=[    summary["elapsed_ms"] = int((time.perf_counter() - started) * 1000)
    if pids:
        _camoufox_debug("descendant_cleanup", **summary)
    return summary]=]
[=[    summary["elapsed_ms"] = int((time.perf_counter() - started) * 1000)
    summary["after_pids"] = _windows_descendant_pids(_os.getpid())[:24]
    summary["after_count"] = len(summary["after_pids"])
    _camoufox_debug("descendant_cleanup", **summary)
    return summary]=]
        AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")

    string(REPLACE [=[    for pid in reversed(pids):
        try:
            proc_started = time.perf_counter()
            result = _subprocess.run(
                ["taskkill.exe", "/PID", str(pid), "/T", "/F"],
                capture_output=True,
                text=True,
                timeout=6,
            )
            summary["results"].append({
                "pid": pid,
                "returncode": int(result.returncode),
                "elapsed_ms": int((time.perf_counter() - proc_started) * 1000),
                "stdout": _safe_text(result.stdout, 240),
                "stderr": _safe_text(result.stderr, 240),
            })
        except Exception as exc:
            summary["results"].append({
                "pid": pid,
                "error_type": type(exc).__name__,
                "error": _safe_text(exc, 240),
            })]=]
[=[    try:
        kernel32 = _ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = [_ctypes.c_ulong, _ctypes.c_int, _ctypes.c_ulong]
        kernel32.OpenProcess.restype = _ctypes.c_void_p
        kernel32.TerminateProcess.argtypes = [_ctypes.c_void_p, _ctypes.c_uint]
        kernel32.TerminateProcess.restype = _ctypes.c_int
        kernel32.WaitForSingleObject.argtypes = [_ctypes.c_void_p, _ctypes.c_ulong]
        kernel32.WaitForSingleObject.restype = _ctypes.c_ulong
        kernel32.GetExitCodeProcess.argtypes = [_ctypes.c_void_p, _ctypes.POINTER(_ctypes.c_ulong)]
        kernel32.GetExitCodeProcess.restype = _ctypes.c_int
        kernel32.CloseHandle.argtypes = [_ctypes.c_void_p]
        kernel32.CloseHandle.restype = _ctypes.c_int
    except Exception as exc:
        summary["setup_error_type"] = type(exc).__name__
        summary["setup_error"] = _safe_text(exc, 240)
        summary["elapsed_ms"] = int((time.perf_counter() - started) * 1000)
        summary["after_pids"] = _windows_descendant_pids(_os.getpid())[:24]
        summary["after_count"] = len(summary["after_pids"])
        _camoufox_debug("descendant_cleanup", **summary)
        return summary

    process_access = 0x0001 | 0x1000 | 0x00100000
    still_active = 259
    for pid in reversed(pids):
        proc_started = time.perf_counter()
        entry: dict[str, Any] = {"pid": int(pid)}
        handle = None
        try:
            _camoufox_debug("descendant_cleanup_process_begin", target_pid=int(pid), reason=reason)
            handle = kernel32.OpenProcess(process_access, 0, int(pid))
            _camoufox_debug("descendant_cleanup_process_open", target_pid=int(pid), open_ok=bool(handle), error=0 if handle else int(_ctypes.get_last_error()))
            if not handle:
                entry["open_ok"] = False
                entry["open_error"] = int(_ctypes.get_last_error())
            else:
                entry["open_ok"] = True
                exit_before = _ctypes.c_ulong(0)
                if kernel32.GetExitCodeProcess(handle, _ctypes.byref(exit_before)):
                    entry["exit_code_before"] = int(exit_before.value)
                    _camoufox_debug("descendant_cleanup_process_exit_before", target_pid=int(pid), exit_code=int(exit_before.value))
                else:
                    entry["exit_code_before_error"] = int(_ctypes.get_last_error())
                    _camoufox_debug("descendant_cleanup_process_exit_before", target_pid=int(pid), error=int(entry["exit_code_before_error"]))
                if entry.get("exit_code_before", still_active) == still_active:
                    terminate_ok = bool(kernel32.TerminateProcess(handle, 1))
                    entry["terminate_ok"] = terminate_ok
                    if not terminate_ok:
                        entry["terminate_error"] = int(_ctypes.get_last_error())
                    _camoufox_debug("descendant_cleanup_process_terminate", target_pid=int(pid), terminate_ok=terminate_ok, error=int(entry.get("terminate_error", 0)))
                    entry["wait_result"] = int(kernel32.WaitForSingleObject(handle, 2000 if terminate_ok else 0))
                    _camoufox_debug("descendant_cleanup_process_wait", target_pid=int(pid), wait_result=int(entry["wait_result"]))
                else:
                    entry["terminate_ok"] = False
                    entry["already_exited"] = True
                    entry["wait_result"] = int(kernel32.WaitForSingleObject(handle, 0))
                    _camoufox_debug("descendant_cleanup_process_wait", target_pid=int(pid), wait_result=int(entry["wait_result"]), already_exited=True)
                exit_after = _ctypes.c_ulong(0)
                if kernel32.GetExitCodeProcess(handle, _ctypes.byref(exit_after)):
                    entry["exit_code_after"] = int(exit_after.value)
                    _camoufox_debug("descendant_cleanup_process_exit_after", target_pid=int(pid), exit_code=int(exit_after.value))
                else:
                    entry["exit_code_after_error"] = int(_ctypes.get_last_error())
                    _camoufox_debug("descendant_cleanup_process_exit_after", target_pid=int(pid), error=int(entry["exit_code_after_error"]))
        except Exception as exc:
            entry["error_type"] = type(exc).__name__
            entry["error"] = _safe_text(exc, 240)
            _camoufox_debug("descendant_cleanup_process_exception", target_pid=int(pid), error_type=type(exc).__name__, error=_safe_text(exc, 240))
        finally:
            if handle:
                close_ok = bool(kernel32.CloseHandle(handle))
                entry["close_ok"] = close_ok
                if not close_ok:
                    entry["close_error"] = int(_ctypes.get_last_error())
                _camoufox_debug("descendant_cleanup_process_close", target_pid=int(pid), close_ok=close_ok, error=int(entry.get("close_error", 0)))
            entry["elapsed_ms"] = int((time.perf_counter() - proc_started) * 1000)
            summary["results"].append(entry)
            _camoufox_debug("descendant_cleanup_process", target_pid=int(pid), cleanup_result=entry)]=]
        AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "descendant_cleanup_process_begin")
        string(REPLACE
"        try:
            handle = kernel32.OpenProcess(process_access, 0, int(pid))"
"        try:
            _camoufox_debug(\"descendant_cleanup_process_begin\", target_pid=int(pid), reason=reason)
            handle = kernel32.OpenProcess(process_access, 0, int(pid))
            _camoufox_debug(\"descendant_cleanup_process_open\", target_pid=int(pid), open_ok=bool(handle), error=0 if handle else int(_ctypes.get_last_error()))"
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")

        string(REPLACE
"                if kernel32.GetExitCodeProcess(handle, _ctypes.byref(exit_before)):
                    entry[\"exit_code_before\"] = int(exit_before.value)
                else:
                    entry[\"exit_code_before_error\"] = int(_ctypes.get_last_error())"
"                if kernel32.GetExitCodeProcess(handle, _ctypes.byref(exit_before)):
                    entry[\"exit_code_before\"] = int(exit_before.value)
                    _camoufox_debug(\"descendant_cleanup_process_exit_before\", target_pid=int(pid), exit_code=int(exit_before.value))
                else:
                    entry[\"exit_code_before_error\"] = int(_ctypes.get_last_error())
                    _camoufox_debug(\"descendant_cleanup_process_exit_before\", target_pid=int(pid), error=int(entry[\"exit_code_before_error\"]))"
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")

        string(REPLACE
"                    if not terminate_ok:
                        entry[\"terminate_error\"] = int(_ctypes.get_last_error())
                    entry[\"wait_result\"] = int(kernel32.WaitForSingleObject(handle, 2000 if terminate_ok else 0))"
"                    if not terminate_ok:
                        entry[\"terminate_error\"] = int(_ctypes.get_last_error())
                    _camoufox_debug(\"descendant_cleanup_process_terminate\", target_pid=int(pid), terminate_ok=terminate_ok, error=int(entry.get(\"terminate_error\", 0)))
                    entry[\"wait_result\"] = int(kernel32.WaitForSingleObject(handle, 2000 if terminate_ok else 0))
                    _camoufox_debug(\"descendant_cleanup_process_wait\", target_pid=int(pid), wait_result=int(entry[\"wait_result\"]))"
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")

        string(REPLACE
"                    entry[\"already_exited\"] = True
                    entry[\"wait_result\"] = int(kernel32.WaitForSingleObject(handle, 0))"
"                    entry[\"already_exited\"] = True
                    entry[\"wait_result\"] = int(kernel32.WaitForSingleObject(handle, 0))
                    _camoufox_debug(\"descendant_cleanup_process_wait\", target_pid=int(pid), wait_result=int(entry[\"wait_result\"]), already_exited=True)"
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")

        string(REPLACE
"                if kernel32.GetExitCodeProcess(handle, _ctypes.byref(exit_after)):
                    entry[\"exit_code_after\"] = int(exit_after.value)
                else:
                    entry[\"exit_code_after_error\"] = int(_ctypes.get_last_error())"
"                if kernel32.GetExitCodeProcess(handle, _ctypes.byref(exit_after)):
                    entry[\"exit_code_after\"] = int(exit_after.value)
                    _camoufox_debug(\"descendant_cleanup_process_exit_after\", target_pid=int(pid), exit_code=int(exit_after.value))
                else:
                    entry[\"exit_code_after_error\"] = int(_ctypes.get_last_error())
                    _camoufox_debug(\"descendant_cleanup_process_exit_after\", target_pid=int(pid), error=int(entry[\"exit_code_after_error\"]))"
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")

        string(REPLACE
"        except Exception as exc:
            entry[\"error_type\"] = type(exc).__name__
            entry[\"error\"] = _safe_text(exc, 240)"
"        except Exception as exc:
            entry[\"error_type\"] = type(exc).__name__
            entry[\"error\"] = _safe_text(exc, 240)
            _camoufox_debug(\"descendant_cleanup_process_exception\", target_pid=int(pid), error_type=type(exc).__name__, error=_safe_text(exc, 240))"
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")

        string(REPLACE
"                if not close_ok:
                    entry[\"close_error\"] = int(_ctypes.get_last_error())"
"                if not close_ok:
                    entry[\"close_error\"] = int(_ctypes.get_last_error())
                _camoufox_debug(\"descendant_cleanup_process_close\", target_pid=int(pid), close_ok=close_ok, error=int(entry.get(\"close_error\", 0)))"
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    string(REPLACE [=[            if self._cm is not None:
                try:
                    await asyncio.wait_for(self._cm.__aexit__(None, None, None), timeout=10)
                except Exception:
                    pass]=]
[=[            if self._cm is not None:
                try:
                    cleanup_started = time.perf_counter()
                    _camoufox_debug("launch_error_context_exit_begin")
                    await asyncio.wait_for(self._cm.__aexit__(None, None, None), timeout=10)
                    _camoufox_debug("launch_error_context_exit_ok", elapsed_ms=int((time.perf_counter() - cleanup_started) * 1000))
                except Exception as cleanup_exc:
                    _camoufox_debug(
                        "launch_error_context_exit_failed",
                        elapsed_ms=int((time.perf_counter() - cleanup_started) * 1000),
                        error_type=type(cleanup_exc).__name__,
                        error_len=len(str(cleanup_exc)),
                        error_summary=_safe_text(cleanup_exc),
                    )]=]
        AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "error_traceback")
        string(REPLACE [=[                error_len=len(str(exc)),
                error_summary=_safe_text(exc),
                window=window_diag,
                persistent=bool(kwargs.get("persistent_context")),
                profile=profile_info,]=]
[=[                error_len=len(str(exc)),
                error_summary=_safe_text(exc),
                error_repr=_safe_text(repr(exc), 1000),
                error_args=[_safe_text(arg, 500) for arg in getattr(exc, "args", ())],
                error_dict={str(k): _safe_text(v, 500) for k, v in getattr(exc, "__dict__", {}).items()},
                error_traceback=_safe_text("".join(_traceback.format_exception(type(exc), exc, exc.__traceback__)), 4000),
                window=window_diag,
                persistent=bool(kwargs.get("persistent_context")),
                profile=profile_info,
                profile_snapshot=_profile_snapshot(profile_dir),
                descendants=_windows_descendant_pids(_os.getpid())[:32],]=]
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    string(REPLACE [=[                except Exception:
                    _camoufox_debug("launch_error_context_exit_failed")]=]
[=[                except Exception as cleanup_exc:
                    _camoufox_debug(
                        "launch_error_context_exit_failed",
                        elapsed_ms=int((time.perf_counter() - cleanup_started) * 1000),
                        error_type=type(cleanup_exc).__name__,
                        error_len=len(str(cleanup_exc)),
                        error_summary=_safe_text(cleanup_exc),
                    )]=]
        AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")

    string(REPLACE
        "                await self._cm.__aexit__(None, None, None)"
        "                await asyncio.wait_for(self._cm.__aexit__(None, None, None), timeout=10)"
        AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")

    string(REPLACE [=[            except Exception:
                _camoufox_debug("close_context_exit_failed")]=]
[=[            except Exception as close_exc:
                _camoufox_debug(
                    "close_context_exit_failed",
                    elapsed_ms=int((time.perf_counter() - exit_started) * 1000),
                    error_type=type(close_exc).__name__,
                    error_len=len(str(close_exc)),
                    error_summary=_safe_text(close_exc),
                )]=]
        AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "_shutil.rmtree\\(profile_dir"
        AND NOT AIDA_CAMOUFOX_CONTENT MATCHES "shutil.rmtree\\(profile_dir")
        string(REPLACE [=[    async def close(self) -> dict:
        """Close the browser and clean up all resources."""
        if self._cm is not None:]=]
[=[    async def close(self) -> dict:
        """Close the browser and clean up all resources."""
        profile_dir = self._profile_dir
        profile_generated = getattr(self, "_profile_generated", False)
        if self._cm is not None:]=]
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")

        string(REPLACE [=[        self._persistent_traces.clear()
        self._nav_responses.clear()
        self._route_handlers.clear()
        return {"status": "closed"}]=]
[=[        self._persistent_traces.clear()
        self._nav_responses.clear()
        self._route_handlers.clear()
        self._profile_dir = None
        self._profile_generated = False
        if profile_dir and profile_generated:
            try:
                import shutil
                shutil.rmtree(profile_dir, ignore_errors=True)
            except Exception:
                pass
        return {"status": "closed"}]=]
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    string(FIND "${AIDA_CAMOUFOX_CONTENT}" "_os.environ.get(\"AIDA_CAMOUFOX_EXECUTABLE\")" AIDA_CAMOUFOX_SHADOWED_ENV_POS)

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "AIDA_CAMOUFOX_EXECUTABLE"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "bundled_visible_launch"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "ff_version"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "launch_bundled_options"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "_build_camoufox_launch_options"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "AIDA_CAMOUFOX_DEBUG_LOG"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "def _create_private_context"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "def _verify_page_privacy"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "def _probe_webrtc_ice_leak"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "ice_probe_ok"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "ice_candidate_leak_detected"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "privacy_fail_closed"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "service_workers"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "launch_existing_config_mismatch"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "ua_policy"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "navigator\\.oscpu"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "launch_context_enter_begin"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "launch_privacy_verified"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "launch_timeout_s"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "persistent_context"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "_profile_dir"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "_profile_generated"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "def _mark_page_terminal"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "close_page_target_closed"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "context_close_event"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "AIDA_CAMOUFOX_FAST_VISIBLE_FALLBACK"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "AIDA_CAMOUFOX_BRIDGE_PATCH_ID"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "aida_camoufox_bridge_20260620_crash_diag_1"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "aida_context_viewport_sanitizer_v1"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "_sanitize_camoufox_context_options"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "context_options_sanitized"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "page_viewport_set_ok"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "protocol_schema_viewport"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "aida_bridge_patch_active"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "aida_launch_policy_resolved"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "aida_default_addon_policy_v1"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "DefaultAddons\\.UBO"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "exclude_addons"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "launch_options_addon_policy"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "launch_options_addon_invalid"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "default_exclusion_scope"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "all_launches"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "default_addons_excluded"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "explicit_addons_validated"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "selected_launch_path"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "block_service_workers"
        OR AIDA_CAMOUFOX_CONTENT MATCHES "aida_fast_visible_launch\", True"
        OR AIDA_CAMOUFOX_CONTENT MATCHES "if explicit_addon_count == 0:"
        OR AIDA_CAMOUFOX_CONTENT MATCHES "context_options: dict\\[str, Any\\] = \\{\"service_workers\": \"block\"\\}"
        OR AIDA_CAMOUFOX_CONTENT MATCHES "new_context\\(service_workers=\"block\"\\)"
        OR AIDA_CAMOUFOX_CONTENT MATCHES "self\\.browser\\.new_context\\("
        OR AIDA_CAMOUFOX_CONTENT MATCHES "browser\\.new_context\\(\\)"
        OR AIDA_CAMOUFOX_CONTENT MATCHES "new_context\\([^\\n\\)]*viewport"
        OR AIDA_CAMOUFOX_CONTENT MATCHES "new_context\\([^\\n\\)]*screen"
        OR AIDA_CAMOUFOX_CONTENT MATCHES "new_context\\([^\\n\\)]*device_scale_factor"
        OR AIDA_CAMOUFOX_CONTENT MATCHES "new_context\\([^\\n\\)]*deviceScaleFactor"
        OR AIDA_CAMOUFOX_CONTENT MATCHES "new_context\\([^\\n\\)]*is_mobile"
        OR AIDA_CAMOUFOX_CONTENT MATCHES "new_context\\([^\\n\\)]*isMobile"
        OR AIDA_CAMOUFOX_CONTENT MATCHES "new_page\\([^\\n\\)]*viewport"
        OR AIDA_CAMOUFOX_CONTENT MATCHES "new_page\\([^\\n\\)]*screen"
        OR AIDA_CAMOUFOX_CONTENT MATCHES "new_page\\([^\\n\\)]*device_scale_factor"
        OR AIDA_CAMOUFOX_CONTENT MATCHES "new_page\\([^\\n\\)]*deviceScaleFactor"
        OR AIDA_CAMOUFOX_CONTENT MATCHES "new_page\\([^\\n\\)]*is_mobile"
        OR AIDA_CAMOUFOX_CONTENT MATCHES "new_page\\([^\\n\\)]*isMobile"
        OR AIDA_CAMOUFOX_SHADOWED_ENV_POS GREATER -1)
        message(WARNING "Failed to patch ${AIDA_CAMOUFOX_PATCH_FILE}")
    endif()

    if(NOT AIDA_CAMOUFOX_CONTENT STREQUAL AIDA_CAMOUFOX_ORIGINAL)
        file(WRITE "${AIDA_CAMOUFOX_PATCH_FILE}" "${AIDA_CAMOUFOX_CONTENT}")
        message(STATUS "Patched ${AIDA_CAMOUFOX_PATCH_FILE}")
    endif()
endforeach()


set(AIDA_CAMOUFOX_HOOKING_PATCH_FILES
    "${AIDA_CAMOUFOX_STAGE_ROOT}/deps/camoufox-reverse-mcp/src/camoufox_reverse_mcp/tools/hooking.py"
    "${AIDA_CAMOUFOX_STAGE_ROOT}/deps/camoufox-runtime/Lib/site-packages/camoufox_reverse_mcp/tools/hooking.py"
)

foreach(AIDA_CAMOUFOX_HOOKING_PATCH_FILE IN LISTS AIDA_CAMOUFOX_HOOKING_PATCH_FILES)
    if(NOT EXISTS "${AIDA_CAMOUFOX_HOOKING_PATCH_FILE}")
        continue()
    endif()

    file(READ "${AIDA_CAMOUFOX_HOOKING_PATCH_FILE}" AIDA_CAMOUFOX_HOOKING_CONTENT)
    set(AIDA_CAMOUFOX_HOOKING_ORIGINAL "${AIDA_CAMOUFOX_HOOKING_CONTENT}")
    string(REPLACE "\r\n" "\n" AIDA_CAMOUFOX_HOOKING_CONTENT "${AIDA_CAMOUFOX_HOOKING_CONTENT}")
    string(REPLACE "\r" "\n" AIDA_CAMOUFOX_HOOKING_CONTENT "${AIDA_CAMOUFOX_HOOKING_CONTENT}")

    set(AIDA_CAMOUFOX_HOOKING_ADD_INIT_SCRIPT [=[@mcp.tool()
async def add_init_script(
    script: str,
    name: str = "",
    persistent: bool = True,
    page_id: str | None = None,
    aida_operation_id=None,
) -> dict:
    try:
        if not isinstance(script, str) or not script.strip():
            return {"error": "script is required"}
        script_name = name.strip() if isinstance(name, str) and name.strip() else f"inline:{hashlib.sha256(script.encode('utf-8')).hexdigest()[:16]}"
        page = await browser_manager.resolve_page_for_operation(page_id, "add_init_script", True, aida_operation_id)
        if persistent:
            await browser_manager.add_persistent_script(script_name, script)
        else:
            await page.add_init_script(script=script)
        if script_name not in browser_manager._init_scripts:
            browser_manager._init_scripts.append(script_name)
        warning = None
        try:
            await page.evaluate(script)
        except Exception as e:
            warning = str(e)
        out = {
            "status": "injected",
            "name": script_name,
            "persistent": bool(persistent),
            "context_init": bool(persistent),
            "page_init": not bool(persistent),
            "page_id": browser_manager.page_id_for(page) if hasattr(browser_manager, "page_id_for") else page_id,
            "applied_to_current_page": warning is None,
            "contexts": len(browser_manager.contexts),
            "pages": len(browser_manager.pages),
        }
        if warning:
            out["warning"] = f"current page evaluate failed: {warning}"
        return out
    except Exception as e:
        return {"error": str(e)}
]=])
    string(REPLACE [=[@mcp.tool()
async def add_init_script(script: str, name: str = "") -> dict:
    try:
        if not isinstance(script, str) or not script.strip():
            return {"error": "script is required"}
        script_name = name.strip() if isinstance(name, str) and name.strip() else f"inline:{hashlib.sha256(script.encode('utf-8')).hexdigest()[:16]}"
        page = await browser_manager.get_active_page()
        await browser_manager.add_persistent_script(script_name, script)
        if script_name not in browser_manager._init_scripts:
            browser_manager._init_scripts.append(script_name)
        warning = None
        try:
            await page.evaluate(script)
        except Exception as e:
            warning = str(e)
        out = {
            "status": "injected",
            "name": script_name,
            "persistent": True,
            "context_init": True,
            "page_init": False,
            "applied_to_current_page": warning is None,
            "contexts": len(browser_manager.contexts),
            "pages": len(browser_manager.pages),
        }
        if warning:
            out["warning"] = f"current page evaluate failed: {warning}"
        return out
    except Exception as e:
        return {"error": str(e)}
]=] "${AIDA_CAMOUFOX_HOOKING_ADD_INIT_SCRIPT}" AIDA_CAMOUFOX_HOOKING_CONTENT "${AIDA_CAMOUFOX_HOOKING_CONTENT}")
    string(REPLACE [=[@mcp.tool()
async def add_init_script(script: str, name: str = "") -> dict:
    try:
        if not isinstance(script, str) or not script.strip():
            return {"error": "script is required"}
        script_name = name.strip() if isinstance(name, str) and name.strip() else f"inline:{hashlib.sha256(script.encode('utf-8')).hexdigest()[:16]}"
        page = await browser_manager.get_active_page()
        await page.add_init_script(script=script)
        browser_manager._init_scripts.append(script_name)
        warning = None
        try:
            await page.evaluate(script)
        except Exception as e:
            warning = str(e)
        out = {
            "status": "injected",
            "name": script_name,
            "persistent": False,
            "page_init": True,
            "applied_to_current_page": warning is None,
        }
        if warning:
            out["warning"] = f"current page evaluate failed: {warning}"
        return out
    except Exception as e:
        return {"error": str(e)}
]=] "${AIDA_CAMOUFOX_HOOKING_ADD_INIT_SCRIPT}" AIDA_CAMOUFOX_HOOKING_CONTENT "${AIDA_CAMOUFOX_HOOKING_CONTENT}")

    if(NOT AIDA_CAMOUFOX_HOOKING_CONTENT MATCHES "context_init"
        OR NOT AIDA_CAMOUFOX_HOOKING_CONTENT MATCHES "browser_manager.add_persistent_script"
        OR NOT AIDA_CAMOUFOX_HOOKING_CONTENT MATCHES "persistent: bool = True"
        OR NOT AIDA_CAMOUFOX_HOOKING_CONTENT MATCHES "browser_manager.resolve_page_for_operation\\(page_id"
        OR NOT AIDA_CAMOUFOX_HOOKING_CONTENT MATCHES "_persistent_scripts")
        message(WARNING "Failed to patch ${AIDA_CAMOUFOX_HOOKING_PATCH_FILE}")
    endif()

    if(NOT AIDA_CAMOUFOX_HOOKING_CONTENT STREQUAL AIDA_CAMOUFOX_HOOKING_ORIGINAL)
        file(WRITE "${AIDA_CAMOUFOX_HOOKING_PATCH_FILE}" "${AIDA_CAMOUFOX_HOOKING_CONTENT}")
        message(STATUS "Patched ${AIDA_CAMOUFOX_HOOKING_PATCH_FILE}")
    endif()
endforeach()

set(AIDA_CAMOUFOX_JSVMP_HOOK_PATCH_FILES
    "${AIDA_CAMOUFOX_STAGE_ROOT}/deps/camoufox-reverse-mcp/src/camoufox_reverse_mcp/hooks/jsvmp_hook.js"
    "${AIDA_CAMOUFOX_STAGE_ROOT}/deps/camoufox-runtime/Lib/site-packages/camoufox_reverse_mcp/hooks/jsvmp_hook.js"
)

foreach(AIDA_CAMOUFOX_JSVMP_HOOK_PATCH_FILE IN LISTS AIDA_CAMOUFOX_JSVMP_HOOK_PATCH_FILES)
    if(NOT EXISTS "${AIDA_CAMOUFOX_JSVMP_HOOK_PATCH_FILE}")
        continue()
    endif()

    file(READ "${AIDA_CAMOUFOX_JSVMP_HOOK_PATCH_FILE}" AIDA_CAMOUFOX_JSVMP_HOOK_CONTENT)
    set(AIDA_CAMOUFOX_JSVMP_HOOK_ORIGINAL "${AIDA_CAMOUFOX_JSVMP_HOOK_CONTENT}")
    string(REPLACE "\r\n" "\n" AIDA_CAMOUFOX_JSVMP_HOOK_CONTENT "${AIDA_CAMOUFOX_JSVMP_HOOK_CONTENT}")
    string(REPLACE "\r" "\n" AIDA_CAMOUFOX_JSVMP_HOOK_CONTENT "${AIDA_CAMOUFOX_JSVMP_HOOK_CONTENT}")

    string(REPLACE
        "try { src = _FP_call.call(_FP_toString, v); } catch (e) {}"
        "try { src = _Reflect_apply(_FP_toString, v, []); } catch (e) {}"
        AIDA_CAMOUFOX_JSVMP_HOOK_CONTENT "${AIDA_CAMOUFOX_JSVMP_HOOK_CONTENT}")
    string(REPLACE
        "return _FP_apply.call(this, thisArg, argsArray);"
        "return _Reflect_apply(_FP_apply, this, [thisArg, argsArray]);"
        AIDA_CAMOUFOX_JSVMP_HOOK_CONTENT "${AIDA_CAMOUFOX_JSVMP_HOOK_CONTENT}")
    string(REPLACE
        "var argsArr = _Array.prototype.slice.call(arguments, 1);"
        "var argsArr = _Reflect_apply(_Array.prototype.slice, arguments, [1]);"
        AIDA_CAMOUFOX_JSVMP_HOOK_CONTENT "${AIDA_CAMOUFOX_JSVMP_HOOK_CONTENT}")
    string(REPLACE
        "return _FP_apply.call(this, thisArg, _Array.prototype.slice.call(arguments, 1));"
        "return _Reflect_apply(_FP_apply, this, [thisArg, _Reflect_apply(_Array.prototype.slice, arguments, [1])]);"
        AIDA_CAMOUFOX_JSVMP_HOOK_CONTENT "${AIDA_CAMOUFOX_JSVMP_HOOK_CONTENT}")
    string(REPLACE
        "return _FP_apply.call(_FP_bind, this, arguments);"
        "return _Reflect_apply(_FP_bind, this, arguments);"
        AIDA_CAMOUFOX_JSVMP_HOOK_CONTENT "${AIDA_CAMOUFOX_JSVMP_HOOK_CONTENT}")
    string(REPLACE
        "var r = _FP_apply.call(origFn, this, arguments);"
        "var r = _Reflect_apply(origFn, this, arguments);"
        AIDA_CAMOUFOX_JSVMP_HOOK_CONTENT "${AIDA_CAMOUFOX_JSVMP_HOOK_CONTENT}")

    string(FIND "${AIDA_CAMOUFOX_JSVMP_HOOK_CONTENT}" "_FP_apply.call" AIDA_CAMOUFOX_JSVMP_HOOK_APPLY_CALL_POS)
    string(FIND "${AIDA_CAMOUFOX_JSVMP_HOOK_CONTENT}" "_FP_call.call" AIDA_CAMOUFOX_JSVMP_HOOK_CALL_CALL_POS)
    string(FIND "${AIDA_CAMOUFOX_JSVMP_HOOK_CONTENT}" "slice.call(arguments" AIDA_CAMOUFOX_JSVMP_HOOK_SLICE_CALL_POS)
    if(AIDA_CAMOUFOX_JSVMP_HOOK_APPLY_CALL_POS GREATER -1
        OR AIDA_CAMOUFOX_JSVMP_HOOK_CALL_CALL_POS GREATER -1
        OR AIDA_CAMOUFOX_JSVMP_HOOK_SLICE_CALL_POS GREATER -1
        OR NOT AIDA_CAMOUFOX_JSVMP_HOOK_CONTENT MATCHES "_Reflect_apply\\(_FP_apply, this"
        OR NOT AIDA_CAMOUFOX_JSVMP_HOOK_CONTENT MATCHES "_Reflect_apply\\(origFn, this")
        message(WARNING "Failed to patch ${AIDA_CAMOUFOX_JSVMP_HOOK_PATCH_FILE}")
    endif()

    if(NOT AIDA_CAMOUFOX_JSVMP_HOOK_CONTENT STREQUAL AIDA_CAMOUFOX_JSVMP_HOOK_ORIGINAL)
        file(WRITE "${AIDA_CAMOUFOX_JSVMP_HOOK_PATCH_FILE}" "${AIDA_CAMOUFOX_JSVMP_HOOK_CONTENT}")
        message(STATUS "Patched ${AIDA_CAMOUFOX_JSVMP_HOOK_PATCH_FILE}")
    endif()
endforeach()

set(AIDA_CAMOUFOX_VERIFICATION_PATCH_FILES
    "${AIDA_CAMOUFOX_STAGE_ROOT}/deps/camoufox-reverse-mcp/src/camoufox_reverse_mcp/tools/verification.py"
    "${AIDA_CAMOUFOX_STAGE_ROOT}/deps/camoufox-runtime/Lib/site-packages/camoufox_reverse_mcp/tools/verification.py"
)

foreach(AIDA_CAMOUFOX_VERIFICATION_PATCH_FILE IN LISTS AIDA_CAMOUFOX_VERIFICATION_PATCH_FILES)
    if(NOT EXISTS "${AIDA_CAMOUFOX_VERIFICATION_PATCH_FILE}")
        continue()
    endif()

    file(READ "${AIDA_CAMOUFOX_VERIFICATION_PATCH_FILE}" AIDA_CAMOUFOX_VERIFICATION_CONTENT)
    set(AIDA_CAMOUFOX_VERIFICATION_ORIGINAL "${AIDA_CAMOUFOX_VERIFICATION_CONTENT}")
    string(REPLACE "\r\n" "\n" AIDA_CAMOUFOX_VERIFICATION_CONTENT "${AIDA_CAMOUFOX_VERIFICATION_CONTENT}")
    string(REPLACE "\r" "\n" AIDA_CAMOUFOX_VERIFICATION_CONTENT "${AIDA_CAMOUFOX_VERIFICATION_CONTENT}")

    if(NOT AIDA_CAMOUFOX_VERIFICATION_CONTENT MATCHES "import json as _json")
        string(REPLACE
"from __future__ import annotations

from ..server import mcp, browser_manager"
"from __future__ import annotations

import json as _json

from ..server import mcp, browser_manager"
            AIDA_CAMOUFOX_VERIFICATION_CONTENT "${AIDA_CAMOUFOX_VERIFICATION_CONTENT}")
    endif()

    string(REPLACE [=[                computed = await page.evaluate(
                    "(sample) => window.__mcp_signer_fn(sample)", sample_input)]=]
[=[                sample_json = _json.dumps(sample_input)
                computed = await page.evaluate(
                    f"() => window.__mcp_signer_fn({sample_json})")]=]
        AIDA_CAMOUFOX_VERIFICATION_CONTENT "${AIDA_CAMOUFOX_VERIFICATION_CONTENT}")

    string(FIND "${AIDA_CAMOUFOX_VERIFICATION_CONTENT}" "(sample) => window.__mcp_signer_fn(sample)" AIDA_CAMOUFOX_VERIFICATION_OLD_EVAL_POS)
    if(NOT AIDA_CAMOUFOX_VERIFICATION_CONTENT MATCHES "import json as _json"
        OR NOT AIDA_CAMOUFOX_VERIFICATION_CONTENT MATCHES "sample_json = _json.dumps\\(sample_input\\)"
        OR AIDA_CAMOUFOX_VERIFICATION_OLD_EVAL_POS GREATER -1)
        message(WARNING "Failed to patch ${AIDA_CAMOUFOX_VERIFICATION_PATCH_FILE}")
    endif()

    if(NOT AIDA_CAMOUFOX_VERIFICATION_CONTENT STREQUAL AIDA_CAMOUFOX_VERIFICATION_ORIGINAL)
        file(WRITE "${AIDA_CAMOUFOX_VERIFICATION_PATCH_FILE}" "${AIDA_CAMOUFOX_VERIFICATION_CONTENT}")
        message(STATUS "Patched ${AIDA_CAMOUFOX_VERIFICATION_PATCH_FILE}")
    endif()
endforeach()

set(AIDA_CAMOUFOX_NAV_PATCH_FILES
    "${AIDA_CAMOUFOX_STAGE_ROOT}/deps/camoufox-reverse-mcp/src/camoufox_reverse_mcp/tools/navigation.py"
    "${AIDA_CAMOUFOX_STAGE_ROOT}/deps/camoufox-runtime/Lib/site-packages/camoufox_reverse_mcp/tools/navigation.py"
)

foreach(AIDA_CAMOUFOX_NAV_PATCH_FILE IN LISTS AIDA_CAMOUFOX_NAV_PATCH_FILES)
    if(NOT EXISTS "${AIDA_CAMOUFOX_NAV_PATCH_FILE}")
        continue()
    endif()

    file(READ "${AIDA_CAMOUFOX_NAV_PATCH_FILE}" AIDA_CAMOUFOX_NAV_CONTENT)
    set(AIDA_CAMOUFOX_NAV_ORIGINAL "${AIDA_CAMOUFOX_NAV_CONTENT}")
    string(REPLACE "\r\n" "\n" AIDA_CAMOUFOX_NAV_CONTENT "${AIDA_CAMOUFOX_NAV_CONTENT}")
    string(REPLACE "\r" "\n" AIDA_CAMOUFOX_NAV_CONTENT "${AIDA_CAMOUFOX_NAV_CONTENT}")

    string(FIND "${AIDA_CAMOUFOX_NAV_CONTENT}" "executable_path: str | None" AIDA_CAMOUFOX_NAV_EXECUTABLE_POS)
    string(FIND "${AIDA_CAMOUFOX_NAV_CONTENT}" "ff_version: int | None" AIDA_CAMOUFOX_NAV_VERSION_POS)
    string(FIND "${AIDA_CAMOUFOX_NAV_CONTENT}" "launch_timeout_ms: int" AIDA_CAMOUFOX_NAV_TIMEOUT_POS)
    string(FIND "${AIDA_CAMOUFOX_NAV_CONTENT}" "config[\"executable_path\"] = executable_path" AIDA_CAMOUFOX_NAV_CONFIG_EXECUTABLE_POS)
    string(FIND "${AIDA_CAMOUFOX_NAV_CONTENT}" "config[\"ff_version\"] = int(ff_version)" AIDA_CAMOUFOX_NAV_CONFIG_VERSION_POS)
    string(FIND "${AIDA_CAMOUFOX_NAV_CONTENT}" "int(launch_policy" AIDA_CAMOUFOX_NAV_CONFIG_TIMEOUT_POS)
    string(FIND "${AIDA_CAMOUFOX_NAV_CONTENT}" "\"aida_launch_budget_policy\": launch_policy" AIDA_CAMOUFOX_NAV_CONFIG_POLICY_POS)

    if(AIDA_CAMOUFOX_NAV_EXECUTABLE_POS EQUAL -1)
        string(REPLACE
"    window_width: int = 1280,
    window_height: int = 900,
) -> dict:"
"    window_width: int = 1280,
    window_height: int = 900,
    executable_path: str | None = None,
    ff_version: int | None = None,
    launch_timeout_ms: int = AIDA_LAUNCH_DEFAULT_BUNDLED_VISIBLE_MS,
) -> dict:"
            AIDA_CAMOUFOX_NAV_CONTENT "${AIDA_CAMOUFOX_NAV_CONTENT}")
    endif()

    if(AIDA_CAMOUFOX_NAV_TIMEOUT_POS EQUAL -1 AND NOT AIDA_CAMOUFOX_NAV_EXECUTABLE_POS EQUAL -1)
        string(REPLACE
"    ff_version: int | None = None,
) -> dict:"
"    ff_version: int | None = None,
    launch_timeout_ms: int = AIDA_LAUNCH_DEFAULT_BUNDLED_VISIBLE_MS,
) -> dict:"
            AIDA_CAMOUFOX_NAV_CONTENT "${AIDA_CAMOUFOX_NAV_CONTENT}")
    endif()

    string(FIND "${AIDA_CAMOUFOX_NAV_CONTENT}" "config[\"executable_path\"] = executable_path" AIDA_CAMOUFOX_NAV_CONFIG_EXECUTABLE_POS)
    string(FIND "${AIDA_CAMOUFOX_NAV_CONTENT}" "\"launch_timeout_ms\": int(launch_policy[\"launch_timeout_ms\"])" AIDA_CAMOUFOX_NAV_CONFIG_TIMEOUT_POS)
    string(FIND "${AIDA_CAMOUFOX_NAV_CONTENT}" "\"aida_launch_budget_policy\": launch_policy" AIDA_CAMOUFOX_NAV_CONFIG_POLICY_POS)
    if(AIDA_CAMOUFOX_NAV_CONFIG_EXECUTABLE_POS EQUAL -1)
        string(REPLACE
"            \"enable_trace\": enable_trace,
            \"window_width\": window_width,
            \"window_height\": window_height,
        }
        if proxy:"
"            \"enable_trace\": enable_trace,
            \"window_width\": window_width,
            \"window_height\": window_height,
        }
        if executable_path:
            config[\"executable_path\"] = executable_path
        if ff_version is not None:
            try:
                config[\"ff_version\"] = int(ff_version)
            except (TypeError, ValueError):
                pass
        if proxy:"
            AIDA_CAMOUFOX_NAV_CONTENT "${AIDA_CAMOUFOX_NAV_CONTENT}")
    endif()

    if(AIDA_CAMOUFOX_NAV_CONFIG_TIMEOUT_POS EQUAL -1)
        string(REPLACE
"            \"window_width\": window_width,
            \"window_height\": window_height,
        }"
"            \"window_width\": window_width,
            \"window_height\": window_height,
            \"launch_timeout_ms\": launch_timeout_ms,
        }"
            AIDA_CAMOUFOX_NAV_CONTENT "${AIDA_CAMOUFOX_NAV_CONTENT}")
    endif()

    string(REPLACE
"        await page.goto(current_url, wait_until=wait_until)
        return {\"url\": page.url, \"title\": await page.title()}"
"        await page.goto(current_url, wait_until=wait_until)
        title = \"\"
        title_error = None
        try:
            title = await page.title()
        except Exception as e:
            title_error = str(e)
        out = {\"url\": page.url, \"title\": title}
        if title_error:
            out[\"title_error\"] = title_error
        return out"
        AIDA_CAMOUFOX_NAV_CONTENT "${AIDA_CAMOUFOX_NAV_CONTENT}")

    string(REPLACE
"        bounds = await browser_manager._page_bounds(page)
        return {
            \"url\": page.url, \"title\": await page.title(),
            \"viewport_width\": viewport.get(\"width\"),
            \"viewport_height\": viewport.get(\"height\"),
            \"window_bounds\": bounds,
        }"
"        bounds = await browser_manager._page_bounds(page)
        title = \"\"
        title_error = None
        try:
            title = await page.title()
        except Exception as e:
            title_error = str(e)
        out = {
            \"url\": page.url, \"title\": title,
            \"viewport_width\": viewport.get(\"width\"),
            \"viewport_height\": viewport.get(\"height\"),
            \"window_bounds\": bounds,
        }
        if title_error:
            out[\"title_error\"] = title_error
        return out"
        AIDA_CAMOUFOX_NAV_CONTENT "${AIDA_CAMOUFOX_NAV_CONTENT}")

    string(FIND "${AIDA_CAMOUFOX_NAV_CONTENT}" "executable_path: str | None" AIDA_CAMOUFOX_NAV_EXECUTABLE_POS)
    string(FIND "${AIDA_CAMOUFOX_NAV_CONTENT}" "ff_version: int | None" AIDA_CAMOUFOX_NAV_VERSION_POS)
    string(FIND "${AIDA_CAMOUFOX_NAV_CONTENT}" "launch_timeout_ms: int" AIDA_CAMOUFOX_NAV_TIMEOUT_POS)
    string(FIND "${AIDA_CAMOUFOX_NAV_CONTENT}" "config[\"executable_path\"] = executable_path" AIDA_CAMOUFOX_NAV_CONFIG_EXECUTABLE_POS)
    string(FIND "${AIDA_CAMOUFOX_NAV_CONTENT}" "config[\"ff_version\"] = int(ff_version)" AIDA_CAMOUFOX_NAV_CONFIG_VERSION_POS)
    string(FIND "${AIDA_CAMOUFOX_NAV_CONTENT}" "int(launch_policy" AIDA_CAMOUFOX_NAV_CONFIG_TIMEOUT_POS)
    string(FIND "${AIDA_CAMOUFOX_NAV_CONTENT}" "aida_launch_budget_policy" AIDA_CAMOUFOX_NAV_CONFIG_POLICY_POS)
    string(FIND "${AIDA_CAMOUFOX_NAV_CONTENT}" "bounds = await browser_manager._page_bounds(page)" AIDA_CAMOUFOX_NAV_PAGE_BOUNDS_POS)
    string(FIND "${AIDA_CAMOUFOX_NAV_CONTENT}" "title_error = None" AIDA_CAMOUFOX_NAV_TITLE_ERROR_INIT_POS)
    string(FIND "${AIDA_CAMOUFOX_NAV_CONTENT}" "out[\"title_error\"] = title_error" AIDA_CAMOUFOX_NAV_TITLE_ERROR_OUT_POS)
    string(FIND "${AIDA_CAMOUFOX_NAV_CONTENT}" "return {\"url\": page.url, \"title\": await page.title()}" AIDA_CAMOUFOX_NAV_UNSAFE_TITLE_POS)
    if(AIDA_CAMOUFOX_NAV_EXECUTABLE_POS EQUAL -1
        OR AIDA_CAMOUFOX_NAV_VERSION_POS EQUAL -1
        OR AIDA_CAMOUFOX_NAV_TIMEOUT_POS EQUAL -1
        OR AIDA_CAMOUFOX_NAV_CONFIG_EXECUTABLE_POS EQUAL -1
        OR AIDA_CAMOUFOX_NAV_CONFIG_VERSION_POS EQUAL -1
        OR AIDA_CAMOUFOX_NAV_CONFIG_TIMEOUT_POS EQUAL -1
        OR AIDA_CAMOUFOX_NAV_CONFIG_POLICY_POS EQUAL -1
        OR AIDA_CAMOUFOX_NAV_PAGE_BOUNDS_POS EQUAL -1
        OR AIDA_CAMOUFOX_NAV_TITLE_ERROR_INIT_POS EQUAL -1
        OR AIDA_CAMOUFOX_NAV_TITLE_ERROR_OUT_POS EQUAL -1
        OR AIDA_CAMOUFOX_NAV_UNSAFE_TITLE_POS GREATER -1)
        message(WARNING "Failed to patch ${AIDA_CAMOUFOX_NAV_PATCH_FILE} markers executable=${AIDA_CAMOUFOX_NAV_EXECUTABLE_POS} version=${AIDA_CAMOUFOX_NAV_VERSION_POS} timeout_arg=${AIDA_CAMOUFOX_NAV_TIMEOUT_POS} config_executable=${AIDA_CAMOUFOX_NAV_CONFIG_EXECUTABLE_POS} config_version=${AIDA_CAMOUFOX_NAV_CONFIG_VERSION_POS} config_timeout=${AIDA_CAMOUFOX_NAV_CONFIG_TIMEOUT_POS} config_policy=${AIDA_CAMOUFOX_NAV_CONFIG_POLICY_POS} page_bounds=${AIDA_CAMOUFOX_NAV_PAGE_BOUNDS_POS} title_error_init=${AIDA_CAMOUFOX_NAV_TITLE_ERROR_INIT_POS} title_error_out=${AIDA_CAMOUFOX_NAV_TITLE_ERROR_OUT_POS} unsafe_title=${AIDA_CAMOUFOX_NAV_UNSAFE_TITLE_POS}")
    endif()

    if(NOT AIDA_CAMOUFOX_NAV_CONTENT STREQUAL AIDA_CAMOUFOX_NAV_ORIGINAL)
        file(WRITE "${AIDA_CAMOUFOX_NAV_PATCH_FILE}" "${AIDA_CAMOUFOX_NAV_CONTENT}")
        message(STATUS "Patched ${AIDA_CAMOUFOX_NAV_PATCH_FILE}")
    endif()
endforeach()

foreach(AIDA_CAMOUFOX_STAGE_MCP_ROOT IN LISTS AIDA_CAMOUFOX_STAGE_MCP_ROOTS)
    set(AIDA_CAMOUFOX_STAGE_BROWSER_PATH "${AIDA_CAMOUFOX_STAGE_MCP_ROOT}/browser.py")
    set(AIDA_CAMOUFOX_STAGE_MAIN_PATH "${AIDA_CAMOUFOX_STAGE_MCP_ROOT}/__main__.py")
    set(AIDA_CAMOUFOX_STAGE_PLAYWRIGHT_PATCH_PATH "${AIDA_CAMOUFOX_STAGE_MCP_ROOT}/_playwright_patch.py")
    set(AIDA_CAMOUFOX_STAGE_NAV_PATH "${AIDA_CAMOUFOX_STAGE_MCP_ROOT}/tools/navigation.py")
    set(AIDA_CAMOUFOX_STAGE_SCRIPT_PATH "${AIDA_CAMOUFOX_STAGE_MCP_ROOT}/tools/script_analysis.py")
    set(AIDA_CAMOUFOX_STAGE_NETWORK_PATH "${AIDA_CAMOUFOX_STAGE_MCP_ROOT}/tools/network.py")
    if(EXISTS "${AIDA_CAMOUFOX_STAGE_MCP_ROOT}" AND NOT EXISTS "${AIDA_CAMOUFOX_STAGE_PLAYWRIGHT_PATCH_PATH}")
        message(WARNING "Staged Camoufox reverse-MCP Playwright patch source is missing: ${AIDA_CAMOUFOX_STAGE_PLAYWRIGHT_PATCH_PATH}")
    endif()
    if(EXISTS "${AIDA_CAMOUFOX_STAGE_BROWSER_PATH}")
        file(READ "${AIDA_CAMOUFOX_STAGE_BROWSER_PATH}" AIDA_CAMOUFOX_STAGE_BROWSER_CONTENT)
        string(REPLACE "\r\n" "\n" AIDA_CAMOUFOX_STAGE_BROWSER_CONTENT "${AIDA_CAMOUFOX_STAGE_BROWSER_CONTENT}")
        string(REPLACE "\r" "\n" AIDA_CAMOUFOX_STAGE_BROWSER_CONTENT "${AIDA_CAMOUFOX_STAGE_BROWSER_CONTENT}")
        foreach(AIDA_CAMOUFOX_STAGE_BROWSER_MARKER IN ITEMS
            "page_recovery_created"
            "resolve_page_default_recovery_begin"
            "browser_page_id_unavailable"
            "def _launch_error_summary"
            "last_launch_failure_payload"
            "launch_new_page_task_result"
            "privacy_verify_exception"
            "page_closed_during_launch"
            "aida_launch_budget_policy_v1"
            "aida_resolve_launch_budget_policy"
            "aida_validate_launch_budget_policy"
            "aida_retry_launch_timeout_ms"
            "cmdline_sha256"
            "subprocess_diagnostics_installed"
            "stdout_capture"
            "stderr_capture"
            "exit_ts_ms"
            "diagnostic_original_style_bundled"
            "_registered_page_records"
            "requestfinished_event"
            "websocket_event"
            "response_body_length")
            string(FIND "${AIDA_CAMOUFOX_STAGE_BROWSER_CONTENT}" "${AIDA_CAMOUFOX_STAGE_BROWSER_MARKER}" AIDA_CAMOUFOX_STAGE_BROWSER_MARKER_POS)
            if(AIDA_CAMOUFOX_STAGE_BROWSER_MARKER_POS EQUAL -1)
                message(WARNING "Staged Camoufox reverse-MCP browser source is missing required marker ${AIDA_CAMOUFOX_STAGE_BROWSER_MARKER}: ${AIDA_CAMOUFOX_STAGE_BROWSER_PATH}")
            endif()
        endforeach()
    endif()
    if(EXISTS "${AIDA_CAMOUFOX_STAGE_MAIN_PATH}")
        file(READ "${AIDA_CAMOUFOX_STAGE_MAIN_PATH}" AIDA_CAMOUFOX_STAGE_MAIN_CONTENT)
        string(REPLACE "\r\n" "\n" AIDA_CAMOUFOX_STAGE_MAIN_CONTENT "${AIDA_CAMOUFOX_STAGE_MAIN_CONTENT}")
        string(REPLACE "\r" "\n" AIDA_CAMOUFOX_STAGE_MAIN_CONTENT "${AIDA_CAMOUFOX_STAGE_MAIN_CONTENT}")
        foreach(AIDA_CAMOUFOX_STAGE_MAIN_MARKER IN ITEMS
            "_aida_apply_playwright_pageerror_patch"
            "patch_playwright_pageerror"
            "aida_launch_budget_policy_v1"
            "launch_budget_policy_marker_present"
            "launch_budget_retry_contract_ok"
            "playwright_patch=playwright_patch")
            string(FIND "${AIDA_CAMOUFOX_STAGE_MAIN_CONTENT}" "${AIDA_CAMOUFOX_STAGE_MAIN_MARKER}" AIDA_CAMOUFOX_STAGE_MAIN_MARKER_POS)
            if(AIDA_CAMOUFOX_STAGE_MAIN_MARKER_POS EQUAL -1)
                message(WARNING "Staged Camoufox reverse-MCP main source is missing required marker ${AIDA_CAMOUFOX_STAGE_MAIN_MARKER}: ${AIDA_CAMOUFOX_STAGE_MAIN_PATH}")
            endif()
        endforeach()
    endif()
    if(EXISTS "${AIDA_CAMOUFOX_STAGE_PLAYWRIGHT_PATCH_PATH}")
        file(READ "${AIDA_CAMOUFOX_STAGE_PLAYWRIGHT_PATCH_PATH}" AIDA_CAMOUFOX_STAGE_PLAYWRIGHT_PATCH_CONTENT)
        string(REPLACE "\r\n" "\n" AIDA_CAMOUFOX_STAGE_PLAYWRIGHT_PATCH_CONTENT "${AIDA_CAMOUFOX_STAGE_PLAYWRIGHT_PATCH_CONTENT}")
        string(REPLACE "\r" "\n" AIDA_CAMOUFOX_STAGE_PLAYWRIGHT_PATCH_CONTENT "${AIDA_CAMOUFOX_STAGE_PLAYWRIGHT_PATCH_CONTENT}")
        foreach(AIDA_CAMOUFOX_STAGE_PLAYWRIGHT_PATCH_MARKER IN ITEMS
            "AIDA_PLAYWRIGHT_PAGEERROR_PATCH_ID"
            "aida_playwright_pageerror_location_patch_20260620_1"
            "patch_playwright_pageerror"
            "coreBundle.js"
            "pageError.location.url"
            "pageError.location?.url ?? ''"
            "pageError.location.lineNumber"
            "pageError.location?.lineNumber ?? 0"
            "pageError.location.columnNumber"
            "pageError.location?.columnNumber ?? 0")
            string(FIND "${AIDA_CAMOUFOX_STAGE_PLAYWRIGHT_PATCH_CONTENT}" "${AIDA_CAMOUFOX_STAGE_PLAYWRIGHT_PATCH_MARKER}" AIDA_CAMOUFOX_STAGE_PLAYWRIGHT_PATCH_MARKER_POS)
            if(AIDA_CAMOUFOX_STAGE_PLAYWRIGHT_PATCH_MARKER_POS EQUAL -1)
                message(WARNING "Staged Camoufox reverse-MCP Playwright patch source is missing required marker ${AIDA_CAMOUFOX_STAGE_PLAYWRIGHT_PATCH_MARKER}: ${AIDA_CAMOUFOX_STAGE_PLAYWRIGHT_PATCH_PATH}")
            endif()
        endforeach()
    endif()
    if(EXISTS "${AIDA_CAMOUFOX_STAGE_NAV_PATH}")
        file(READ "${AIDA_CAMOUFOX_STAGE_NAV_PATH}" AIDA_CAMOUFOX_STAGE_NAV_CONTENT)
        string(REPLACE "\r\n" "\n" AIDA_CAMOUFOX_STAGE_NAV_CONTENT "${AIDA_CAMOUFOX_STAGE_NAV_CONTENT}")
        string(REPLACE "\r" "\n" AIDA_CAMOUFOX_STAGE_NAV_CONTENT "${AIDA_CAMOUFOX_STAGE_NAV_CONTENT}")
        foreach(AIDA_CAMOUFOX_STAGE_NAV_MARKER IN ITEMS
            "diagnostic_navigation_goto_begin"
            "diagnostic_navigation_goto_exception"
            "bloxflip_navigation_state"
            "navigation_lifecycle_degraded"
            "first_failure_phase"
            "diagnose_bloxflip_matrix"
            "launch_browser_tool_exception"
            "browser_manager.last_launch_failure_payload"
            "bridge_attempt_id"
            "original_style_bundled"
            "node_exit_code"
            "camoufox_child_exits"
            "cloudflare"
            "aida_clamp_navigation_timeout_ms"
            "aida_resolve_launch_budget_policy"
            "nav_timeout_ms"
            "\"timeout_ms\": nav_timeout_ms"
            "_await_no_cancel_wait(page.evaluate(\"document.readyState\")"
            "_navigation_capture_summary"
            "\"capture_compacted\""
            "\"body_access\""
            "\"network_requests\""
            "\"network_capture\"")
            string(FIND "${AIDA_CAMOUFOX_STAGE_NAV_CONTENT}" "${AIDA_CAMOUFOX_STAGE_NAV_MARKER}" AIDA_CAMOUFOX_STAGE_NAV_MARKER_POS)
            if(AIDA_CAMOUFOX_STAGE_NAV_MARKER_POS EQUAL -1)
                message(WARNING "Staged Camoufox reverse-MCP navigation source is missing required marker ${AIDA_CAMOUFOX_STAGE_NAV_MARKER}: ${AIDA_CAMOUFOX_STAGE_NAV_PATH}")
            endif()
        endforeach()
    endif()
    if(EXISTS "${AIDA_CAMOUFOX_STAGE_SCRIPT_PATH}")
        file(READ "${AIDA_CAMOUFOX_STAGE_SCRIPT_PATH}" AIDA_CAMOUFOX_STAGE_SCRIPT_CONTENT)
        string(REPLACE "\r\n" "\n" AIDA_CAMOUFOX_STAGE_SCRIPT_CONTENT "${AIDA_CAMOUFOX_STAGE_SCRIPT_CONTENT}")
        string(REPLACE "\r" "\n" AIDA_CAMOUFOX_STAGE_SCRIPT_CONTENT "${AIDA_CAMOUFOX_STAGE_SCRIPT_CONTENT}")
        foreach(AIDA_CAMOUFOX_STAGE_SCRIPT_MARKER IN ITEMS
            "async def scripts("
            "async def _script_error"
            "\"scripts\""
            "\"count\""
            "scripts_error"
            "requested_page_id")
            string(FIND "${AIDA_CAMOUFOX_STAGE_SCRIPT_CONTENT}" "${AIDA_CAMOUFOX_STAGE_SCRIPT_MARKER}" AIDA_CAMOUFOX_STAGE_SCRIPT_MARKER_POS)
            if(AIDA_CAMOUFOX_STAGE_SCRIPT_MARKER_POS EQUAL -1)
                message(WARNING "Staged Camoufox reverse-MCP script source is missing required marker ${AIDA_CAMOUFOX_STAGE_SCRIPT_MARKER}: ${AIDA_CAMOUFOX_STAGE_SCRIPT_PATH}")
            endif()
        endforeach()
    endif()
    if(EXISTS "${AIDA_CAMOUFOX_STAGE_NETWORK_PATH}")
        file(READ "${AIDA_CAMOUFOX_STAGE_NETWORK_PATH}" AIDA_CAMOUFOX_STAGE_NETWORK_CONTENT)
        string(REPLACE "\r\n" "\n" AIDA_CAMOUFOX_STAGE_NETWORK_CONTENT "${AIDA_CAMOUFOX_STAGE_NETWORK_CONTENT}")
        string(REPLACE "\r" "\n" AIDA_CAMOUFOX_STAGE_NETWORK_CONTENT "${AIDA_CAMOUFOX_STAGE_NETWORK_CONTENT}")
        foreach(AIDA_CAMOUFOX_STAGE_NETWORK_MARKER IN ITEMS
            "\"request_id\""
            "\"network_request_id\""
            "\"response_body_length\""
            "\"request_body_length\""
            "\"redirect_chain\""
            "\"websocket\""
            "\"timing\""
            "\"initiator\""
            "_NETWORK_DEFAULT_LIMIT"
            "url_prefix: str | None = None"
            "_request_matches_text_filter"
            "\"filtered_count\""
            "\"returned_count\""
            "\"has_more\"")
            string(FIND "${AIDA_CAMOUFOX_STAGE_NETWORK_CONTENT}" "${AIDA_CAMOUFOX_STAGE_NETWORK_MARKER}" AIDA_CAMOUFOX_STAGE_NETWORK_MARKER_POS)
            if(AIDA_CAMOUFOX_STAGE_NETWORK_MARKER_POS EQUAL -1)
                message(WARNING "Staged Camoufox reverse-MCP network source is missing required marker ${AIDA_CAMOUFOX_STAGE_NETWORK_MARKER}: ${AIDA_CAMOUFOX_STAGE_NETWORK_PATH}")
            endif()
        endforeach()
    endif()
endforeach()

set(AIDA_CAMOUFOX_MULTIPAGE_PATCHER "${CMAKE_CURRENT_LIST_DIR}/aida_camoufox_reverse_mcp_multipage.py")
set(AIDA_CAMOUFOX_PATCH_PYTHON "${AIDA_CAMOUFOX_STAGE_ROOT}/deps/camoufox-runtime/python.exe")
if(NOT EXISTS "${AIDA_CAMOUFOX_PATCH_PYTHON}")
    message(FATAL_ERROR "Bundled Camoufox CPython 3.12 runtime is required for offline staging: ${AIDA_CAMOUFOX_PATCH_PYTHON}")
endif()
if(NOT EXISTS "${AIDA_CAMOUFOX_MULTIPAGE_PATCHER}")
    message(FATAL_ERROR "Missing Camoufox multipage patcher: ${AIDA_CAMOUFOX_MULTIPAGE_PATCHER}")
endif()
execute_process(
    COMMAND "${AIDA_CAMOUFOX_PATCH_PYTHON}" -I -S -c "import sys; raise SystemExit(0 if sys.implementation.name == 'cpython' and sys.version_info[:2] == (3, 12) else 1)"
    RESULT_VARIABLE AIDA_CAMOUFOX_PATCH_PYTHON_VERSION_RESULT
    OUTPUT_QUIET
    ERROR_QUIET
)
if(NOT AIDA_CAMOUFOX_PATCH_PYTHON_VERSION_RESULT EQUAL 0)
    message(FATAL_ERROR "Bundled Camoufox runtime must be CPython 3.12: ${AIDA_CAMOUFOX_PATCH_PYTHON}")
endif()
execute_process(
    COMMAND "${AIDA_CAMOUFOX_PATCH_PYTHON}" "${AIDA_CAMOUFOX_MULTIPAGE_PATCHER}" "${AIDA_CAMOUFOX_STAGE_ROOT}"
    RESULT_VARIABLE AIDA_CAMOUFOX_MULTIPAGE_PATCH_RESULT
    OUTPUT_VARIABLE AIDA_CAMOUFOX_MULTIPAGE_PATCH_OUT
    ERROR_VARIABLE AIDA_CAMOUFOX_MULTIPAGE_PATCH_ERR
)
message(STATUS "[AIDA-CAMOUFOX] multipage_patch_result=${AIDA_CAMOUFOX_MULTIPAGE_PATCH_RESULT}")
if(NOT AIDA_CAMOUFOX_MULTIPAGE_PATCH_RESULT EQUAL 0)
    message(FATAL_ERROR "Camoufox multipage patch failed: ${AIDA_CAMOUFOX_MULTIPAGE_PATCH_OUT} ${AIDA_CAMOUFOX_MULTIPAGE_PATCH_ERR}")
endif()
if(AIDA_CAMOUFOX_MULTIPAGE_PATCH_OUT)
    string(STRIP "${AIDA_CAMOUFOX_MULTIPAGE_PATCH_OUT}" AIDA_CAMOUFOX_MULTIPAGE_PATCH_OUT_STRIPPED)
    message(STATUS "${AIDA_CAMOUFOX_MULTIPAGE_PATCH_OUT_STRIPPED}")
endif()

execute_process(
    COMMAND "${AIDA_CAMOUFOX_PATCH_PYTHON}" -I -c "import camoufox_reverse_mcp"
    RESULT_VARIABLE AIDA_CAMOUFOX_PACKAGE_IMPORT_RESULT
    OUTPUT_VARIABLE AIDA_CAMOUFOX_PACKAGE_IMPORT_OUT
    ERROR_VARIABLE AIDA_CAMOUFOX_PACKAGE_IMPORT_ERR
)
if(NOT AIDA_CAMOUFOX_PACKAGE_IMPORT_RESULT EQUAL 0)
    message(FATAL_ERROR "Bundled Camoufox reverse-MCP package import failed: ${AIDA_CAMOUFOX_PACKAGE_IMPORT_OUT} ${AIDA_CAMOUFOX_PACKAGE_IMPORT_ERR}")
endif()
execute_process(
    COMMAND "${AIDA_CAMOUFOX_PATCH_PYTHON}" -I -c "import mcp.server.fastmcp, playwright.async_api, camoufox.async_api"
    RESULT_VARIABLE AIDA_CAMOUFOX_RUNTIME_IMPORT_RESULT
    OUTPUT_VARIABLE AIDA_CAMOUFOX_RUNTIME_IMPORT_OUT
    ERROR_VARIABLE AIDA_CAMOUFOX_RUNTIME_IMPORT_ERR
)
if(NOT AIDA_CAMOUFOX_RUNTIME_IMPORT_RESULT EQUAL 0)
    set(AIDA_CAMOUFOX_STAGED_WHEELHOUSE "${AIDA_CAMOUFOX_STAGE_ROOT}/deps/camoufox-wheelhouse")
    if(NOT EXISTS "${AIDA_CAMOUFOX_STAGED_WHEELHOUSE}")
        message(FATAL_ERROR "Bundled Camoufox runtime dependencies are missing and no offline wheelhouse was staged: ${AIDA_CAMOUFOX_RUNTIME_IMPORT_OUT} ${AIDA_CAMOUFOX_RUNTIME_IMPORT_ERR}")
    endif()
    execute_process(
        COMMAND "${AIDA_CAMOUFOX_PATCH_PYTHON}" -I -m pip install
            --disable-pip-version-check
            --no-index
            --find-links "${AIDA_CAMOUFOX_STAGED_WHEELHOUSE}"
            "mcp==1.29.0"
            "camoufox[geoip]>=0.4.0"
            "playwright>=1.40.0"
        RESULT_VARIABLE AIDA_CAMOUFOX_OFFLINE_INSTALL_RESULT
        OUTPUT_VARIABLE AIDA_CAMOUFOX_OFFLINE_INSTALL_OUT
        ERROR_VARIABLE AIDA_CAMOUFOX_OFFLINE_INSTALL_ERR
    )
    if(NOT AIDA_CAMOUFOX_OFFLINE_INSTALL_RESULT EQUAL 0)
        message(FATAL_ERROR "Offline Camoufox runtime dependency installation failed: ${AIDA_CAMOUFOX_OFFLINE_INSTALL_OUT} ${AIDA_CAMOUFOX_OFFLINE_INSTALL_ERR}")
    endif()
endif()
execute_process(
    COMMAND "${AIDA_CAMOUFOX_PATCH_PYTHON}" -I -c "import camoufox_reverse_mcp.server, mcp.server.fastmcp, playwright.async_api, camoufox.async_api"
    RESULT_VARIABLE AIDA_CAMOUFOX_SERVER_IMPORT_RESULT
    OUTPUT_VARIABLE AIDA_CAMOUFOX_SERVER_IMPORT_OUT
    ERROR_VARIABLE AIDA_CAMOUFOX_SERVER_IMPORT_ERR
)
if(NOT AIDA_CAMOUFOX_SERVER_IMPORT_RESULT EQUAL 0)
    message(FATAL_ERROR "Bundled Camoufox reverse-MCP server import failed after offline staging: ${AIDA_CAMOUFOX_SERVER_IMPORT_OUT} ${AIDA_CAMOUFOX_SERVER_IMPORT_ERR}")
endif()
execute_process(
    COMMAND "${AIDA_CAMOUFOX_PATCH_PYTHON}" -I -m camoufox_reverse_mcp --aida-contract-check
    RESULT_VARIABLE AIDA_CAMOUFOX_CONTRACT_RESULT
    OUTPUT_VARIABLE AIDA_CAMOUFOX_CONTRACT_OUT
    ERROR_VARIABLE AIDA_CAMOUFOX_CONTRACT_ERR
)
if(NOT AIDA_CAMOUFOX_CONTRACT_RESULT EQUAL 0
   OR NOT AIDA_CAMOUFOX_CONTRACT_OUT MATCHES "\"runtime_marker\"[ \t]*:[ \t]*\"AIDA_CAMOUFOX_RUNTIME_CONTRACT_OK\""
   OR NOT AIDA_CAMOUFOX_CONTRACT_OUT MATCHES "\"contract\"[ \t]*:[ \t]*\"AIDA_INITIATOR_CONTRACT_V2\""
   OR NOT AIDA_CAMOUFOX_CONTRACT_OUT MATCHES "\"ok\"[ \t]*:[ \t]*true"
   OR NOT AIDA_CAMOUFOX_CONTRACT_OUT MATCHES "\"initiator_params\"[ \t]*:")
    message(FATAL_ERROR "Bundled Camoufox reverse-MCP contract probe failed after offline staging: ${AIDA_CAMOUFOX_CONTRACT_OUT} ${AIDA_CAMOUFOX_CONTRACT_ERR}")
endif()
