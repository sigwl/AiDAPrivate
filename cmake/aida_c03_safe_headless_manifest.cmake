include_guard(GLOBAL)

set(AIDA_C03_SAFE_HEADLESS_CMAKE_ROOT "${CMAKE_CURRENT_LIST_DIR}")
set(AIDA_C03_SAFE_HEADLESS_CMAKE_MODULE "${CMAKE_CURRENT_LIST_FILE}")
set(AIDA_C03_PATH_POLICY_MODULE "${CMAKE_CURRENT_LIST_DIR}/c03_safe_headless/package_policy_fixture/aida_c03_path_policy.cmake")
set(AIDA_C03_PATH_IDENTITY_POLICY "${CMAKE_CURRENT_LIST_DIR}/c03_safe_headless/package_policy_fixture/aida_c03_path_identity.ps1")
include("${AIDA_C03_PATH_POLICY_MODULE}")

if(NOT DEFINED STANDALONE_ROOT OR NOT IS_DIRECTORY "${STANDALONE_ROOT}")
    message(WARNING "AiDA C03 integration requires STANDALONE_ROOT")
endif()

set(AIDA_C03_TEST_ROOT "${STANDALONE_ROOT}/../tests/c03")
set(AIDA_C03_MCP_TEST_ROOT "${STANDALONE_ROOT}/../tests/mcp_compat")
set(AIDA_C03_WORKSPACE_TEST_ROOT "${STANDALONE_ROOT}/../tests/analysis_workspace")
if(NOT DEFINED ENV{LOCALAPPDATA} OR NOT IS_ABSOLUTE "$ENV{LOCALAPPDATA}")
    message(WARNING "AiDA C03 requires the canonical per-user local application-data root")
endif()
file(TO_CMAKE_PATH "$ENV{LOCALAPPDATA}" _aida_c03_local_app_data)
file(REAL_PATH "${_aida_c03_local_app_data}" _aida_c03_local_app_data)
file(TO_CMAKE_PATH "${_aida_c03_local_app_data}" _aida_c03_local_app_data)
string(SHA256 _aida_c03_stage_id
    "aida-c03-stage-v1|${CMAKE_SOURCE_DIR}|${CMAKE_BINARY_DIR}|ninja-msvc-release")
string(SUBSTRING "${_aida_c03_stage_id}" 0 24 _aida_c03_stage_id)
set(AIDA_C03_STAGE_OWNER_ROOT
    "${_aida_c03_local_app_data}/AiDA/C03/${_aida_c03_stage_id}")
set(AIDA_C03_DEVELOPER_ROOT "${AIDA_C03_STAGE_OWNER_ROOT}/developer")
set(AIDA_C03_SAFE_HEADLESS_STAGE_ROOT "${AIDA_C03_DEVELOPER_ROOT}/suite/$<CONFIG>")
set(AIDA_C03_SAFE_HEADLESS_GENERATED_ROOT "${AIDA_C03_DEVELOPER_ROOT}/generated")
set(AIDA_C03_SAFE_HEADLESS_INVENTORY "${AIDA_C03_TEST_ROOT}/testlab_runtime/safe_headless_inventory.json")
set(AIDA_C03_SAFE_HEADLESS_ASSERTION_INVENTORY "${AIDA_C03_TEST_ROOT}/testlab_runtime/assertion_site_inventory.json")
set(AIDA_C03_SAFE_HEADLESS_MATERIALIZER "${AIDA_C03_TEST_ROOT}/testlab_runtime/materialize_safe_headless_manifest.py")
set(AIDA_C03_SAFE_HEADLESS_RESOURCE_POLICY_CASES "${AIDA_C03_SAFE_HEADLESS_CMAKE_ROOT}/c03_safe_headless/target_resource_policy_cases.json")
set(AIDA_C03_SAFE_HEADLESS_RECORDS "${AIDA_C03_SAFE_HEADLESS_GENERATED_ROOT}/target-records-$<CONFIG>.json")
set(AIDA_C03_SAFE_HEADLESS_MANIFEST "${AIDA_C03_SAFE_HEADLESS_STAGE_ROOT}/manifest.json")
file(MAKE_DIRECTORY "${AIDA_C03_SAFE_HEADLESS_GENERATED_ROOT}")

set(AIDA_C03_MCP_PRODUCTION_CLOSURE_SOURCES
    "${STANDALONE_ROOT}/core/analysis/analysis_tools_standalone.cpp"
    "${STANDALONE_ROOT}/core/analysis/binary_map.cpp"
    "${STANDALONE_ROOT}/core/debugger/debugger_engine.cpp"
    "${STANDALONE_ROOT}/core/debugger/debugger_tools_standalone.cpp"
    "${STANDALONE_ROOT}/core/debugger/thread_intel.cpp"
    "${STANDALONE_ROOT}/core/debugger/thread_intel_tools_standalone.cpp"
    "${STANDALONE_ROOT}/core/disasm/decompile_tools_standalone.cpp"
    "${STANDALONE_ROOT}/core/disasm/disasm_tools_standalone.cpp"
    "${STANDALONE_ROOT}/core/editor/programming_language_service.cpp"
    "${STANDALONE_ROOT}/core/mcp/mcp_client.cpp"
    "${STANDALONE_ROOT}/core/network/api_enum_tools_standalone.cpp"
    "${STANDALONE_ROOT}/core/network/burp/active_scanner.cpp"
    "${STANDALONE_ROOT}/core/network/burp/api_definition.cpp"
    "${STANDALONE_ROOT}/core/network/burp/audit_http.cpp"
    "${STANDALONE_ROOT}/core/network/burp/collaborator.cpp"
    "${STANDALONE_ROOT}/core/network/burp/cookie_jar.cpp"
    "${STANDALONE_ROOT}/core/network/burp/insertion_points.cpp"
    "${STANDALONE_ROOT}/core/network/burp/issue.cpp"
    "${STANDALONE_ROOT}/core/network/burp/jwt_lab.cpp"
    "${STANDALONE_ROOT}/core/network/burp/match_replace.cpp"
    "${STANDALONE_ROOT}/core/network/burp/payload_library.cpp"
    "${STANDALONE_ROOT}/core/network/burp/burp_logger.cpp"
    "${STANDALONE_ROOT}/core/network/burp/scanner_module.cpp"
    "${STANDALONE_ROOT}/core/network/burp/scope.cpp"
    "${STANDALONE_ROOT}/core/network/burp/session_handler.cpp"
    "${STANDALONE_ROOT}/core/network/burp/site_map.cpp"
    "${STANDALONE_ROOT}/core/network/cert_generator.cpp"
    "${STANDALONE_ROOT}/core/network/cloud_tools_standalone.cpp"
    "${STANDALONE_ROOT}/core/network/conn_pool.cpp"
    "${STANDALONE_ROOT}/core/network/flow_serializer.cpp"
    "${STANDALONE_ROOT}/core/network/game_protocol.cpp"
    "${STANDALONE_ROOT}/core/network/gameproto_tools_standalone.cpp"
    "${STANDALONE_ROOT}/core/network/http_tools_standalone.cpp"
    "${STANDALONE_ROOT}/core/network/intercept/cert_profile_manager.cpp"
    "${STANDALONE_ROOT}/core/network/intercept/diagnostics.cpp"
    "${STANDALONE_ROOT}/core/network/intercept/instrumentation_provider.cpp"
    "${STANDALONE_ROOT}/core/network/js_analysis_tools_standalone.cpp"
    "${STANDALONE_ROOT}/core/network/map_resource.cpp"
    "${STANDALONE_ROOT}/core/network/mitm_proxy.cpp"
    "${STANDALONE_ROOT}/core/network/net_proto_analysis.cpp"
    "${STANDALONE_ROOT}/core/network/net_proto_tools_standalone.cpp"
    "${STANDALONE_ROOT}/core/network/net_security_tools_standalone.cpp"
    "${STANDALONE_ROOT}/core/network/network_tool_aliases_standalone.cpp"
    "${STANDALONE_ROOT}/core/network/network_tools_standalone.cpp"
    "${STANDALONE_ROOT}/core/network/pac_resolver.cpp"
    "${STANDALONE_ROOT}/core/network/protocol_parser.cpp"
    "${STANDALONE_ROOT}/core/network/quic_proxy.cpp"
    "${STANDALONE_ROOT}/core/network/server_replay.cpp"
    "${STANDALONE_ROOT}/core/network/web_vuln_tools_standalone.cpp"
    "${STANDALONE_ROOT}/core/re/artifact_store.cpp"
    "${STANDALONE_ROOT}/core/re/dx_hook.cpp"
    "${STANDALONE_ROOT}/core/re/encptr.cpp"
    "${STANDALONE_ROOT}/core/re/heap_track.cpp"
    "${STANDALONE_ROOT}/core/re/offsets.cpp"
    "${STANDALONE_ROOT}/core/re/re_common.cpp"
    "${STANDALONE_ROOT}/core/re/rtti.cpp"
    "${STANDALONE_ROOT}/core/re/sigs.cpp"
    "${STANDALONE_ROOT}/core/re/struct_adv.cpp"
    "${STANDALONE_ROOT}/core/re/vmt.cpp"
    "${STANDALONE_ROOT}/core/scanner/memory_scanner.cpp"
    "${STANDALONE_ROOT}/core/scanner/scanner_tools_standalone.cpp"
    "${STANDALONE_ROOT}/core/session/session_store.cpp"
    "${STANDALONE_ROOT}/core/tools/coding_tools_standalone.cpp"
    "${STANDALONE_ROOT}/core/tools/driver_tools_standalone.cpp"
    "${STANDALONE_ROOT}/core/tools/emulation_tools_standalone.cpp"
    "${STANDALONE_ROOT}/core/tools/protected_re_tools_standalone.cpp"
    "${STANDALONE_ROOT}/core/tools/re_tools_standalone.cpp"
    "${STANDALONE_ROOT}/core/tools/script_engine.cpp"
    "${STANDALONE_ROOT}/core/tools/session_tools_standalone.cpp"
    "${STANDALONE_ROOT}/core/tools/workflow_tools_standalone.cpp"
    "${STANDALONE_ROOT}/core/ai/agent_registry.cpp"
    "${STANDALONE_ROOT}/core/ai/standalone_ai_client.cpp"
    "${STANDALONE_ROOT}/core/ai/standalone_chat.cpp"
    "${CMAKE_SOURCE_DIR}/src/emulation_engine.cpp"
    "${CMAKE_SOURCE_DIR}/src/net_security.cpp")

set(AIDA_C03_CAMOUFOX_AUDIT_PRODUCTION_CLOSURE_SOURCES
    "${STANDALONE_ROOT}/core/infra/event_bus.cpp"
    "${STANDALONE_ROOT}/core/network/burp/audit_trail.cpp"
    "${STANDALONE_ROOT}/core/network/burp/camoufox_install.cpp"
    "${STANDALONE_ROOT}/core/network/burp/evidence_store.cpp"
    "${STANDALONE_ROOT}/core/network/burp/findings_db.cpp"
    "${STANDALONE_ROOT}/core/network/burp/vuln_taxonomy.cpp")

set(AIDA_C03_PRODUCTION_STANDALONE_SOURCES
    ${AIDA_C03_MCP_PRODUCTION_CLOSURE_SOURCES}
    "${STANDALONE_ROOT}/core/network/tls_exporter.cpp"
    "${STANDALONE_ROOT}/core/settings/settings_persistence_service.cpp"
    ${AIDA_C03_CAMOUFOX_AUDIT_PRODUCTION_CLOSURE_SOURCES}
    "${STANDALONE_ROOT}/core/ai/agent_manager_service.cpp"
    "${STANDALONE_ROOT}/core/ai/agent_task.cpp"
    "${STANDALONE_ROOT}/core/ai/command_registry.cpp"
    "${STANDALONE_ROOT}/core/ai/conversation_evidence_store.cpp"
    "${STANDALONE_ROOT}/core/ai/provider_catalog.cpp"
    "${STANDALONE_ROOT}/core/ai/provider_transforms.cpp"
    "${STANDALONE_ROOT}/core/ai/skill_manager_service.cpp"
    "${STANDALONE_ROOT}/core/analysis/analysis_budget.cpp"
    "${STANDALONE_ROOT}/core/analysis/analysis_fabric_metrics.cpp"
    "${STANDALONE_ROOT}/core/analysis/analysis_resource_metrics.cpp"
    "${STANDALONE_ROOT}/core/analysis/analysis_scheduler.cpp"
    "${STANDALONE_ROOT}/core/analysis/benchmark/benchmark_runner.cpp"
    "${STANDALONE_ROOT}/core/analysis/call_graph_builder.cpp"
    "${STANDALONE_ROOT}/core/analysis/collection/artifact_collection.cpp"
    "${STANDALONE_ROOT}/core/analysis/collection/member_graph.cpp"
    "${STANDALONE_ROOT}/core/analysis/container/streaming_member_provider.cpp"
    "${STANDALONE_ROOT}/core/analysis/decode/capstone_tile_decoder.cpp"
    "${STANDALONE_ROOT}/core/analysis/decode/x86_tile_decoder.cpp"
    "${STANDALONE_ROOT}/core/analysis/decode_frontier.cpp"
    "${STANDALONE_ROOT}/core/analysis/decode_worker_pool.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/decompile_batch_orchestrator.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/decompiler_cache.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/decompiler_contracts.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/decompiler_provider_registry.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/decompiler_service.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/decompiler_ui_integration.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/legacy_document_adapter.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/managed_entity_binding.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/metadata_provenance.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/native_worker_host.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/providers/cli_provider.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/providers/dalvik_ssa.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/providers/ghidra_ir_adapter.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/providers/jvm_ssa.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/pseudocode_readability.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/pseudocode_renderer.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/semantic_refiner.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/triton_z3_adapter.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/type_graph_builder.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/typed_ast.cpp"
    "${STANDALONE_ROOT}/core/analysis/image_layout_index.cpp"
    "${STANDALONE_ROOT}/core/analysis/incremental_reanalysis.cpp"
    "${STANDALONE_ROOT}/core/analysis/live_request_budget.cpp"
    "${STANDALONE_ROOT}/core/analysis/live_snapshot_provider.cpp"
    "${STANDALONE_ROOT}/core/analysis/mapped_window_cache.cpp"
    "${STANDALONE_ROOT}/core/analysis/overlay_apply_engine.cpp"
    "${STANDALONE_ROOT}/core/analysis/overlay_projection.cpp"
    "${STANDALONE_ROOT}/core/analysis/packed_analysis_store.cpp"
    "${STANDALONE_ROOT}/core/analysis/packed_string_pool.cpp"
    "${STANDALONE_ROOT}/core/analysis/pdb_downloader.cpp"
    "${STANDALONE_ROOT}/core/analysis/provider_snapshot.cpp"
    "${STANDALONE_ROOT}/core/analysis/readers/macho_reader.cpp"
    "${STANDALONE_ROOT}/core/analysis/readers/managed/classfile_reader.cpp"
    "${STANDALONE_ROOT}/core/analysis/readers/managed/cli_metadata_reader.cpp"
    "${STANDALONE_ROOT}/core/analysis/readers/managed/dex_reader.cpp"
    "${STANDALONE_ROOT}/core/analysis/readers/managed/managed_reader_contracts.cpp"
    "${STANDALONE_ROOT}/core/analysis/spill_provider.cpp"
    "${STANDALONE_ROOT}/core/analysis/subrange_provider.cpp"
    "${STANDALONE_ROOT}/core/analysis/tile_decode_orchestrator.cpp"
    "${STANDALONE_ROOT}/core/analysis/working_set_governor.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/baseline_engine_integration.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/c03_analysis_contracts.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/data_discovery.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/decode_materializer.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/paged_fact_staging.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/paged_snapshot_view.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/packed_page_codec.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/publication_indexes.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/query_index.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/regex_query.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/string_arena.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/string_discovery.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/string_discovery_simd_avx2.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/symbol_type_candidates.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/workspace_schema_v9.cpp"
    "${STANDALONE_ROOT}/core/auth/auth_store.cpp"
    "${STANDALONE_ROOT}/core/auth/auth_http.cpp"
    "${STANDALONE_ROOT}/core/auth/auth_codex.cpp"
    "${STANDALONE_ROOT}/core/auth/auth_copilot.cpp"
    "${STANDALONE_ROOT}/core/auth/auth_claude_code.cpp"
    "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_pretty_xml_encode.cpp"
    "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_function_db.cpp"
    "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_arch_map.cpp"
    "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_load_image.cpp"
    "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_pcode_fixup.cpp"
    "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_print_c.cpp"
    "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_scope.cpp"
    "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_architecture.cpp"
    "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_code_xml_parse.cpp"
    "${STANDALONE_ROOT}/core/infra/host_topology.cpp"
    "${STANDALONE_ROOT}/core/infra/allocator.cpp"
    "${STANDALONE_ROOT}/core/mcp/calculator_tool.cpp"
    "${STANDALONE_ROOT}/core/mcp/calculator_engine.cpp"
    "${STANDALONE_ROOT}/core/mcp/ida_compat_mut.cpp"
    "${STANDALONE_ROOT}/core/mcp/ida_compat_read.cpp"
    "${STANDALONE_ROOT}/core/mcp/mcp_standalone.cpp"
    "${STANDALONE_ROOT}/core/mcp/mcp_standalone_tools.cpp"
    "${STANDALONE_ROOT}/core/mcp/protocol/mcp_result.cpp"
    "${STANDALONE_ROOT}/core/mcp/protocol/mcp_tool_contract.cpp"
    "${STANDALONE_ROOT}/core/mcp/protocol/schema_runtime.cpp"
    "${STANDALONE_ROOT}/core/mcp/schema_validator.cpp"
    "${STANDALONE_ROOT}/core/mcp/registry/application_debugger_capability.cpp"
    "${STANDALONE_ROOT}/core/mcp/registry/tool_registry.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/c03_compatibility_registration.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/debugger_lane.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/effect_policy.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/ida_contracts_generated.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/live_routing_integration.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/mcp_server_integration.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/python_worker_host.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/target_resolver.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/workspace_adapter.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/analysis.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/composite.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/core.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/debugger.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/memory.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/modify.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/python.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/routing_extensions.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/signature_operand_mask.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/signatures.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/stack.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/survey.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/types.cpp"
    "${STANDALONE_ROOT}/core/debugger/source_debug_service.cpp"
    "${STANDALONE_ROOT}/core/debugger/debugger_interaction_context.cpp"
    "${STANDALONE_ROOT}/core/network/burp/camoufox_bridge.cpp"
    "${STANDALONE_ROOT}/core/runtime/vm_guest_bridge.cpp"
    "${STANDALONE_ROOT}/core/session/analysis_session.cpp"
    "${STANDALONE_ROOT}/core/session/compaction.cpp"
    "${STANDALONE_ROOT}/core/session/cost_calculator.cpp"
    "${STANDALONE_ROOT}/core/ui/application_action_registry.cpp"
    "${STANDALONE_ROOT}/core/ui/application_ui_runtime.cpp"
    "${STANDALONE_ROOT}/core/ui/analysis_context_menu.cpp"
    "${STANDALONE_ROOT}/core/ui/context_menu_contract.cpp"
    "${STANDALONE_ROOT}/core/ui/imgui_capability_guard.cpp"
    "${STANDALONE_ROOT}/core/ui/interaction_context.cpp"
    "${STANDALONE_ROOT}/core/ui/shortcut_resolver.cpp"
    "${STANDALONE_ROOT}/core/ui/view_registry.cpp"
    "${STANDALONE_ROOT}/core/workbench/adapters/diff_document.cpp"
    "${STANDALONE_ROOT}/core/workbench/adapters/disasm_document.cpp"
    "${STANDALONE_ROOT}/core/workbench/adapters/document_adapter_base.cpp"
    "${STANDALONE_ROOT}/core/workbench/adapters/graph_document.cpp"
    "${STANDALONE_ROOT}/core/workbench/adapters/hex_document.cpp"
    "${STANDALONE_ROOT}/core/workbench/adapters/pseudocode_document.cpp"
    "${STANDALONE_ROOT}/core/workbench/document_registry.cpp"
    "${STANDALONE_ROOT}/core/workbench/inspector/workbench_inspector_contracts.cpp"
    "${STANDALONE_ROOT}/core/workbench/navigator/workbench_navigator.cpp"
    "${STANDALONE_ROOT}/core/workbench/workbench_contracts.cpp"
    "${STANDALONE_ROOT}/core/workbench/workbench_model.cpp"
    "${STANDALONE_ROOT}/core/workbench/workbench_persistence.cpp"
    "${STANDALONE_ROOT}/core/workbench/workbench_shell_integration.cpp"
    "${STANDALONE_ROOT}/core/testlab/test_lab_features_c03_safe_headless.cpp"
    "${STANDALONE_ROOT}/core/analysis/flirt/flirt_engine.cpp"
    "${STANDALONE_ROOT}/core/analysis/flirt/flirt_signature_db.cpp"
    "${STANDALONE_ROOT}/core/analysis/flirt/static_recognition_service.cpp"
    "${STANDALONE_ROOT}/core/analysis/flirt/type_seed_exporter.cpp"
)
list(REMOVE_DUPLICATES AIDA_C03_PRODUCTION_STANDALONE_SOURCES)

set_source_files_properties("${STANDALONE_ROOT}/core/analysis/workspace/string_discovery_simd_avx2.cpp"
    PROPERTIES COMPILE_OPTIONS /arch:AVX2)

set(AIDA_C03_COMPILER_MATRIX_CM_01
    "${STANDALONE_ROOT}/core/analysis/provider_snapshot.cpp"
    "${STANDALONE_ROOT}/core/analysis/mapped_window_cache.cpp"
    "${STANDALONE_ROOT}/core/analysis/subrange_provider.cpp"
    "${STANDALONE_ROOT}/core/analysis/spill_provider.cpp"
    "${STANDALONE_ROOT}/core/analysis/image_layout_index.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/c03_analysis_contracts.cpp")
set(AIDA_C03_COMPILER_MATRIX_CM_02
    "${STANDALONE_ROOT}/core/analysis/packed_analysis_store.cpp"
    "${STANDALONE_ROOT}/core/analysis/packed_string_pool.cpp"
    "${STANDALONE_ROOT}/core/analysis/analysis_budget.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/analysis_workspace.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/workspace_identity.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/workspace_registry.cpp"
    "${STANDALONE_ROOT}/core/session/analysis_session.cpp"
    "${STANDALONE_ROOT}/core/analysis/pdb_downloader.cpp")
set(AIDA_C03_COMPILER_MATRIX_CM_03
    "${STANDALONE_ROOT}/core/analysis/analysis_scheduler.cpp"
    "${STANDALONE_ROOT}/core/analysis/analysis_resource_metrics.cpp"
    "${STANDALONE_ROOT}/core/analysis/analysis_fabric_metrics.cpp"
    "${STANDALONE_ROOT}/core/analysis/benchmark/benchmark_runner.cpp"
    "${STANDALONE_ROOT}/core/analysis/decode/x86_tile_decoder.cpp"
    "${STANDALONE_ROOT}/core/analysis/decode/capstone_tile_decoder.cpp"
    "${STANDALONE_ROOT}/core/analysis/decode_frontier.cpp"
    "${STANDALONE_ROOT}/core/analysis/decode_worker_pool.cpp"
    "${STANDALONE_ROOT}/core/analysis/tile_decode_orchestrator.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/x86_decoder.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/arch_decoder.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/arm_decoder.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/aarch64_decoder.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/mips_decoder.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/ppc_decoder.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/riscv_decoder.cpp"
    "${STANDALONE_ROOT}/core/analysis/call_graph_builder.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/baseline_engine_integration.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/baseline_pipeline.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/function_recovery.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/advanced_cfg.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/calling_convention.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/xref_builder.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/data_discovery.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/decode_materializer.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/paged_fact_staging.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/paged_snapshot_view.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/string_discovery.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/string_discovery_simd_avx2.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/symbol_type_candidates.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/publication_indexes.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/query_index.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/regex_query.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/search_index.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/analysis_metrics.cpp"
    "${STANDALONE_ROOT}/core/analysis/overlay_apply_engine.cpp"
    "${STANDALONE_ROOT}/core/analysis/overlay_projection.cpp"
    "${STANDALONE_ROOT}/core/analysis/incremental_reanalysis.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/patched_export.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/pe_baseline_analyzer.cpp"
    "${STANDALONE_ROOT}/core/analysis/working_set_governor.cpp"
    "${STANDALONE_ROOT}/core/infra/host_topology.cpp"
    "${STANDALONE_ROOT}/core/infra/allocator.cpp"
    )
set(AIDA_C03_COMPILER_MATRIX_CM_04
    "${STANDALONE_ROOT}/core/analysis/readers/pe_coff_reader.cpp"
    "${STANDALONE_ROOT}/core/analysis/readers/elf_reader.cpp"
    "${STANDALONE_ROOT}/core/analysis/readers/macho_reader.cpp"
    "${STANDALONE_ROOT}/core/analysis/readers/managed/classfile_reader.cpp"
    "${STANDALONE_ROOT}/core/analysis/readers/managed/cli_metadata_reader.cpp"
    "${STANDALONE_ROOT}/core/analysis/readers/managed/dex_reader.cpp"
    "${STANDALONE_ROOT}/core/analysis/readers/managed/managed_reader_contracts.cpp"
    "${STANDALONE_ROOT}/core/analysis/container/streaming_member_provider.cpp"
    "${STANDALONE_ROOT}/core/analysis/collection/artifact_collection.cpp"
    "${STANDALONE_ROOT}/core/analysis/collection/member_graph.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/byte_provider.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/pe_image.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/coff_image.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/elf_image.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/macho_image.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/classfile_parser.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/dex_image.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/zip_container.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/apk_container.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/ipa_container.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/jar_container.cpp")
set(AIDA_C03_COMPILER_MATRIX_CM_05
    "${STANDALONE_ROOT}/core/analysis/workspace/workspace_schema_v9.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/packed_page_codec.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/persistence_queue.cpp"
    "${STANDALONE_ROOT}/core/analysis/working_set_metrics.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/workspace_database.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/sqlite_reader_pool.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/overlay_journal.cpp"
    "${STANDALONE_ROOT}/core/analysis/fact_page_cache.cpp"
    "${STANDALONE_ROOT}/core/workbench/workbench_persistence.cpp")
set(AIDA_C03_COMPILER_MATRIX_CM_06
    "${STANDALONE_ROOT}/core/analysis/decompiler/native_worker_host.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/decompiler_contracts.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/providers/ghidra_ir_adapter.cpp"
    "${STANDALONE_ROOT}/../workers/native_decompiler/native_decompiler_worker.cpp"
    "${STANDALONE_ROOT}/../workers/native_decompiler/ghidra_native_provider.cpp"
    "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_pretty_xml_encode.cpp"
    "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_function_db.cpp"
    "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_arch_map.cpp"
    "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_load_image.cpp"
    "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_pcode_fixup.cpp"
    "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_print_c.cpp"
    "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_scope.cpp"
    "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_architecture.cpp"
    "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_code_xml_parse.cpp")
set(AIDA_C03_COMPILER_MATRIX_CM_07
    "${STANDALONE_ROOT}/core/analysis/decompiler/providers/cli_provider.cpp"
    "${STANDALONE_ROOT}/../workers/managed_decompiler/ManagedDecompilerWorker.csproj"
    "${STANDALONE_ROOT}/../workers/managed_decompiler/packages.lock.json"
    "${STANDALONE_ROOT}/../workers/managed_decompiler/NuGet.Config"
    "${AIDA_C03_TEST_ROOT}/managed_cli/ManagedCliFixtures.csproj"
    "${AIDA_C03_TEST_ROOT}/managed_cli/packages.lock.json"
    "${AIDA_C03_TEST_ROOT}/managed_cli/NuGet.Config")
set(AIDA_C03_COMPILER_MATRIX_CM_08
    "${STANDALONE_ROOT}/core/analysis/decompiler/providers/jvm_ssa.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/providers/dalvik_ssa.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/type_graph_builder.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/semantic_refiner.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/triton_z3_adapter.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/typed_ast.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/pseudocode_renderer.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/pseudocode_readability.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/managed_entity_binding.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/metadata_provenance.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/decompiler_feedback.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/semantic_fusion.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/type_recovery.cpp")
set(AIDA_C03_COMPILER_MATRIX_CM_09
    "${STANDALONE_ROOT}/core/analysis/decompiler/decompile_batch_orchestrator.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/decompiler_cache.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/decompiler_provider_registry.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/decompiler_service.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/decompiler_ui_integration.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/legacy_document_adapter.cpp"
    "${STANDALONE_ROOT}/core/workbench/adapters/pseudocode_document.cpp"
    "${STANDALONE_ROOT}/core/disasm/pseudocode_view.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/decompiler_service.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/pseudocode_readability.cpp"
    "${STANDALONE_ROOT}/core/analysis/flirt/flirt_engine.cpp"
    "${STANDALONE_ROOT}/core/analysis/flirt/flirt_signature_db.cpp"
    "${STANDALONE_ROOT}/core/analysis/flirt/static_recognition_service.cpp"
    "${STANDALONE_ROOT}/core/analysis/flirt/type_seed_exporter.cpp")
set(AIDA_C03_COMPILER_MATRIX_CM_10
    "${STANDALONE_ROOT}/core/mcp/protocol/mcp_result.cpp"
    "${STANDALONE_ROOT}/core/mcp/protocol/schema_runtime.cpp"
    "${STANDALONE_ROOT}/core/mcp/protocol/mcp_tool_contract.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/ida_contracts_generated.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/effect_policy.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/target_resolver.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/workspace_adapter.cpp"
    "${STANDALONE_ROOT}/core/mcp/registry/tool_registry.cpp"
    "${STANDALONE_ROOT}/core/mcp/registry/application_debugger_capability.cpp")
set(AIDA_C03_COMPILER_MATRIX_CM_11
    ${AIDA_C03_MCP_PRODUCTION_CLOSURE_SOURCES}
    "${STANDALONE_ROOT}/core/analysis/workspace/string_arena.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/c03_compatibility_registration.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/mcp_server_integration.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/analysis.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/composite.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/core.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/debugger.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/memory.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/modify.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/python.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/routing_extensions.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/signature_operand_mask.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/signatures.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/stack.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/survey.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/types.cpp"
    "${STANDALONE_ROOT}/core/mcp/ida_compat_read.cpp"
    "${STANDALONE_ROOT}/core/mcp/ida_compat_mut.cpp"
    "${STANDALONE_ROOT}/core/mcp/calculator_tool.cpp"
    "${STANDALONE_ROOT}/core/mcp/calculator_engine.cpp"
    "${STANDALONE_ROOT}/core/mcp/schema_validator.cpp"
    "${STANDALONE_ROOT}/core/mcp/mcp_standalone.cpp"
    "${STANDALONE_ROOT}/core/mcp/mcp_standalone_tools.cpp")
set(AIDA_C03_COMPILER_MATRIX_CM_12
    "${STANDALONE_ROOT}/core/runtime/vm_guest_bridge.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/debugger_lane.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/python_worker_host.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/live_routing_integration.cpp"
    "${STANDALONE_ROOT}/core/analysis/live_request_budget.cpp"
    "${STANDALONE_ROOT}/core/analysis/live_snapshot_provider.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/live_snapshot_provider.cpp"
    "${STANDALONE_ROOT}/core/debugger/debugger_engine.cpp"
    "${STANDALONE_ROOT}/core/debugger/source_debug_service.cpp"
    "${STANDALONE_ROOT}/core/runtime/standalone_driver.cpp")
set(AIDA_C03_COMPILER_MATRIX_CM_13
    "${STANDALONE_ROOT}/main.cpp"
    "${STANDALONE_ROOT}/helpers/helpers.cpp"
    "${STANDALONE_ROOT}/core/ai/agent_manager_service.cpp"
    "${STANDALONE_ROOT}/core/ai/agent_registry.cpp"
    "${STANDALONE_ROOT}/core/ai/agent_task.cpp"
    "${STANDALONE_ROOT}/core/ai/command_registry.cpp"
    "${STANDALONE_ROOT}/core/ai/conversation_evidence_store.cpp"
    "${STANDALONE_ROOT}/core/ai/provider_transforms.cpp"
    "${STANDALONE_ROOT}/core/ai/skill_manager_service.cpp"
    "${STANDALONE_ROOT}/core/ai/standalone_ai_client.cpp"
    "${STANDALONE_ROOT}/core/ai/standalone_chat.cpp"
    "${STANDALONE_ROOT}/core/session/compaction.cpp"
    "${STANDALONE_ROOT}/core/session/cost_calculator.cpp"
    "${STANDALONE_ROOT}/core/debugger/thread_intel.cpp"
    "${STANDALONE_ROOT}/core/debugger/debugger_interaction_context.cpp"
    "${STANDALONE_ROOT}/core/ui/application_action_registry.cpp"
    "${STANDALONE_ROOT}/core/ui/application_ui_runtime.cpp"
    "${STANDALONE_ROOT}/core/ui/analysis_context_menu.cpp"
    "${STANDALONE_ROOT}/core/ui/context_menu_contract.cpp"
    "${STANDALONE_ROOT}/core/ui/imgui_capability_guard.cpp"
    "${STANDALONE_ROOT}/core/ui/interaction_context.cpp"
    "${STANDALONE_ROOT}/core/ui/shortcut_resolver.cpp"
    "${STANDALONE_ROOT}/core/ui/view_registry.cpp"
    "${STANDALONE_ROOT}/core/workbench/adapters/diff_document.cpp"
    "${STANDALONE_ROOT}/core/workbench/adapters/disasm_document.cpp"
    "${STANDALONE_ROOT}/core/workbench/adapters/document_adapter_base.cpp"
    "${STANDALONE_ROOT}/core/workbench/adapters/graph_document.cpp"
    "${STANDALONE_ROOT}/core/workbench/adapters/hex_document.cpp"
    "${STANDALONE_ROOT}/core/workbench/document_registry.cpp"
    "${STANDALONE_ROOT}/core/workbench/inspector/workbench_inspector_contracts.cpp"
    "${STANDALONE_ROOT}/core/workbench/navigator/workbench_navigator.cpp"
    "${STANDALONE_ROOT}/core/workbench/workbench_contracts.cpp"
    "${STANDALONE_ROOT}/core/workbench/workbench_model.cpp"
    "${STANDALONE_ROOT}/core/workbench/workbench_shell_integration.cpp")
set(AIDA_C03_COMPILER_MATRIX_CM_14
    "${STANDALONE_ROOT}/core/testlab/test_lab_features_c03_safe_headless.cpp"
    "${STANDALONE_ROOT}/core/testlab/test_lab_registry.cpp"
    "${STANDALONE_ROOT}/core/testlab/test_lab_view.cpp"
    "${STANDALONE_ROOT}/core/testlab/test_all_disasm.cpp"
    "${STANDALONE_ROOT}/core/testlab/test_all_ui.cpp"
    "${STANDALONE_ROOT}/core/testlab/test_all_features.cpp"
    "${STANDALONE_ROOT}/core/testlab/test_all_mcp.cpp"
    "${AIDA_C03_TEST_ROOT}/harness_testlab_integration.cpp"
    "${AIDA_C03_TEST_ROOT}/testlab_runtime/result_adapter.cpp"
    "${AIDA_C03_TEST_ROOT}/testlab_runtime/safe_headless_driver_bridge.cpp"
    "${AIDA_C03_TEST_ROOT}/testlab_runtime/safe_headless_emulation_bridge.cpp"
    "${AIDA_C03_TEST_ROOT}/testlab_runtime/safe_headless_runtime_bridges.cpp"
    "${AIDA_C03_SAFE_HEADLESS_ASSERTION_INVENTORY}"
    "${AIDA_C03_SAFE_HEADLESS_RESOURCE_POLICY_CASES}"
    "${DEPS_DIR}/sqlite-amalgamation-3530300/sqlite3.c"
    "${CMAKE_SOURCE_DIR}/driver/syscall.asm"
    "${STANDALONE_ROOT}/resources/aida_embedded.rc.in")
set(AIDA_C03_COMPILER_MATRIX_CM_15
    "${STANDALONE_ROOT}/core/network/tls_exporter.cpp"
    "${STANDALONE_ROOT}/core/settings/settings_persistence_service.cpp"
    ${AIDA_C03_CAMOUFOX_AUDIT_PRODUCTION_CLOSURE_SOURCES}
    "${STANDALONE_ROOT}/core/auth/auth_store.cpp"
    "${STANDALONE_ROOT}/core/auth/auth_http.cpp"
    "${STANDALONE_ROOT}/core/auth/auth_codex.cpp"
    "${STANDALONE_ROOT}/core/auth/auth_copilot.cpp"
    "${STANDALONE_ROOT}/core/auth/auth_claude_code.cpp"
    "${STANDALONE_ROOT}/core/ai/provider_catalog.cpp"
    "${STANDALONE_ROOT}/core/analysis/surface_reconciliation.cpp"
    "${AIDA_C03_TEST_ROOT}/managed_decompiler_consumers/managed_decompiler_consumers_harness.cpp"
    "${AIDA_C03_TEST_ROOT}/managed_publication_persistence/managed_publication_persistence_harness.cpp"
    "${AIDA_C03_TEST_ROOT}/auth_browser_dispatch/auth_browser_dispatch_harness.cpp"
    "${AIDA_C03_TEST_ROOT}/surface_reconciliation_harness.cpp"
    "${CMAKE_SOURCE_DIR}/src/emulation_engine.cpp"
    "${STANDALONE_ROOT}/core/network/burp/camoufox_bridge.cpp"
    "${STANDALONE_ROOT}/core/network/burp/offensive/auth_attack_engine.cpp"
    "${STANDALONE_ROOT}/core/network/burp/offensive/business_logic_engine.cpp"
    "${STANDALONE_ROOT}/core/network/burp/offensive/js_analysis_engine.cpp"
    "${STANDALONE_ROOT}/core/network/burp/offensive/offensive_auth_attack.cpp"
    "${STANDALONE_ROOT}/core/network/burp/offensive/offensive_business_logic.cpp"
    "${STANDALONE_ROOT}/core/network/burp/offensive/recon_engine.cpp"
    "${STANDALONE_ROOT}/core/network/burp/offensive/sqli_engine.cpp"
    "${STANDALONE_ROOT}/core/network/burp/offensive/xss_engine.cpp"
    "${STANDALONE_ROOT}/core/network/burp/tls_analyzer.cpp"
    "${STANDALONE_ROOT}/core/network/http_tools_standalone.cpp"
    "${STANDALONE_ROOT}/core/network/net_proto_analysis.cpp"
    "${STANDALONE_ROOT}/core/network/network_tool_aliases_standalone.cpp"
    "${STANDALONE_ROOT}/core/tools/coding_tools_standalone.cpp"
    "${STANDALONE_ROOT}/core/tools/session_tools_standalone.cpp"
    "${STANDALONE_ROOT}/core/tools/workflow_tools_standalone.cpp"
    "${CMAKE_SOURCE_DIR}/CMakeLists.txt"
    "${CMAKE_SOURCE_DIR}/cmake/aida_c03_dependencies.cmake"
    "${AIDA_C03_SAFE_HEADLESS_CMAKE_MODULE}"
    "${AIDA_C03_PATH_POLICY_MODULE}"
    "${AIDA_C03_PATH_IDENTITY_POLICY}")
set(AIDA_C03_COMPILER_MATRIX_UNION)
foreach(_aida_matrix_suffix IN ITEMS 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15)
    list(APPEND AIDA_C03_COMPILER_MATRIX_UNION ${AIDA_C03_COMPILER_MATRIX_CM_${_aida_matrix_suffix}})
endforeach()
list(REMOVE_DUPLICATES AIDA_C03_COMPILER_MATRIX_UNION)

set(AIDA_C03_HARNESS_SUPPORT_SOURCES
    "${STANDALONE_ROOT}/core/analysis/fact_page_cache.cpp"
    "${STANDALONE_ROOT}/core/analysis/surface_reconciliation.cpp"
    "${STANDALONE_ROOT}/core/analysis/working_set_metrics.cpp"
    "${STANDALONE_ROOT}/core/analysis/working_set_governor.cpp"
    "${STANDALONE_ROOT}/core/analysis/readers/elf_reader.cpp"
    "${STANDALONE_ROOT}/core/analysis/readers/pe_coff_reader.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/advanced_cfg.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/byte_provider.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/calling_convention.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/function_recovery.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/live_snapshot_provider.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/overlay_journal.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/persistence_queue.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/search_index.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/sqlite_reader_pool.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/workspace_database.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/workspace_identity.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/xref_builder.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/zip_container.cpp"
    "${STANDALONE_ROOT}/core/testlab/test_lab_registry.cpp"
    "${AIDA_C03_TEST_ROOT}/testlab_runtime/safe_headless_driver_bridge.cpp"
    "${AIDA_C03_TEST_ROOT}/testlab_runtime/safe_headless_runtime_bridges.cpp"
    "${DEPS_DIR}/sqlite-amalgamation-3530300/sqlite3.c"
)
set(AIDA_C03_WORKSPACE_HARNESS_SUPPORT_SOURCES
    "${STANDALONE_ROOT}/core/analysis/workspace/aarch64_decoder.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/analysis_metrics.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/analysis_workspace.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/apk_container.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/arch_decoder.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/arm_decoder.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/baseline_pipeline.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/classfile_parser.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/coff_image.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/decompiler_feedback.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/decompiler_service.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/dex_image.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/elf_image.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/ipa_container.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/jar_container.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/macho_image.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/mips_decoder.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/patched_export.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/pe_baseline_analyzer.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/pe_image.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/ppc_decoder.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/pseudocode_readability.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/riscv_decoder.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/semantic_fusion.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/type_recovery.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/workspace_registry.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/x86_decoder.cpp"
)

function(aida_c03_require_sources descriptor)
    if(NOT ARGN)
        message(WARNING "AiDA C03 source list is empty: ${descriptor}")
    endif()
    foreach(_aida_source IN LISTS ARGN)
        if(NOT IS_ABSOLUTE "${_aida_source}" OR NOT EXISTS "${_aida_source}" OR IS_DIRECTORY "${_aida_source}")
            message(WARNING "AiDA C03 source is absent or invalid: ${descriptor} -> ${_aida_source}")
        endif()
    endforeach()
endfunction()

aida_c03_require_sources("production registration" ${AIDA_C03_PRODUCTION_STANDALONE_SOURCES})
aida_c03_require_sources("safe-headless support" ${AIDA_C03_HARNESS_SUPPORT_SOURCES})
aida_c03_require_sources("workspace safe-headless support" ${AIDA_C03_WORKSPACE_HARNESS_SUPPORT_SOURCES})
aida_c03_require_sources("safe-headless assertion inventory" "${AIDA_C03_SAFE_HEADLESS_ASSERTION_INVENTORY}")
aida_c03_require_sources("safe-headless target resource policy cases" "${AIDA_C03_SAFE_HEADLESS_RESOURCE_POLICY_CASES}")

function(aida_c03_configure_native_target target)
    target_include_directories(${target} PRIVATE
        "${CMAKE_CURRENT_BINARY_DIR}/generated"
        "${AIDA_C03_SAFE_HEADLESS_GENERATED_ROOT}"
        "${STANDALONE_ROOT}"
        "${STANDALONE_ROOT}/core"
        "${STANDALONE_ROOT}/core/analysis"
        "${STANDALONE_ROOT}/core/analysis/workspace"
        "${STANDALONE_ROOT}/core/analysis/decompiler"
        "${STANDALONE_ROOT}/core/disasm"
        "${STANDALONE_ROOT}/core/infra"
        "${STANDALONE_ROOT}/core/runtime"
        "${STANDALONE_ROOT}/core/mcp"
        "${STANDALONE_ROOT}/core/mcp/compat"
        "${STANDALONE_ROOT}/core/settings"
        "${STANDALONE_ROOT}/core/ui"
        "${STANDALONE_ROOT}/core/workbench"
        "${AIDA_C03_TEST_ROOT}"
        "${AIDA_C03_MCP_TEST_ROOT}"
        "${CMAKE_CURRENT_SOURCE_DIR}/libs"
        "${CMAKE_CURRENT_SOURCE_DIR}/libs/cpp-httplib"
        "${DEPS_DIR}/sqlite-amalgamation-3530300"
        "${zlib_SOURCE_DIR}"
        "${zlib_BINARY_DIR}"
        "${zstd_SOURCE_DIR}/../../lib"
        "${xz_SOURCE_DIR}/src/liblzma/api"
        "${zydis_SOURCE_DIR}/include"
        "${zydis_SOURCE_DIR}/dependencies/zycore/include"
        "${zydis_BINARY_DIR}"
        "${zydis_BINARY_DIR}/zycore"
        "${capstone_SOURCE_DIR}/include"
        "${json_schema_validator_SOURCE_DIR}/src"
        "${CMAKE_BINARY_DIR}/_imgui_wrapper"
        "${imgui_SOURCE_DIR}"
        "${GHIDRA_DECOMP_DIR}"
        "${OPENSSL_INCLUDE_DIR}"
        "${Z3_INCLUDE_DIRS}"
    )
    target_include_directories(${target} SYSTEM PRIVATE "${DEPS_DIR}/taskflow"
        "${parallel_hashmap_SOURCE_DIR}" "${concurrentqueue_SOURCE_DIR}")
    target_compile_definitions(${target} PRIVATE
        __NT__ _CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN UNICODE _UNICODE AIDA_STANDALONE
        LZMA_API_STATIC
        GHIDRA_SPECS_DIR=${GHIDRA_SPECS_OUTPUT_DIR}
    )
    target_compile_options(${target} PRIVATE
        /W3 /Zp8 /bigobj
        "$<$<COMPILE_LANGUAGE:CXX>:/EHsc>"
        "$<$<COMPILE_LANGUAGE:CXX>:/Zc:__cplusplus>"
        "$<$<COMPILE_LANGUAGE:CXX>:/permissive->")
    if(TARGET aida_hardening)
        target_link_libraries(${target} PRIVATE aida_hardening)
    endif()
    set_target_properties(${target} PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED YES
        CXX_EXTENSIONS NO
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
    )
endfunction()

function(aida_c03_json_quote output value)
    string(REPLACE "\\" "\\\\" _aida_value "${value}")
    string(REPLACE "\"" "\\\"" _aida_value "${_aida_value}")
    string(REPLACE "\n" "\\n" _aida_value "${_aida_value}")
    string(REPLACE "\r" "\\r" _aida_value "${_aida_value}")
    set(${output} "\"${_aida_value}\"" PARENT_SCOPE)
endfunction()

function(aida_c03_json_array output)
    set(_aida_items)
    foreach(_aida_item IN LISTS ARGN)
        aida_c03_json_quote(_aida_quoted "${_aida_item}")
        list(APPEND _aida_items "${_aida_quoted}")
    endforeach()
    string(JOIN "," _aida_joined ${_aida_items})
    set(${output} "[${_aida_joined}]" PARENT_SCOPE)
endfunction()

function(aida_c03_repository_relative output source)
    cmake_path(ABSOLUTE_PATH source NORMALIZE OUTPUT_VARIABLE _aida_absolute)
    cmake_path(IS_PREFIX CMAKE_SOURCE_DIR "${_aida_absolute}" NORMALIZE _aida_inside)
    if(_aida_inside)
        file(RELATIVE_PATH _aida_relative "${CMAKE_SOURCE_DIR}" "${_aida_absolute}")
        string(REPLACE "\\" "/" _aida_relative "${_aida_relative}")
    else()
        message(WARNING "AiDA C03 manifest source escapes the repository: ${_aida_absolute}")
    endif()
    set(${output} "${_aida_relative}" PARENT_SCOPE)
endfunction()

function(aida_c03_stage_runtime_file source relative)
    if(NOT IS_ABSOLUTE "${source}" OR NOT EXISTS "${source}" OR IS_DIRECTORY "${source}")
        message(WARNING "AiDA C03 runtime source is invalid: ${source}")
    endif()
    if(relative MATCHES "(^|/)\\.\\.(/|$)" OR IS_ABSOLUTE "${relative}")
        message(WARNING "AiDA C03 runtime destination is invalid: ${relative}")
    endif()
    string(REPLACE "\\" "/" _aida_relative "${relative}")
    get_property(_aida_registered GLOBAL PROPERTY AIDA_C03_RUNTIME_RELATIVE_PATHS)
    string(SHA256 _aida_runtime_key "${_aida_relative}")
    if(_aida_relative IN_LIST _aida_registered)
        get_property(_aida_prior_source GLOBAL PROPERTY "AIDA_C03_RUNTIME_SOURCE_${_aida_runtime_key}")
        if(NOT _aida_prior_source STREQUAL "${source}")
            message(WARNING "AiDA C03 runtime destination collision: ${_aida_relative}")
        endif()
        return()
    endif()
    set(_aida_output "${AIDA_C03_SAFE_HEADLESS_STAGE_ROOT}/${_aida_relative}")
    cmake_path(GET _aida_output PARENT_PATH _aida_parent)
    add_custom_command(OUTPUT "${_aida_output}"
        COMMAND ${CMAKE_COMMAND} -E make_directory "${_aida_parent}"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different "${source}" "${_aida_output}"
        DEPENDS "${source}"
        VERBATIM)
    set_property(GLOBAL APPEND PROPERTY AIDA_C03_RUNTIME_RELATIVE_PATHS "${_aida_relative}")
    set_property(GLOBAL APPEND PROPERTY AIDA_C03_RUNTIME_OUTPUTS "${_aida_output}")
    set_property(GLOBAL PROPERTY "AIDA_C03_RUNTIME_SOURCE_${_aida_runtime_key}" "${source}")
endfunction()

function(aida_c03_stage_runtime_tree source_root relative_root output)
    file(GLOB_RECURSE _aida_files CONFIGURE_DEPENDS LIST_DIRECTORIES FALSE "${source_root}/*")
    set(_aida_relatives)
    foreach(_aida_file IN LISTS _aida_files)
        file(RELATIVE_PATH _aida_leaf "${source_root}" "${_aida_file}")
        string(REPLACE "\\" "/" _aida_leaf "${_aida_leaf}")
        set(_aida_relative "${relative_root}/${_aida_leaf}")
        aida_c03_stage_runtime_file("${_aida_file}" "${_aida_relative}")
        list(APPEND _aida_relatives "${_aida_relative}")
    endforeach()
    set(${output} "${_aida_relatives}" PARENT_SCOPE)
endfunction()

function(aida_c03_copy_z3_runtime_dlls target)
    set(_aida_z3_dlls)
    foreach(_aida_z3_dll_name IN LISTS AIDA_Z3_RUNTIME_DLL_NAMES)
        list(APPEND _aida_z3_dlls "${Z3_INSTALL_DIR}/bin/${_aida_z3_dll_name}")
    endforeach()
    add_custom_command(TARGET ${target} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${_aida_z3_dlls}
            "$<TARGET_FILE_DIR:${target}>"
        COMMAND_EXPAND_LISTS
        COMMENT "Staging Z3 runtime DLLs for ${target}..."
        VERBATIM
    )
endfunction()

function(aida_c03_register_manifest_entry)
    cmake_parse_arguments(PARSE_ARGV 0 _aida "ARGS_ENTRY" "TARGET;PACKAGE;ENTRY_DEFINITION;OUTPUT_NAME;MAX_ACTIVE_PROCESSES;MAX_WALL_MS" "SOURCES;ARGUMENTS;RUNTIME_FILES;LINK_LIBRARIES;INCLUDE_DIRECTORIES;COMPILE_DEFINITIONS;SOURCE_RECORDS")
    if(_aida_UNPARSED_ARGUMENTS OR _aida_KEYWORDS_MISSING_VALUES OR
       NOT _aida_TARGET OR NOT _aida_PACKAGE OR NOT _aida_SOURCES)
        message(WARNING "AiDA C03 adapted manifest entry is malformed: ${_aida_TARGET}")
    endif()
    if(NOT _aida_TARGET MATCHES "^aida_c03_[a-z0-9_]+$" OR TARGET "${_aida_TARGET}")
        message(WARNING "AiDA C03 adapted manifest target is invalid or duplicated: ${_aida_TARGET}")
    endif()
    if("${_aida_MAX_ACTIVE_PROCESSES}" STREQUAL "")
        set(_aida_MAX_ACTIVE_PROCESSES 1)
    endif()
    if("${_aida_MAX_WALL_MS}" STREQUAL "")
        set(_aida_MAX_WALL_MS 120000)
    endif()
    if(NOT "${_aida_MAX_ACTIVE_PROCESSES}" MATCHES "^[1-4]$")
        message(WARNING "AiDA C03 adapted manifest active-process limit is invalid: ${_aida_TARGET}")
    endif()
    if(NOT "${_aida_MAX_WALL_MS}" MATCHES "^[0-9]+$")
        message(WARNING "AiDA C03 adapted manifest wall limit is invalid: ${_aida_TARGET}")
    endif()
    if(_aida_TARGET STREQUAL "aida_c03_a06_decompiler_quality_scorer_harness")
        if(NOT _aida_MAX_ACTIVE_PROCESSES EQUAL 4)
            message(WARNING "AiDA C03 quality provider matrix requires the exact four-process containment bound")
        endif()
        if(NOT _aida_MAX_WALL_MS EQUAL 1800000)
            message(WARNING "AiDA C03 quality provider matrix requires the exact thirty-minute wall bound")
        endif()
    elseif(NOT _aida_MAX_ACTIVE_PROCESSES EQUAL 1)
        message(WARNING "AiDA C03 ordinary safe-headless entries require single-process containment: ${_aida_TARGET}")
    elseif(NOT _aida_MAX_WALL_MS EQUAL 120000)
        message(WARNING "AiDA C03 ordinary safe-headless entries require the exact two-minute wall bound: ${_aida_TARGET}")
    endif()
    aida_c03_require_sources("${_aida_PACKAGE}/${_aida_TARGET}" ${_aida_SOURCES})
    set(_aida_payload "${_aida_TARGET}_payload")
    add_library(${_aida_payload} OBJECT ${_aida_SOURCES})
    aida_c03_configure_native_target(${_aida_payload})
    target_compile_definitions(${_aida_payload} PRIVATE main=aida_c03_harness_entry)
    if(_aida_ENTRY_DEFINITION)
        target_compile_definitions(${_aida_payload} PRIVATE "${_aida_ENTRY_DEFINITION}")
    endif()
    if(_aida_COMPILE_DEFINITIONS)
        target_compile_definitions(${_aida_payload} PRIVATE ${_aida_COMPILE_DEFINITIONS})
    endif()
    if(_aida_INCLUDE_DIRECTORIES)
        target_include_directories(${_aida_payload} PRIVATE ${_aida_INCLUDE_DIRECTORIES})
    endif()
    if(_aida_ARGS_ENTRY)
        set(_aida_adapter "${AIDA_C03_TEST_ROOT}/testlab_runtime/adapter_main_args.cpp")
    else()
        set(_aida_adapter "${AIDA_C03_TEST_ROOT}/testlab_runtime/adapter_main_noargs.cpp")
    endif()
    add_executable(${_aida_TARGET}
        "${_aida_adapter}"
        "${AIDA_C03_TEST_ROOT}/testlab_runtime/result_adapter.cpp"
        $<TARGET_OBJECTS:${_aida_payload}>)
    aida_c03_configure_native_target(${_aida_TARGET})
    target_link_libraries(${_aida_TARGET} PRIVATE aida_c03_safe_headless_runtime ${_aida_LINK_LIBRARIES})
    if(_aida_OUTPUT_NAME)
        set(_aida_output_name "${_aida_OUTPUT_NAME}")
    else()
        set(_aida_output_name "${_aida_TARGET}")
    endif()
    set_target_properties(${_aida_TARGET} PROPERTIES
        OUTPUT_NAME "${_aida_output_name}"
        RUNTIME_OUTPUT_DIRECTORY "${AIDA_C03_SAFE_HEADLESS_STAGE_ROOT}/bin"
        RUNTIME_OUTPUT_DIRECTORY_DEBUG "${AIDA_C03_SAFE_HEADLESS_STAGE_ROOT}/bin"
        RUNTIME_OUTPUT_DIRECTORY_RELEASE "${AIDA_C03_SAFE_HEADLESS_STAGE_ROOT}/bin"
        RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${AIDA_C03_SAFE_HEADLESS_STAGE_ROOT}/bin"
        PDB_OUTPUT_DIRECTORY "${AIDA_C03_SAFE_HEADLESS_STAGE_ROOT}/symbols"
        FOLDER "Tests/C03/SafeHeadless/Manifest"
        AIDA_C03_PACKAGE "${_aida_PACKAGE}"
        AIDA_C03_SAFE_HEADLESS TRUE
        LABELS "c03;c03_safe_headless;safe-headless;${_aida_PACKAGE}"
    )
    if(_aida_SOURCE_RECORDS)
        set(_aida_source_records ${_aida_SOURCE_RECORDS})
    else()
        set(_aida_source_records)
        foreach(_aida_source IN LISTS _aida_SOURCES)
            aida_c03_repository_relative(_aida_relative "${_aida_source}")
            list(APPEND _aida_source_records "${_aida_relative}")
        endforeach()
    endif()
    list(REMOVE_DUPLICATES _aida_source_records)
    list(REMOVE_DUPLICATES _aida_RUNTIME_FILES)
    aida_c03_json_quote(_aida_target_json "${_aida_TARGET}")
    aida_c03_json_quote(_aida_executable_json "bin/${_aida_output_name}.exe")
    aida_c03_json_array(_aida_arguments_json ${_aida_ARGUMENTS})
    aida_c03_json_array(_aida_sources_json ${_aida_source_records})
    aida_c03_json_array(_aida_runtime_json ${_aida_RUNTIME_FILES})
    set(_aida_record "{\"source_target\":${_aida_target_json},\"executable_relative_path\":${_aida_executable_json},\"working_directory_relative_path\":\".\",\"arguments\":${_aida_arguments_json},\"source_files\":${_aida_sources_json},\"runtime_files\":${_aida_runtime_json},\"max_active_processes\":${_aida_MAX_ACTIVE_PROCESSES},\"max_wall_ms\":${_aida_MAX_WALL_MS}}")
    set_property(GLOBAL APPEND PROPERTY AIDA_C03_MANIFEST_TARGET_RECORDS "${_aida_record}")
    set_property(GLOBAL APPEND PROPERTY AIDA_C03_MANIFEST_TARGETS "${_aida_TARGET}")
    set_property(GLOBAL APPEND PROPERTY AIDA_C03_COMPILER_MATRIX_HARNESS_INPUTS
        ${_aida_SOURCES} "${_aida_adapter}" "${AIDA_C03_TEST_ROOT}/testlab_runtime/result_adapter.cpp")
    aida_c03_copy_z3_runtime_dlls(${_aida_TARGET})
endfunction()

function(aida_c03_register_direct_test)
    cmake_parse_arguments(PARSE_ARGV 0 _aida "NO_SHARED_RUNTIME" "TARGET;PACKAGE;TIMEOUT" "SOURCES;ARGUMENTS;LINK_LIBRARIES;INCLUDE_DIRECTORIES;COMPILE_DEFINITIONS;DEPENDS")
    if(_aida_UNPARSED_ARGUMENTS OR _aida_KEYWORDS_MISSING_VALUES OR
       NOT _aida_TARGET OR NOT _aida_PACKAGE OR NOT _aida_SOURCES)
        message(WARNING "AiDA C03 direct safe-headless test is malformed: ${_aida_TARGET}")
    endif()
    if(TARGET "${_aida_TARGET}")
        message(WARNING "AiDA C03 direct safe-headless target is duplicated: ${_aida_TARGET}")
    endif()
    aida_c03_require_sources("${_aida_PACKAGE}/${_aida_TARGET}" ${_aida_SOURCES})
    add_executable(${_aida_TARGET} ${_aida_SOURCES})
    aida_c03_configure_native_target(${_aida_TARGET})
    if(_aida_NO_SHARED_RUNTIME)
        if(NOT _aida_LINK_LIBRARIES)
            message(WARNING "AiDA C03 isolated direct target requires an explicit implementation graph: ${_aida_TARGET}")
        endif()
        target_link_libraries(${_aida_TARGET} PRIVATE ${_aida_LINK_LIBRARIES})
    else()
        target_link_libraries(${_aida_TARGET} PRIVATE aida_c03_safe_headless_runtime ${_aida_LINK_LIBRARIES})
    endif()
    if(_aida_INCLUDE_DIRECTORIES)
        target_include_directories(${_aida_TARGET} PRIVATE ${_aida_INCLUDE_DIRECTORIES})
    endif()
    if(_aida_COMPILE_DEFINITIONS)
        target_compile_definitions(${_aida_TARGET} PRIVATE ${_aida_COMPILE_DEFINITIONS})
    endif()
    if(_aida_DEPENDS)
        add_dependencies(${_aida_TARGET} ${_aida_DEPENDS})
    endif()
    set_target_properties(${_aida_TARGET} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${AIDA_C03_DEVELOPER_ROOT}/direct/$<CONFIG>"
        FOLDER "Tests/C03/SafeHeadless/Direct"
        AIDA_C03_PACKAGE "${_aida_PACKAGE}"
        AIDA_C03_SAFE_HEADLESS TRUE
        LABELS "c03;c03_safe_headless;safe-headless;direct;${_aida_PACKAGE}")
    if(NOT _aida_TIMEOUT)
        set(_aida_TIMEOUT 120)
    endif()
    add_test(NAME ${_aida_TARGET} COMMAND $<TARGET_FILE:${_aida_TARGET}> ${_aida_ARGUMENTS})
    set_tests_properties(${_aida_TARGET} PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        TIMEOUT "${_aida_TIMEOUT}"
        LABELS "c03;c03_safe_headless;safe-headless;direct;${_aida_PACKAGE}"
        RESOURCE_LOCK "aida_c03_safe_headless_direct")
    set_property(GLOBAL APPEND PROPERTY AIDA_C03_DIRECT_TARGETS "${_aida_TARGET}")
    set_property(GLOBAL APPEND PROPERTY AIDA_C03_COMPILER_MATRIX_HARNESS_INPUTS ${_aida_SOURCES})
    if(NOT _aida_NO_SHARED_RUNTIME)
        aida_c03_copy_z3_runtime_dlls(${_aida_TARGET})
    endif()
endfunction()

function(aida_c03_register_worker_targets application_target)
    if(NOT TARGET "${application_target}")
        message(WARNING "AiDA C03 worker registration requires the standalone target")
    endif()
    if(TARGET aida_c03_b14_native_decompiler_worker OR TARGET aida_c03_b16_managed_decompiler_worker)
        message(WARNING "AiDA C03 worker targets were registered more than once")
    endif()
    if(NOT Python3_Interpreter_FOUND)
        find_package(Python3 COMPONENTS Interpreter)
    endif()
    set(_aida_native_sources
        "${STANDALONE_ROOT}/../workers/native_decompiler/native_decompiler_worker.cpp"
        "${STANDALONE_ROOT}/../workers/native_decompiler/ghidra_native_provider.cpp"
        "${STANDALONE_ROOT}/core/analysis/decompiler/decompiler_contracts.cpp"
        "${STANDALONE_ROOT}/core/analysis/decompiler/legacy_document_adapter.cpp"
        "${STANDALONE_ROOT}/core/analysis/decompiler/providers/dalvik_ssa.cpp"
        "${STANDALONE_ROOT}/core/analysis/decompiler/providers/ghidra_ir_adapter.cpp"
        "${STANDALONE_ROOT}/core/analysis/decompiler/providers/jvm_ssa.cpp"
        "${STANDALONE_ROOT}/core/analysis/decompiler/pseudocode_readability.cpp"
        "${STANDALONE_ROOT}/core/analysis/decompiler/pseudocode_renderer.cpp"
        "${STANDALONE_ROOT}/core/analysis/decompiler/typed_ast.cpp"
        "${STANDALONE_ROOT}/core/analysis/decompiler/type_graph_builder.cpp"
        "${STANDALONE_ROOT}/core/analysis/decompiler/metadata_provenance.cpp"
        "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_pretty_xml_encode.cpp"
        "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_function_db.cpp"
        "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_load_image.cpp"
        "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_pcode_fixup.cpp"
        "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_print_c.cpp"
        "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_scope.cpp"
        "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_architecture.cpp"
        "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_code_xml_parse.cpp"
        "${STANDALONE_ROOT}/core/infra/allocator.cpp"
        "${STANDALONE_ROOT}/core/infra/host_topology.cpp"
        "${STANDALONE_ROOT}/core/analysis/workspace/workspace_identity.cpp")
    aida_c03_require_sources("B14 native decompiler worker" ${_aida_native_sources})
    add_executable(aida_c03_b14_native_decompiler_worker ${_aida_native_sources})
    aida_c03_configure_native_target(aida_c03_b14_native_decompiler_worker)
    target_compile_definitions(aida_c03_b14_native_decompiler_worker PRIVATE
        AIDA_C03_ISOLATED_NATIVE_DECOMPILER_WORKER=1)
    target_link_libraries(aida_c03_b14_native_decompiler_worker PRIVATE libdecomp_aida bcrypt advapi32 userenv ws2_32 zlibstatic mimalloc-static)
    target_include_directories(aida_c03_b14_native_decompiler_worker PRIVATE ${DEPS_DIR}/mimalloc/include)
    target_link_options(aida_c03_b14_native_decompiler_worker PRIVATE /ENTRY:wmainCRTStartup)
    set_target_properties(aida_c03_b14_native_decompiler_worker PROPERTIES
        OUTPUT_NAME "AiDA_NativeDecompilerWorker"
        RUNTIME_OUTPUT_DIRECTORY "${AIDA_C03_DEVELOPER_ROOT}/workers/$<CONFIG>"
        FOLDER "Workers/C03"
        WIN32_EXECUTABLE TRUE
        AIDA_C03_PACKAGE "B14"
        AIDA_C03_SAFE_HEADLESS FALSE)

    file(GLOB _aida_managed_inputs CONFIGURE_DEPENDS
        "${AIDA_C03_MANAGED_WORKER_ROOT}/*.cs"
        "${AIDA_C03_MANAGED_WORKER_ROOT}/*.json"
        "${AIDA_C03_MANAGED_WORKER_ROOT}/*.csproj"
        "${AIDA_C03_MANAGED_WORKER_ROOT}/NuGet.Config")
    aida_c03_require_sources("B16 managed decompiler worker" ${_aida_managed_inputs})
    set(AIDA_C03_MANAGED_WORKER_PUBLISH_ROOT "${AIDA_C03_DEVELOPER_ROOT}/managed-worker/publish")
    get_filename_component(_aida_c03_dotnet_root "${AIDA_C03_DOTNET_EXECUTABLE}" DIRECTORY)
    set_property(GLOBAL APPEND PROPERTY AIDA_C03_COMPILER_MATRIX_NATIVE_WORKER_INPUTS
        ${_aida_native_sources})
    set_property(GLOBAL APPEND PROPERTY AIDA_C03_COMPILER_MATRIX_MANAGED_WORKER_INPUTS
        ${_aida_managed_inputs})
    add_custom_target(aida_c03_b16_managed_decompiler_worker
        COMMAND ${CMAKE_COMMAND} -E rm -rf
            "${AIDA_C03_DEVELOPER_ROOT}/managed-worker/packages"
            "${AIDA_C03_DEVELOPER_ROOT}/managed-worker/cli-home"
            "${AIDA_C03_MANAGED_WORKER_PUBLISH_ROOT}"
        COMMAND ${CMAKE_COMMAND} -E make_directory
            "${AIDA_C03_DEVELOPER_ROOT}/managed-worker/packages"
            "${AIDA_C03_DEVELOPER_ROOT}/managed-worker/cli-home"
            "${AIDA_C03_MANAGED_WORKER_PUBLISH_ROOT}"
        COMMAND ${CMAKE_COMMAND} -E env
            DOTNET_CLI_HOME=${AIDA_C03_DEVELOPER_ROOT}/managed-worker/cli-home
            DOTNET_CLI_TELEMETRY_OPTOUT=1
            DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE=1
            DOTNET_NOLOGO=1
            DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
            DOTNET_MULTILEVEL_LOOKUP=0
            DOTNET_ROOT=${_aida_c03_dotnet_root}
            DOTNET_ROLL_FORWARD=Disable
            NUGET_CERT_REVOCATION_MODE=offline
            NUGET_PACKAGES=${AIDA_C03_DEVELOPER_ROOT}/managed-worker/packages
            "${AIDA_C03_DOTNET_EXECUTABLE}" restore "${AIDA_C03_MANAGED_WORKER_PROJECT}"
            --configfile "${AIDA_C03_MANAGED_WORKER_NUGET_CONFIG}"
            --packages "${AIDA_C03_DEVELOPER_ROOT}/managed-worker/packages"
            --locked-mode --no-cache --disable-parallel
            -p:AssemblyName=AiDA_ManagedDecompilerWorker
            -p:RuntimeFrameworkVersion=10.0.9
            -p:TargetLatestRuntimePatch=false
            -p:NuGetAudit=false
        COMMAND ${CMAKE_COMMAND} -E env
            DOTNET_CLI_HOME=${AIDA_C03_DEVELOPER_ROOT}/managed-worker/cli-home
            DOTNET_CLI_TELEMETRY_OPTOUT=1
            DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE=1
            DOTNET_NOLOGO=1
            DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
            DOTNET_MULTILEVEL_LOOKUP=0
            DOTNET_ROOT=${_aida_c03_dotnet_root}
            DOTNET_ROLL_FORWARD=Disable
            NUGET_CERT_REVOCATION_MODE=offline
            NUGET_PACKAGES=${AIDA_C03_DEVELOPER_ROOT}/managed-worker/packages
            "${AIDA_C03_DOTNET_EXECUTABLE}" publish "${AIDA_C03_MANAGED_WORKER_PROJECT}"
            --configuration Release --framework net10.0 --self-contained false --no-restore
            --output "${AIDA_C03_MANAGED_WORKER_PUBLISH_ROOT}"
            -p:AssemblyName=AiDA_ManagedDecompilerWorker
            -p:RuntimeFrameworkVersion=10.0.9
            -p:TargetLatestRuntimePatch=false
            -p:NuGetAudit=false
            -p:ContinuousIntegrationBuild=true -p:Deterministic=true -p:TreatWarningsAsErrors=true
        DEPENDS ${_aida_managed_inputs} "${AIDA_C03_DOTNET_EXECUTABLE}"
            "${AIDA_C03_MANAGED_APPHOST_SOURCE}"
        COMMENT "Publishing the locked offline C03 managed decompiler worker"
        VERBATIM)
    set_target_properties(aida_c03_b16_managed_decompiler_worker PROPERTIES
        FOLDER "Workers/C03"
        AIDA_C03_PACKAGE "B16"
        AIDA_C03_SAFE_HEADLESS FALSE)

    set(AIDA_C03_MANAGED_FIXTURE_ROOT "${AIDA_C03_TEST_ROOT}/managed_cli")
    set(AIDA_C03_MANAGED_FIXTURE_PROJECT "${AIDA_C03_MANAGED_FIXTURE_ROOT}/ManagedCliFixtures.csproj")
    set(AIDA_C03_MANAGED_FIXTURE_LOCK "${AIDA_C03_MANAGED_FIXTURE_ROOT}/packages.lock.json")
    set(AIDA_C03_MANAGED_FIXTURE_NUGET_CONFIG "${AIDA_C03_MANAGED_FIXTURE_ROOT}/NuGet.Config")
    file(SHA256 "${AIDA_C03_MANAGED_FIXTURE_PROJECT}" _aida_c03_managed_fixture_project_sha256)
    file(SHA256 "${AIDA_C03_MANAGED_FIXTURE_LOCK}" _aida_c03_managed_fixture_lock_sha256)
    string(TOUPPER "${_aida_c03_managed_fixture_project_sha256}" _aida_c03_managed_fixture_project_sha256)
    string(TOUPPER "${_aida_c03_managed_fixture_lock_sha256}" _aida_c03_managed_fixture_lock_sha256)
    if(NOT _aida_c03_managed_fixture_project_sha256 STREQUAL "A7FF5D7F3F7E9DF755FC61E3095D56EEC16BFF902D172BFF4A4E032CC0242874" OR
       NOT _aida_c03_managed_fixture_lock_sha256 STREQUAL "98540F8C8005E000CC83CFFB4598281F61900A13426B470F1D1114C62B54A63D")
        message(WARNING "AiDA C03 managed CLI fixture project or lock identity changed")
    endif()
    file(GLOB _aida_c03_managed_fixture_inputs CONFIGURE_DEPENDS
        "${AIDA_C03_MANAGED_FIXTURE_ROOT}/*.cs"
        "${AIDA_C03_MANAGED_FIXTURE_ROOT}/*.json"
        "${AIDA_C03_MANAGED_FIXTURE_ROOT}/*.csproj"
        "${AIDA_C03_MANAGED_FIXTURE_ROOT}/NuGet.Config")
    aida_c03_require_sources("A06 managed CLI fixture" ${_aida_c03_managed_fixture_inputs})
    set(AIDA_C03_MANAGED_FIXTURE_PUBLISH_ROOT "${AIDA_C03_DEVELOPER_ROOT}/managed-fixture/publish")
    set(AIDA_C03_MANAGED_FIXTURE_DLL "${AIDA_C03_MANAGED_FIXTURE_PUBLISH_ROOT}/ManagedCliFixtures.dll")
    add_custom_target(aida_c03_a06_managed_cli_fixture
        COMMAND ${CMAKE_COMMAND} -E rm -rf
            "${AIDA_C03_DEVELOPER_ROOT}/managed-fixture/packages"
            "${AIDA_C03_DEVELOPER_ROOT}/managed-fixture/cli-home"
            "${AIDA_C03_MANAGED_FIXTURE_PUBLISH_ROOT}"
        COMMAND ${CMAKE_COMMAND} -E make_directory
            "${AIDA_C03_DEVELOPER_ROOT}/managed-fixture/packages"
            "${AIDA_C03_DEVELOPER_ROOT}/managed-fixture/cli-home"
            "${AIDA_C03_MANAGED_FIXTURE_PUBLISH_ROOT}"
        COMMAND ${CMAKE_COMMAND} -E env
            DOTNET_CLI_HOME=${AIDA_C03_DEVELOPER_ROOT}/managed-fixture/cli-home
            DOTNET_CLI_TELEMETRY_OPTOUT=1
            DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE=1
            DOTNET_NOLOGO=1
            DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
            DOTNET_MULTILEVEL_LOOKUP=0
            DOTNET_ROOT=${_aida_c03_dotnet_root}
            DOTNET_ROLL_FORWARD=Disable
            NUGET_CERT_REVOCATION_MODE=offline
            NUGET_PACKAGES=${AIDA_C03_DEVELOPER_ROOT}/managed-fixture/packages
            "${AIDA_C03_DOTNET_EXECUTABLE}" restore "${AIDA_C03_MANAGED_FIXTURE_PROJECT}"
            --configfile "${AIDA_C03_MANAGED_FIXTURE_NUGET_CONFIG}"
            --packages "${AIDA_C03_DEVELOPER_ROOT}/managed-fixture/packages"
            --locked-mode --no-cache --disable-parallel
            -p:NuGetAudit=false
        COMMAND ${CMAKE_COMMAND} -E env
            DOTNET_CLI_HOME=${AIDA_C03_DEVELOPER_ROOT}/managed-fixture/cli-home
            DOTNET_CLI_TELEMETRY_OPTOUT=1
            DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE=1
            DOTNET_NOLOGO=1
            DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
            DOTNET_MULTILEVEL_LOOKUP=0
            DOTNET_ROOT=${_aida_c03_dotnet_root}
            DOTNET_ROLL_FORWARD=Disable
            NUGET_CERT_REVOCATION_MODE=offline
            NUGET_PACKAGES=${AIDA_C03_DEVELOPER_ROOT}/managed-fixture/packages
            "${AIDA_C03_DOTNET_EXECUTABLE}" build "${AIDA_C03_MANAGED_FIXTURE_PROJECT}"
            --configuration Release --framework net10.0 --no-restore
            --output "${AIDA_C03_MANAGED_FIXTURE_PUBLISH_ROOT}"
            -p:NuGetAudit=false
            -p:ContinuousIntegrationBuild=true -p:Deterministic=true -p:TreatWarningsAsErrors=true
        BYPRODUCTS "${AIDA_C03_MANAGED_FIXTURE_DLL}"
        DEPENDS ${_aida_c03_managed_fixture_inputs} "${AIDA_C03_DOTNET_EXECUTABLE}"
        VERBATIM)
    set_target_properties(aida_c03_a06_managed_cli_fixture PROPERTIES
        FOLDER "Tests/C03/SafeHeadless/Fixtures"
        AIDA_C03_PACKAGE "A06"
        AIDA_C03_SAFE_HEADLESS TRUE
        AIDA_C03_TARGET_FRAMEWORK "net10.0"
        AIDA_C03_PINNED_SDK_VERSION "10.0.301"
        AIDA_C03_MACHINE_RUNTIME_FALLBACK FALSE)
    set_property(GLOBAL APPEND PROPERTY AIDA_C03_COMPILER_MATRIX_MANAGED_WORKER_INPUTS
        ${_aida_c03_managed_fixture_inputs})

    set(AIDA_C03_SAFE_HEADLESS_WORKER_RUNTIME_ROOT
        "${AIDA_C03_DEVELOPER_ROOT}/safe-headless-worker-runtime/$<CONFIG>")
    set(AIDA_C03_MANAGED_FIXTURE_DLL "${AIDA_C03_MANAGED_FIXTURE_DLL}" PARENT_SCOPE)
    set(AIDA_C03_SAFE_HEADLESS_WORKER_RUNTIME_ROOT
        "${AIDA_C03_SAFE_HEADLESS_WORKER_RUNTIME_ROOT}" PARENT_SCOPE)
endfunction()

function(aida_c03_register_safe_headless_targets application_target)
    if(NOT WIN32 OR NOT MSVC OR NOT TARGET "${application_target}")
        message(WARNING "AiDA C03 safe-headless registration requires the Windows MSVC standalone target")
    endif()
    if(TARGET aida_c03_safe_headless_harnesses)
        message(WARNING "AiDA C03 safe-headless integration was registered more than once")
    endif()
    if(NOT Python3_Interpreter_FOUND OR NOT Python3_EXECUTABLE)
        message(WARNING "AiDA C03 safe-headless materialization requires the pinned local Python interpreter")
    endif()
    aida_c03_validate_canonical_regular_file(
        _aida_python_executable
        _aida_python_sha256
        "${Python3_EXECUTABLE}"
        "Python interpreter")
    if(NOT DEFINED ENV{SystemDrive} OR NOT "$ENV{SystemDrive}" MATCHES "^[A-Z]:$" OR
       NOT DEFINED ENV{SystemRoot} OR
       NOT "$ENV{SystemRoot}" STREQUAL "$ENV{SystemDrive}\\Windows")
        message(WARNING "AiDA C03 authority reproduction requires the canonical Windows system root")
    endif()
    set(_aida_system_root_input "$ENV{SystemDrive}/Windows")
    aida_c03_validate_canonical_directory(
        _aida_system_root
        "${_aida_system_root_input}"
        "Windows system root")
    aida_c03_validate_canonical_regular_file(
        _aida_system_powershell
        _aida_system_powershell_sha256
        "${_aida_system_root}/System32/WindowsPowerShell/v1.0/powershell.exe"
        "Windows system PowerShell interpreter")
    set(_aida_authority_archive "C:/Users/tyler/Downloads/ida-pro-mcp.zip")
    aida_c03_validate_canonical_regular_file(
        _aida_authority_archive
        _aida_authority_archive_sha256
        "${_aida_authority_archive}"
        "pinned ida-pro-mcp archive")
    if(NOT _aida_authority_archive_sha256 STREQUAL "77FB255DEF04BA8ABD3D6BFA306916FA27597CF369D2863C4614ECFFEA288F0C")
        message(WARNING "AiDA C03 pinned ida-pro-mcp archive SHA-256 is invalid")
    endif()
    set(_aida_authority_repository_files
        "${AIDA_C03_PATH_POLICY_MODULE}"
        "${AIDA_C03_PATH_IDENTITY_POLICY}"
        "${CMAKE_SOURCE_DIR}/tools/generate_ida_mcp_contracts/generate_ida_mcp_contracts.py"
        "${CMAKE_SOURCE_DIR}/src/standalone/tests/analysis_workspace/generate_surface_manifest.ps1"
        "${CMAKE_SOURCE_DIR}/src/standalone/tests/analysis_workspace/standalone_surface_baseline.json"
        "${CMAKE_SOURCE_DIR}/src/standalone/tests/analysis_workspace/standalone_surface_final.json"
        "${CMAKE_SOURCE_DIR}/src/standalone/src/resources/mcp/ida_pro_mcp_2_0_0/contracts.json"
        "${CMAKE_SOURCE_DIR}/src/standalone/src/resources/mcp/ida_pro_mcp_2_0_0/effect_ledger.json"
        "${CMAKE_SOURCE_DIR}/src/standalone/src/resources/mcp/ida_pro_mcp_2_0_0/archive_manifest.json"
        "${CMAKE_SOURCE_DIR}/src/standalone/src/core/mcp/compat/ida_contracts_generated.hpp"
        "${CMAKE_SOURCE_DIR}/src/standalone/src/core/mcp/compat/ida_contracts_generated.cpp")
    aida_c03_require_sources("authority and surface reproduction" ${_aida_authority_repository_files})
    foreach(_aida_authority_path IN ITEMS
            "${_aida_system_root}"
            "${_aida_system_powershell}"
            "${_aida_python_executable}"
            "${_aida_authority_archive}"
            ${_aida_authority_repository_files})
        aida_c03_validate_no_reparse_chain(
            "${_aida_system_powershell}"
            "${AIDA_C03_PATH_IDENTITY_POLICY}"
            "${_aida_authority_path}"
            "authority path")
    endforeach()
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
        ${_aida_authority_repository_files}
        "${_aida_python_executable}"
        "${_aida_system_powershell}"
        "${_aida_authority_archive}")
    set(_aida_authority_identity_material "aida-c03-authority-surface-reproduction-v1")
    foreach(_aida_authority_file IN LISTS _aida_authority_repository_files)
        file(SHA256 "${_aida_authority_file}" _aida_authority_file_sha256)
        string(TOUPPER "${_aida_authority_file_sha256}" _aida_authority_file_sha256)
        file(RELATIVE_PATH _aida_authority_relative "${CMAKE_SOURCE_DIR}" "${_aida_authority_file}")
        string(REPLACE "\\" "/" _aida_authority_relative "${_aida_authority_relative}")
        string(APPEND _aida_authority_identity_material
            "|${_aida_authority_relative}=${_aida_authority_file_sha256}")
    endforeach()
    string(APPEND _aida_authority_identity_material
        "|python=${_aida_python_executable}:${_aida_python_sha256}"
        "|powershell=${_aida_system_powershell}:${_aida_system_powershell_sha256}"
        "|archive=${_aida_authority_archive}:${_aida_authority_archive_sha256}")
    string(SHA256 _aida_authority_identity "${_aida_authority_identity_material}")
    string(TOUPPER "${_aida_authority_identity}" _aida_authority_identity)
    file(SHA256 "${CMAKE_SOURCE_DIR}/tools/generate_ida_mcp_contracts/generate_ida_mcp_contracts.py" _aida_contract_generator_sha256)
    file(SHA256 "${CMAKE_SOURCE_DIR}/src/standalone/tests/analysis_workspace/generate_surface_manifest.ps1" _aida_surface_generator_sha256)
    file(SHA256 "${CMAKE_SOURCE_DIR}/src/standalone/tests/analysis_workspace/standalone_surface_baseline.json" _aida_surface_baseline_sha256)
    file(SHA256 "${CMAKE_SOURCE_DIR}/src/standalone/tests/analysis_workspace/standalone_surface_final.json" _aida_surface_final_sha256)
    foreach(_aida_hash_variable IN ITEMS
            _aida_contract_generator_sha256
            _aida_surface_generator_sha256
            _aida_surface_baseline_sha256
            _aida_surface_final_sha256)
        string(TOUPPER "${${_aida_hash_variable}}" ${_aida_hash_variable})
    endforeach()
    set_property(GLOBAL PROPERTY AIDA_C03_MANIFEST_TARGETS "")
    set_property(GLOBAL PROPERTY AIDA_C03_MANIFEST_TARGET_RECORDS "")
    set_property(GLOBAL PROPERTY AIDA_C03_DIRECT_TARGETS "")
    set_property(GLOBAL PROPERTY AIDA_C03_RUNTIME_RELATIVE_PATHS "")
    set_property(GLOBAL PROPERTY AIDA_C03_RUNTIME_OUTPUTS "")
    set_property(GLOBAL PROPERTY AIDA_C03_COMPILER_MATRIX_HARNESS_INPUTS "")

    set(_aida_runtime_sources
        ${AIDA_C03_PRODUCTION_STANDALONE_SOURCES}
        ${AIDA_C03_HARNESS_SUPPORT_SOURCES}
        ${AIDA_C03_WORKSPACE_HARNESS_SUPPORT_SOURCES})
    set(_aida_auth_implementation_sources
        "${STANDALONE_ROOT}/core/auth/auth_store.cpp"
        "${STANDALONE_ROOT}/core/auth/auth_http.cpp"
        "${STANDALONE_ROOT}/core/auth/auth_codex.cpp"
        "${STANDALONE_ROOT}/core/auth/auth_copilot.cpp"
        "${STANDALONE_ROOT}/core/auth/auth_claude_code.cpp"
        "${STANDALONE_ROOT}/core/ai/provider_catalog.cpp")
    aida_c03_require_sources("D08 normal and preview auth implementation graph"
        ${_aida_auth_implementation_sources})
    list(REMOVE_ITEM _aida_runtime_sources
        "${STANDALONE_ROOT}/core/testlab/test_lab_features_c03_safe_headless.cpp"
        "${STANDALONE_ROOT}/core/mcp/registry/application_debugger_capability.cpp"
        "${CMAKE_SOURCE_DIR}/src/emulation_engine.cpp")
    list(APPEND _aida_runtime_sources
        "${AIDA_C03_TEST_ROOT}/testlab_runtime/safe_headless_emulation_bridge.cpp"
        "${STANDALONE_ROOT}/core/runtime/kernel_symbols.cpp"
        "${imgui_SOURCE_DIR}/imgui.cpp"
        "${imgui_SOURCE_DIR}/imgui_draw.cpp"
        "${imgui_SOURCE_DIR}/imgui_tables.cpp"
        "${imgui_SOURCE_DIR}/imgui_widgets.cpp")
    list(REMOVE_DUPLICATES _aida_runtime_sources)
    aida_use_static_msvc_runtime(pcre2-8-static)
    add_library(aida_c03_safe_headless_runtime STATIC ${_aida_runtime_sources})
    aida_c03_configure_native_target(aida_c03_safe_headless_runtime)
    target_include_directories(aida_c03_safe_headless_runtime PRIVATE
        "${IDA_STUBS_DIR}"
        "${CMAKE_SOURCE_DIR}/src"
        "${STANDALONE_ROOT}/core/emulation"
        "${CMAKE_SOURCE_DIR}/driver"
        "${STANDALONE_ROOT}/core/ai"
        "${STANDALONE_ROOT}/core/auth"
        "${STANDALONE_ROOT}/core/debugger"
        "${STANDALONE_ROOT}/core/editor"
        "${STANDALONE_ROOT}/core/network"
        "${STANDALONE_ROOT}/core/scanner"
        "${STANDALONE_ROOT}/core/session"
        "${STANDALONE_ROOT}/core/tools"
        "${sol2_SOURCE_DIR}/include"
        "${DEPS_DIR}/MemPDB/include")
    set_source_files_properties("${STANDALONE_ROOT}/core/runtime/kernel_symbols.cpp"
        PROPERTIES COMPILE_OPTIONS "/std:c++20" SKIP_PRECOMPILE_HEADERS ON)
    target_compile_definitions(aida_c03_safe_headless_runtime PRIVATE
        AIDA_C03_SAFE_HEADLESS_RUNTIME=1
        CPPHTTPLIB_OPENSSL_SUPPORT)
    target_link_libraries(aida_c03_safe_headless_runtime PUBLIC
        Zydis capstone::capstone triton "${Z3_LIBRARIES}"
        nlohmann_json_schema_validator::validator libdecomp_aida
        zlibstatic libzstd_static liblzma pcre2-8
        brotlidec brotlienc brotlicommon llhttp_static nghttp2_static lua54_static
        aida_openssl_ssl_mt aida_openssl_crypto_mt
        mimalloc-static
        MemPDB
        bcrypt crypt32 advapi32 userenv ws2_32 shell32 ole32 Shlwapi
        cabinet cfgmgr32 dnsapi gdiplus iphlpapi ntdll Psapi setupapi version winhttp wintrust)
    set_target_properties(aida_c03_safe_headless_runtime PROPERTIES
        FOLDER "Tests/C03/SafeHeadless"
        AIDA_C03_SAFE_HEADLESS TRUE
        LABELS "c03;c03_safe_headless;safe-headless;runtime")
    add_library(aida_c03_auth_preview_implementation STATIC
        ${_aida_auth_implementation_sources})
    aida_c03_configure_native_target(aida_c03_auth_preview_implementation)
    target_compile_definitions(aida_c03_auth_preview_implementation PRIVATE
        AIDA_IMGUI_STUDIO_PREVIEW=1)
    target_link_libraries(aida_c03_auth_preview_implementation PUBLIC
        bcrypt crypt32 advapi32 userenv ws2_32 shell32 ole32 Shlwapi)
    set_target_properties(aida_c03_auth_preview_implementation PROPERTIES
        FOLDER "Tests/C03/SafeHeadless/Support"
        AIDA_C03_SAFE_HEADLESS TRUE
        AIDA_C03_IMPLEMENTATION_VARIANT "preview"
        AIDA_C03_IMPLEMENTATION_SOURCES "${_aida_auth_implementation_sources}")
    set_target_properties(aida_c03_safe_headless_runtime PROPERTIES
        AIDA_C03_AUTH_IMPLEMENTATION_VARIANT "normal"
        AIDA_C03_AUTH_IMPLEMENTATION_SOURCES "${_aida_auth_implementation_sources}")

    set(_aida_entries "${AIDA_C03_SAFE_HEADLESS_CMAKE_ROOT}/c03_safe_headless/generated_entrypoints.cpp")
    set(_aida_result_sources
        "${AIDA_C03_TEST_ROOT}/testlab_runtime/result_adapter.cpp"
        "${AIDA_C03_TEST_ROOT}/testlab_runtime/adapter_main_args.cpp"
        "${AIDA_C03_TEST_ROOT}/testlab_runtime/adapter_main_noargs.cpp")
    aida_c03_require_sources("safe-headless adapters" ${_aida_result_sources} "${_aida_entries}")

    aida_c03_stage_runtime_tree("${AIDA_C03_TEST_ROOT}/fixtures" "src/standalone/tests/c03/fixtures" _aida_fixture_runtime)
    aida_c03_stage_runtime_file(
        "${AIDA_C03_TEST_ROOT}/fixture_materializer.cpp"
        "src/standalone/tests/c03/fixture_materializer.cpp")
    list(APPEND _aida_fixture_runtime "src/standalone/tests/c03/fixture_materializer.cpp")
    aida_c03_stage_runtime_file("${AIDA_C03_SAFE_HEADLESS_CMAKE_ROOT}/c03_safe_headless/benchmark_search_receipt.json" "fixtures/benchmark_search_receipt.json")
    aida_c03_stage_runtime_file("${AIDA_C03_TEST_ROOT}/fixtures/external_sla_qualification_policy.json" "fixtures/external_sla_qualification_policy.json")

    aida_c03_register_manifest_entry(
        TARGET aida_c03_a01_analysis_contracts_harness PACKAGE A01
        SOURCES "${AIDA_C03_TEST_ROOT}/analysis_contracts_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_a02_decompiler_contracts_harness PACKAGE A02
        SOURCES "${AIDA_C03_TEST_ROOT}/decompiler_contracts_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_a04_workbench_contracts_harness PACKAGE A04
        SOURCES "${AIDA_C03_TEST_ROOT}/workbench_contracts_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_a06_fixture_materializer_harness PACKAGE A06 ARGS_ENTRY
        SOURCES
            "${AIDA_C03_TEST_ROOT}/fixture_materializer_harness_main.cpp"
            "${AIDA_C03_TEST_ROOT}/fixture_materializer_harness.cpp"
            "${AIDA_C03_TEST_ROOT}/fixture_materializer.cpp"
            "${AIDA_C03_TEST_ROOT}/managed_fixture_fidelity/managed_fixture_fidelity.cpp"
            "${AIDA_C03_TEST_ROOT}/decompiler_quality_schema.cpp"
            "${AIDA_C03_TEST_ROOT}/evidence_hash.cpp"
        ARGUMENTS "." "scratch/fixture-materializer"
        RUNTIME_FILES ${_aida_fixture_runtime})

    aida_c03_register_manifest_entry(
        TARGET aida_c03_b01_provider_snapshot_harness PACKAGE B01
        ENTRY_DEFINITION AIDA_C03_ENTRY_PROVIDER_SNAPSHOT
        SOURCES "${_aida_entries}" "${AIDA_C03_TEST_ROOT}/provider_snapshot_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b02_image_layout_index_harness PACKAGE B02
        SOURCES "${AIDA_C03_TEST_ROOT}/image_layout_index_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b03_packed_store_harness PACKAGE B03
        ENTRY_DEFINITION AIDA_C03_ENTRY_PACKED_STORE
        SOURCES "${_aida_entries}" "${AIDA_C03_TEST_ROOT}/packed_store_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b04_analysis_scheduler_harness PACKAGE B04
        SOURCES "${AIDA_C03_TEST_ROOT}/analysis_scheduler_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b05_x86_tile_decoder_harness PACKAGE B05
        SOURCES "${AIDA_C03_TEST_ROOT}/x86_tile_decoder_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b06_capstone_tile_decoder_harness PACKAGE B06
        SOURCES "${AIDA_C03_TEST_ROOT}/capstone_tile_decoder_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b07_container_stream_harness PACKAGE B07
        SOURCES "${AIDA_C03_TEST_ROOT}/container_stream_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b08_pe_reader_harness PACKAGE B08
        ENTRY_DEFINITION AIDA_C03_ENTRY_PE_READER
        SOURCES "${_aida_entries}" "${AIDA_C03_TEST_ROOT}/pe_reader_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b09_elf_reader_harness PACKAGE B09
        SOURCES "${AIDA_C03_TEST_ROOT}/elf_reader_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b10_macho_reader_harness PACKAGE B10
        SOURCES "${AIDA_C03_TEST_ROOT}/macho_reader_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b11_managed_reader_harness PACKAGE B11
        ENTRY_DEFINITION AIDA_C03_ENTRY_MANAGED_READER
        SOURCES "${_aida_entries}" "${AIDA_C03_TEST_ROOT}/managed_reader_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b12_collection_graph_harness PACKAGE B12
        SOURCES "${AIDA_C03_TEST_ROOT}/collection_graph_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b13_metrics_contract_harness PACKAGE B13
        SOURCES "${AIDA_C03_TEST_ROOT}/metrics_contract_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b14_native_worker_protocol_harness PACKAGE B14 ARGS_ENTRY
        SOURCES "${AIDA_C03_TEST_ROOT}/native_worker_protocol_harness.cpp"
        ARGUMENTS "--protocol-only")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b15_ghidra_ir_adapter_harness PACKAGE B15
        SOURCES "${AIDA_C03_TEST_ROOT}/ghidra_ir_adapter_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b16_cli_provider_harness PACKAGE B16
        SOURCES "${AIDA_C03_TEST_ROOT}/cli_provider_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b17_jvm_ssa_harness PACKAGE B17
        SOURCES "${AIDA_C03_TEST_ROOT}/jvm_ssa_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b18_dalvik_ssa_harness PACKAGE B18
        SOURCES "${AIDA_C03_TEST_ROOT}/dalvik_ssa_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b19_type_graph_harness PACKAGE B19
        SOURCES "${AIDA_C03_TEST_ROOT}/type_graph_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b20_semantic_refiner_harness PACKAGE B20
        SOURCES "${AIDA_C03_TEST_ROOT}/semantic_refiner_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b21_pseudocode_renderer_harness PACKAGE B21
        SOURCES "${AIDA_C03_TEST_ROOT}/pseudocode_renderer_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b22_protocol_core_harness PACKAGE B22
        ENTRY_DEFINITION AIDA_C03_ENTRY_PROTOCOL_CORE
        SOURCES "${_aida_entries}" "${AIDA_C03_MCP_TEST_ROOT}/protocol_core_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b23_workspace_adapter_harness PACKAGE B23
        ENTRY_DEFINITION AIDA_C03_ENTRY_WORKSPACE_ADAPTER
        SOURCES "${_aida_entries}" "${AIDA_C03_MCP_TEST_ROOT}/workspace_adapter_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b24_python_worker_harness PACKAGE B24
        SOURCES "${AIDA_C03_SAFE_HEADLESS_CMAKE_ROOT}/c03_safe_headless/python_protocol_harness.cpp"
        INCLUDE_DIRECTORIES "${STANDALONE_ROOT}/../workers/analysis_python"
        LINK_LIBRARIES bcrypt)
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b25_workbench_model_harness PACKAGE B25
        SOURCES "${AIDA_C03_TEST_ROOT}/workbench_model_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b26_workbench_navigator_harness PACKAGE B26
        SOURCES "${AIDA_C03_TEST_ROOT}/workbench_navigator_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b27_workbench_inspector_harness PACKAGE B27
        SOURCES "${AIDA_C03_TEST_ROOT}/workbench_inspector_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b29_overlay_journal_v9_harness PACKAGE B29
        SOURCES "${AIDA_C03_TEST_ROOT}/overlay_journal_v9_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b30_live_snapshot_harness PACKAGE B30
        SOURCES "${AIDA_C03_TEST_ROOT}/live_snapshot_harness.cpp")

    aida_c03_register_manifest_entry(
        TARGET aida_c03_c01_tile_decode_orchestrator_harness PACKAGE C01
        SOURCES "${AIDA_C03_TEST_ROOT}/tile_decode_orchestrator_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_c02_function_cfg_callgraph_harness PACKAGE C02
        SOURCES "${AIDA_C03_TEST_ROOT}/function_cfg_callgraph_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_c03_xref_discovery_harness PACKAGE C03
        SOURCES "${AIDA_C03_TEST_ROOT}/xref_discovery_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_c04_search_query_harness PACKAGE C04
        ENTRY_DEFINITION AIDA_C03_ENTRY_SEARCH_QUERY
        SOURCES "${_aida_entries}" "${AIDA_C03_TEST_ROOT}/search_query_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_c05_schema_v9_harness PACKAGE C05
        ENTRY_DEFINITION AIDA_C03_ENTRY_SCHEMA_V9
        SOURCES
            "${_aida_entries}"
            "${AIDA_C03_TEST_ROOT}/schema_v9_harness.cpp"
            "${AIDA_C03_TEST_ROOT}/managed_publication_persistence/managed_publication_persistence_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_c06_decompiler_service_harness PACKAGE C06
        SOURCES "${AIDA_C03_TEST_ROOT}/decompiler_service_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_c07_decompiler_readability_harness PACKAGE C07
        SOURCES "${AIDA_C03_TEST_ROOT}/decompiler_readability_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_c07_pseudocode_quality_differential_harness PACKAGE C07
        SOURCES "${AIDA_C03_TEST_ROOT}/pseudocode_quality_differential_harness.cpp")

    set(_aida_mcp_harness_sources
        "${AIDA_C03_MCP_TEST_ROOT}/contract_generation_harness.cpp"
        "${AIDA_C03_MCP_TEST_ROOT}/analysis_handlers_harness.cpp"
        "${AIDA_C03_MCP_TEST_ROOT}/composite_handlers_harness.cpp"
        "${AIDA_C03_MCP_TEST_ROOT}/core_handlers_harness.cpp"
        "${AIDA_C03_MCP_TEST_ROOT}/debugger_handlers_harness.cpp"
        "${AIDA_C03_MCP_TEST_ROOT}/memory_handlers_harness.cpp"
        "${AIDA_C03_MCP_TEST_ROOT}/modify_handlers_harness.cpp"
        "${AIDA_C03_MCP_TEST_ROOT}/python_handler_harness.cpp"
        "${AIDA_C03_MCP_TEST_ROOT}/signature_handlers_harness.cpp"
        "${AIDA_C03_MCP_TEST_ROOT}/stack_handlers_harness.cpp"
        "${AIDA_C03_MCP_TEST_ROOT}/survey_handler_harness.cpp"
        "${AIDA_C03_MCP_TEST_ROOT}/type_handlers_harness.cpp"
        "${AIDA_C03_MCP_TEST_ROOT}/routing_extensions_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_c08_c19_mcp_compatibility_harness PACKAGE C08
        ENTRY_DEFINITION AIDA_C03_ENTRY_MCP_COMPATIBILITY
        SOURCES "${_aida_entries}" ${_aida_mcp_harness_sources})
    set_target_properties(aida_c03_c08_c19_mcp_compatibility_harness PROPERTIES
        AIDA_C03_PACKAGES "C08;C09;C10;C11;C12;C13;C14;C15;C16;C17;C18;C19"
        LABELS "c03;c03_safe_headless;safe-headless;C08;C09;C10;C11;C12;C13;C14;C15;C16;C17;C18;C19")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_c20_c22_workbench_documents_harness PACKAGE C20
        SOURCES "${AIDA_C03_TEST_ROOT}/workbench_documents_harness.cpp")
    set_target_properties(aida_c03_c20_c22_workbench_documents_harness PROPERTIES
        AIDA_C03_PACKAGES "C20;C21;C22"
        LABELS "c03;c03_safe_headless;safe-headless;C20;C21;C22")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_c22_workbench_shell_lifecycle_harness PACKAGE C22
        SOURCES "${AIDA_C03_TEST_ROOT}/workbench_shell_lifecycle_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_c23_workbench_persistence_harness PACKAGE C23
        SOURCES "${AIDA_C03_TEST_ROOT}/workbench_persistence_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_c24_overlay_projection_harness PACKAGE C24
        SOURCES "${AIDA_C03_TEST_ROOT}/overlay_projection_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_c19_live_routing_integration_harness PACKAGE C19
        SOURCES "${AIDA_C03_TEST_ROOT}/live_routing_integration_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_managed_cli_snapshot_protocol_harness PACKAGE B16
        SOURCES
            "${AIDA_C03_TEST_ROOT}/managed_cli_snapshot_protocol/main.cpp"
            "${AIDA_C03_TEST_ROOT}/managed_cli_snapshot_protocol/managed_cli_snapshot_protocol_harness.cpp")

    aida_c03_register_manifest_entry(
        TARGET aida_c03_a06_decompiler_quality_scorer_harness PACKAGE A06 ARGS_ENTRY
        MAX_ACTIVE_PROCESSES 4
        MAX_WALL_MS 1800000
        COMPILE_DEFINITIONS AIDA_SAFE_HEADLESS=1
        SOURCES
            "${AIDA_C03_SAFE_HEADLESS_CMAKE_ROOT}/c03_safe_headless/decompiler_quality_pipeline_main.cpp"
            "${AIDA_C03_TEST_ROOT}/decompiler_provider_matrix/provider_matrix.cpp"
            "${AIDA_C03_TEST_ROOT}/decompiler_provider_matrix/provider_matrix.hpp"
            "${AIDA_C03_TEST_ROOT}/decompiler_quality_scorer_harness.cpp"
            "${AIDA_C03_TEST_ROOT}/decompiler_quality_scorer_harness.hpp"
            "${AIDA_C03_TEST_ROOT}/decompiler_quality_scorer.cpp"
            "${AIDA_C03_TEST_ROOT}/decompiler_quality_scorer.hpp"
            "${AIDA_C03_TEST_ROOT}/decompiler_quality_schema.cpp"
            "${AIDA_C03_TEST_ROOT}/decompiler_quality_schema.hpp"
            "${AIDA_C03_TEST_ROOT}/fixture_materializer.cpp"
            "${AIDA_C03_TEST_ROOT}/fixture_materializer.hpp"
            "${AIDA_C03_TEST_ROOT}/managed_fixture_fidelity/managed_fixture_fidelity.cpp"
            "${AIDA_C03_TEST_ROOT}/managed_fixture_fidelity/managed_fixture_fidelity.hpp"
            "${AIDA_C03_TEST_ROOT}/evidence_hash.cpp"
            "${AIDA_C03_TEST_ROOT}/evidence_hash.hpp"
            "${AIDA_C03_WORKSPACE_TEST_ROOT}/workspace_fixture_builder.hpp"
        ARGUMENTS
            "."
            "scratch/quality/evidence"
            "${AIDA_C03_SAFE_HEADLESS_WORKER_RUNTIME_ROOT}"
            "scratch/quality/materialized"
            "scratch/quality/results"
            "120000"
        RUNTIME_FILES ${_aida_fixture_runtime})
    aida_c03_register_manifest_entry(
        TARGET aida_c03_a06_benchmark_sla_receipt_harness PACKAGE A06 ARGS_ENTRY
        SOURCES
            "${AIDA_C03_TEST_ROOT}/benchmark_sla_receipt_harness_main.cpp"
            "${AIDA_C03_TEST_ROOT}/benchmark_sla_receipt_harness.cpp"
            "${AIDA_C03_TEST_ROOT}/benchmark_sla_receipt.cpp"
            "${AIDA_C03_TEST_ROOT}/benchmark_sla_schema.cpp"
            "${AIDA_C03_TEST_ROOT}/decompiler_quality_schema.cpp"
            "${AIDA_C03_TEST_ROOT}/evidence_hash.cpp"
        ARGUMENTS "not-run" "scratch/benchmark" "fixtures/benchmark_search_receipt.json"
        RUNTIME_FILES
            "fixtures/benchmark_search_receipt.json"
            "fixtures/external_sla_qualification_policy.json"
            "src/standalone/tests/c03/fixtures/external_sla_qualification_policy.json")

    aida_c03_register_manifest_entry(
        TARGET aida_c03_surface_reconciliation_harness PACKAGE D08
        SOURCES "${AIDA_C03_TEST_ROOT}/surface_reconciliation_harness.cpp")

    aida_c03_register_manifest_entry(
        TARGET aida_c03_srec_api_prototype_lookup_harness PACKAGE SREC
        SOURCES "${AIDA_C03_TEST_ROOT}/api_prototype_lookup_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_srec_flirt_engine_harness PACKAGE SREC
        SOURCES "${AIDA_C03_TEST_ROOT}/flirt_engine_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_srec_rtti_static_harness PACKAGE SREC
        SOURCES "${AIDA_C03_TEST_ROOT}/rtti_static_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_srec_type_seed_exporter_harness PACKAGE SREC
        SOURCES "${AIDA_C03_TEST_ROOT}/type_seed_exporter_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_srec_flirt_db_builder PACKAGE SREC ARGS_ENTRY
        SOURCES
            "${AIDA_C03_TEST_ROOT}/flirt_db_builder_main.cpp"
            "${STANDALONE_ROOT}/core/analysis/flirt/flirt_db_builder.cpp")
    file(READ "${STANDALONE_ROOT}/core/analysis/flirt/flirt_signature_db_seed.hpp" _aida_flirt_seed_header)
    string(REGEX MATCH "k_afdb_seed_entry_count = ([0-9]+)u" _aida_flirt_seed_match "${_aida_flirt_seed_header}")
    if(NOT _aida_flirt_seed_match OR CMAKE_MATCH_1 EQUAL 0)
        message(WARNING "AiDA FLIRT embedded seed database is unpopulated (k_afdb_seed_entry_count=0); CRT/library recognition and batch decompile library exclusion are disabled. Regenerate via the aida_c03_srec_flirt_db_builder tool (plans/PLAN_A_flirt_libcode.md section 6.10).")
    endif()

    get_property(_aida_manifest_targets GLOBAL PROPERTY AIDA_C03_MANIFEST_TARGETS)
    get_property(_aida_manifest_records GLOBAL PROPERTY AIDA_C03_MANIFEST_TARGET_RECORDS)
    list(LENGTH _aida_manifest_targets _aida_manifest_target_count)
    list(LENGTH _aida_manifest_records _aida_manifest_record_count)
    if(NOT _aida_manifest_target_count EQUAL 56 OR NOT _aida_manifest_record_count EQUAL 56)
        message(WARNING "AiDA C03 canonical manifest cardinality is invalid: targets=${_aida_manifest_target_count}, records=${_aida_manifest_record_count}")
    endif()
    file(READ "${AIDA_C03_SAFE_HEADLESS_INVENTORY}" _aida_inventory_json)
    string(JSON _aida_inventory_schema GET "${_aida_inventory_json}" schema)
    string(JSON _aida_inventory_count LENGTH "${_aida_inventory_json}" entries)
    if(NOT _aida_inventory_schema STREQUAL "aida.c03.safe-headless.inventory.v1" OR
       NOT _aida_inventory_count EQUAL 56)
        message(WARNING "AiDA C03 safe-headless inventory identity or cardinality is invalid")
    endif()
    math(EXPR _aida_inventory_last "${_aida_inventory_count} - 1")
    set(_aida_inventory_targets)
    foreach(_aida_index RANGE 0 ${_aida_inventory_last})
        string(JSON _aida_inventory_target GET "${_aida_inventory_json}" entries ${_aida_index} source_target)
        if(_aida_inventory_target IN_LIST _aida_inventory_targets OR
           NOT _aida_inventory_target IN_LIST _aida_manifest_targets)
            message(WARNING "AiDA C03 inventory target is duplicated or unregistered: ${_aida_inventory_target}")
        endif()
        list(APPEND _aida_inventory_targets "${_aida_inventory_target}")
    endforeach()
    foreach(_aida_target IN LISTS _aida_manifest_targets)
        if(NOT _aida_target IN_LIST _aida_inventory_targets)
            message(WARNING "AiDA C03 manifest target is absent from the canonical inventory: ${_aida_target}")
        endif()
    endforeach()
    file(READ "${AIDA_C03_SAFE_HEADLESS_ASSERTION_INVENTORY}" _aida_assertion_inventory_json)
    string(JSON _aida_assertion_inventory_schema GET "${_aida_assertion_inventory_json}" schema)
    string(JSON _aida_assertion_inventory_version GET "${_aida_assertion_inventory_json}" version)
    string(JSON _aida_assertion_entry_count GET "${_aida_assertion_inventory_json}" entry_count)
    string(JSON _aida_assertion_pending_count GET "${_aida_assertion_inventory_json}" pending_handoff_entry_count)
    string(JSON _aida_assertion_entries_length LENGTH "${_aida_assertion_inventory_json}" entries)
    if(NOT _aida_assertion_inventory_schema STREQUAL "aida.c03.safe-headless.assertion-sites.v1" OR
       NOT _aida_assertion_inventory_version EQUAL 1 OR
       NOT _aida_assertion_entry_count EQUAL 56 OR
       NOT _aida_assertion_entries_length EQUAL 56 OR
       NOT _aida_assertion_pending_count EQUAL 0)
        message(WARNING "AiDA C03 assertion telemetry inventory identity, cardinality, or handoff state is invalid")
    endif()
    set(_aida_assertion_targets)
    foreach(_aida_index RANGE 0 55)
        string(JSON _aida_assertion_target GET "${_aida_assertion_inventory_json}" entries ${_aida_index} target)
        if(_aida_assertion_target IN_LIST _aida_assertion_targets OR
           NOT _aida_assertion_target IN_LIST _aida_manifest_targets)
            message(WARNING "AiDA C03 assertion telemetry target is duplicated or unregistered: ${_aida_assertion_target}")
        endif()
        list(APPEND _aida_assertion_targets "${_aida_assertion_target}")
    endforeach()

    string(JOIN "," _aida_records_joined ${_aida_manifest_records})
    file(GENERATE OUTPUT "${AIDA_C03_SAFE_HEADLESS_RECORDS}"
        CONTENT "{\"schema\":\"aida.c03.safe-headless.target-records.v2\",\"version\":2,\"targets\":[${_aida_records_joined}]}\n")
    get_property(_aida_runtime_outputs GLOBAL PROPERTY AIDA_C03_RUNTIME_OUTPUTS)
    add_custom_target(aida_c03_safe_headless_runtime_files DEPENDS ${_aida_runtime_outputs})
    set_target_properties(aida_c03_safe_headless_runtime_files PROPERTIES
        FOLDER "Tests/C03/SafeHeadless"
        AIDA_C03_SAFE_HEADLESS TRUE
        AIDA_C03_AUTHORITY_SURFACE_IDENTITY "${_aida_authority_identity}"
        AIDA_C03_SURFACE_GENERATOR_SHA256 "${_aida_surface_generator_sha256}"
        AIDA_C03_SURFACE_BASELINE_SHA256 "${_aida_surface_baseline_sha256}"
        AIDA_C03_SURFACE_FINAL_SHA256 "${_aida_surface_final_sha256}"
        LABELS "c03;c03_safe_headless;safe-headless;fixtures")

    file(SHA256 "${AIDA_C03_SAFE_HEADLESS_INVENTORY}" _aida_contract_identity)
    file(SHA256 "${AIDA_C03_SAFE_HEADLESS_ASSERTION_INVENTORY}" _aida_assertion_inventory_identity)
    file(SHA256 "${AIDA_C03_SAFE_HEADLESS_MATERIALIZER}" _aida_materializer_identity)
    file(SHA256 "${AIDA_C03_SAFE_HEADLESS_RESOURCE_POLICY_CASES}" _aida_resource_policy_cases_identity)
    file(SHA256 "${CMAKE_SOURCE_DIR}/CMakeLists.txt" _aida_root_cmake_identity)
    file(SHA256 "${AIDA_C03_SAFE_HEADLESS_CMAKE_MODULE}" _aida_manifest_cmake_identity)
    file(SHA256 "${CMAKE_SOURCE_DIR}/cmake/aida_c03_dependencies.cmake" _aida_dependency_cmake_identity)
    string(TOLOWER "${_aida_contract_identity}" _aida_contract_identity)
    string(TOLOWER "${_aida_assertion_inventory_identity}" _aida_assertion_inventory_identity)
    string(SHA256 _aida_build_identity
        "aida-c03-safe-headless|${_aida_contract_identity}|${_aida_assertion_inventory_identity}|${_aida_materializer_identity}|${_aida_resource_policy_cases_identity}|${_aida_root_cmake_identity}|${_aida_manifest_cmake_identity}|${_aida_dependency_cmake_identity}|${_aida_authority_identity}")
    string(TOLOWER "${_aida_build_identity}" _aida_build_identity)
    add_custom_command(OUTPUT "${AIDA_C03_SAFE_HEADLESS_MANIFEST}"
        COMMAND ${CMAKE_COMMAND} -E make_directory "${AIDA_C03_SAFE_HEADLESS_STAGE_ROOT}"
        COMMAND ${CMAKE_COMMAND} -E make_directory "${AIDA_C03_SAFE_HEADLESS_STAGE_ROOT}/scratch"
        COMMAND "${_aida_python_executable}" "${AIDA_C03_SAFE_HEADLESS_MATERIALIZER}"
            --inventory "${AIDA_C03_SAFE_HEADLESS_INVENTORY}"
            --target-records "${AIDA_C03_SAFE_HEADLESS_RECORDS}"
            --policy-cases "${AIDA_C03_SAFE_HEADLESS_RESOURCE_POLICY_CASES}"
            --approved-root "${AIDA_C03_SAFE_HEADLESS_STAGE_ROOT}"
            --output "${AIDA_C03_SAFE_HEADLESS_MANIFEST}"
            --build-identity "${_aida_build_identity}"
            --contract-identity "${_aida_contract_identity}"
        DEPENDS
            ${_aida_manifest_targets}
            aida_c03_safe_headless_runtime_files
            "${AIDA_C03_SAFE_HEADLESS_RECORDS}"
            "${AIDA_C03_SAFE_HEADLESS_INVENTORY}"
            "${AIDA_C03_SAFE_HEADLESS_ASSERTION_INVENTORY}"
            "${AIDA_C03_SAFE_HEADLESS_MATERIALIZER}"
            "${AIDA_C03_SAFE_HEADLESS_RESOURCE_POLICY_CASES}"
        VERBATIM)
    add_custom_target(aida_c03_safe_headless_manifest
        DEPENDS
            "${AIDA_C03_SAFE_HEADLESS_MANIFEST}")
    set_target_properties(aida_c03_safe_headless_manifest PROPERTIES
        FOLDER "Tests/C03/SafeHeadless"
        AIDA_C03_SAFE_HEADLESS TRUE
        AIDA_C03_DEVELOPER_ONLY TRUE
        AIDA_C03_DEVELOPER_SUITE_OUTPUTS "suite/$<CONFIG>/manifest.json"
        AIDA_C03_ASSERTION_INVENTORY_SHA256 "${_aida_assertion_inventory_identity}"
        AIDA_C03_AUTHORITY_SURFACE_IDENTITY "${_aida_authority_identity}"
        AIDA_C03_CONTRACT_GENERATOR_SHA256 "${_aida_contract_generator_sha256}"
        AIDA_C03_SURFACE_GENERATOR_SHA256 "${_aida_surface_generator_sha256}"
        AIDA_C03_SURFACE_BASELINE_SHA256 "${_aida_surface_baseline_sha256}"
        AIDA_C03_SURFACE_FINAL_SHA256 "${_aida_surface_final_sha256}"
        AIDA_C03_PYTHON_EXECUTABLE "${_aida_python_executable}"
        AIDA_C03_PYTHON_SHA256 "${_aida_python_sha256}"
        AIDA_C03_POWERSHELL_EXECUTABLE "${_aida_system_powershell}"
        AIDA_C03_POWERSHELL_SHA256 "${_aida_system_powershell_sha256}"
        AIDA_C03_MCP_ARCHIVE "${_aida_authority_archive}"
        AIDA_C03_MCP_ARCHIVE_SHA256 "${_aida_authority_archive_sha256}"
        LABELS "c03;c03_safe_headless;safe-headless;manifest")

    add_custom_target(aida_c03_safe_headless_application_package
        DEPENDS aida_c03_safe_headless_manifest
        COMMENT "Binding the detached C03 safe-headless manifest identity to ${application_target}"
        VERBATIM)
    set_target_properties(aida_c03_safe_headless_application_package PROPERTIES
        FOLDER "Packaging/C03"
        AIDA_C03_SAFE_HEADLESS TRUE
        AIDA_C03_AUTHORITY_SURFACE_IDENTITY "${_aida_authority_identity}"
        AIDA_C03_PYTHON_SHA256 "${_aida_python_sha256}"
        AIDA_C03_POWERSHELL_SHA256 "${_aida_system_powershell_sha256}"
        AIDA_C03_MCP_ARCHIVE_SHA256 "${_aida_authority_archive_sha256}"
        AIDA_C03_CUSTOMER_PAYLOAD_FORBIDDEN TRUE
        LABELS "c03;c03_safe_headless;safe-headless;package")
    add_dependencies(${application_target} aida_c03_safe_headless_application_package)
    target_include_directories(${application_target} PRIVATE "${AIDA_C03_SAFE_HEADLESS_GENERATED_ROOT}")

    add_executable(aida_c03_safe_headless_manifest_suite
        "${AIDA_C03_SAFE_HEADLESS_CMAKE_ROOT}/c03_safe_headless/manifest_suite_main.cpp"
        "${STANDALONE_ROOT}/core/testlab/test_lab_features_c03_safe_headless.cpp"
        "${imgui_SOURCE_DIR}/imgui.cpp"
        "${imgui_SOURCE_DIR}/imgui_draw.cpp"
        "${imgui_SOURCE_DIR}/imgui_tables.cpp"
        "${imgui_SOURCE_DIR}/imgui_widgets.cpp")
    aida_c03_configure_native_target(aida_c03_safe_headless_manifest_suite)
    target_include_directories(aida_c03_safe_headless_manifest_suite PRIVATE "${imgui_SOURCE_DIR}")
    target_link_libraries(aida_c03_safe_headless_manifest_suite PRIVATE
        aida_c03_safe_headless_runtime bcrypt advapi32 userenv)
    add_dependencies(aida_c03_safe_headless_manifest_suite aida_c03_safe_headless_manifest)
    set_target_properties(aida_c03_safe_headless_manifest_suite PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${AIDA_C03_DEVELOPER_ROOT}/direct/$<CONFIG>"
        FOLDER "Tests/C03/SafeHeadless/Direct"
        AIDA_C03_SAFE_HEADLESS TRUE
        LABELS "c03;c03_safe_headless;safe-headless;manifest-suite")
    aida_c03_copy_z3_runtime_dlls(aida_c03_safe_headless_manifest_suite)
    add_test(NAME aida_c03_safe_headless_manifest_suite
        COMMAND $<TARGET_FILE:aida_c03_safe_headless_manifest_suite> "${AIDA_C03_SAFE_HEADLESS_STAGE_ROOT}")
    set_tests_properties(aida_c03_safe_headless_manifest_suite PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        TIMEOUT 14400
        LABELS "c03;c03_safe_headless;safe-headless;manifest-suite"
        RESOURCE_LOCK "aida_c03_safe_headless_manifest")

    add_executable(aida_c03_testlab_fake_safe_headless_adapter
        "${AIDA_C03_TEST_ROOT}/testlab_runtime/fake_safe_headless_adapter.cpp"
        "${AIDA_C03_TEST_ROOT}/testlab_runtime/result_adapter.cpp")
    aida_c03_configure_native_target(aida_c03_testlab_fake_safe_headless_adapter)
    set_target_properties(aida_c03_testlab_fake_safe_headless_adapter PROPERTIES
        OUTPUT_NAME "aida_c03_testlab_fake_safe_headless_adapter"
        RUNTIME_OUTPUT_DIRECTORY "${AIDA_C03_DEVELOPER_ROOT}/direct/$<CONFIG>"
        FOLDER "Tests/C03/SafeHeadless/Support"
        AIDA_C03_SAFE_HEADLESS TRUE)
    add_executable(aida_c03_b14_fake_native_decompiler_worker
        "${STANDALONE_ROOT}/../workers/native_decompiler/fake_native_decompiler_worker.cpp"
        "${STANDALONE_ROOT}/core/analysis/decompiler/decompiler_contracts.cpp"
        "${STANDALONE_ROOT}/core/analysis/workspace/workspace_identity.cpp")
    aida_c03_configure_native_target(aida_c03_b14_fake_native_decompiler_worker)
    target_link_libraries(aida_c03_b14_fake_native_decompiler_worker PRIVATE bcrypt advapi32 ws2_32)
    target_link_options(aida_c03_b14_fake_native_decompiler_worker PRIVATE /ENTRY:wmainCRTStartup)
    set_target_properties(aida_c03_b14_fake_native_decompiler_worker PROPERTIES
        OUTPUT_NAME "fake_native_decompiler_worker"
        RUNTIME_OUTPUT_DIRECTORY "${AIDA_C03_DEVELOPER_ROOT}/direct/$<CONFIG>"
        FOLDER "Tests/C03/SafeHeadless/Support"
        WIN32_EXECUTABLE TRUE
        AIDA_C03_SAFE_HEADLESS TRUE)
    add_executable(aida_c03_b24_fake_analysis_python_worker
        "${STANDALONE_ROOT}/../workers/analysis_python/fake_analysis_python_worker.cpp")
    aida_c03_configure_native_target(aida_c03_b24_fake_analysis_python_worker)
    target_include_directories(aida_c03_b24_fake_analysis_python_worker PRIVATE
        "${STANDALONE_ROOT}/../workers/analysis_python")
    target_link_libraries(aida_c03_b24_fake_analysis_python_worker PRIVATE bcrypt advapi32 ws2_32)
    set_target_properties(aida_c03_b24_fake_analysis_python_worker PROPERTIES
        OUTPUT_NAME "fake_analysis_python_worker"
        RUNTIME_OUTPUT_DIRECTORY "${AIDA_C03_DEVELOPER_ROOT}/direct/$<CONFIG>"
        FOLDER "Tests/C03/SafeHeadless/Support"
        AIDA_C03_SAFE_HEADLESS TRUE)
    set_property(GLOBAL APPEND PROPERTY AIDA_C03_COMPILER_MATRIX_HARNESS_INPUTS
        "${AIDA_C03_SAFE_HEADLESS_CMAKE_ROOT}/c03_safe_headless/manifest_suite_main.cpp"
        "${STANDALONE_ROOT}/core/testlab/test_lab_features_c03_safe_headless.cpp"
        "${AIDA_C03_TEST_ROOT}/testlab_runtime/fake_safe_headless_adapter.cpp"
        "${STANDALONE_ROOT}/../workers/native_decompiler/fake_native_decompiler_worker.cpp"
        "${STANDALONE_ROOT}/core/analysis/decompiler/decompiler_contracts.cpp"
        "${STANDALONE_ROOT}/core/analysis/workspace/workspace_identity.cpp"
        "${STANDALONE_ROOT}/../workers/analysis_python/fake_analysis_python_worker.cpp")

    aida_c03_register_direct_test(
        TARGET aida_c03_testlab_runtime_integration_harness PACKAGE D07 TIMEOUT 180
        SOURCES
            "${AIDA_C03_TEST_ROOT}/harness_testlab_integration.cpp"
            "${AIDA_C03_TEST_ROOT}/testlab_runtime/result_adapter.cpp"
            "${STANDALONE_ROOT}/core/testlab/test_lab_features_c03_safe_headless.cpp"
            "${imgui_SOURCE_DIR}/imgui.cpp"
            "${imgui_SOURCE_DIR}/imgui_draw.cpp"
            "${imgui_SOURCE_DIR}/imgui_tables.cpp"
            "${imgui_SOURCE_DIR}/imgui_widgets.cpp"
        ARGUMENTS
            "$<TARGET_FILE:aida_c03_testlab_fake_safe_headless_adapter>"
            "${AIDA_C03_DEVELOPER_ROOT}/scratch/testlab"
        INCLUDE_DIRECTORIES "${imgui_SOURCE_DIR}"
        LINK_LIBRARIES bcrypt advapi32 userenv
        DEPENDS aida_c03_testlab_fake_safe_headless_adapter)
    aida_c03_register_direct_test(
        TARGET aida_c03_b14_native_worker_containment_harness PACKAGE B14 TIMEOUT 180
        SOURCES "${AIDA_C03_TEST_ROOT}/native_worker_protocol_harness.cpp"
        ARGUMENTS
            "$<TARGET_FILE:aida_c03_b14_fake_native_decompiler_worker>"
            "${AIDA_C03_DEVELOPER_ROOT}/scratch/native-worker"
        LINK_LIBRARIES bcrypt advapi32 userenv ws2_32
        DEPENDS aida_c03_b14_fake_native_decompiler_worker)
    aida_c03_register_direct_test(
        TARGET aida_c03_b24_python_worker_containment_harness PACKAGE B24 TIMEOUT 180
        SOURCES
            "${AIDA_C03_MCP_TEST_ROOT}/python_worker_harness_main.cpp"
            "${AIDA_C03_MCP_TEST_ROOT}/python_worker_harness.cpp"
        ARGUMENTS "$<TARGET_FILE:aida_c03_b24_fake_analysis_python_worker>"
        INCLUDE_DIRECTORIES "${STANDALONE_ROOT}/../workers/analysis_python"
        LINK_LIBRARIES bcrypt advapi32 userenv ws2_32
        DEPENDS aida_c03_b24_fake_analysis_python_worker)
    aida_c03_register_direct_test(
        TARGET aida_c03_mcp_production_core_harness PACKAGE D03 TIMEOUT 300
        SOURCES
            "${AIDA_C03_TEST_ROOT}/mcp_production_core/main.cpp"
            "${AIDA_C03_TEST_ROOT}/mcp_production_core/mcp_production_core_harness.cpp")
    aida_c03_register_direct_test(
        TARGET aida_c03_compact_dex_harness PACKAGE B11
        SOURCES "${AIDA_C03_TEST_ROOT}/compact_dex/compact_dex_harness.cpp")
    aida_c03_register_direct_test(
        TARGET aida_c03_overlay_lifecycle_harness PACKAGE C24
        SOURCES "${AIDA_C03_TEST_ROOT}/overlay_lifecycle_harness.cpp")
    aida_c03_register_direct_test(
        TARGET aida_c03_managed_overlay_identity_harness PACKAGE C24 TIMEOUT 300
        SOURCES
            "${AIDA_C03_TEST_ROOT}/managed_overlay_identity/main.cpp"
            "${AIDA_C03_TEST_ROOT}/managed_overlay_identity/managed_overlay_identity_harness.cpp")
    aida_c03_register_direct_test(
        TARGET aida_c03_auth_browser_dispatch_harness PACKAGE D08 TIMEOUT 300
        SOURCES
            "${AIDA_C03_TEST_ROOT}/auth_browser_dispatch/auth_browser_dispatch_harness.cpp")
    aida_c03_register_direct_test(
        NO_SHARED_RUNTIME
        TARGET aida_c03_auth_browser_dispatch_preview_harness PACKAGE D08 TIMEOUT 300
        SOURCES
            "${AIDA_C03_TEST_ROOT}/auth_browser_dispatch/auth_browser_dispatch_harness.cpp"
        COMPILE_DEFINITIONS AIDA_IMGUI_STUDIO_PREVIEW=1
        LINK_LIBRARIES aida_c03_auth_preview_implementation)

    aida_c03_register_direct_test(
        TARGET aida_c03_fixture_materializer_direct PACKAGE A06 TIMEOUT 300
        SOURCES
            "${AIDA_C03_TEST_ROOT}/fixture_materializer_harness_main.cpp"
            "${AIDA_C03_TEST_ROOT}/fixture_materializer_harness.cpp"
            "${AIDA_C03_TEST_ROOT}/fixture_materializer.cpp"
            "${AIDA_C03_TEST_ROOT}/managed_fixture_fidelity/managed_fixture_fidelity.cpp"
            "${AIDA_C03_TEST_ROOT}/decompiler_quality_schema.cpp"
            "${AIDA_C03_TEST_ROOT}/evidence_hash.cpp"
        ARGUMENTS
            "${CMAKE_SOURCE_DIR}"
            "${AIDA_C03_DEVELOPER_ROOT}/fixtures/materialized")
    set_tests_properties(aida_c03_fixture_materializer_direct PROPERTIES
        FIXTURES_SETUP aida_c03_materialized_corpus)

    aida_c03_register_direct_test(
        TARGET aida_c03_workspace_core_harness PACKAGE D01 TIMEOUT 600
        SOURCES
            "${AIDA_C03_WORKSPACE_TEST_ROOT}/workspace_core_harness.cpp"
            "${STANDALONE_ROOT}/core/session/analysis_session.cpp"
        LINK_LIBRARIES bcrypt)
    aida_c03_register_direct_test(
        TARGET aida_c03_workspace_persistence_harness PACKAGE D01 TIMEOUT 600
        SOURCES "${AIDA_C03_WORKSPACE_TEST_ROOT}/workspace_persistence_harness.cpp")
    aida_c03_register_direct_test(
        TARGET aida_c03_workspace_multitarget_harness PACKAGE D01 TIMEOUT 600
        SOURCES "${AIDA_C03_WORKSPACE_TEST_ROOT}/workspace_multitarget_harness.cpp")

    aida_c03_register_direct_test(
        TARGET aida_c03_analysis_benchmark_harness PACKAGE A06 TIMEOUT 1200
        SOURCES
            "${AIDA_C03_WORKSPACE_TEST_ROOT}/analysis_benchmark_harness.cpp"
            "${AIDA_C03_TEST_ROOT}/benchmark_sla_schema.cpp"
            "${AIDA_C03_TEST_ROOT}/decompiler_quality_schema.cpp"
            "${AIDA_C03_TEST_ROOT}/evidence_hash.cpp"
        ARGUMENTS
            "deterministic_component"
            "${AIDA_C03_DEVELOPER_ROOT}/fixtures/materialized/first/pe32plus-x64.exe"
        LINK_LIBRARIES bcrypt)
    set_tests_properties(aida_c03_analysis_benchmark_harness PROPERTIES
        FIXTURES_REQUIRED aida_c03_materialized_corpus)

    aida_c03_register_direct_test(
        TARGET aida_c03_search_index_parity_harness PACKAGE A06 TIMEOUT 600
        SOURCES "${AIDA_C03_WORKSPACE_TEST_ROOT}/search_index_parity_harness.cpp"
        LINK_LIBRARIES bcrypt)
    aida_c03_register_direct_test(
        TARGET aida_c03_workspace_provider_budget_harness PACKAGE D01 TIMEOUT 600
        SOURCES "${AIDA_C03_TEST_ROOT}/workspace_provider_budget_harness.cpp"
        LINK_LIBRARIES bcrypt)
    aida_c03_register_direct_test(
        TARGET aida_c03_analysis_validation_parity_harness PACKAGE A06 TIMEOUT 600
        SOURCES "${AIDA_C03_WORKSPACE_TEST_ROOT}/analysis_validation_parity_harness.cpp"
        LINK_LIBRARIES bcrypt)
    aida_c03_register_direct_test(
        TARGET aida_c03_large_pe_fixture_harness PACKAGE A06 TIMEOUT 900
        SOURCES "${AIDA_C03_WORKSPACE_TEST_ROOT}/large_pe_fixture_harness.cpp"
        LINK_LIBRARIES bcrypt)
    aida_c03_register_direct_test(
        TARGET aida_c03_benchmark_synthetic_harness PACKAGE A06 TIMEOUT 1200
        SOURCES
            "${AIDA_C03_WORKSPACE_TEST_ROOT}/analysis_benchmark_harness.cpp"
            "${AIDA_C03_TEST_ROOT}/benchmark_sla_schema.cpp"
            "${AIDA_C03_TEST_ROOT}/decompiler_quality_schema.cpp"
            "${AIDA_C03_TEST_ROOT}/evidence_hash.cpp"
        ARGUMENTS "synthetic" "32" "0xA1DA0001"
        LINK_LIBRARIES bcrypt)
    aida_c03_register_direct_test(
        TARGET aida_c03_benchmark_scaling_harness PACKAGE A06 TIMEOUT 2400
        SOURCES
            "${AIDA_C03_WORKSPACE_TEST_ROOT}/analysis_benchmark_harness.cpp"
            "${AIDA_C03_TEST_ROOT}/benchmark_sla_schema.cpp"
            "${AIDA_C03_TEST_ROOT}/decompiler_quality_schema.cpp"
            "${AIDA_C03_TEST_ROOT}/evidence_hash.cpp"
        ARGUMENTS "scaling" "32" "0xA1DA0002" "1,2,4"
        LINK_LIBRARIES bcrypt)
    aida_c03_register_direct_test(
        TARGET aida_c03_benchmark_determinism_harness PACKAGE A06 TIMEOUT 2400
        SOURCES
            "${AIDA_C03_WORKSPACE_TEST_ROOT}/analysis_benchmark_harness.cpp"
            "${AIDA_C03_TEST_ROOT}/benchmark_sla_schema.cpp"
            "${AIDA_C03_TEST_ROOT}/decompiler_quality_schema.cpp"
            "${AIDA_C03_TEST_ROOT}/evidence_hash.cpp"
        ARGUMENTS "determinism" "32" "0xA1DA0003"
        LINK_LIBRARIES bcrypt)
    aida_c03_register_direct_test(
        TARGET aida_c03_benchmark_determinism_hw_harness PACKAGE A06 TIMEOUT 2400
        SOURCES
            "${AIDA_C03_WORKSPACE_TEST_ROOT}/analysis_benchmark_harness.cpp"
            "${AIDA_C03_TEST_ROOT}/benchmark_sla_schema.cpp"
            "${AIDA_C03_TEST_ROOT}/decompiler_quality_schema.cpp"
            "${AIDA_C03_TEST_ROOT}/evidence_hash.cpp"
        ARGUMENTS "determinism_hw" "32" "0xA1DA0005"
        LINK_LIBRARIES bcrypt)
    aida_c03_register_direct_test(
        TARGET aida_c03_benchmark_synthetic_256mb_harness PACKAGE A06 TIMEOUT 2400
        SOURCES
            "${AIDA_C03_WORKSPACE_TEST_ROOT}/analysis_benchmark_harness.cpp"
            "${AIDA_C03_TEST_ROOT}/benchmark_sla_schema.cpp"
            "${AIDA_C03_TEST_ROOT}/decompiler_quality_schema.cpp"
            "${AIDA_C03_TEST_ROOT}/evidence_hash.cpp"
        ARGUMENTS "synthetic" "256" "0xA1DA0004"
        LINK_LIBRARIES bcrypt)
    aida_c03_register_direct_test(
        TARGET aida_c03_benchmark_real_harness PACKAGE A06 TIMEOUT 1800
        SOURCES
            "${AIDA_C03_WORKSPACE_TEST_ROOT}/analysis_benchmark_harness.cpp"
            "${AIDA_C03_TEST_ROOT}/benchmark_sla_schema.cpp"
            "${AIDA_C03_TEST_ROOT}/decompiler_quality_schema.cpp"
            "${AIDA_C03_TEST_ROOT}/evidence_hash.cpp"
        ARGUMENTS "real" "${AIDA_BENCHMARK_REAL_PE}"
        LINK_LIBRARIES bcrypt)
    if(NOT AIDA_BENCHMARK_REAL_PE)
        set_tests_properties(aida_c03_benchmark_real_harness PROPERTIES DISABLED TRUE)
    endif()
    aida_c03_register_direct_test(
        TARGET aida_c03_benchmark_synthetic_320mb_harness PACKAGE A06 TIMEOUT 3000
        SOURCES
            "${AIDA_C03_WORKSPACE_TEST_ROOT}/analysis_benchmark_harness.cpp"
            "${AIDA_C03_TEST_ROOT}/benchmark_sla_schema.cpp"
            "${AIDA_C03_TEST_ROOT}/decompiler_quality_schema.cpp"
            "${AIDA_C03_TEST_ROOT}/evidence_hash.cpp"
        ARGUMENTS "synthetic" "320" "0xA1DA0007"
        LINK_LIBRARIES bcrypt)
    aida_c03_register_direct_test(
        TARGET aida_c03_benchmark_synthetic_320mb_compare_harness PACKAGE A06 TIMEOUT 3000
        SOURCES
            "${AIDA_C03_WORKSPACE_TEST_ROOT}/analysis_benchmark_harness.cpp"
            "${AIDA_C03_TEST_ROOT}/benchmark_sla_schema.cpp"
            "${AIDA_C03_TEST_ROOT}/decompiler_quality_schema.cpp"
            "${AIDA_C03_TEST_ROOT}/evidence_hash.cpp"
        ARGUMENTS "synthetic_compare" "320" "0xA1DA0008" "${AIDA_C03_WORKSPACE_TEST_ROOT}/baselines/synthetic_320mb_baseline.json"
        LINK_LIBRARIES bcrypt)
    aida_c03_register_direct_test(
        TARGET aida_c03_benchmark_synthetic_compare_harness PACKAGE A06 TIMEOUT 1200
        SOURCES
            "${AIDA_C03_WORKSPACE_TEST_ROOT}/analysis_benchmark_harness.cpp"
            "${AIDA_C03_TEST_ROOT}/benchmark_sla_schema.cpp"
            "${AIDA_C03_TEST_ROOT}/decompiler_quality_schema.cpp"
            "${AIDA_C03_TEST_ROOT}/evidence_hash.cpp"
        ARGUMENTS "synthetic_compare" "32" "0xA1DA0006" "${AIDA_C03_WORKSPACE_TEST_ROOT}/baselines/synthetic_32mb_baseline.json"
        LINK_LIBRARIES bcrypt)

    set(_aida_managed_consumer_sources
        "${AIDA_C03_TEST_ROOT}/managed_decompiler_consumers/main.cpp"
        "${AIDA_C03_TEST_ROOT}/managed_decompiler_consumers/managed_decompiler_consumers_harness.cpp")
    aida_c03_register_direct_test(
        TARGET aida_c03_managed_decompiler_consumers_harness PACKAGE D02 TIMEOUT 1200
        SOURCES ${_aida_managed_consumer_sources}
        ARGUMENTS
            "--cli-fixture" "${AIDA_C03_MANAGED_FIXTURE_DLL}"
            "--class-fixture" "${AIDA_C03_DEVELOPER_ROOT}/fixtures/materialized/first/classfile-jvm.class"
            "--dex-fixture" "${AIDA_C03_DEVELOPER_ROOT}/fixtures/materialized/first/dex-dalvik.dex"
        LINK_LIBRARIES
            bcrypt
        DEPENDS aida_c03_a06_managed_cli_fixture)
    set_tests_properties(aida_c03_managed_decompiler_consumers_harness PROPERTIES
        FIXTURES_REQUIRED aida_c03_materialized_corpus)

    get_property(_aida_compiler_harness_inputs GLOBAL PROPERTY AIDA_C03_COMPILER_MATRIX_HARNESS_INPUTS)
    get_property(_aida_compiler_native_worker_inputs GLOBAL PROPERTY AIDA_C03_COMPILER_MATRIX_NATIVE_WORKER_INPUTS)
    get_property(_aida_compiler_managed_worker_inputs GLOBAL PROPERTY AIDA_C03_COMPILER_MATRIX_MANAGED_WORKER_INPUTS)
    list(APPEND AIDA_C03_COMPILER_MATRIX_CM_06 ${_aida_compiler_native_worker_inputs})
    list(APPEND AIDA_C03_COMPILER_MATRIX_CM_07 ${_aida_compiler_managed_worker_inputs})
    list(APPEND AIDA_C03_COMPILER_MATRIX_CM_14 ${_aida_compiler_harness_inputs})
    list(REMOVE_DUPLICATES AIDA_C03_COMPILER_MATRIX_CM_06)
    list(REMOVE_DUPLICATES AIDA_C03_COMPILER_MATRIX_CM_07)
    list(REMOVE_DUPLICATES AIDA_C03_COMPILER_MATRIX_CM_14)
    set(AIDA_C03_COMPILER_MATRIX_UNION)
    foreach(_aida_matrix_suffix IN ITEMS 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15)
        list(APPEND AIDA_C03_COMPILER_MATRIX_UNION ${AIDA_C03_COMPILER_MATRIX_CM_${_aida_matrix_suffix}})
    endforeach()
    list(REMOVE_DUPLICATES AIDA_C03_COMPILER_MATRIX_UNION)
    foreach(_aida_production_source IN LISTS AIDA_C03_PRODUCTION_STANDALONE_SOURCES)
        if(NOT _aida_production_source IN_LIST AIDA_C03_COMPILER_MATRIX_UNION)
            message(WARNING "AiDA C03 production source is absent from CM-01..CM-15: ${_aida_production_source}")
        endif()
    endforeach()
    foreach(_aida_runtime_source IN LISTS _aida_runtime_sources)
        if(NOT _aida_runtime_source IN_LIST AIDA_C03_COMPILER_MATRIX_UNION)
            message(WARNING "AiDA C03 safe-headless runtime source is absent from CM-01..CM-15: ${_aida_runtime_source}")
        endif()
    endforeach()
    aida_c03_require_sources("CM-01..CM-15 compiler matrix" ${AIDA_C03_COMPILER_MATRIX_UNION})

    get_property(_aida_direct_targets GLOBAL PROPERTY AIDA_C03_DIRECT_TARGETS)
    add_custom_target(aida_c03_safe_headless_harnesses ALL
        DEPENDS
            aida_c03_safe_headless_manifest
            aida_c03_safe_headless_manifest_suite
            ${_aida_direct_targets}
        SOURCES ${AIDA_C03_COMPILER_MATRIX_UNION})
    set_target_properties(aida_c03_safe_headless_harnesses PROPERTIES
        FOLDER "Tests/C03/SafeHeadless"
        AIDA_C03_SAFE_HEADLESS TRUE
        LABELS "c03;c03_safe_headless;safe-headless")
    set_property(TARGET aida_c03_safe_headless_harnesses PROPERTY
        AIDA_C03_COMPILER_MATRIX_UNION "${AIDA_C03_COMPILER_MATRIX_UNION}")
    set_property(TARGET ${application_target} PROPERTY
        AIDA_C03_COMPILER_MATRIX_UNION "${AIDA_C03_COMPILER_MATRIX_UNION}")

    set(AIDA_C03_SAFE_HEADLESS_TARGETS "${_aida_manifest_targets}" PARENT_SCOPE)
    set(AIDA_C03_SAFE_HEADLESS_DIRECT_TARGETS "${_aida_direct_targets}" PARENT_SCOPE)
    set(AIDA_C03_SAFE_HEADLESS_MANIFEST "${AIDA_C03_SAFE_HEADLESS_MANIFEST}" PARENT_SCOPE)
    set(AIDA_C03_COMPILER_MATRIX_CM_15 "${AIDA_C03_COMPILER_MATRIX_CM_15}" PARENT_SCOPE)
    set(AIDA_C03_COMPILER_MATRIX_UNION "${AIDA_C03_COMPILER_MATRIX_UNION}" PARENT_SCOPE)
endfunction()
