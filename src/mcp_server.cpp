#include "aida_pro.hpp"
#include "ida_utils.hpp"
#include "instance_registry.hpp"
#ifdef __NT__
#include "aida_ipc.hpp"
#endif

#include <algorithm>
#include <queue>
#include <deque>
#include <chrono>
#include <exception>
#include <future>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

using json = nlohmann::json;

static std::atomic<instance_registry_t*> g_active_registry{nullptr};
thread_local const std::atomic<bool>* g_mcp_cancel_flag = nullptr;

struct scoped_mcp_cancel_flag_t
{
    const std::atomic<bool>* previous = nullptr;

    explicit scoped_mcp_cancel_flag_t(const std::atomic<bool>* flag)
        : previous(g_mcp_cancel_flag)
    {
        g_mcp_cancel_flag = flag;
    }

    ~scoped_mcp_cancel_flag_t()
    {
        g_mcp_cancel_flag = previous;
    }
};

static instance_registry_t* current_registry()
{
    return g_active_registry.load(std::memory_order_acquire);
}

static const char* kInstanceArgKey = "instance_id";
static const char* kPidArgKey      = "pid";
static const char* kPeerInstanceHeader = "X-AiDA-Peer-Instance";
static const char* kPeerGenerationHeader = "X-AiDA-Peer-Generation";
static const char* kPeerCapabilityHeader = "X-AiDA-Peer-Capability";

static bool authenticate_peer_request(const httplib::Request& req)
{
    auto* registry = current_registry();
    if (!registry)
        return false;
    ida_peer_authentication_t presented;
    presented.instance_id = req.get_header_value(kPeerInstanceHeader);
    presented.lifecycle_generation = req.get_header_value(kPeerGenerationHeader);
    presented.capability = req.get_header_value(kPeerCapabilityHeader);
    ida_peer_authentication_t local_auth;
    if (!registry->self_peer_authentication(local_auth))
        return false;
    presented.pid = 0;
    std::string pid_text = req.get_header_value("X-AiDA-Peer-Pid");
    try { presented.pid = static_cast<uint64_t>(std::stoull(pid_text)); }
    catch (...) { return false; }
    std::string started_text = req.get_header_value("X-AiDA-Peer-Started-At");
    try { presented.started_at_ms = static_cast<uint64_t>(std::stoull(started_text)); }
    catch (...) { return false; }
    return registry->authenticate_peer(presented);
}

static bool resolve_target_instance(const json& arguments,
                                    instance_registry_t* registry,
                                    bool& has_target,
                                    bool& target_is_self,
                                    ida_instance_record_t& out_peer,
                                    std::string& out_error)
{
    has_target = false;
    target_is_self = false;
    out_error.clear();

    if (!registry)
        return true;

    std::string requested_instance;
    if (arguments.contains(kInstanceArgKey) && arguments[kInstanceArgKey].is_string())
    {
        std::string s = arguments[kInstanceArgKey].get<std::string>();
        if (!s.empty())
            requested_instance = std::move(s);
    }

    uint64_t requested_pid = 0;
    if (arguments.contains(kPidArgKey))
    {
        const auto& v = arguments[kPidArgKey];
        if (v.is_number_integer())
        {
            int64_t n = v.get<int64_t>();
            if (n > 0)
                requested_pid = static_cast<uint64_t>(n);
        }
        else if (v.is_string())
        {
            try
            {
                std::string ps = v.get<std::string>();
                if (!ps.empty())
                {
                    int base = 10;
                    if (ps.size() > 2 && (ps[0] == '0') && (ps[1] == 'x' || ps[1] == 'X'))
                        base = 16;
                    requested_pid = static_cast<uint64_t>(std::stoull(ps, nullptr, base));
                }
            }
            catch (...) { requested_pid = 0; }
        }
    }

    if (!requested_instance.empty())
    {
        if (requested_instance == registry->self_instance_id())
        {
            has_target = true;
            target_is_self = true;
            return true;
        }
        if (!registry->find_instance(requested_instance, out_peer))
        {
            out_error = "Unknown instance_id: " + requested_instance;
            return false;
        }
        has_target = true;
        target_is_self = (out_peer.instance_id == registry->self_instance_id());
        return true;
    }

    if (requested_pid != 0)
    {
        if (requested_pid == registry->self_record().pid)
        {
            has_target = true;
            target_is_self = true;
            return true;
        }
        if (!registry->find_instance_by_pid(requested_pid, out_peer))
        {
            out_error = "Unknown pid: " + std::to_string(requested_pid);
            return false;
        }
        has_target = true;
        target_is_self = (out_peer.instance_id == registry->self_instance_id());
        return true;
    }

    return true;
}

static json strip_routing_args(const json& arguments)
{
    json out = arguments;
    if (out.is_object())
    {
        if (out.contains(kInstanceArgKey))
            out.erase(kInstanceArgKey);
        if (out.contains(kPidArgKey))
            out.erase(kPidArgKey);
    }
    return out;
}

struct mcp_remote_call_result_t
{
    bool ok = false;
    int  http_status = 0;
    json payload;
    std::string error_text;
};

static mcp_remote_call_result_t mcp_invoke_remote(const ida_instance_record_t& peer,
                                                  const json& request_body,
                                                  int timeout_seconds)
{
    mcp_remote_call_result_t out;
    if (peer.port <= 0)
    {
        out.error_text = "peer has no port";
        return out;
    }
    try
    {
        std::string host = "127.0.0.1";
        httplib::Client client(host, peer.port);
        client.set_connection_timeout(timeout_seconds);
        client.set_read_timeout(timeout_seconds);
        client.set_write_timeout(timeout_seconds);
        client.set_keep_alive(false);

        std::string body = json_dump_safe(request_body);
        httplib::Headers headers = {
            {"Content-Type", "application/json"},
            {"Accept",       "application/json"}
        };
        auto* registry = current_registry();
        ida_peer_authentication_t auth;
        if (!registry || !registry->self_peer_authentication(auth)
            || auth.instance_id.empty())
        {
            out.error_text = "local peer authentication unavailable";
            return out;
        }
        ida_peer_authentication_t peer_auth;
        if (!registry->load_peer_authentication(peer.instance_id, peer_auth)
            || peer_auth.instance_id != peer.instance_id
            || peer_auth.pid != peer.pid
            || peer_auth.started_at_ms != peer.started_at_ms)
        {
            out.error_text = "peer authentication unavailable";
            return out;
        }
        headers.emplace("X-AiDA-Peer-Instance", auth.instance_id);
        headers.emplace("X-AiDA-Peer-Generation", auth.lifecycle_generation);
        headers.emplace("X-AiDA-Peer-Capability", auth.capability);
        headers.emplace("X-AiDA-Peer-Pid", std::to_string(auth.pid));
        headers.emplace("X-AiDA-Peer-Started-At", std::to_string(auth.started_at_ms));
        auto res = client.Post("/mcp", headers, body, "application/json");
        if (!res)
        {
            out.error_text = "no response from peer";
            return out;
        }
        out.http_status = res->status;
        if (res->status < 200 || res->status >= 300)
        {
            out.error_text = "peer returned HTTP " + std::to_string(res->status);
            if (!res->body.empty())
                out.error_text += ": " + res->body.substr(0, 256);
            return out;
        }
        if (res->body.empty())
        {
            out.ok = true;
            return out;
        }
        try
        {
            out.payload = json::parse(res->body);
            out.ok = true;
        }
        catch (const json::parse_error& e)
        {
            out.error_text = std::string("malformed JSON from peer: ") + e.what();
        }
    }
    catch (const std::exception& e)
    {
        out.error_text = std::string("HTTP exception: ") + e.what();
    }
    return out;
}

static json mcp_proxy_tools_call_to_peer(const ida_instance_record_t& peer,
                                         const std::string& tool_name,
                                         const json& sanitized_arguments,
                                         int timeout_seconds)
{
    json req;
    req["jsonrpc"] = "2.0";
    req["id"] = 1;
    req["method"] = "tools/call";
    json params;
    params["name"] = tool_name;
    params["arguments"] = sanitized_arguments;
    req["params"] = params;
    auto rr = mcp_invoke_remote(peer, req, timeout_seconds);
    if (!rr.ok || rr.payload.is_null())
    {
        json err;
        err["isError"] = true;
        err["content"] = json::array({
            { {"type", "text"}, {"text",
                "Remote instance " + peer.instance_id + " (" + peer.display_name +
                ") failed: " + (rr.error_text.empty() ? "unknown error" : rr.error_text) } }
        });
        return err;
    }
    if (rr.payload.contains("result") && rr.payload["result"].is_object())
        return rr.payload["result"];
    if (rr.payload.contains("error") && rr.payload["error"].is_object())
    {
        json err;
        err["isError"] = true;
        std::string msg_txt = rr.payload["error"].value("message", "remote error");
        err["content"] = json::array({
            { {"type", "text"}, {"text",
                "Remote instance " + peer.instance_id + " error: " + msg_txt } }
        });
        return err;
    }
    json err;
    err["isError"] = true;
    err["content"] = json::array({
        { {"type", "text"}, {"text",
            "Remote instance " + peer.instance_id + " returned unexpected payload" } }
    });
    return err;
}

static json record_to_public_json(const ida_instance_record_t& r);
static agent_tools::tool_result_t aggregator_query_all(const json& params);

static bool mcp_is_manage_operation(const json& args, const std::string& op)
{
    return args.is_object() && args.value("operation", args.value("action", std::string())) == op;
}

static json mcp_prepare_inventory_all_arguments(const json& args)
{
    if (!mcp_is_manage_operation(args, "inventory_all"))
        return args;
    json out = args;
    if (!out.contains("payload") || !out["payload"].is_object())
        out["payload"] = json::object();
    json& payload = out["payload"];
    if (payload.contains("fanout_result") || payload.contains("inventories"))
        return out;
    json inventory_payload = payload;
    inventory_payload.erase("fanout_result");
    inventory_payload.erase("inventories");
    json fanout_args = {
        {"tool", "ida_project_manage"},
        {"arguments", {{"operation", "inventory_current"}, {"payload", inventory_payload}}},
        {"timeout_seconds", 60}
    };
    agent_tools::tool_result_t fanout = aggregator_query_all(fanout_args);
    if (fanout.success)
        payload["fanout_result"] = fanout.data;
    else
        payload["fanout_result"] = {{"ok", false}, {"error_code", fanout.error_code}, {"message", fanout.output}};
    payload["fanout_executed_by_router"] = true;
    return out;
}

static std::string mcp_module_id_from_peer_ref(const json& ref)
{
    if (!ref.is_object())
        return std::string();
    if (ref.contains("peer") && ref["peer"].is_object())
    {
        const json& peer = ref["peer"];
        for (const char* key : {"module_id", "corpus_id", "peer_id", "target_corpus_id"})
        {
            std::string value = peer.value(key, std::string());
            if (!value.empty())
                return value;
        }
    }
    for (const char* key : {"target_module_id", "module_id", "target_corpus_id", "corpus_id", "peer_id"})
    {
        std::string value = ref.value(key, std::string());
        if (!value.empty())
            return value;
    }
    return std::string();
}

static bool mcp_peer_matches_module(const ida_instance_record_t& rec, const std::string& module_id)
{
    if (module_id.empty())
        return false;
    return rec.module_id == module_id
        || rec.instance_id == module_id
        || rec.file_sha256 == module_id
        || rec.input_basename == module_id
        || rec.input_file == module_id;
}

static json mcp_address_from_trace_ref(const json& node)
{
    if (!node.is_object())
        return json();
    for (const char* key : {"address", "target", "callee", "entry", "function"})
    {
        if (node.contains(key) && (node[key].is_string() || node[key].is_object() || node[key].is_number()))
            return node[key];
    }
    for (const char* key : {"target_rva", "rva", "callee_rva", "entry_rva"})
    {
        if (node.contains(key) && !node[key].is_null())
            return json::object({{"rva", node[key]}});
    }
    return json();
}

static bool mcp_has_remote_trace_evidence(const json& cross)
{
    if (!cross.is_object())
        return false;
    if (cross.contains("remote_trace_evidence") && cross["remote_trace_evidence"].is_array() && !cross["remote_trace_evidence"].empty())
        return true;
    if (cross.contains("abi") && cross["abi"].is_object()
        && cross["abi"].contains("remote_trace_evidence")
        && cross["abi"]["remote_trace_evidence"].is_array()
        && !cross["abi"]["remote_trace_evidence"].empty())
        return true;
    return false;
}

static void mcp_append_peer_corpus(json& chain, const ida_instance_record_t& peer)
{
    if (!chain.contains("corpus") || !chain["corpus"].is_array())
        chain["corpus"] = json::array();
    const std::string corpus_id = peer.module_id.empty() ? peer.instance_id : peer.module_id;
    for (const auto& item : chain["corpus"])
    {
        if (!item.is_object())
            continue;
        if (item.value("corpus_id", item.value("id", std::string())) == corpus_id)
            return;
    }
    chain["corpus"].push_back({
        {"corpus_id", corpus_id},
        {"kind", "binary"},
        {"availability", "peer_loaded"},
        {"trust", "ida_peer"},
        {"chain_critical", true},
        {"identity", record_to_public_json(peer)}
    });
}

static void mcp_merge_remote_trace_for_cross(json& cross,
                                             const ida_instance_record_t& peer,
                                             const json& trace,
                                             const std::string& requested_module)
{
    if (!cross.contains("peer") || !cross["peer"].is_object())
        cross["peer"] = json::object();
    json& peer_json = cross["peer"];
    peer_json["peer_id"] = requested_module.empty() ? (peer.module_id.empty() ? peer.instance_id : peer.module_id) : requested_module;
    peer_json["instance_id"] = peer.instance_id;
    peer_json["module_id"] = peer.module_id;
    peer_json["index_generation"] = peer.index_generation;
    peer_json["image_base"] = peer.image_base;
    peer_json["image_min_ea"] = peer.image_min_ea;
    peer_json["image_max_ea"] = peer.image_max_ea;
    peer_json["missing"] = false;
    if (peer_json.contains("expected_index_generation") && peer_json["expected_index_generation"].is_string())
        peer_json["stale_generation"] = peer.index_generation != peer_json["expected_index_generation"].get<std::string>();
    if (!cross.contains("remote_trace_evidence") || !cross["remote_trace_evidence"].is_array())
        cross["remote_trace_evidence"] = json::array();
    cross["remote_trace_evidence"].push_back(trace);
    if (!cross.contains("abi") || !cross["abi"].is_object())
        cross["abi"] = json::object();
    json& abi = cross["abi"];
    if (!abi.contains("remote_trace_evidence") || !abi["remote_trace_evidence"].is_array())
        abi["remote_trace_evidence"] = json::array();
    abi["remote_trace_evidence"].push_back(trace);
}

static json mcp_remote_trace_request_for_cross(const json& cross)
{
    json address = mcp_address_from_trace_ref(cross);
    if ((address.is_null() || address.empty()) && cross.contains("cross_module_calls") && cross["cross_module_calls"].is_array())
    {
        for (const auto& call : cross["cross_module_calls"])
        {
            address = mcp_address_from_trace_ref(call);
            if (!address.is_null() && !address.empty())
                break;
        }
    }
    if (address.is_null() || address.empty())
        return json();
    json payload;
    payload["address"] = address;
    payload["layers"] = json::array({"xrefs", "calls", "types"});
    payload["max_depth"] = 4;
    payload["max_functions"] = 512;
    return {{"operation", "extract_xref_graph"}, {"payload", payload}};
}

static json mcp_remote_trace_result(const ida_instance_record_t& peer, const json& request, int timeout_seconds)
{
    json trace;
    trace["schema"] = "aida_remote_idb_trace_evidence_v1";
    trace["peer"] = record_to_public_json(peer);
    trace["request"] = request;
    trace["ok"] = false;
    json response = mcp_proxy_tools_call_to_peer(peer, "ida_extract_manage", request, timeout_seconds);
    trace["response"] = response;
    const bool is_error = response.contains("isError") && response["isError"].is_boolean() && response["isError"].get<bool>();
    trace["ok"] = !is_error;
    if (is_error)
        trace["reason"] = "remote_trace_request_failed";
    return trace;
}

static void mcp_mark_missing_peer(json& cross, const std::string& requested_module)
{
    if (!cross.contains("peer") || !cross["peer"].is_object())
        cross["peer"] = json::object();
    cross["peer"]["peer_id"] = requested_module;
    cross["peer"]["missing"] = true;
    cross["remote_trace_evidence"] = json::array({{{"schema", "aida_remote_idb_trace_evidence_v1"}, {"ok", false}, {"reason", "peer_data_missing"}, {"module_id", requested_module}}});
}

static json mcp_prepare_chain_arguments_with_remote_evidence(const json& args, instance_registry_t* registry)
{
    if (!registry || !args.is_object())
        return args;
    const std::string operation = args.value("operation", args.value("action", std::string()));
    if (operation != "submit" && operation != "start" && operation != "verify_link"
        && operation != "verify_chain" && operation != "case_study_regressions")
        return args;
    if (!args.contains("payload") || !args["payload"].is_object() || !args["payload"].contains("chain") || !args["payload"]["chain"].is_object())
        return args;
    json out = args;
    json& chain = out["payload"]["chain"];
    if (!chain.contains("links") || !chain["links"].is_array())
        return out;
    const std::string self_id = registry->self_instance_id();
    const auto instances = registry->all_live_instances();
    for (auto& link : chain["links"])
    {
        if (!link.is_object())
            continue;
        json* cross = nullptr;
        for (const char* key : {"cross_domain", "boundary_transition", "cross_transition"})
        {
            if (link.contains(key) && link[key].is_object())
            {
                cross = &link[key];
                break;
            }
        }
        if (cross == nullptr || mcp_has_remote_trace_evidence(*cross))
            continue;
        const std::string module_id = mcp_module_id_from_peer_ref(*cross);
        if (module_id.empty())
            continue;
        auto peer_it = std::find_if(instances.begin(), instances.end(), [&](const ida_instance_record_t& rec) {
            return rec.instance_id != self_id && mcp_peer_matches_module(rec, module_id);
        });
        if (peer_it == instances.end())
        {
            mcp_mark_missing_peer(*cross, module_id);
            continue;
        }
        mcp_append_peer_corpus(chain, *peer_it);
        json request = mcp_remote_trace_request_for_cross(*cross);
        if (request.empty())
        {
            mcp_merge_remote_trace_for_cross(*cross, *peer_it, {{"schema", "aida_remote_idb_trace_evidence_v1"}, {"ok", false}, {"reason", "target_address_missing"}}, module_id);
            continue;
        }
        json trace = mcp_remote_trace_result(*peer_it, request, 60);
        mcp_merge_remote_trace_for_cross(*cross, *peer_it, trace, module_id);
    }
    return out;
}

static json mcp_prepare_local_tool_arguments(const std::string& tool_name, const json& args, instance_registry_t* registry)
{
    if (tool_name == "ida_project_manage")
    {
        json prepared = mcp_prepare_inventory_all_arguments(args);
        return mcp_prepare_chain_arguments_with_remote_evidence(prepared, registry);
    }
    if (tool_name == "ida_chain_manage")
        return mcp_prepare_chain_arguments_with_remote_evidence(args, registry);
    return args;
}

static constexpr int JSONRPC_PARSE_ERROR      = -32700;
static constexpr int JSONRPC_INVALID_REQUEST  = -32600;
static constexpr int JSONRPC_METHOD_NOT_FOUND = -32601;
static constexpr int JSONRPC_INVALID_PARAMS   = -32602;
static constexpr int JSONRPC_INTERNAL_ERROR   = -32603;

static const std::string& get_mcp_protocol_version()
{
    static const std::string v = std::string("2025-06-18");
    return v;
}

static const std::string& get_mcp_server_instructions()
{
    static const std::string instructions =
        "AiDA IDA Pro Plugin MCP is self-describing. Do not expect external markdown files such as TOOLS.md; shipped users normally receive only AiDA.dll and AiDAStandalone.exe. Learn the available surface from this initialize response, `tools/list`, and targeted tool-schema discovery.\n\n"
        "AiDA IDA Pro Plugin - IDB-centered zero-day analysis for binaries loaded in IDA Pro. This plugin performs static analysis against the database and exposes debugger-backed process module inventory when IDA has an active debug session. Kernel-memory, number/address conversion, sandbox, browser, and network-interception capabilities live in AiDAStandalone and are NOT available here.\n\n"
        "Number, endian, VA, RVA, and file-offset conversions are handled by AiDAStandalone's `convert_number` tool. This IDA plugin does not expose `convert_number`; use IDA addresses as database EAs and prefer IDA segment/image-base evidence when reporting offsets.\n\n"
        "Capability families exposed by this plugin:\n"
        "- Function, decompilation, xref, type, segment, and static/dynamic module introspection over the loaded IDB and the active IDA debugger module list when present.\n"
        "- Pattern-based searches: strings, byte patterns, immediate values, and instruction patterns.\n"
        "- Static analysis: control flow, complexity metrics, obfuscation patterns, anti-analysis detection, PE parsing and entropy, indirect-call classification, vtable reconstruction, and VM-handler mapping.\n"
        "- Static deobfuscation: control-flow flattening unflattening, opaque predicate solving, stack-string decoding, anti-debug NOP patching of the in-memory IDB, import reconstruction, and section unpacking — all performed statically against the database.\n"
        "- GraphRAG: semantic search, taint paths, function communities, and network-flow graphs over the indexed binary.\n"
        "- Zero-day vulnerability tools: callsite enumeration of dangerous APIs, format-string bug discovery, microcode SSA dataflow analysis, interprocedural taint path enumeration, kernel IOCTL handler discovery with ProbeForRead/ProbeForWrite coverage analysis, attack-surface scoring, indirect-call resolution, and check-bypass path enumeration.\n\n"
        "First-use workflow: call `wait_for_analysis`, then `get_binary_info` or `survey_binary`, then `get_graph_stats`. If indexed, prefer `search_semantic` before slower string or instruction searches. Follow with `get_function`, `decompile_function`, `disassemble_function`, xrefs, basic blocks, and targeted type/comment tools.\n\n"
        "Batch related read-only tool calls aggressively, avoid duplicate calls with identical parameters, use pagination/limits before broad searches, and keep conclusions tied to concrete addresses, imports, strings, decompilation, microcode, or taint evidence. Mutating tools can patch or change the IDB; use them only when requested.\n\n"
        "MULTI-INSTANCE: Every running IDA Pro is a peer in this MCP mesh. Start by calling `list_ida_instances` "
        "to enumerate all live IDAs; each entry has instance_id (stable UUID), pid (OS process id), display_name, "
        "idb_path, input_file, file_md5/sha256, processor, bitness, port, and base_url. To target a specific IDA, "
        "pass EITHER `instance_id` OR `pid` as an argument on ANY tool call (every tool accepts both). instance_id "
        "wins if both are set; instance_id is stable across PID reuse, pid is human-friendly and matches Task Manager. "
        "Omit both to run against the locally connected IDA. To run a tool concurrently across every IDA, use "
        "`query_all_instances` with {tool, arguments}; it returns a per-instance result map with ok/error flags. "
        "Use `get_local_instance_info` if you need to know which IDA the current connection is bound to. Mix and "
        "match freely across calls — e.g., `find_bytes(pattern=A, pid=1234)` then `find_bytes(pattern=B, pid=5678)` "
        "addresses two different IDAs from the same conversation.\n\n"
        "Standard zero-day discovery chain: `find_input_sources` -> `find_vulnerable_sinks` -> `trace_taint_path` -> `explain_vulnerability_chain`.";
    return instructions;
}
#define MCP_PROTOCOL_VERSION get_mcp_protocol_version().c_str()

static std::string generate_session_id()
{

    unsigned char rnd[16] = {};
    NTSTATUS st = BCryptGenRandom(nullptr, rnd, sizeof(rnd),
                                  BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (st != 0) {
        auto t = std::chrono::steady_clock::now().time_since_epoch().count();
        for (size_t i = 0; i < sizeof(rnd); ++i)
            rnd[i] = static_cast<unsigned char>((t >> (i * 8)) ^ i);
    }
    static const char hex[] = "0123456789abcdef";
    std::string id;
    id.reserve(32);
    for (size_t i = 0; i < sizeof(rnd); ++i) {
        id.push_back(hex[rnd[i] >> 4]);
        id.push_back(hex[rnd[i] & 0x0f]);
    }
    return id;
}

static constexpr size_t MCP_OUTPUT_TEXT_LIMIT = 120000;
static constexpr size_t MCP_OUTPUT_CACHE_LIMIT = 64;

struct mcp_output_cache_t
{
    std::mutex mtx;
    std::deque<std::string> order;
    std::map<std::string, json> payloads;
};

static mcp_output_cache_t& get_mcp_output_cache()
{
    static mcp_output_cache_t cache;
    return cache;
}

static std::string cache_mcp_output_payload(const json& payload)
{
    std::string id = generate_session_id();
    auto& cache = get_mcp_output_cache();
    std::lock_guard<std::mutex> lock(cache.mtx);
    cache.payloads[id] = payload;
    cache.order.push_back(id);
    while (cache.order.size() > MCP_OUTPUT_CACHE_LIMIT)
    {
        cache.payloads.erase(cache.order.front());
        cache.order.pop_front();
    }
    return id;
}

static bool get_cached_mcp_output_payload(const std::string& id, json& out)
{
    auto& cache = get_mcp_output_cache();
    std::lock_guard<std::mutex> lock(cache.mtx);
    auto it = cache.payloads.find(id);
    if (it == cache.payloads.end())
        return false;
    out = it->second;
    return true;
}

// Slice B9 — extern accessor for meta_tools::list_outputs (lives in
// agent_tools.cpp). The cache itself is a translation-unit-local static so
// meta_tools cannot reach it directly; this helper exposes the three ops the
// MCP tool needs (list / stats / evict-by-id / evict-all). Keep the function
// signatures stable — meta_tools::list_outputs is the only consumer.
namespace aida_mcp_internal {

struct output_cache_entry_t
{
    std::string id;
    size_t      json_bytes = 0;
};

struct output_cache_stats_t
{
    size_t total_entries = 0;
    size_t total_bytes   = 0;
    size_t limit         = 0;
    size_t text_limit    = 0;
};

std::vector<output_cache_entry_t> output_cache_list();
output_cache_stats_t              output_cache_stats();
bool                              output_cache_evict_one(const std::string& id);
size_t                            output_cache_evict_all();

} // namespace aida_mcp_internal

std::vector<aida_mcp_internal::output_cache_entry_t>
aida_mcp_internal::output_cache_list()
{
    std::vector<output_cache_entry_t> out;
    auto& cache = get_mcp_output_cache();
    std::lock_guard<std::mutex> lock(cache.mtx);
    out.reserve(cache.order.size());
    for (const auto& id : cache.order)
    {
        auto it = cache.payloads.find(id);
        if (it == cache.payloads.end())
            continue;
        output_cache_entry_t e;
        e.id = id;
        try { e.json_bytes = json_dump_safe(it->second).size(); }
        catch (...) { e.json_bytes = 0; }
        out.push_back(std::move(e));
    }
    return out;
}

aida_mcp_internal::output_cache_stats_t
aida_mcp_internal::output_cache_stats()
{
    output_cache_stats_t s;
    auto& cache = get_mcp_output_cache();
    std::lock_guard<std::mutex> lock(cache.mtx);
    s.total_entries = cache.order.size();
    s.limit         = MCP_OUTPUT_CACHE_LIMIT;
    s.text_limit    = MCP_OUTPUT_TEXT_LIMIT;
    for (const auto& kv : cache.payloads)
    {
        try { s.total_bytes += json_dump_safe(kv.second).size(); }
        catch (...) {}
    }
    return s;
}

bool aida_mcp_internal::output_cache_evict_one(const std::string& id)
{
    auto& cache = get_mcp_output_cache();
    std::lock_guard<std::mutex> lock(cache.mtx);
    auto it = cache.payloads.find(id);
    if (it == cache.payloads.end())
        return false;
    cache.payloads.erase(it);
    for (auto oit = cache.order.begin(); oit != cache.order.end(); ++oit)
    {
        if (*oit == id) { cache.order.erase(oit); break; }
    }
    return true;
}

size_t aida_mcp_internal::output_cache_evict_all()
{
    auto& cache = get_mcp_output_cache();
    std::lock_guard<std::mutex> lock(cache.mtx);
    size_t n = cache.payloads.size();
    cache.payloads.clear();
    cache.order.clear();
    return n;
}

static json make_mcp_structured_content(const json& data)
{
    if (data.is_null() || data.empty())
        return json();
    if (data.is_object())
        return data;
    return json::object({{"result", data}});
}

static json build_mcp_tool_result_payload(const agent_tools::tool_result_t& tool_result)
{
    json content = json::array();
    json result;

    if (!tool_result.output.empty())
    {
        content.push_back({
            {"type", "text"},
            {"text", sanitize_utf8(tool_result.output)}
        });
    }

    if (!tool_result.data.is_null() && !tool_result.data.empty())
    {
        std::string data_text = json_dump_safe(tool_result.data, 2);
        if (data_text.size() > MCP_OUTPUT_TEXT_LIMIT)
        {
            std::string output_id = cache_mcp_output_payload(tool_result.data);
            std::string url = "/output/" + output_id + ".json";
            std::string preview = data_text.substr(0, MCP_OUTPUT_TEXT_LIMIT);
            preview += "\n\n[truncated: full JSON is available at " + url + "]";
            content.push_back({
                {"type", "text"},
                {"text", sanitize_utf8(preview)}
            });
            result["structuredContent"] = json::object({
                {"truncated", true},
                {"download_url", url},
                {"preview_bytes", MCP_OUTPUT_TEXT_LIMIT},
                {"total_bytes", data_text.size()}
            });
            result["_meta"]["ida_mcp"] = json::object({
                {"truncated", true},
                {"download_url", url},
                {"output_id", output_id},
                {"total_bytes", data_text.size()},
                {"preview_bytes", MCP_OUTPUT_TEXT_LIMIT}
            });
        }
        else
        {
            content.push_back({
                {"type", "text"},
                {"text", sanitize_utf8(data_text)}
            });
            result["structuredContent"] = make_mcp_structured_content(tool_result.data);
        }
    }

    if (content.empty())
    {
        content.push_back({
            {"type", "text"},
            {"text", tool_result.success ? "Tool executed successfully (no output)." : "Tool execution failed (no details)."}
        });
    }

    result["content"] = content;
    if (!tool_result.success)
        result["isError"] = true;
    return result;
}

struct mcp_tool_exec_request_t : public exec_request_t
{
    std::string tool_name;
    json tool_params;
    agent_tools::tool_result_t result;
    uint64_t exec_ms = 0;

    ssize_t idaapi execute() override
    {
        auto t0 = std::chrono::steady_clock::now();

        result = agent_tools::ToolRegistry::instance().execute_tool(tool_name, tool_params);

        exec_ms = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0).count());

        return 0;
    }
};

struct mcp_resource_exec_request_t : public exec_request_t
{
    std::string tool_name;
    json tool_params;
    agent_tools::tool_result_t result;

    ssize_t idaapi execute() override
    {
        result = agent_tools::ToolRegistry::instance().execute_tool(tool_name, tool_params);
        return 0;
    }
};

static void progress_begin(const std::string& tool, const std::string& stage);
static void progress_update(const std::string& tool, const std::string& stage, double fraction);
static void progress_end(const std::string& tool, const std::string& stage);

struct mcp_batch_exec_request_t : public exec_request_t
{
    std::vector<std::pair<std::string, json>> calls;
    std::vector<agent_tools::tool_result_t> results;
    bool include_rag = false;
    std::string rag_addr_str;
    json rag_result;
    bool rag_resolved = false;

    ssize_t idaapi execute() override
    {

        results.clear();
        results.reserve(calls.size());

        const bool multi = calls.size() > 1;
        if (multi)
            progress_begin("mcp_prompt_batch", "execute");

        for (size_t ci = 0; ci < calls.size(); ++ci)
        {
            if (multi)
                progress_update("mcp_prompt_batch", calls[ci].first, static_cast<double>(ci) / static_cast<double>(calls.size()));

            results.push_back(agent_tools::ToolRegistry::instance().execute_tool(
                calls[ci].first, calls[ci].second));
        }

        if (multi)
            progress_end("mcp_prompt_batch", "complete");

        if (include_rag && !rag_addr_str.empty())
        {
            ea_t ea = BADADDR;
            ea = get_name_ea(BADADDR, rag_addr_str.c_str());
            if (ea == BADADDR)
            {
                try
                {
                    std::string clean = rag_addr_str;
                    if (clean.size() > 2
                        && clean[0] == '0'
                        && (clean[1] == 'x' || clean[1] == 'X'))
                    {
                        clean = clean.substr(2);
                    }
                    ea = static_cast<ea_t>(std::stoull(clean, nullptr, 16));
                }
                catch (...) {}
            }

            if (ea != BADADDR)
            {
                rag_result = ida_utils::get_full_cached_context(ea, g_settings);
                rag_resolved = rag_result.contains("ok") && rag_result["ok"].is_boolean()
                             && rag_result["ok"].get<bool>();
            }
        }

        return 0;
    }
};

static json make_jsonrpc_result(const json& id, const json& result)
{
    return {
        {"jsonrpc", "2.0"},
        {"id",      id},
        {"result",  result}
    };
}

static json make_jsonrpc_error(const json& id, int code, const std::string& message)
{
    return {
        {"jsonrpc", "2.0"},
        {"id",      id},
        {"error",   {
            {"code",    code},
            {"message", message}
        }}
    };
}

struct mcp_resource_def_t
{
    std::string uri;
    std::string name;
    std::string description;
    std::string mime_type;
    std::string backing_tool;
    json        backing_params;
};

static const std::vector<mcp_resource_def_t>& get_resource_definitions()
{
    static const std::vector<mcp_resource_def_t> defs = {
        {
            "ida://binary-info",
            "Binary Information",
            "Metadata about the loaded binary (filename, architecture, base address, compiler, etc.)",
            "application/json",
            "get_binary_info",
            json::object()
        },
        {
            "ida://database-info",
            "Database Information",
            "IDA database (IDB) information including analysis state and statistics",
            "application/json",
            "get_binary_info",
            json::object()
        },
        {
            "ida://segments",
            "Segments",
            "List of all memory segments in the binary",
            "application/json",
            "list_segments",
            json::object()
        },
        {
            "ida://imports",
            "Imports",
            "List of all imported functions/symbols",
            "application/json",
            "list_imports",
            json::object()
        },
        {
            "ida://exports",
            "Exports",
            "List of all exported functions/symbols",
            "application/json",
            "list_exports",
            json::object()
        },
        {
            "ida://entry-points",
            "Entry Points",
            "Program entry points",
            "application/json",
            "list_exports",
            json::object()
        },
        {
            "ida://idb/metadata",
            "IDB Metadata",
            "Metadata about the currently loaded IDA database",
            "application/json",
            "get_binary_info",
            json::object()
        },
        {
            "ida://idb/segments",
            "IDB Segments",
            "Segments in the currently loaded IDA database",
            "application/json",
            "list_segments",
            json::object()
        },
        {
            "ida://idb/entrypoints",
            "IDB Entry Points",
            "Entry points and exports in the currently loaded IDA database",
            "application/json",
            "list_exports",
            json::object()
        },
        {
            "ida://cursor",
            "Cursor",
            "Current IDA cursor address",
            "application/json",
            "get_current_address",
            json::object()
        },
        {
            "ida://selection",
            "Selection",
            "Current IDA range selection",
            "application/json",
            "__selection",
            json::object()
        },
        {
            "ida://types",
            "Types",
            "Local type library entries",
            "application/json",
            "list_types",
            json::object({{"offset", 0}, {"limit", 200}})
        },
        {
            "ida://structs",
            "Structs",
            "Struct and UDT entries from the local type library",
            "application/json",
            "search_structs",
            json::object({{"pattern", ".*"}, {"limit", 200}})
        },
        {
            "ida://databases",
            "Databases",
            "Live AiDA IDA MCP instances",
            "application/json",
            "__databases",
            json::object()
        },
        {
            "ida://corpus/current/manifest",
            "Current Corpus Manifest",
            "Manifest for the currently loaded IDA module and any bound corpus state",
            "application/json",
            "ida_project_manage",
            json::object({{"operation", "corpus_export"}, {"payload", json::object()}})
        },
        {
            "ida://cache/status",
            "Cache Status",
            "Plugin cache, index, extraction, and output-cache status",
            "application/json",
            "ida_cache_manage",
            json::object({{"operation", "status"}, {"payload", json::object()}})
        },
        {
            "ida://jobs",
            "Jobs",
            "Plugin-owned MCP job records",
            "application/json",
            "ida_job_manage",
            json::object({{"operation", "list"}, {"payload", json::object()}})
        },
        {
            "ida://chain/reports",
            "Chain Reports",
            "Stored chain verification report records",
            "application/json",
            "ida_report_manage",
            json::object({{"operation", "list_reports"}, {"payload", json::object()}})
        },
    };
    return defs;
}

static bool mcp_has_prefix(const std::string& s, const std::string& prefix)
{
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

static int mcp_hex_nibble(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static std::string mcp_uri_decode(std::string s)
{
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i)
    {
        if (s[i] == '%' && i + 2 < s.size())
        {
            int hi = mcp_hex_nibble(s[i + 1]);
            int lo = mcp_hex_nibble(s[i + 2]);
            if (hi >= 0 && lo >= 0)
            {
                out.push_back(static_cast<char>((hi << 4) | lo));
                i += 2;
                continue;
            }
        }
        out.push_back(s[i] == '+' ? ' ' : s[i]);
    }
    return out;
}

static bool resolve_mcp_resource_definition(const std::string& uri, mcp_resource_def_t& out)
{
    for (const auto& rdef : get_resource_definitions())
    {
        if (rdef.uri == uri)
        {
            out = rdef;
            return true;
        }
    }

    if (mcp_has_prefix(uri, "ida://function/"))
    {
        std::string address = mcp_uri_decode(uri.substr(strlen("ida://function/")));
        out = {"ida://function/" + address, "Function", "Decompiled function by address", "application/json", "decompile_function", json::object({{"address", address}})};
        return true;
    }

    if (mcp_has_prefix(uri, "ida://address/"))
    {
        std::string address = mcp_uri_decode(uri.substr(strlen("ida://address/")));
        out = {"ida://address/" + address, "Address Information", "Address information", "application/json", "get_address_info", json::object({{"address", address}})};
        return true;
    }

    if (mcp_has_prefix(uri, "ida://struct/"))
    {
        std::string name = mcp_uri_decode(uri.substr(strlen("ida://struct/")));
        out = {"ida://struct/" + name, "Struct", "Struct or UDT details", "application/json", "get_struct", json::object({{"name", name}})};
        return true;
    }

    if (mcp_has_prefix(uri, "ida://import/"))
    {
        std::string name = mcp_uri_decode(uri.substr(strlen("ida://import/")));
        out = {"ida://import/" + name, "Import", "Import details", "application/json", "get_import", json::object({{"name", name}})};
        return true;
    }

    if (mcp_has_prefix(uri, "ida://export/"))
    {
        std::string name = mcp_uri_decode(uri.substr(strlen("ida://export/")));
        out = {"ida://export/" + name, "Export", "Export query", "application/json", "list_exports", json::object({{"offset", 0}, {"limit", 200}, {"filter", name}})};
        return true;
    }

    if (mcp_has_prefix(uri, "ida://xrefs/from/"))
    {
        std::string address = mcp_uri_decode(uri.substr(strlen("ida://xrefs/from/")));
        out = {"ida://xrefs/from/" + address, "Xrefs From", "Cross-references from an address", "application/json", "get_xrefs_from", json::object({{"address", address}, {"limit", 200}})};
        return true;
    }

    if (mcp_has_prefix(uri, "ida://chain/reports/"))
    {
        std::string rest = uri.substr(strlen("ida://chain/reports/"));
        std::string query;
        const size_t q = rest.find('?');
        if (q != std::string::npos)
        {
            query = rest.substr(q + 1);
            rest = rest.substr(0, q);
        }
        std::string format = "json";
        const std::string key = "format=";
        const size_t fp = query.find(key);
        if (fp != std::string::npos)
        {
            format = mcp_uri_decode(query.substr(fp + key.size()));
            const size_t amp = format.find('&');
            if (amp != std::string::npos)
                format = format.substr(0, amp);
        }
        if (format != "json" && format != "markdown" && format != "sarif")
            format = "json";
        const std::string report_id = mcp_uri_decode(rest);
        std::string mime = "application/json";
        if (format == "markdown")
            mime = "text/markdown";
        else if (format == "sarif")
            mime = "application/sarif+json";
        out = {uri, "Chain Report", "Stored chain verification report export", mime, "ida_report_manage",
            json::object({{"operation", "export_report"}, {"payload", {{"report_id", report_id}, {"format", format}}}})};
        return true;
    }

    if (mcp_has_prefix(uri, "ida://reports/exports/"))
    {
        std::string rest = mcp_uri_decode(uri.substr(strlen("ida://reports/exports/")));
        std::string format = "json";
        const size_t dot = rest.find_last_of('.');
        if (dot != std::string::npos)
        {
            format = rest.substr(dot + 1);
            rest = rest.substr(0, dot);
        }
        if (format == "md")
            format = "markdown";
        if (format != "json" && format != "markdown" && format != "sarif")
            format = "json";
        std::string mime = format == "markdown" ? "text/markdown" : (format == "sarif" ? "application/sarif+json" : "application/json");
        out = {uri, "Report Export", "Stored report export by report id and format", mime, "ida_report_manage",
            json::object({{"operation", "export_report"}, {"payload", {{"report_id", rest}, {"format", format}}}})};
        return true;
    }

    if (mcp_has_prefix(uri, "ida://jobs/"))
    {
        std::string rest = mcp_uri_decode(uri.substr(strlen("ida://jobs/")));
        const size_t slash = rest.find('/');
        if (slash != std::string::npos)
        {
            const std::string job_id = rest.substr(0, slash);
            const std::string part = rest.substr(slash + 1);
            if (part == "result")
            {
                out = {uri, "Job Result", "Stored MCP job result page", "application/json", "ida_job_manage",
                    json::object({{"operation", "result"}, {"payload", {{"job_id", job_id}}}})};
                return true;
            }
            if (part == "events")
            {
                out = {uri, "Job Events", "Stored MCP job event ring", "application/json", "ida_job_manage",
                    json::object({{"operation", "events"}, {"payload", {{"job_id", job_id}}}})};
                return true;
            }
        }
    }

    if (mcp_has_prefix(uri, "ida://corpus/"))
    {
        std::string rest = mcp_uri_decode(uri.substr(strlen("ida://corpus/")));
        if (rest == "current/manifest")
        {
            out = {uri, "Current Corpus Manifest", "Current corpus manifest", "application/json", "ida_project_manage",
                json::object({{"operation", "corpus_export"}, {"payload", json::object()}})};
            return true;
        }
        const std::string suffix = "/manifest";
        if (rest.size() > suffix.size() && rest.compare(rest.size() - suffix.size(), suffix.size(), suffix) == 0)
        {
            std::string project_id = rest.substr(0, rest.size() - suffix.size());
            out = {uri, "Corpus Manifest", "Project corpus manifest", "application/json", "ida_project_manage",
                json::object({{"operation", "corpus_export"}, {"payload", {{"project_id", project_id}}}})};
            return true;
        }
    }

    if (mcp_has_prefix(uri, "ida://cache/"))
    {
        std::string rest = mcp_uri_decode(uri.substr(strlen("ida://cache/")));
        if (rest == "status")
        {
            out = {uri, "Cache Status", "Plugin cache status", "application/json", "ida_cache_manage",
                json::object({{"operation", "status"}, {"payload", json::object()}})};
            return true;
        }
        if (rest == "extraction/status")
        {
            out = {uri, "Extraction Cache Status", "Extraction cache status", "application/json", "ida_cache_manage",
                json::object({{"operation", "extraction_status"}, {"payload", json::object()}})};
            return true;
        }
    }

    if (mcp_has_prefix(uri, "ida://evidence/"))
    {
        std::string rest = mcp_uri_decode(uri.substr(strlen("ida://evidence/")));
        const size_t slash = rest.find('/');
        if (slash != std::string::npos)
        {
            const std::string report_id = rest.substr(0, slash);
            const std::string evidence_id = rest.substr(slash + 1);
            out = {uri, "Evidence Record", "Evidence record from a stored chain report", "application/json", "ida_report_manage",
                json::object({{"operation", "evidence_fetch"}, {"payload", {{"report_id", report_id}, {"evidence_id", evidence_id}}}})};
            return true;
        }
    }

    return false;
}

struct mcp_prompt_arg_def_t
{
    std::string name;
    std::string description;
    bool required;
};

struct mcp_prompt_def_t
{
    std::string name;
    std::string description;
    std::vector<mcp_prompt_arg_def_t> arguments;
};

static const std::vector<mcp_prompt_def_t>& get_prompt_definitions()
{
    static const std::vector<mcp_prompt_def_t> defs = {
        {
            "analyze_function",
            "Perform a detailed reverse engineering analysis of a function in the loaded binary. Returns decompiled code, cross-references, and contextual information for AI analysis.",
            {{"address", "Function address in hex (e.g., '0x140001000') or function name", true}}
        },
        {
            "decompile_function",
            "Decompile a function to C/C++ pseudocode using the Hex-Rays decompiler and present it for explanation.",
            {{"address", "Function address in hex (e.g., '0x140001000') or function name", true}}
        },
        {
            "binary_overview",
            "Get a comprehensive overview of the loaded binary including metadata, segments, imports, exports, and entry points.",
            {}
        },
        {
            "explain_address",
            "Explain what exists at a specific address in the binary - function, data, string, etc.",
            {{"address", "Address in hex (e.g., '0x140001000')", true}}
        },
        {
            "find_vulnerabilities",
            "Analyze a function for potential security vulnerabilities including buffer overflows, format string issues, integer overflows, and memory corruption.",
            {{"address", "Function address in hex (e.g., '0x140001000') or function name", true}}
        }
    };
    return defs;
}

// SSE session — hoisted earlier so progress emission can reuse it. The
// definition and format_sse_event helper used to live ~line 2060; moved here
// to keep mcp_emit_progress's transitive dependencies in source order.
struct sse_session_t
{
    std::string id;
    std::string remote_address;
    std::mutex mtx;
    std::condition_variable cv;
    std::queue<std::string> events;
    std::atomic<bool> closed{false};

    void push_event(const std::string& event)
    {
        {
            std::lock_guard<std::mutex> lk(mtx);
            events.push(event);
        }
        cv.notify_one();
    }

    bool wait_event(std::string& out, int timeout_ms)
    {
        std::unique_lock<std::mutex> lk(mtx);
        if (cv.wait_for(lk, std::chrono::milliseconds(timeout_ms),
            [this] { return !events.empty() || closed.load(std::memory_order_relaxed); }))
        {
            if (closed.load(std::memory_order_relaxed))
                return false;
            if (!events.empty())
            {
                out = std::move(events.front());
                events.pop();
                return true;
            }
        }
        return false;
    }

    void close()
    {
        closed.store(true, std::memory_order_relaxed);
        cv.notify_all();
    }
};

static std::string format_sse_event(const std::string& event_type, const std::string& data)
{
    std::string result;
    if (!event_type.empty())
        result += "event: " + event_type + "\n";

    std::istringstream iss(data);
    std::string line;
    while (std::getline(iss, line))
        result += "data: " + line + "\n";

    result += "\n";
    return result;
}

// ----------------------------------------------------------------------------
// Slice B15 — Deterministic tool LRU result cache.
// SHA256(tool_name + json::dump(args)) → tool_result_t. Up to 64 entries,
// 5-minute TTL. Used to short-circuit repeated reads when the tool is
// registered with deterministic=true. The cache is *globally flushed* on any
// destructive tool call so we never return stale data from before a mutation.
// ----------------------------------------------------------------------------
struct mcp_dedup_entry_t
{
    agent_tools::tool_result_t result;
    std::chrono::steady_clock::time_point inserted_at;
};

struct mcp_dedup_cache_t
{
    std::mutex mtx;
    std::deque<std::string> order;
    std::map<std::string, mcp_dedup_entry_t> entries;
};

static constexpr size_t MCP_DEDUP_CACHE_LIMIT = 64;
static constexpr std::chrono::seconds MCP_DEDUP_TTL{300};

static mcp_dedup_cache_t& get_mcp_dedup_cache()
{
    static mcp_dedup_cache_t c;
    return c;
}

// SHA256 helper backed by bcrypt (already linked).
static std::string sha256_hex(const std::string& input)
{
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    unsigned char digest[32] = {};
    std::string out;

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0)
        return out;
    if (BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) != 0)
    {
        BCryptCloseAlgorithmProvider(alg, 0);
        return out;
    }
    if (BCryptHashData(hash, (PUCHAR)input.data(), (ULONG)input.size(), 0) != 0)
    {
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(alg, 0);
        return out;
    }
    if (BCryptFinishHash(hash, digest, sizeof(digest), 0) != 0)
    {
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(alg, 0);
        return out;
    }
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);

    static const char hex[] = "0123456789abcdef";
    out.reserve(64);
    for (unsigned char b : digest)
    {
        out.push_back(hex[b >> 4]);
        out.push_back(hex[b & 0x0f]);
    }
    return out;
}

static std::string make_dedup_key(const std::string& tool, const json& args)
{
    std::string compact = tool + "|" + json_dump_safe(args);
    return sha256_hex(compact);
}

static bool dedup_lookup(const std::string& key, agent_tools::tool_result_t& out)
{
    auto& c = get_mcp_dedup_cache();
    std::lock_guard<std::mutex> lk(c.mtx);
    auto it = c.entries.find(key);
    if (it == c.entries.end())
        return false;
    auto age = std::chrono::steady_clock::now() - it->second.inserted_at;
    if (age > MCP_DEDUP_TTL)
    {
        c.entries.erase(it);
        // Lazily evict from order on next insert.
        return false;
    }
    out = it->second.result;
    return true;
}

static void dedup_store(const std::string& key, const agent_tools::tool_result_t& res)
{
    auto& c = get_mcp_dedup_cache();
    std::lock_guard<std::mutex> lk(c.mtx);
    auto& e = c.entries[key];
    e.result = res;
    e.inserted_at = std::chrono::steady_clock::now();
    c.order.push_back(key);
    while (c.order.size() > MCP_DEDUP_CACHE_LIMIT)
    {
        const std::string& victim = c.order.front();
        c.entries.erase(victim);
        c.order.pop_front();
    }
}

static void dedup_flush_all()
{
    auto& c = get_mcp_dedup_cache();
    std::lock_guard<std::mutex> lk(c.mtx);
    c.entries.clear();
    c.order.clear();
}

static bool is_destructive_tool_legacy(const std::string& name);

// ----------------------------------------------------------------------------
// Slice B13 — Progress SSE notifications.
// The active SSE sessions map is keyed by session id. mcp_emit_progress
// broadcasts a notifications/progress JSON-RPC envelope to every live SSE
// peer. POST /mcp clients do not have a session attached; for them this is a
// silent no-op (the response body is the only delivery channel).
// ----------------------------------------------------------------------------
struct mcp_progress_broadcast_t
{
    std::mutex mtx;
    // Pointers borrowed from the server thread's local sse_sessions map.
    std::vector<std::shared_ptr<sse_session_t>> active;
};

static mcp_progress_broadcast_t& get_progress_broadcast()
{
    static mcp_progress_broadcast_t b;
    return b;
}

static void progress_register_session(const std::shared_ptr<sse_session_t>& s)
{
    auto& b = get_progress_broadcast();
    std::lock_guard<std::mutex> lk(b.mtx);
    b.active.push_back(s);
}

static void progress_unregister_session(const std::shared_ptr<sse_session_t>& s)
{
    auto& b = get_progress_broadcast();
    std::lock_guard<std::mutex> lk(b.mtx);
    for (auto it = b.active.begin(); it != b.active.end(); )
    {
        if (it->get() == s.get())
            it = b.active.erase(it);
        else
            ++it;
    }
}

static void mcp_emit_progress(const std::string& tool,
                              const std::string& stage,
                              double fraction)
{
    json msg_obj;
    msg_obj["jsonrpc"] = "2.0";
    msg_obj["method"]  = "notifications/progress";
    json p;
    p["tool"]     = tool;
    p["stage"]    = stage;
    if (fraction >= 0.0 && fraction <= 1.0)
        p["progress"] = fraction;
    p["timestamp_ms"] = (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    msg_obj["params"] = p;

    std::string body = json_dump_safe(msg_obj);
    std::string event = format_sse_event("message", body);

    auto& b = get_progress_broadcast();
    std::vector<std::shared_ptr<sse_session_t>> snapshot;
    {
        std::lock_guard<std::mutex> lk(b.mtx);
        snapshot = b.active;
    }
    for (auto& s : snapshot)
    {
        if (s && !s->closed.load(std::memory_order_relaxed))
            s->push_event(event);
    }
}

static void progress_begin(const std::string& tool, const std::string& stage)
{
    mcp_emit_progress(tool, stage, 0.0);
}
static void progress_update(const std::string& tool, const std::string& stage, double fraction)
{
    mcp_emit_progress(tool, stage, fraction);
}
static void progress_end(const std::string& tool, const std::string& stage)
{
    mcp_emit_progress(tool, stage, 1.0);
}

static agent_tools::tool_result_t execute_tool_in_main_thread(
    const std::string& name,
    const json& params,
    const std::atomic<bool>* cancel_flag /* Slice B14 */)
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("ida_mcp_exec_tool_enter name=%s cancel=%d", name.c_str(), cancel_flag ? 1 : 0);
#endif

    const auto* tool_def = agent_tools::ToolRegistry::instance().get_tool(name);
    if (!tool_def)
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("ida_mcp_exec_tool_unknown name=%s", name.c_str());
#endif
        return agent_tools::tool_result_t::error("Unknown tool: " + name);
    }
#ifdef __NT__
    aida_ipc::trace_breadcrumb("ida_mcp_exec_tool_found name=%s read_only=%d destructive=%d",
                               name.c_str(), tool_def->read_only ? 1 : 0, tool_def->destructive ? 1 : 0);
#endif

    // Slice B14 — bail before scheduling on the main thread if the caller has
    // already cancelled (HTTP disconnect). Avoids tying up the IDA thread.
    if (cancel_flag && cancel_flag->load(std::memory_order_relaxed))
    {
        agent_tools::tool_result_t r;
        r.success = false;
        r.output = "Cancelled by client";
        r.error_code = "timeout";
        return r;
    }

    // Slice B15 — deterministic-cache short-circuit. Only applies when the tool
    // self-declares deterministic and the destructive flag is clear.
    std::string dedup_key;
    const bool dedup_eligible = tool_def->deterministic && !tool_def->destructive;
    if (dedup_eligible)
    {
        dedup_key = make_dedup_key(name, params);
        agent_tools::tool_result_t cached;
        if (!dedup_key.empty() && dedup_lookup(dedup_key, cached))
            return cached;
    }

    mcp_tool_exec_request_t req;
    req.tool_name = name;
    req.tool_params = params;

    int mff_flag = tool_def->read_only ? MFF_READ : MFF_WRITE;
    auto sync_t0 = std::chrono::steady_clock::now();
#ifdef __NT__
    aida_ipc::trace_breadcrumb("ida_mcp_exec_tool_before_sync name=%s mff=%d", name.c_str(), mff_flag);
#endif
    execute_sync(req, mff_flag);
#ifdef __NT__
    aida_ipc::trace_breadcrumb("ida_mcp_exec_tool_after_sync name=%s success=%d exec_ms=%llu",
                               name.c_str(), req.result.success ? 1 : 0,
                               static_cast<unsigned long long>(req.exec_ms));
#endif
    const auto sync_total_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - sync_t0).count());

    const uint64_t queue_wait_ms = (sync_total_ms > req.exec_ms)
        ? (sync_total_ms - req.exec_ms)
        : 0;

    msg("AiDA PERF: mcp tool=%s mff=%s total=%llums exec=%llums queue=%llums\n",
        name.c_str(),
        mff_flag == MFF_READ ? "READ" : "WRITE",
        static_cast<unsigned long long>(sync_total_ms),
        static_cast<unsigned long long>(req.exec_ms),
        static_cast<unsigned long long>(queue_wait_ms));

    // Slice B15 — destructive tools flush the entire dedup cache so any
    // subsequent deterministic read reflects post-mutation state.
    if (tool_def->destructive || is_destructive_tool_legacy(name))
        dedup_flush_all();
    else if (dedup_eligible && req.result.success && !dedup_key.empty())
        dedup_store(dedup_key, req.result);

    return req.result;
}

// Backward-compatible overload — existing call sites pass nullptr cancel flag.
static inline agent_tools::tool_result_t execute_tool_in_main_thread(
    const std::string& name,
    const json& params)
{
    return execute_tool_in_main_thread(name, params, nullptr);
}

struct mcp_batch_worker_arg_t
{
    std::string tool_name;
    json args;
    std::string label;
    agent_tools::tool_result_t result;
    qsemaphore_t done_sem = nullptr;
    std::atomic<bool>* cancel = nullptr;
    std::atomic<int>* finished_counter = nullptr;
};

static int idaapi mcp_batch_worker_thread(void* user_data)
{
    auto* arg = static_cast<mcp_batch_worker_arg_t*>(user_data);
    try
    {
        if (!arg->cancel || !arg->cancel->load(std::memory_order_relaxed))
        {
            // Each parallel worker uses a *separate* execute_sync slice — that
            // is safe because every sub-call is read-only (verified by caller).
            arg->result = execute_tool_in_main_thread(arg->tool_name, arg->args, arg->cancel);
        }
        else
        {
            arg->result.success = false;
            arg->result.output = "Cancelled before dispatch";
            arg->result.error_code = "timeout";
        }
    }
    catch (const std::exception& e)
    {
        arg->result.success = false;
        arg->result.output = std::string("worker exception: ") + e.what();
        arg->result.error_code = "unknown";
    }
    catch (...)
    {
        arg->result.success = false;
        arg->result.output = "worker crashed";
        arg->result.error_code = "unknown";
    }

    if (arg->finished_counter)
        arg->finished_counter->fetch_add(1, std::memory_order_release);
    if (arg->done_sem)
        qsem_post(arg->done_sem);
    return 0;
}

namespace aida_mcp_internal {

struct parallel_batch_outcome_t
{
    std::vector<agent_tools::tool_result_t> results;
    std::vector<std::string> labels;
    size_t partial_count = 0;
    uint64_t total_ms = 0;
    bool cancelled = false;
    bool timed_out = false;
};

// Externally linkable helper used by meta_tools::tool_batch_call (in
// agent_tools.cpp). Not declared in agent_tools.hpp because the parameters
// reference internal MCP types.
parallel_batch_outcome_t run_batch_parallel(
    const std::vector<std::pair<std::string, json>>& calls,
    const std::vector<std::string>& labels,
    bool stop_on_error,
    int max_wall_seconds);

} // namespace aida_mcp_internal

using mcp_parallel_batch_outcome_t = aida_mcp_internal::parallel_batch_outcome_t;

aida_mcp_internal::parallel_batch_outcome_t aida_mcp_internal::run_batch_parallel(
    const std::vector<std::pair<std::string, json>>& calls,
    const std::vector<std::string>& labels,
    bool stop_on_error,
    int max_wall_seconds)
{
    mcp_parallel_batch_outcome_t outcome;
    outcome.results.resize(calls.size());
    outcome.labels = labels;
    if (calls.empty())
        return outcome;

    auto t0 = std::chrono::steady_clock::now();
    std::atomic<bool> cancel{false};
    std::atomic<int> finished{0};

    qsemaphore_t sem = qsem_create(nullptr, 0);
    std::vector<mcp_batch_worker_arg_t> args(calls.size());
    std::vector<qthread_t> threads(calls.size(), nullptr);

    progress_begin("tool_batch_call", "parallel");

    for (size_t i = 0; i < calls.size(); ++i)
    {
        args[i].tool_name = calls[i].first;
        args[i].args      = calls[i].second;
        args[i].label     = (i < labels.size()) ? labels[i] : std::string();
        args[i].done_sem  = sem;
        args[i].cancel    = &cancel;
        args[i].finished_counter = &finished;
        threads[i] = qthread_create(mcp_batch_worker_thread, &args[i]);
        if (!threads[i])
        {
            // Could not spawn — run inline so result is populated.
            mcp_batch_worker_thread(&args[i]);
        }
    }

    const int total = (int)calls.size();
    const auto deadline = (max_wall_seconds > 0)
        ? t0 + std::chrono::seconds(max_wall_seconds)
        : std::chrono::steady_clock::time_point::max();

    while (finished.load(std::memory_order_acquire) < total)
    {
        if (std::chrono::steady_clock::now() >= deadline)
        {
            cancel.store(true, std::memory_order_release);
            outcome.timed_out = true;
            break;
        }
        qsem_wait(sem, 100);
        progress_update("tool_batch_call", "parallel", static_cast<double>(finished.load(std::memory_order_acquire)) / static_cast<double>(total));

        if (stop_on_error)
        {
            int f = finished.load(std::memory_order_acquire);
            for (int i = 0; i < f; ++i)
            {
                if (!args[i].result.success && !args[i].result.output.empty())
                {
                    cancel.store(true, std::memory_order_release);
                    outcome.cancelled = true;
                    break;
                }
            }
        }
    }

    for (size_t i = 0; i < threads.size(); ++i)
    {
        if (threads[i])
            qthread_join(threads[i]);
    }
    if (sem)
        qsem_free(sem);

    progress_end("tool_batch_call", outcome.timed_out ? "timed_out" : (outcome.cancelled ? "cancelled" : "complete"));

    for (size_t i = 0; i < args.size(); ++i)
    {
        if (finished.load() <= (int)i && (outcome.cancelled || outcome.timed_out))
        {
            args[i].result.success = false;
            args[i].result.output = outcome.timed_out ? "timed out" : "cancelled";
            args[i].result.error_code = "timeout";
            outcome.partial_count++;
        }
        outcome.results[i] = std::move(args[i].result);
    }

    outcome.total_ms = (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0).count();
    return outcome;
}

static json record_to_public_json(const ida_instance_record_t& r);

static std::string mcp_format_ea(ea_t ea)
{
    std::ostringstream ss;
    ss << "0x" << std::hex << std::uppercase << static_cast<uint64_t>(ea);
    return ss.str();
}

struct mcp_special_resource_exec_request_t : public exec_request_t
{
    std::string kind;
    agent_tools::tool_result_t result;

    ssize_t idaapi execute() override
    {
        if (kind == "__selection")
        {
            json data;
            ea_t current = get_screen_ea();
            data["current_address"] = current == BADADDR ? json(nullptr) : json(mcp_format_ea(current));
            data["has_selection"] = false;
            TWidget* viewer = get_current_viewer();
            ea_t ea1 = BADADDR;
            ea_t ea2 = BADADDR;
            if (viewer && read_range_selection(viewer, &ea1, &ea2))
            {
                data["has_selection"] = true;
                data["start"] = mcp_format_ea(ea1);
                data["end"] = mcp_format_ea(ea2);
                data["size"] = ea2 > ea1 ? static_cast<uint64_t>(ea2 - ea1) : 0;
            }
            result = agent_tools::tool_result_t::ok("Selection resource read", data);
            return 0;
        }

        if (kind == "__databases")
        {
            auto* registry = current_registry();
            if (!registry)
            {
                result = agent_tools::tool_result_t::ok("No registry active", json::object({{"instances", json::array()}}));
                return 0;
            }
            json data;
            data["self"] = record_to_public_json(registry->self_record());
            data["instances"] = json::array();
            for (const auto& peer : registry->all_live_instances())
                data["instances"].push_back(record_to_public_json(peer));
            result = agent_tools::tool_result_t::ok("Database instances read", data);
            return 0;
        }

        result = agent_tools::tool_result_t::error("Unknown special resource");
        return 0;
    }
};

static agent_tools::tool_result_t execute_resource_read(const mcp_resource_def_t& rdef)
{
    if (mcp_has_prefix(rdef.backing_tool, "__"))
    {
        mcp_special_resource_exec_request_t req;
        req.kind = rdef.backing_tool;
        execute_sync(req, MFF_READ);
        return req.result;
    }

    mcp_resource_exec_request_t req;
    req.tool_name = rdef.backing_tool;
    req.tool_params = rdef.backing_params;
    execute_sync(req, MFF_READ);
    return req.result;
}

static std::string snake_to_title(const std::string& name)
{
    std::string title;
    title.reserve(name.size());
    bool capitalize_next = true;
    for (char c : name)
    {
        if (c == '_')
        {
            title += ' ';
            capitalize_next = true;
        }
        else
        {
            title += capitalize_next
                ? static_cast<char>(toupper(static_cast<unsigned char>(c)))
                : c;
            capitalize_next = false;
        }
    }
    return title;
}

static std::string compact_tool_text(const std::string& text, std::size_t max_len)
{
    std::string sanitized = sanitize_utf8(text);
    std::string compact;
    compact.reserve(sanitized.size());

    bool previous_was_space = false;
    for (unsigned char ch : sanitized)
    {
        if (std::isspace(ch) != 0)
        {
            if (!compact.empty() && !previous_was_space)
            {
                compact.push_back(' ');
                previous_was_space = true;
            }
            continue;
        }

        compact.push_back(static_cast<char>(ch));
        previous_was_space = false;
    }

    while (!compact.empty() && compact.back() == ' ')
        compact.pop_back();

    if (compact.size() <= max_len)
        return compact;

    std::size_t cut = compact.rfind('.', max_len);
    if (cut == std::string::npos || cut < max_len / 2)
        cut = compact.rfind(' ', max_len);
    if (cut == std::string::npos || cut < max_len / 2)
        cut = max_len;

    compact.erase(cut);
    while (!compact.empty() && compact.back() == ' ')
        compact.pop_back();
    compact += "...";
    return compact;
}

// Legacy migration fallback list — kept for one release cycle so we can detect
// drift between the old hard-coded list and the new tool_definition_t::destructive
// flag. Both is_destructive_tool_legacy() and the new flag are consulted by
// reconcile_destructive(); a startup audit logs warnings when they disagree.
static bool is_destructive_tool_legacy(const std::string& name)
{
    return name == "delete_function"
        || name == "delete_stack_var"
        || name == "rename_function"
        || name == "set_function_signature"
        || name == "patch_bytes"
        || name == "undefine"
        || name == "write_memory"
        || name == "idb_save"
        || name == "diff_before_after"
        || name == "patch"
        || name == "patch_asm"
        || name == "put_int"
        || name == "set_comments"
        || name == "set_comment"
        || name == "set_repeatable_comment"
        || name == "set_function_comment"
        || name == "append_comments"
        || name == "rename"
        || name == "define_func"
        || name == "define_code"
        || name == "declare_stack"
        || name == "delete_stack"
        || name == "declare_type"
        || name == "apply_type"
        || name == "enum_upsert"
        || name == "create_enum"
        || name == "create_struct"
        || name == "add_struct_member"
        || name == "create_stack_var"
        || name == "create_segment"
        || name == "set_type"
        || name == "type_apply_batch"
        || name == "py_eval"
        || name == "py_exec_file";
}

// Slice B12 — data-driven destructive/idempotent classification. Prefers the
// per-tool `destructive` / `deterministic` fields registered by Slice A; falls
// back to the legacy string list when a tool registration predates the flag
// (which still happens during the migration window).
static bool is_destructive_tool(const std::string& name)
{
    const auto* tool = agent_tools::ToolRegistry::instance().get_tool(name);
    if (tool)
    {
        // Read the flag first. The flag default is `false`, which collides with
        // legacy destructive tools that haven't yet been migrated; if the flag
        // is unset we fall through to the legacy list.
        if (tool->destructive)
            return true;
    }
    return is_destructive_tool_legacy(name);
}

static bool is_idempotent_tool(const std::string& name, bool read_only)
{
    const auto* tool = agent_tools::ToolRegistry::instance().get_tool(name);
    if (tool)
    {
        // `deterministic` defaults to true. When the registration explicitly
        // sets it false we trust that. Otherwise apply the legacy fallback.
        if (!tool->deterministic)
            return false;
    }
    if (read_only)
        return true;
    if (name == "execute_python" || name == "py_eval" || name == "py_exec_file" || name == "write_memory")
        return false;
    return !is_destructive_tool_legacy(name);
}

// Logs disagreements between the legacy destructive list and the new flag.
// Invoked once at server start; safe to call without a registered tool table.
static void audit_destructive_flag_drift()
{
    auto names = agent_tools::ToolRegistry::instance().get_tool_names();
    size_t warned = 0;
    for (const auto& n : names)
    {
        const auto* tool = agent_tools::ToolRegistry::instance().get_tool(n);
        if (!tool)
            continue;
        bool legacy = is_destructive_tool_legacy(n);
        bool flag   = tool->destructive;
        if (legacy != flag)
        {
            msg("AiDA MCP: destructive flag drift for tool=%s legacy=%d flag=%d\n",
                n.c_str(), int(legacy), int(flag));
            if (++warned > 32)
            {
                msg("AiDA MCP: ... further drift warnings suppressed\n");
                break;
            }
        }
    }
}

static bool is_mcp_public_tool(const agent_tools::tool_definition_t* tool)
{
    return tool && tool->category != "session" && tool->visibility == "public";
}

static bool is_mcp_callable_tool(const agent_tools::tool_definition_t* tool)
{
    return tool && tool->category != "session" && tool->visibility != "internal";
}

static json mcp_operation_metadata_to_json(const agent_tools::tool_operation_t& op)
{
    json j;
    j["operation"] = op.name;
    j["description"] = op.description;
    j["read_only"] = op.read_only;
    j["destructive"] = op.destructive;
    j["deterministic"] = op.deterministic;
    j["job_mode"] = op.job_mode;
    j["cache_policy"] = op.cache_policy;
    j["default_timeout_ms"] = op.default_timeout_ms;
    j["hard_timeout_ms"] = op.hard_timeout_ms;
    j["required_indices"] = op.required_indices;
    if (!op.input_schema.is_null() && !op.input_schema.empty())
        j["inputSchema"] = op.input_schema;
    if (!op.output_schema.is_null() && !op.output_schema.empty())
        j["outputSchema"] = op.output_schema;
    return j;
}

static json build_aggregator_tool_entries()
{
    json out = json::array();

    {
        json input_schema;
        input_schema["type"] = "object";
        input_schema["properties"] = json::object();
        json t;
        t["name"] = "list_ida_instances";
        t["description"] = "Enumerate every live IDA Pro instance currently exposing AiDA MCP. "
            "Returns each peer's instance_id (UUID), pid (OS process id), display_name, idb_path, input_file, "
            "file_md5, file_sha256, processor, bitness, port, and base_url. Use the returned instance_id OR pid "
            "as the optional instance_id/pid argument on any tool to target a specific IDA, or call "
            "query_all_instances to fan out a tool to every instance at once.";
        t["inputSchema"] = input_schema;
        t["outputSchema"] = json::object({{"type", "object"}, {"additionalProperties", true}});
        json ann;
        ann["title"] = "List IDA Instances";
        ann["readOnlyHint"] = true;
        ann["destructiveHint"] = false;
        ann["idempotentHint"] = true;
        ann["openWorldHint"] = false;
        t["annotations"] = ann;
        out.push_back(t);
    }
    {
        json input_schema;
        input_schema["type"] = "object";
        json props;
        json p_tool;
        p_tool["type"] = "string";
        p_tool["description"] = "Tool name to invoke on every live IDA instance (e.g., get_binary_info, list_imports).";
        props["tool"] = p_tool;
        json p_args;
        p_args["type"] = "object";
        p_args["description"] = "Arguments object passed to the tool on each instance. Optional.";
        props["arguments"] = p_args;
        json p_to;
        p_to["type"] = "integer";
        p_to["description"] = "Per-instance timeout in seconds (default 60).";
        props["timeout_seconds"] = p_to;
        input_schema["properties"] = props;
        input_schema["required"] = json::array({"tool"});
        json t;
        t["name"] = "query_all_instances";
        t["description"] = "Run a single tool concurrently across every live IDA Pro instance and "
            "return a per-instance result map. Each entry contains {instance_id, display_name, input_file, "
            "ok, result_or_error}. Use this to compare or correlate findings across multiple binaries (e.g., "
            "checking imports/exports/strings across ntoskrnl.exe, ci.dll, and acpi.sys at the same time).";
        t["inputSchema"] = input_schema;
        t["outputSchema"] = json::object({{"type", "object"}, {"additionalProperties", true}});
        json ann;
        ann["title"] = "Query All Instances";
        ann["readOnlyHint"] = false;
        ann["destructiveHint"] = false;
        ann["idempotentHint"] = false;
        ann["openWorldHint"] = true;
        t["annotations"] = ann;
        out.push_back(t);
    }
    {
        json input_schema;
        input_schema["type"] = "object";
        input_schema["properties"] = json::object();
        json t;
        t["name"] = "get_local_instance_info";
        t["description"] = "Identify which IDA database the current MCP connection is bound to. "
            "Returns the local instance_id, display name, idb path, and input file metadata. Useful when "
            "an aggregator entry is the connected endpoint and the agent needs to know which IDA it just hit.";
        t["inputSchema"] = input_schema;
        t["outputSchema"] = json::object({{"type", "object"}, {"additionalProperties", true}});
        json ann;
        ann["title"] = "Get Local Instance Info";
        ann["readOnlyHint"] = true;
        ann["destructiveHint"] = false;
        ann["idempotentHint"] = true;
        ann["openWorldHint"] = false;
        t["annotations"] = ann;
        out.push_back(t);
    }

    return out;
}

static json build_mcp_tools_list()
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("ida_mcp_build_tools_list_enter");
#endif
    json tools = json::array();
    const auto all_tools = agent_tools::ToolRegistry::instance().get_all_tools();
#ifdef __NT__
    aida_ipc::trace_breadcrumb("ida_mcp_build_tools_list_all_tools=%zu", all_tools.size());
#endif

    json instance_param;
    instance_param["type"] = "string";
    instance_param["description"] =
        "Optional routing key. The IDA Pro instance_id (UUID from list_ida_instances) to target. "
        "Omit to run against the locally connected IDA. instance_id wins over pid if both are set. "
        "instance_id is stable across PID reuse.";

    json pid_param;
    pid_param["type"] = "integer";
    pid_param["description"] =
        "Optional routing key. The OS process id of the target IDA Pro instance "
        "(visible in Task Manager / ps and returned by list_ida_instances). Use this when you "
        "already know the IDA's pid; otherwise prefer instance_id. Ignored when instance_id is set.";

    for (const auto* tool : all_tools)
    {
        if (!is_mcp_public_tool(tool))
            continue;
        if (tool->category == "instances")
            continue;

        json input_schema = json::object();
        input_schema["type"] = "object";

        json properties = json::object();
        json required_arr = json::array();

        for (const auto& param : tool->parameters)
        {
            json p;
            p["type"] = param.type;
            p["description"] = compact_tool_text(param.description, 160);
            if (!param.enum_values.empty())
                p["enum"] = param.enum_values;
            if (param.type == "array" && !param.items_schema.is_null())
                p["items"] = param.items_schema;
            else if (param.type == "array")
                p["items"] = json::object({{"type", "object"}});
            properties[param.name] = p;
            if (param.required)
                required_arr.push_back(param.name);
        }

        properties[kInstanceArgKey] = instance_param;
        properties[kPidArgKey]      = pid_param;

        input_schema["properties"] = properties;
        if (!required_arr.empty())
            input_schema["required"] = required_arr;

        json annotations;
        annotations["title"]           = snake_to_title(tool->name);
        annotations["readOnlyHint"]    = tool->read_only;
        annotations["destructiveHint"] = is_destructive_tool(tool->name);
        annotations["idempotentHint"]  = is_idempotent_tool(tool->name, tool->read_only);
        annotations["openWorldHint"]   = (tool->name == "execute_python" || tool->name == "py_eval" || tool->name == "py_exec_file");

        json t;
        t["name"]        = tool->name;
        t["description"] = compact_tool_text(tool->description, 320);
        t["inputSchema"] = input_schema;
        t["visibility"] = tool->visibility;
        if (!tool->operations.empty())
        {
            t["operations"] = json::array();
            for (const auto& op : tool->operations)
                t["operations"].push_back(mcp_operation_metadata_to_json(op));
        }
        if (!tool->deprecated_by_tool.empty())
        {
            t["deprecated_by"] = {
                {"tool", tool->deprecated_by_tool},
                {"operation", tool->deprecated_by_operation.empty() ? json(nullptr) : json(tool->deprecated_by_operation)}
            };
        }
        if (!tool->output_schema.is_null() && !tool->output_schema.empty())
        {
            t["outputSchema"] = tool->output_schema;
        }
        else
        {
            t["outputSchema"] = json::object({
                {"type", "object"},
                {"additionalProperties", true}
            });
        }
        t["requiredIndices"] = tool->required_indices;
        t["annotations"] = annotations;
        tools.push_back(t);
    }

    json aggregators = build_aggregator_tool_entries();
    for (auto& a : aggregators)
        tools.push_back(std::move(a));

#ifdef __NT__
    aida_ipc::trace_breadcrumb("ida_mcp_build_tools_list_exit total_tools=%zu", tools.size());
#endif
    return tools;
}

static const json& get_cached_mcp_tools_list()
{
    static const json tools = build_mcp_tools_list();
    return tools;
}

static json build_mcp_resources_list()
{
    json resources = json::array();
    for (const auto& rdef : get_resource_definitions())
    {
        json r;
        r["uri"] = rdef.uri;
        r["name"] = rdef.name;
        r["description"] = rdef.description;
        r["mimeType"] = rdef.mime_type;
        resources.push_back(r);
    }
    return resources;
}

static const json& get_cached_mcp_resources_list()
{
    static const json resources = build_mcp_resources_list();
    return resources;
}

static json build_mcp_prompts_catalog()
{
    json prompts_arr = json::array();
    for (const auto& pdef : get_prompt_definitions())
    {
        json p;
        p["name"] = pdef.name;
        p["description"] = pdef.description;
        if (!pdef.arguments.empty())
        {
            json args = json::array();
            for (const auto& arg : pdef.arguments)
            {
                args.push_back({
                    {"name", arg.name},
                    {"description", arg.description},
                    {"required", arg.required}
                });
            }
            p["arguments"] = args;
        }
        prompts_arr.push_back(p);
    }
    return prompts_arr;
}

static const json& get_cached_mcp_prompts_catalog()
{
    static const json prompts = build_mcp_prompts_catalog();
    return prompts;
}

static json handle_initialize(const json& id, const json& )
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("ida_mcp_handle_initialize_enter");
#endif
    json capabilities;
    capabilities["tools"]     = {{"listChanged", true}};
    capabilities["resources"] = {{"listChanged", true}};
    capabilities["prompts"]   = {{"listChanged", true}};
    capabilities["logging"]   = json::object();

    json server_info;
    server_info["name"] = std::string("aida-ida-mcp");
    server_info["version"] = AIDA_VERSION;

    json result;
    result["protocolVersion"] = MCP_PROTOCOL_VERSION;
    result["capabilities"] = capabilities;
    result["serverInfo"] = server_info;
    result["instructions"] = get_mcp_server_instructions();

    return make_jsonrpc_result(id, result);
}

static json handle_ping(const json& id)
{
    return make_jsonrpc_result(id, json::object());
}

static json handle_tools_list(const json& id)
{
    json result;
    result["tools"] = get_cached_mcp_tools_list();
    return make_jsonrpc_result(id, result);
}

static json handle_tools_call(const json& id, const json& params)
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("ida_mcp_handle_tools_call_enter");
#endif
    if (!params.contains("name") || !params["name"].is_string())
        return make_jsonrpc_error(id, JSONRPC_INVALID_PARAMS, "Missing required field: 'name'");

    std::string tool_name = params["name"].get<std::string>();
    json arguments = params.contains("arguments") && params["arguments"].is_object()
                   ? params["arguments"]
                   : json::object();

    auto* registry = current_registry();
    bool has_target = false;
    bool target_is_self = false;
    ida_instance_record_t target_peer;
    std::string resolve_err;
    if (!resolve_target_instance(arguments, registry, has_target, target_is_self, target_peer, resolve_err))
        return make_jsonrpc_error(id, JSONRPC_INVALID_PARAMS, resolve_err);

    json local_args = strip_routing_args(arguments);

    if (has_target && !target_is_self)
    {
        json result = mcp_proxy_tools_call_to_peer(target_peer, tool_name, local_args, 60);
        return make_jsonrpc_result(id, result);
    }

    json prepared_args = mcp_prepare_local_tool_arguments(tool_name, local_args, registry);

    if (tool_name == "list_ida_instances" || tool_name == "query_all_instances"
        || tool_name == "get_local_instance_info")
    {
        auto tool_result = agent_tools::ToolRegistry::instance().execute_tool(tool_name, prepared_args);
        json result = build_mcp_tool_result_payload(tool_result);
        return make_jsonrpc_result(id, result);
    }

    const auto* tool = agent_tools::ToolRegistry::instance().get_tool(tool_name);
    if (!is_mcp_callable_tool(tool))
        return make_jsonrpc_error(id, JSONRPC_INVALID_PARAMS, "Tool is not exposed through MCP");

    auto tool_result = execute_tool_in_main_thread(tool_name, prepared_args, g_mcp_cancel_flag);
    json result = build_mcp_tool_result_payload(tool_result);
    return make_jsonrpc_result(id, result);
}

static json handle_resources_list(const json& id)
{
    json result;
    result["resources"] = get_cached_mcp_resources_list();
    return make_jsonrpc_result(id, result);
}

static json handle_resources_read(const json& id, const json& params)
{
    if (!params.contains("uri") || !params["uri"].is_string())
        return make_jsonrpc_error(id, JSONRPC_INVALID_PARAMS, "Missing required field: 'uri'");

    std::string uri = params["uri"].get<std::string>();

    mcp_resource_def_t found;
    if (!resolve_mcp_resource_definition(uri, found))
        return make_jsonrpc_error(id, JSONRPC_INVALID_PARAMS, "Unknown resource URI: " + uri);

    auto tool_result = execute_resource_read(found);

    std::string text_content;
    if (!tool_result.data.is_null() && !tool_result.data.empty())
        text_content = json_dump_safe(tool_result.data, 2);
    else
        text_content = sanitize_utf8(tool_result.output);

    json contents = json::array();
    contents.push_back({
        {"uri",      found.uri},
        {"mimeType", found.mime_type},
        {"text",     text_content}
    });

    json result;
    result["contents"] = contents;
    return make_jsonrpc_result(id, result);
}

static json handle_resources_templates_list(const json& id)
{
    json templates = json::array();

    templates.push_back({
        {"uriTemplate", "ida://function/{address}"},
        {"name", "Function by Address"},
        {"description", "Access a function's decompiled code by its hexadecimal address"},
        {"mimeType", "application/json"}
    });

    templates.push_back({
        {"uriTemplate", "ida://address/{address}"},
        {"name", "Address Information"},
        {"description", "Get detailed information about any address in the binary"},
        {"mimeType", "application/json"}
    });

    templates.push_back({
        {"uriTemplate", "ida://struct/{name}"},
        {"name", "Struct by Name"},
        {"description", "Access struct or UDT details by type name"},
        {"mimeType", "application/json"}
    });

    templates.push_back({
        {"uriTemplate", "ida://import/{name}"},
        {"name", "Import by Name"},
        {"description", "Access import details by import name or address"},
        {"mimeType", "application/json"}
    });

    templates.push_back({
        {"uriTemplate", "ida://export/{name}"},
        {"name", "Export by Name"},
        {"description", "Query exports by name"},
        {"mimeType", "application/json"}
    });

    templates.push_back({
        {"uriTemplate", "ida://xrefs/from/{addr}"},
        {"name", "Xrefs From Address"},
        {"description", "Access outgoing cross-references from an address"},
        {"mimeType", "application/json"}
    });

    templates.push_back({
        {"uriTemplate", "ida://chain/reports/{report_id}?format={format}"},
        {"name", "Chain Report Export"},
        {"description", "Read a stored chain report as json, markdown, or sarif"},
        {"mimeType", "application/json"}
    });

    templates.push_back({
        {"uriTemplate", "ida://reports/exports/{report_id}.{format}"},
        {"name", "Report Export"},
        {"description", "Read a stored report export by report id and extension"},
        {"mimeType", "application/json"}
    });

    templates.push_back({
        {"uriTemplate", "ida://jobs/{job_id}/result"},
        {"name", "Job Result"},
        {"description", "Read a stored MCP job result"},
        {"mimeType", "application/json"}
    });

    templates.push_back({
        {"uriTemplate", "ida://jobs/{job_id}/events"},
        {"name", "Job Events"},
        {"description", "Read a stored MCP job event ring"},
        {"mimeType", "application/json"}
    });

    templates.push_back({
        {"uriTemplate", "ida://corpus/{project_id}/manifest"},
        {"name", "Corpus Manifest"},
        {"description", "Read a project or current corpus manifest"},
        {"mimeType", "application/json"}
    });

    templates.push_back({
        {"uriTemplate", "ida://cache/{area}/status"},
        {"name", "Cache Status"},
        {"description", "Read cache status for extraction, index, output, or all areas"},
        {"mimeType", "application/json"}
    });

    templates.push_back({
        {"uriTemplate", "ida://evidence/{report_id}/{evidence_id}"},
        {"name", "Evidence Record"},
        {"description", "Read an evidence record emitted by a stored report"},
        {"mimeType", "application/json"}
    });

    json result;
    result["resourceTemplates"] = templates;
    return make_jsonrpc_result(id, result);
}

static json handle_prompts_list(const json& id)
{
    json result;
    result["prompts"] = get_cached_mcp_prompts_catalog();
    return make_jsonrpc_result(id, result);
}

static std::string build_rag_section_from_result(const json& rag_result, bool resolved)
{
    if (!resolved)
        return "";

    std::string section;
    section.reserve(4096);

    std::string metadata = json_str(rag_result, "binary_metadata", "");
    std::string imports  = json_str(rag_result, "imports_context", "");
    std::string types    = json_str(rag_result, "type_context", "");
    std::string callers  = json_str(rag_result, "xrefs_to", "");
    std::string callees  = json_str(rag_result, "xrefs_from", "");
    std::string locals   = json_str(rag_result, "local_vars", "");
    std::string strings  = json_str(rag_result, "string_xrefs", "");
    std::string structs  = json_str(rag_result, "struct_context", "");

    if (!metadata.empty())
        section += "\n## Binary Context\n```\n" + metadata + "\n```\n";
    if (!imports.empty() && imports.find("No import") == std::string::npos
                         && imports.find("No function") == std::string::npos)
        section += "\n## Imports Used by Function\n```\n" + imports + "\n```\n";
    if (!types.empty() && types.find("No custom") == std::string::npos
                       && types.find("No function") == std::string::npos
                       && types.find("not available") == std::string::npos)
        section += "\n## Referenced Types\n```\n" + types + "\n```\n";
    if (!callers.empty() && callers.find("N/A") == std::string::npos
                         && callers.find("No ") == std::string::npos)
        section += "\n## Callers (xrefs to)\n```\n" + callers + "\n```\n";
    if (!callees.empty() && callees.find("N/A") == std::string::npos
                         && callees.find("No ") == std::string::npos)
        section += "\n## Callees (xrefs from)\n```\n" + callees + "\n```\n";
    if (!locals.empty() && locals.find("N/A") == std::string::npos
                        && locals.find("No ") == std::string::npos)
        section += "\n## Local Variables\n```\n" + locals + "\n```\n";
    if (!strings.empty() && strings.find("N/A") == std::string::npos
                         && strings.find("No ") == std::string::npos)
        section += "\n## String References\n" + strings + "\n";
    if (!structs.empty() && structs.find("N/A") == std::string::npos
                         && structs.find("No ") == std::string::npos)
        section += "\n## Struct Usage\n```\n" + structs + "\n```\n";

    return section;
}

static json handle_prompts_get(const json& id, const json& params)
{
    if (!params.contains("name") || !params["name"].is_string())
        return make_jsonrpc_error(id, JSONRPC_INVALID_PARAMS, "Missing required field: 'name'");

    std::string name = params["name"].get<std::string>();
    json arguments = params.value("arguments", json::object());

    const mcp_prompt_def_t* found = nullptr;
    for (const auto& pdef : get_prompt_definitions())
    {
        if (pdef.name == name)
        {
            found = &pdef;
            break;
        }
    }

    if (!found)
        return make_jsonrpc_error(id, JSONRPC_INVALID_PARAMS, "Unknown prompt: " + name);

    json messages = json::array();

    if (name == "analyze_function" || name == "decompile_function" || name == "find_vulnerabilities")
    {
        std::string addr_str = arguments.value("address", "");
        if (addr_str.empty())
            return make_jsonrpc_error(id, JSONRPC_INVALID_PARAMS, "Missing required argument: 'address'");

        mcp_batch_exec_request_t req;
        req.calls.push_back({"decompile_function", {{"address", addr_str}}});
        if (name == "analyze_function")
            req.calls.push_back({"get_xrefs_to", {{"address", addr_str}}});
        req.include_rag = true;
        req.rag_addr_str = addr_str;
        execute_sync(req, MFF_READ);

        const auto& decomp_result = req.results[0];
        std::string code_context;
        if (decomp_result.success)
            code_context = !decomp_result.data.is_null() ? json_dump_safe(decomp_result.data, 2) : decomp_result.output;
        else
            code_context = "Decompilation failed: " + decomp_result.output;

        std::string prompt_text;
        if (name == "analyze_function")
        {
            std::string xrefs_text;
            const auto& xrefs_result = req.results[1];
            if (xrefs_result.success)
                xrefs_text = !xrefs_result.data.is_null() ? json_dump_safe(xrefs_result.data, 2) : xrefs_result.output;

            prompt_text =
                "Analyze the following function from a binary loaded in IDA Pro.\n"
                "Provide a detailed report covering:\n"
                "1. High-level purpose of the function\n"
                "2. Detailed logic flow (step-by-step)\n"
                "3. Function arguments and return value analysis\n"
                "4. Identified programming patterns\n"
                "5. Notable observations and potential use-cases\n\n"
                "## Decompiled Code\n```cpp\n" + code_context + "\n```\n";
            if (!xrefs_text.empty())
                prompt_text += "\n## Cross-References (callers)\n```json\n" + xrefs_text + "\n```\n";
        }
        else if (name == "decompile_function")
        {
            prompt_text =
                "Here is the decompiled C/C++ pseudocode of a function from IDA Pro.\n"
                "Please analyze this code and explain:\n"
                "1. What the function does\n"
                "2. Its parameters and return value\n"
                "3. Any notable patterns or algorithms used\n\n"
                "```cpp\n" + code_context + "\n```\n";
        }
        else if (name == "find_vulnerabilities")
        {
            prompt_text =
                "Analyze the following decompiled function for security vulnerabilities.\n"
                "Check for:\n"
                "- Buffer overflows and out-of-bounds access\n"
                "- Integer overflows and truncation issues\n"
                "- Format string vulnerabilities\n"
                "- Use-after-free and double-free conditions\n"
                "- Race conditions\n"
                "- Uninitialized memory usage\n"
                "- NULL pointer dereferences\n\n"
                "## Decompiled Code\n```cpp\n" + code_context + "\n```\n";
        }

            prompt_text += build_rag_section_from_result(req.rag_result, req.rag_resolved);

        messages.push_back({
            {"role", "user"},
            {"content", {{"type", "text"}, {"text", sanitize_utf8(prompt_text)}}}
        });
    }
    else if (name == "binary_overview")
    {
        mcp_batch_exec_request_t req;
        req.calls.push_back({"get_binary_info", json::object()});
        req.calls.push_back({"list_segments", json::object()});
        req.calls.push_back({"list_imports", json::object()});
        req.calls.push_back({"list_exports", json::object()});
        execute_sync(req, MFF_READ);

        const auto& info_result = req.results[0];
        const auto& segments_result = req.results[1];
        const auto& imports_result = req.results[2];
        const auto& exports_result = req.results[3];

        std::string overview = "Provide a comprehensive analysis of the following binary loaded in IDA Pro.\n\n";

        if (info_result.success && !info_result.data.is_null())
            overview += "## Binary Metadata\n```json\n" + json_dump_safe(info_result.data, 2) + "\n```\n\n";
        if (segments_result.success && !segments_result.data.is_null())
            overview += "## Memory Segments\n```json\n" + json_dump_safe(segments_result.data, 2) + "\n```\n\n";
        if (imports_result.success && !imports_result.data.is_null())
            overview += "## Imports\n```json\n" + json_dump_safe(imports_result.data, 2) + "\n```\n\n";
        if (exports_result.success && !exports_result.data.is_null())
            overview += "## Exports / Entry Points\n```json\n" + json_dump_safe(exports_result.data, 2) + "\n```\n\n";

        messages.push_back({
            {"role", "user"},
            {"content", {{"type", "text"}, {"text", sanitize_utf8(overview)}}}
        });
    }
    else if (name == "explain_address")
    {
        std::string addr_str = arguments.value("address", "");
        if (addr_str.empty())
            return make_jsonrpc_error(id, JSONRPC_INVALID_PARAMS, "Missing required argument: 'address'");

        mcp_batch_exec_request_t req;
        req.calls.push_back({"get_address_info", {{"address", addr_str}}});
        req.include_rag = true;
        req.rag_addr_str = addr_str;
        execute_sync(req, MFF_READ);

        const auto& info_result = req.results[0];

        std::string text = "Explain what exists at address " + addr_str + " in the loaded binary:\n\n";
        if (info_result.success)
        {
            if (!info_result.data.is_null())
                text += "```json\n" + json_dump_safe(info_result.data, 2) + "\n```\n";
            else
                text += info_result.output;
        }
        else
        {
            text += "Could not retrieve information: " + info_result.output;
        }

        text += build_rag_section_from_result(req.rag_result, req.rag_resolved);

        messages.push_back({
            {"role", "user"},
            {"content", {{"type", "text"}, {"text", sanitize_utf8(text)}}}
        });
    }

    json result;
    result["description"] = found->description;
    result["messages"] = messages;
    return make_jsonrpc_result(id, result);
}

static json handle_completion_complete(const json& id, const json& params)
{
    json argument = params.value("argument", json::object());
    std::string arg_name = argument.value("name", "");
    std::string arg_value = argument.value("value", "");

    json values = json::array();

    if (arg_name == "address" && !arg_value.empty())
    {
        auto result = execute_tool_in_main_thread("list_functions",
            {{"filter", arg_value}, {"limit", 20}});
        if (result.success && result.data.is_array())
        {
            for (const auto& func : result.data)
            {
                std::string display;
                if (func.contains("name") && func["name"].is_string())
                    display = func["name"].get<std::string>();
                else if (func.contains("address") && func["address"].is_string())
                    display = func["address"].get<std::string>();
                if (!display.empty())
                    values.push_back(display);
            }
        }
    }

    json completion;
    completion["values"] = values;
    completion["total"] = values.size();
    completion["hasMore"] = false;
    return make_jsonrpc_result(id, completion);
}

static json dispatch_single_message(const json& msg)
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("ida_mcp_dispatch_enter");
#endif
    if (!msg.is_object())
        return make_jsonrpc_error(nullptr, JSONRPC_INVALID_REQUEST, std::string("Request must be a JSON object"));

    std::string method = msg.value("method", "");
    if (method.empty())
        return make_jsonrpc_error(msg.value("id", json(nullptr)), JSONRPC_INVALID_REQUEST, std::string("Missing 'method' field"));

    json id = msg.contains("id") ? msg["id"] : json(nullptr);
    json params = msg.value("params", json::object());
    bool is_notification = !msg.contains("id");

    if (is_notification && method != "notifications/cancelled")
    {
        if (method == "notifications/initialized" || method == "logging/setLevel")
            return json();
        if (method == "initialize")
        {
            (void)handle_initialize(nullptr, params);
            return json();
        }
        if (method == "ping")
        {
            (void)handle_ping(nullptr);
            return json();
        }
        if (method == "tools/list")
        {
            (void)handle_tools_list(nullptr);
            return json();
        }
        if (method == "tools/call")
        {
            (void)handle_tools_call(nullptr, params);
            return json();
        }
        if (method == "resources/list")
        {
            (void)handle_resources_list(nullptr);
            return json();
        }
        if (method == "resources/read")
        {
            (void)handle_resources_read(nullptr, params);
            return json();
        }
        if (method == "resources/templates/list")
        {
            (void)handle_resources_templates_list(nullptr);
            return json();
        }
        if (method == "prompts/list")
        {
            (void)handle_prompts_list(nullptr);
            return json();
        }
        if (method == "prompts/get")
        {
            (void)handle_prompts_get(nullptr, params);
            return json();
        }
        if (method == "completion/complete")
        {
            (void)handle_completion_complete(nullptr, params);
            return json();
        }
    }

    if (method == "initialize")
        return handle_initialize(id, params);

    if (method == "notifications/initialized")
        return json();

    if (method == "ping")
        return handle_ping(id);

    if (method == "tools/list")
        return handle_tools_list(id);

    if (method == "tools/call")
        return handle_tools_call(id, params);

    if (method == "resources/list")
        return handle_resources_list(id);

    if (method == "resources/read")
        return handle_resources_read(id, params);

    if (method == "resources/templates/list")
        return handle_resources_templates_list(id);

    if (method == "prompts/list")
        return handle_prompts_list(id);

    if (method == "prompts/get")
        return handle_prompts_get(id, params);

    if (method == "completion/complete")
        return handle_completion_complete(id, params);

    if (method == "notifications/cancelled" || method == "logging/setLevel")
        return json();

    if (is_notification)
        return json();

    return make_jsonrpc_error(id, JSONRPC_METHOD_NOT_FOUND, std::string("Unknown method: ") + method);
}

static std::string handle_mcp_body(const std::string& body, const std::function<bool()>& connection_closed)
{
    std::atomic<bool> cancel{false};
    std::atomic<bool> monitor_done{false};
    std::thread monitor([&]() {
        while (!monitor_done.load(std::memory_order_acquire))
        {
            bool closed = false;
            try { closed = connection_closed && connection_closed(); } catch (...) {}
            if (closed)
            {
                cancel.store(true, std::memory_order_release);
                return;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(25));
        }
    });
    scoped_mcp_cancel_flag_t cancel_scope(&cancel);
#ifdef __NT__
    aida_ipc::trace_breadcrumb("ida_mcp_handle_body_enter body_len=%zu", body.size());
#endif
    json parsed;
    try
    {
        parsed = json::parse(body);
    }
    catch (const json::parse_error& e)
    {
        monitor_done.store(true, std::memory_order_release);
        monitor.join();
        return json_dump_safe(make_jsonrpc_error(nullptr, JSONRPC_PARSE_ERROR,
            std::string("JSON parse error: ") + e.what()));
    }

    if (parsed.is_array())
    {
        if (parsed.empty())
        {
            monitor_done.store(true, std::memory_order_release);
            monitor.join();
            return json_dump_safe(make_jsonrpc_error(nullptr, JSONRPC_INVALID_REQUEST, "Empty batch"));
        }

        json responses = json::array();
        for (const auto& item : parsed)
        {
            json response = dispatch_single_message(item);
            if (!response.is_null())
                responses.push_back(response);
        }

        if (responses.empty())
        {
        monitor_done.store(true, std::memory_order_release);
        monitor.join();
            return "";
        }
        monitor_done.store(true, std::memory_order_release);
        monitor.join();
        return json_dump_safe(responses);
    }

    json response = dispatch_single_message(parsed);
    if (response.is_null())
    {
        monitor_done.store(true, std::memory_order_release);
        monitor.join();
        return "";
    }
    monitor_done.store(true, std::memory_order_release);
    monitor.join();
    return json_dump_safe(response);
}

static std::once_flag g_aggregator_tools_registered;

static json record_to_public_json(const ida_instance_record_t& r)
{
    json j;
    j["instance_id"]       = r.instance_id;
    j["display_name"]      = r.display_name;
    j["pid"]               = r.pid;
    j["port"]              = r.port;
    j["base_url"]          = r.base_url;
    j["mcp_url"]           = r.mcp_url;
    j["sse_url"]           = r.sse_url;
    j["idb_path"]          = r.idb_path;
    j["input_file"]        = r.input_file;
    j["input_basename"]    = r.input_basename;
    j["config_entry_name"] = r.config_entry_name;
    j["file_md5"]          = r.file_md5;
    j["file_sha256"]       = r.file_sha256;
    j["module_id"]         = r.module_id;
    j["index_generation"]  = r.index_generation;
    j["image_base"]        = r.image_base;
    j["image_min_ea"]      = r.image_min_ea;
    j["image_max_ea"]      = r.image_max_ea;
    j["image_bounds"]      = {{"base", r.image_base}, {"min_ea", r.image_min_ea}, {"max_ea", r.image_max_ea}};
    j["processor"]         = r.processor;
    j["bitness"]           = r.bitness;
    j["hostname"]          = r.hostname;
    j["ida_version"]       = r.ida_version;
    j["started_at_ms"]     = r.started_at_ms;
    j["last_heartbeat_ms"] = r.last_heartbeat_ms;
    j["is_self"]           = r.is_self;
    return j;
}

static agent_tools::tool_result_t aggregator_list_instances(const json&)
{
    auto* reg = current_registry();
    if (!reg)
        return agent_tools::tool_result_t::error("MCP registry is not initialized.");

    auto all = reg->all_live_instances();
    json arr = json::array();
    for (const auto& r : all)
        arr.push_back(record_to_public_json(r));

    json data;
    data["count"] = arr.size();
    data["self_instance_id"] = reg->self_instance_id();
    data["instances"] = arr;

    std::string summary = "Found " + std::to_string(arr.size()) + " live IDA instance"
        + (arr.size() == 1 ? "" : "s") + ".";
    return agent_tools::tool_result_t::ok(summary, data);
}

static agent_tools::tool_result_t aggregator_get_local_info(const json&)
{
    auto* reg = current_registry();
    if (!reg)
        return agent_tools::tool_result_t::error("MCP registry is not initialized.");
    ida_instance_record_t r = reg->self_record();
    r.is_self = true;
    return agent_tools::tool_result_t::ok(
        "Local instance info: " + r.display_name, record_to_public_json(r));
}

static agent_tools::tool_result_t aggregator_query_all(const json& params)
{
    auto* reg = current_registry();
    if (!reg)
        return agent_tools::tool_result_t::error("MCP registry is not initialized.");

    std::string tool_name = params.value("tool", "");
    if (tool_name.empty())
        return agent_tools::tool_result_t::error("Missing required argument: 'tool'.");
    if (tool_name == "query_all_instances")
        return agent_tools::tool_result_t::error("Cannot recursively fan out query_all_instances.");

    json arguments = params.contains("arguments") && params["arguments"].is_object()
                   ? params["arguments"]
                   : json::object();
    arguments = strip_routing_args(arguments);

    int timeout_seconds = 60;
    if (params.contains("timeout_seconds") && params["timeout_seconds"].is_number_integer())
    {
        int t = params["timeout_seconds"].get<int>();
        if (t > 0 && t < 3600)
            timeout_seconds = t;
    }

    const auto* tool_def = agent_tools::ToolRegistry::instance().get_tool(tool_name);
    bool tool_known_locally = is_mcp_callable_tool(tool_def);

    auto all = reg->all_live_instances();
    if (all.empty())
        return agent_tools::tool_result_t::error("No live IDA instances are registered.");

    struct task_t {
        ida_instance_record_t rec;
        std::future<json> fut;
    };
    std::vector<task_t> tasks;
    tasks.reserve(all.size());

    std::string self_id = reg->self_instance_id();

    for (const auto& rec : all)
    {
        task_t task;
        task.rec = rec;
        if (rec.instance_id == self_id)
        {
            json local_args = arguments;
            if (!tool_known_locally)
            {
                json err;
                err["isError"] = true;
                err["content"] = json::array({
                    { {"type","text"}, {"text","Tool '" + tool_name + "' is not registered locally."} }
                });
                std::promise<json> pr;
                pr.set_value(err);
                task.fut = pr.get_future();
            }
            else
            {
                try
                {
                    task.fut = std::async(std::launch::async,
                        [tool_name, local_args]() -> json {
                            auto tr = execute_tool_in_main_thread(tool_name, local_args);
                            json content = json::array();
                            if (!tr.output.empty())
                                content.push_back({ {"type","text"}, {"text",sanitize_utf8(tr.output)} });
                            if (!tr.data.is_null() && !tr.data.empty())
                                content.push_back({ {"type","text"},
                                    {"text", sanitize_utf8(json_dump_safe(tr.data, 2))} });
                            if (content.empty())
                                content.push_back({ {"type","text"},
                                    {"text", tr.success ? "ok" : "error"} });
                            json result;
                            result["content"] = content;
                            if (!tr.success)
                                result["isError"] = true;
                            return result;
                        });
                }
                catch (const std::exception& ex)
                {
                    json err;
                    err["isError"] = true;
                    err["content"] = json::array({
                        { {"type","text"}, {"text", std::string("Tool worker unavailable: ") + ex.what()} }
                    });
                    std::promise<json> pr;
                    pr.set_value(err);
                    task.fut = pr.get_future();
                }
            }
        }
        else
        {
            ida_instance_record_t peer = rec;
            json fwd_args = arguments;
            int t_seconds = timeout_seconds;
            try
            {
                task.fut = std::async(std::launch::async,
                    [peer, tool_name, fwd_args, t_seconds]() -> json {
                        return mcp_proxy_tools_call_to_peer(peer, tool_name, fwd_args, t_seconds);
                    });
            }
            catch (const std::exception& ex)
            {
                json err;
                err["isError"] = true;
                err["content"] = json::array({
                    { {"type","text"}, {"text", std::string("Forward worker unavailable: ") + ex.what()} }
                });
                std::promise<json> pr;
                pr.set_value(err);
                task.fut = pr.get_future();
            }
        }
        tasks.push_back(std::move(task));
    }

    json results = json::array();
    size_t ok_count = 0;
    size_t err_count = 0;
    for (auto& t : tasks)
    {
        json r;
        r["instance_id"]  = t.rec.instance_id;
        r["display_name"] = t.rec.display_name;
        r["input_file"]   = t.rec.input_file;
        r["is_self"]      = (t.rec.instance_id == self_id);

        json call_result;
        try
        {
            call_result = t.fut.get();
        }
        catch (const std::exception& e)
        {
            call_result = json::object();
            call_result["isError"] = true;
            call_result["content"] = json::array({
                { {"type","text"}, {"text", std::string("future exception: ") + e.what()} }
            });
        }

        bool is_error = call_result.contains("isError")
            && call_result["isError"].is_boolean()
            && call_result["isError"].get<bool>();
        r["ok"]     = !is_error;
        r["result"] = call_result;
        if (is_error) ++err_count; else ++ok_count;
        results.push_back(r);
    }

    json data;
    data["tool"]            = tool_name;
    data["arguments"]       = arguments;
    data["instance_count"]  = results.size();
    data["success_count"]   = ok_count;
    data["error_count"]     = err_count;
    data["results"]         = results;

    std::string summary = "Ran '" + tool_name + "' on " + std::to_string(results.size())
        + " instance" + (results.size() == 1 ? "" : "s")
        + " (" + std::to_string(ok_count) + " ok, "
        + std::to_string(err_count) + " error).";
    return agent_tools::tool_result_t::ok(summary, data);
}

static void register_aggregator_tools_once()
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("ida_mcp_register_aggregator_enter");
#endif
    std::call_once(g_aggregator_tools_registered, []() {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("ida_mcp_register_aggregator_call_once");
#endif
        auto& reg = agent_tools::ToolRegistry::instance();

        agent_tools::tool_definition_t list_def;
        list_def.name = "list_ida_instances";
        list_def.category = "instances";
        list_def.description = "Enumerate every live IDA Pro instance currently exposing AiDA MCP. "
            "Returns each peer's instance_id (UUID), pid (OS process id), display_name, idb_path, input_file, "
            "file hashes, processor, bitness, port, and base_url. Use the returned instance_id OR pid as the "
            "optional instance_id/pid argument on any tool to target a specific IDA.";
        list_def.read_only = true;
        list_def.visibility = "public";
        list_def.handler = aggregator_list_instances;
        reg.register_tool(list_def);

        agent_tools::tool_definition_t info_def;
        info_def.name = "get_local_instance_info";
        info_def.category = "instances";
        info_def.description = "Return the metadata of the IDA instance backing this MCP connection.";
        info_def.read_only = true;
        info_def.visibility = "public";
        info_def.handler = aggregator_get_local_info;
        reg.register_tool(info_def);

        agent_tools::tool_definition_t fan_def;
        fan_def.name = "query_all_instances";
        fan_def.category = "instances";
        fan_def.description = "Fan out a single tool call to every live IDA instance concurrently and "
            "aggregate the per-instance results. Use this to compare or correlate findings across multiple "
            "binaries open in different IDAs.";
        fan_def.read_only = false;
        fan_def.visibility = "public";
        agent_tools::tool_param_t p_tool;
        p_tool.name = "tool";
        p_tool.type = "string";
        p_tool.description = "Tool name to invoke on every live IDA instance.";
        p_tool.required = true;
        agent_tools::tool_param_t p_args;
        p_args.name = "arguments";
        p_args.type = "object";
        p_args.description = "Arguments object passed to the tool on each instance.";
        p_args.required = false;
        agent_tools::tool_param_t p_to;
        p_to.name = "timeout_seconds";
        p_to.type = "integer";
        p_to.description = "Per-instance timeout in seconds (default 60).";
        p_to.required = false;
        fan_def.parameters = { p_tool, p_args, p_to };
        fan_def.handler = aggregator_query_all;
        reg.register_tool(fan_def);
#ifdef __NT__
        aida_ipc::trace_breadcrumb("ida_mcp_register_aggregator_done tools_registered=3");
#endif
    });
}

mcp_server_t::mcp_server_t()
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("ida_mcp_ctor_enter");
#endif
}

mcp_server_t::~mcp_server_t()
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("ida_mcp_dtor_enter running=%d port=%d",
                               _running.load() ? 1 : 0, _port);
#endif
    stop();
#ifdef __NT__
    aida_ipc::trace_breadcrumb("ida_mcp_dtor_exit");
#endif
}

bool mcp_server_t::is_running() const
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("ida_mcp_is_running running=%d port=%d",
                               _running.load() ? 1 : 0, _port);
#endif
    return _running.load();
}

int mcp_server_t::get_port() const
{
    int p = _running.load() ? _port : 0;
#ifdef __NT__
    aida_ipc::trace_breadcrumb("ida_mcp_get_port running=%d port=%d", _running.load() ? 1 : 0, p);
#endif
    return p;
}

bool mcp_server_t::start(int port)
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("ida_mcp_start_enter port=%d running=%d bind_failed=%d stop_requested=%d",
                               port, _running.load() ? 1 : 0, _bind_failed.load() ? 1 : 0,
                               _stop_requested.load() ? 1 : 0);
#endif

    if (_running.load())
    {
        msg("AiDA MCP: Server is already running on port %d.\n", _port);
        return true;
    }

    register_aggregator_tools_once();
#ifdef __NT__
    aida_ipc::trace_breadcrumb("ida_mcp_start_after_aggregator_register port=%d", port);
#endif

    // Slice B12 — log any disagreement between the legacy destructive list and
    // the new tool_definition_t::destructive flag. Runs once per start().
    audit_destructive_flag_drift();
#ifdef __NT__
    aida_ipc::trace_breadcrumb("ida_mcp_start_after_destructive_audit port=%d", port);
#endif

    _stop_requested = false;
    _bind_failed = false;
    _port = 0;

    try
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("ida_mcp_start_spawning_thread port=%d", port);
#endif
        _server_thread = std::thread([this, port]() { server_thread_entry(port); });
    }
    catch (const std::exception& e)
    {
        msg("AiDA MCP: Failed to start server thread: %s\n", e.what());
#ifdef __NT__
        aida_ipc::trace_breadcrumb("ida_mcp_start_thread_exception port=%d what=%s", port, e.what());
#endif
        return false;
    }
#ifdef __NT__
    aida_ipc::trace_breadcrumb("ida_mcp_start_thread_spawned port=%d", port);
#endif

    for (int i = 0; i < 100 && !_running.load() && !_stop_requested.load() && !_bind_failed.load(); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(20));

    if (_running.load())
    {
        size_t tool_count = agent_tools::ToolRegistry::instance().get_tool_names().size();
#ifdef __NT__
        aida_ipc::trace_breadcrumb("ida_mcp_start_running port=%d tool_count=%zu", _port, tool_count);
#endif

        std::string base_url = "http://127.0.0.1:" + std::to_string(_port);
        std::string mcp_url  = base_url + "/mcp";
        std::string sse_url  = base_url + "/sse";

        if (!_registry)
            _registry = std::make_unique<instance_registry_t>();
#ifdef __NT__
        aida_ipc::trace_breadcrumb("ida_mcp_start_registry_start port=%d base_url=%s", _port, base_url.c_str());
#endif
        if (_registry->start(_port, base_url, mcp_url, sse_url))
        {
            g_active_registry.store(_registry.get(), std::memory_order_release);
            _registry->on_peer_set_changed([this]() {
                this->write_mcp_client_configs();
            });
#ifdef __NT__
            aida_ipc::trace_breadcrumb("ida_mcp_start_registry_ok port=%d", _port);
#endif
        }
        else
        {
            msg("AiDA MCP: Warning - instance registry failed to start; multi-instance discovery disabled.\n");
#ifdef __NT__
            aida_ipc::trace_breadcrumb("ida_mcp_start_registry_fail port=%d", _port);
#endif
        }

        msg("AiDA MCP: Server started on http://127.0.0.1:%d\n", _port);
        if (port > 0 && _port != port)
            msg("AiDA MCP: Requested port %d was in use; bound to port %d instead.\n", port, _port);
        msg("AiDA MCP: %zu tools available.\n", tool_count);
        msg("AiDA MCP: Streamable HTTP  -> %s\n", mcp_url.c_str());
        msg("AiDA MCP: Legacy SSE       -> %s\n", sse_url.c_str());
        if (_registry)
        {
            msg("AiDA MCP: Instance ID         -> %s\n", _registry->self_instance_id().c_str());
            msg("AiDA MCP: Config entry name   -> %s\n", _registry->self_config_entry_name().c_str());
        }
        return true;
    }
    else if (_stop_requested.load() || _bind_failed.load())
    {
        msg("AiDA MCP: Server failed to start on port %d (no free local port found).\n", port);
#ifdef __NT__
        aida_ipc::trace_breadcrumb("ida_mcp_start_bind_failed port=%d stop=%d bind_failed=%d",
                                   port, _stop_requested.load() ? 1 : 0, _bind_failed.load() ? 1 : 0);
#endif
        if (_server_thread.joinable())
            _server_thread.join();
        return false;
    }
    else
    {
        msg("AiDA MCP: Server starting on port %d (async)...\n", port);
#ifdef __NT__
        aida_ipc::trace_breadcrumb("ida_mcp_start_async port=%d", port);
#endif
        return true;
    }
}

void mcp_server_t::stop()
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("ida_mcp_stop_enter running=%d joinable=%d port=%d",
                               _running.load() ? 1 : 0,
                               _server_thread.joinable() ? 1 : 0,
                               _port);
#endif
    if (!_running.load() && !_server_thread.joinable() && !_registry)
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("ida_mcp_stop_noop not_running_no_thread_no_registry");
#endif
        return;
    }

#ifdef __NT__
    aida_ipc::trace_breadcrumb("ida_mcp_stop_enter running=%d joinable=%d port=%d",
                               _running.load() ? 1 : 0,
                               _server_thread.joinable() ? 1 : 0,
                               _port);
#endif
    _stop_requested = true;

    {
        std::lock_guard<std::mutex> lock(_server_mutex);
        if (_active_server)
        {
            static_cast<httplib::Server*>(_active_server)->stop();
        }
    }

    if (_server_thread.joinable())
        _server_thread.join();
#ifdef __NT__
    aida_ipc::trace_breadcrumb("ida_mcp_stop_thread_joined port=%d", _port);
#endif

    if (_registry)
    {
        g_active_registry.store(nullptr, std::memory_order_release);
        _registry->stop();
        _registry.reset();
    }

    msg("AiDA MCP: Server stopped.\n");
#ifdef __NT__
    aida_ipc::trace_breadcrumb("ida_mcp_stop_exit");
#endif
}

void mcp_server_t::server_thread_entry(int port)
{
    unsigned long seh = 0;
#ifdef __NT__
    aida_ipc::trace_breadcrumb("ida_mcp_server_thread_enter requested_port=%d", port);
    __try
    {
        server_thread_func(port);
    }
    __except ((seh = GetExceptionCode()), EXCEPTION_EXECUTE_HANDLER)
    {
    }
#else
    server_thread_func(port);
#endif
    server_thread_finish(seh, port);
}

void mcp_server_t::server_thread_finish(unsigned long seh, int port)
{
    if (seh != 0)
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("ida_mcp_server_thread_seh code=0x%08lX requested_port=%d bound_port=%d",
                                   seh,
                                   port,
                                   _port);
#endif
        _bind_failed.store(true, std::memory_order_release);
    }
    _running.store(false, std::memory_order_release);
    {
        std::lock_guard<std::mutex> lock(_server_mutex);
        _active_server = nullptr;
    }
#ifdef __NT__
    aida_ipc::trace_breadcrumb("ida_mcp_server_thread_exit seh=0x%08lX requested_port=%d bound_port=%d",
                               seh,
                               port,
                               _port);
#endif
}

void mcp_server_t::server_thread_func(int port)
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("ida_mcp_server_thread_func_enter port=%d", port);
#endif
    httplib::Server svr;
    svr.set_payload_max_length(64u * 1024u * 1024u);
    svr.set_read_timeout(5, 0);
    svr.set_write_timeout(10, 0);
    svr.set_keep_alive_timeout(2);
    svr.set_keep_alive_max_count(64);

    {
        std::lock_guard<std::mutex> lock(_server_mutex);
        _active_server = &svr;
    }

    std::string session_id = generate_session_id();

    svr.set_default_headers({
        {"Cache-Control", "no-store"},
        {"X-Content-Type-Options", "nosniff"}
    });

    svr.set_pre_routing_handler([this](const httplib::Request& req, httplib::Response& res) {
        const bool loopback = req.remote_addr == "127.0.0.1" || req.remote_addr == "::1" || req.remote_addr == "localhost";
        const std::string host = req.get_header_value("Host");
        const std::string expected = "127.0.0.1:" + std::to_string(_port);
        const std::string expected_localhost = "localhost:" + std::to_string(_port);
        const bool host_valid = host == expected || host == expected_localhost;
        const bool origin_valid = req.get_header_value("Origin").empty();
        if (!loopback || !host_valid || !origin_valid) {
            res.status = 403;
            res.set_content(R"({"status":"rejected","error":"MCP local authorization failed","code":"MCP_LOCAL_AUTH_REQUIRED","disposition":"not_started"})", "application/json");
            return httplib::Server::HandlerResponse::Handled;
        }
        if (req.method == "OPTIONS") {
            res.status = 204;
            return httplib::Server::HandlerResponse::Handled;
        }
        const bool has_peer_auth_header =
            req.has_header(kPeerInstanceHeader) || req.has_header(kPeerGenerationHeader)
            || req.has_header(kPeerCapabilityHeader) || req.has_header("X-AiDA-Peer-Pid")
            || req.has_header("X-AiDA-Peer-Started-At");
        const bool has_all_peer_auth_headers =
            req.has_header(kPeerInstanceHeader) && req.has_header(kPeerGenerationHeader)
            && req.has_header(kPeerCapabilityHeader) && req.has_header("X-AiDA-Peer-Pid")
            && req.has_header("X-AiDA-Peer-Started-At");
        if (has_peer_auth_header != has_all_peer_auth_headers
            || (has_all_peer_auth_headers && !authenticate_peer_request(req)))
        {
            res.status = 403;
            res.set_content(R"({"status":"rejected","error":"MCP peer authentication failed","code":"MCP_PEER_AUTH_FAILED"})", "application/json");
            return httplib::Server::HandlerResponse::Handled;
        }
        return httplib::Server::HandlerResponse::Unhandled;
    });

    svr.Post("/mcp", [&session_id](const httplib::Request& req, httplib::Response& res) {
        std::string response_body = handle_mcp_body(req.body, [&req]() { return req.is_connection_closed ? req.is_connection_closed() : false; });

        res.set_header("Mcp-Session-Id", session_id);

        if (response_body.empty())
        {
            res.status = 202;
        }
        else
        {
            res.set_content(response_body, "application/json");
        }
    });

    svr.Get("/mcp", [this, &session_id](const httplib::Request& req, httplib::Response& res) {
        res.set_header("Mcp-Session-Id", session_id);

        std::string accept = req.get_header_value("Accept");
        bool wants_sse = accept.find("text/event-stream") != std::string::npos;

        if (wants_sse)
        {
            res.set_header("Cache-Control", "no-cache");
            res.set_chunked_content_provider(
                "text/event-stream",
                [this](size_t offset, httplib::DataSink& sink) -> bool {
                    if (offset == 0)
                    {
                        std::string evt = ": connected\n\n";
                        if (!sink.write(evt.c_str(), evt.size()))
                            return false;
                    }
                    for (int i = 0; i < 15; ++i)
                    {
                        std::this_thread::sleep_for(std::chrono::seconds(2));
                        if (_stop_requested.load())
                            return false;
                    }
                    std::string ka = ": keepalive\n\n";
                    return sink.write(ka.c_str(), ka.size());
                },
                nullptr
            );
        }
        else
        {
            res.set_content("event: endpoint\ndata: /mcp\n\n", "text/event-stream");
        }
    });

    svr.Delete("/mcp", [&session_id](const httplib::Request&, httplib::Response& res) {
        res.set_header("Mcp-Session-Id", session_id);
        res.status = 200;
        res.set_content("{}", "application/json");
    });

    svr.Get("/health", [](const httplib::Request&, httplib::Response& res) {
        json health;
        health["status"] = "ok";
        health["server"] = std::string("aida-ida-mcp");
        health["version"] = AIDA_VERSION;
        health["tools_count"] = agent_tools::ToolRegistry::instance().get_tool_names().size();
        res.set_content(json_dump_safe(health), "application/json");
    });

    svr.Get("/config", [](const httplib::Request&, httplib::Response& res) {
        json config;
        config["name"] = "aida-ida-mcp";
        config["version"] = AIDA_VERSION;
        config["transport"] = "streamable-http";
        config["legacy_sse"] = true;
        auto* registry = current_registry();
        if (registry)
        {
            auto self = registry->self_record();
            config["self"] = record_to_public_json(self);
            config["mcpServers"] = json::object({
                {"aida-ida-mcp", json::object({{"type", "http"}, {"url", self.mcp_url}})}
            });
            config["sseServers"] = json::object({
                {"aida-ida-mcp", json::object({{"url", self.sse_url}})}
            });
        }
        res.set_content(json_dump_safe(config, 2), "application/json");
    });

    svr.Get("/profile.txt", [](const httplib::Request&, httplib::Response& res) {
        std::string profile;
        profile += "aida-ida-mcp\n";
        profile += "version=";
        profile += AIDA_VERSION;
        profile += "\ntransport=streamable-http\n";
        auto* registry = current_registry();
        if (registry)
        {
            auto self = registry->self_record();
            profile += "mcp_url=" + self.mcp_url + "\n";
            profile += "sse_url=" + self.sse_url + "\n";
            profile += "instance_id=" + self.instance_id + "\n";
        }
        res.set_content(profile, "text/plain");
    });

    svr.Get("/config.html", [](const httplib::Request&, httplib::Response& res) {
        std::string mcp_url = "/mcp";
        std::string sse_url = "/sse";
        auto* registry = current_registry();
        if (registry)
        {
            auto self = registry->self_record();
            mcp_url = self.mcp_url;
            sse_url = self.sse_url;
        }
        std::string html =
            "<!doctype html><html><head><meta charset=\"utf-8\"><title>aida-ida-mcp</title>"
            "<style>body{font-family:Segoe UI,Arial,sans-serif;margin:32px;line-height:1.5}code,pre{background:#f3f4f6;padding:2px 4px;border-radius:4px}pre{padding:12px;overflow:auto}</style>"
            "</head><body><h1>aida-ida-mcp</h1><p>Streamable HTTP endpoint:</p><pre>"
            + mcp_url +
            "</pre><p>Legacy SSE endpoint:</p><pre>"
            + sse_url +
            "</pre><p>JSON configuration is available at <code>/config</code>.</p></body></html>";
        res.set_content(html, "text/html");
    });

    svr.Get("/api/tools", [](const httplib::Request&, httplib::Response& res) {
        res.set_content(json_dump_safe(get_cached_mcp_tools_list(), 2), "application/json");
    });

    svr.Post("/api/tools/call", [](const httplib::Request& req, httplib::Response& res) {
        json body;
        try { body = json::parse(req.body); }
        catch (const json::parse_error& e)
        {
            res.status = 400;
            res.set_content(json_dump_safe({{"error", e.what()}}), "application/json");
            return;
        }

        std::string tool_name = body.value("name", "");
        json arguments = body.value("arguments", json::object());

        if (tool_name.empty())
        {
            res.status = 400;
            res.set_content(json_dump_safe({{"error", "Missing 'name' field"}}), "application/json");
            return;
        }

        const auto* tool = agent_tools::ToolRegistry::instance().get_tool(tool_name);
        if (!is_mcp_callable_tool(tool))
        {
            res.status = 403;
            res.set_content(json_dump_safe({{"error", "Tool is not exposed through MCP"}}), "application/json");
            return;
        }

        std::atomic<bool> cancel{false};
        std::atomic<bool> monitor_done{false};
        std::thread monitor([&]() {
            while (!monitor_done.load(std::memory_order_acquire)) {
                if (req.is_connection_closed && req.is_connection_closed()) {
                    cancel.store(true, std::memory_order_release);
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(25));
            }
        });
        scoped_mcp_cancel_flag_t cancel_scope(&cancel);
        auto tool_result = execute_tool_in_main_thread(tool_name, arguments, &cancel);
        monitor_done.store(true, std::memory_order_release);
        monitor.join();

        json resp;
        resp["success"] = tool_result.success;
        resp["output"] = sanitize_utf8(tool_result.output);
        if (!tool_result.data.is_null() && !tool_result.data.empty())
            resp["data"] = tool_result.data;

        res.set_content(json_dump_safe(resp, 2), "application/json");
    });

    svr.Get(R"(/output/([0-9a-fA-F]+)\.json)", [](const httplib::Request& req, httplib::Response& res) {
        if (req.matches.size() < 2)
        {
            res.status = 400;
            res.set_content(json_dump_safe({{"error", "Missing output id"}}), "application/json");
            return;
        }
        json payload;
        if (!get_cached_mcp_output_payload(req.matches[1].str(), payload))
        {
            res.status = 404;
            res.set_content(json_dump_safe({{"error", "Unknown or expired output id"}}), "application/json");
            return;
        }
        res.set_content(json_dump_safe(payload, 2), "application/json");
    });

    svr.Get("/api/resources", [](const httplib::Request&, httplib::Response& res) {
        json resources = json::array();
        for (const auto& rdef : get_resource_definitions())
        {
            resources.push_back({
                {"uri",         rdef.uri},
                {"name",        rdef.name},
                {"description", rdef.description},
                {"mimeType",    rdef.mime_type}
            });
        }
        res.set_content(json_dump_safe(resources, 2), "application/json");
    });

    svr.Get("/api/resources/read", [](const httplib::Request& req, httplib::Response& res) {
        std::string uri = req.get_param_value("uri");
        if (uri.empty())
        {
            res.status = 400;
            res.set_content(json_dump_safe({{"error", "Missing 'uri' query parameter"}}), "application/json");
            return;
        }

        mcp_resource_def_t found;
        if (!resolve_mcp_resource_definition(uri, found))
        {
            res.status = 404;
            res.set_content(json_dump_safe({{"error", "Unknown resource: " + uri}}), "application/json");
            return;
        }

        auto tool_result = execute_resource_read(found);
        json resp;
        resp["uri"] = found.uri;
        resp["success"] = tool_result.success;
        if (!tool_result.data.is_null() && !tool_result.data.empty())
            resp["data"] = tool_result.data;
        else
            resp["text"] = sanitize_utf8(tool_result.output);

        res.set_content(json_dump_safe(resp, 2), "application/json");
    });

    std::map<std::string, std::shared_ptr<sse_session_t>> sse_sessions;
    std::mutex sse_mtx;

    svr.Get("/sse", [this, &sse_sessions, &sse_mtx](const httplib::Request& req, httplib::Response& res) {
        auto session = std::make_shared<sse_session_t>();
        session->id = generate_session_id();
        session->remote_address = req.remote_addr;

        {
            std::lock_guard<std::mutex> lk(sse_mtx);
            sse_sessions[session->id] = session;
        }
        // Slice B13 — also register with the progress broadcaster so
        // mcp_emit_progress reaches this peer.
        progress_register_session(session);

        res.set_header("Cache-Control", "no-cache");
        res.set_header("Connection", "keep-alive");
        res.set_header("X-Accel-Buffering", "no");

        res.set_chunked_content_provider(
            "text/event-stream",
            [this, session](size_t offset, httplib::DataSink& sink) -> bool {
                if (offset == 0)
                {
                    std::string evt = format_sse_event("endpoint",
                        "/message?sessionId=" + session->id);
                    if (!sink.write(evt.c_str(), evt.size()))
                    {
                        session->close();
                        return false;
                    }
                }

                std::string event;
                if (session->wait_event(event, 2000))
                {
                    if (!sink.write(event.c_str(), event.size()))
                    {
                        session->close();
                        return false;
                    }
                }
                else if (session->closed.load(std::memory_order_relaxed))
                {
                    return false;
                }
                else if (_stop_requested.load())
                {
                    session->close();
                    return false;
                }
                else
                {
                    std::string ka = ": keepalive\n\n";
                    if (!sink.write(ka.c_str(), ka.size()))
                    {
                        session->close();
                        return false;
                    }
                }

                return !session->closed.load(std::memory_order_relaxed);
            },
            [session, &sse_sessions, &sse_mtx](bool ) {
                session->close();
                progress_unregister_session(session);
                std::lock_guard<std::mutex> lk(sse_mtx);
                sse_sessions.erase(session->id);
            }
        );
    });

    svr.Post("/message", [&sse_sessions, &sse_mtx](const httplib::Request& req, httplib::Response& res) {
        std::string sid = req.get_param_value("sessionId");
        if (sid.empty())
        {
            res.status = 400;
            res.set_content(json_dump_safe(make_jsonrpc_error(nullptr,
                JSONRPC_INVALID_REQUEST, "Missing sessionId query parameter")),
                "application/json");
            return;
        }

        std::shared_ptr<sse_session_t> session;
        {
            std::lock_guard<std::mutex> lk(sse_mtx);
            auto it = sse_sessions.find(sid);
            if (it == sse_sessions.end())
            {
                res.status = 404;
                res.set_content(json_dump_safe(make_jsonrpc_error(nullptr,
                    JSONRPC_INVALID_REQUEST, "Unknown or expired session: " + sid)),
                    "application/json");
                return;
            }
            session = it->second;
        }
        if (!session || session->remote_address != req.remote_addr)
        {
            res.status = 403;
            res.set_content(json_dump_safe(make_jsonrpc_error(nullptr,
                JSONRPC_INVALID_REQUEST, "SSE session is bound to another local client")),
                "application/json");
            return;
        }

        std::string response_body = handle_mcp_body(req.body, [&req]() { return req.is_connection_closed ? req.is_connection_closed() : false; });

        if (!response_body.empty())
        {
            std::string event = format_sse_event("message", response_body);
            session->push_event(event);
        }

        res.status = 202;
        res.set_content("Accepted", "text/plain");
    });

    svr.Post("/sse", [&session_id](const httplib::Request& req, httplib::Response& res) {
        std::string response_body = handle_mcp_body(req.body, [&req]() { return req.is_connection_closed ? req.is_connection_closed() : false; });
        res.set_header("Mcp-Session-Id", session_id);
        if (response_body.empty())
            res.status = 202;
        else
            res.set_content(response_body, "application/json");
    });

    svr.Delete("/sse", [&session_id](const httplib::Request&, httplib::Response& res) {
        res.set_header("Mcp-Session-Id", session_id);
        res.status = 200;
        res.set_content("{}", "application/json");
    });

    svr.set_socket_options([](socket_t sock) {
        int yes = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&yes), sizeof(yes));
    });

    int bound_port = 0;
    int seed_port = port > 0 ? port : 13120;
#ifdef __NT__
    aida_ipc::trace_breadcrumb("ida_mcp_bind_enter seed_port=%d", seed_port);
#endif
    for (int candidate = seed_port; candidate < seed_port + 256 && bound_port <= 0; ++candidate)
    {
        if (svr.bind_to_port("127.0.0.1", candidate))
        {
            bound_port = candidate;
            break;
        }
    }
    if (bound_port <= 0)
        bound_port = svr.bind_to_any_port("127.0.0.1");
#ifdef __NT__
    aida_ipc::trace_breadcrumb("ida_mcp_bind_result bound_port=%d", bound_port);
#endif

    if (bound_port <= 0)
    {
        if (!_stop_requested.load())
            msg("AiDA MCP: Failed to bind any port near %d and no fallback port was available.\n", port);
#ifdef __NT__
        aida_ipc::trace_breadcrumb("ida_mcp_bind_failed port=%d", port);
#endif

        _bind_failed.store(true, std::memory_order_release);

        {
            std::lock_guard<std::mutex> lock(_server_mutex);
            _active_server = nullptr;
        }
        return;
    }

    _port = bound_port;
    _running = true;
#ifdef __NT__
    aida_ipc::trace_breadcrumb("ida_mcp_listen_enter bound_port=%d", bound_port);
#endif

    if (!svr.listen_after_bind())
    {
        if (!_stop_requested.load())
            msg("AiDA MCP: Listener terminated on 127.0.0.1:%d\n", bound_port);
#ifdef __NT__
        aida_ipc::trace_breadcrumb("ida_mcp_listen_terminated port=%d", bound_port);
#endif
    }
#ifdef __NT__
    aida_ipc::trace_breadcrumb("ida_mcp_listen_exit port=%d", bound_port);
#endif

    _running = false;

    {
        std::lock_guard<std::mutex> lock(_server_mutex);
        _active_server = nullptr;
    }
}

enum class mcp_cfg_format_t
{
    mcpservers_url,
    mcpservers_serverurl,
    opencode_json,
    vscode_mcp,
    vscode_mcp_json,
    cline_mcp,
    zed_context,
    codex_toml,
    claude_code_json
};

struct mcp_client_def_t
{
    const char* name;
    mcp_cfg_format_t format;
    const char* win_path;
    const char* mac_path;
    const char* linux_path;
};

static const mcp_client_def_t g_mcp_client_defs[] =
{
    {
        "Amazon Q",
        mcp_cfg_format_t::mcpservers_url,
        "~/.aws/amazonq/mcp_config.json",
        "~/.aws/amazonq/mcp_config.json",
        "~/.aws/amazonq/mcp_config.json"
    },
    {
        "Antigravity IDE",
        mcp_cfg_format_t::mcpservers_serverurl,
        "~/.gemini/antigravity/mcp_config.json",
        "~/.gemini/antigravity/mcp_config.json",
        "~/.gemini/antigravity/mcp_config.json"
    },
    {
        "Claude",
        mcp_cfg_format_t::mcpservers_url,
        "%APPDATA%/Claude/claude_desktop_config.json",
        "~/Library/Application Support/Claude/claude_desktop_config.json",
        nullptr
    },
    {
        "Copilot CLI",
        mcp_cfg_format_t::mcpservers_url,
        "~/.copilot/mcp-config.json",
        "~/.copilot/mcp-config.json",
        "~/.copilot/mcp-config.json"
    },
    {
        "Crush",
        mcp_cfg_format_t::mcpservers_url,
        "~/crush.json",
        "~/crush.json",
        "~/crush.json"
    },
    {
        "Cursor",
        mcp_cfg_format_t::mcpservers_url,
        "~/.cursor/mcp.json",
        "~/.cursor/mcp.json",
        "~/.cursor/mcp.json"
    },
    {
        "Gemini CLI",
        mcp_cfg_format_t::mcpservers_url,
        "~/.gemini/settings.json",
        "~/.gemini/settings.json",
        "~/.gemini/settings.json"
    },
    {
        "Kiro",
        mcp_cfg_format_t::mcpservers_url,
        "~/.kiro/settings/mcp.json",
        "~/.kiro/settings/mcp.json",
        "~/.kiro/settings/mcp.json"
    },
    {
        "Kiro Legacy",
        mcp_cfg_format_t::mcpservers_url,
        "~/.kiro/mcp_config.json",
        "~/.kiro/mcp_config.json",
        "~/.kiro/mcp_config.json"
    },
    {
        "LM Studio",
        mcp_cfg_format_t::mcpservers_url,
        "~/.lmstudio/mcp.json",
        "~/.lmstudio/mcp.json",
        "~/.lmstudio/mcp.json"
    },
    {
        "Opencode",
        mcp_cfg_format_t::opencode_json,
        "~/.config/opencode/opencode.json",
        "~/.config/opencode/opencode.json",
        "~/.config/opencode/opencode.json"
    },
    {
        "Qwen Coder",
        mcp_cfg_format_t::mcpservers_url,
        "~/.qwen/settings.json",
        "~/.qwen/settings.json",
        "~/.qwen/settings.json"
    },
    {
        "Trae",
        mcp_cfg_format_t::mcpservers_url,
        "~/.trae/mcp_config.json",
        "~/.trae/mcp_config.json",
        "~/.trae/mcp_config.json"
    },
    {
        "Warp",
        mcp_cfg_format_t::mcpservers_url,
        "~/.warp/mcp_config.json",
        "~/.warp/mcp_config.json",
        "~/.warp/mcp_config.json"
    },

    {
        "Windsurf",
        mcp_cfg_format_t::mcpservers_url,
        "~/.codeium/windsurf/mcp_config.json",
        "~/.codeium/windsurf/mcp_config.json",
        "~/.codeium/windsurf/mcp_config.json"
    },

    {
        "VS Code",
        mcp_cfg_format_t::vscode_mcp,
        "%APPDATA%/Code/User/settings.json",
        "~/Library/Application Support/Code/User/settings.json",
        "~/.config/Code/User/settings.json"
    },
    {
        "VS Code Insiders",
        mcp_cfg_format_t::vscode_mcp,
        "%APPDATA%/Code - Insiders/User/settings.json",
        "~/Library/Application Support/Code - Insiders/User/settings.json",
        "~/.config/Code - Insiders/User/settings.json"
    },
    {
        "Augment Code",
        mcp_cfg_format_t::vscode_mcp,
        "%APPDATA%/Code/User/settings.json",
        "~/Library/Application Support/Code/User/settings.json",
        "~/.config/Code/User/settings.json"
    },
    {
        "Qodo Gen",
        mcp_cfg_format_t::vscode_mcp,
        "%APPDATA%/Code/User/settings.json",
        "~/Library/Application Support/Code/User/settings.json",
        "~/.config/Code/User/settings.json"
    },

    {
        "VS Code (mcp.json)",
        mcp_cfg_format_t::vscode_mcp_json,
        "%APPDATA%/Code/User/mcp.json",
        "~/Library/Application Support/Code/User/mcp.json",
        "~/.config/Code/User/mcp.json"
    },
    {
        "VS Code Insiders (mcp.json)",
        mcp_cfg_format_t::vscode_mcp_json,
        "%APPDATA%/Code - Insiders/User/mcp.json",
        "~/Library/Application Support/Code - Insiders/User/mcp.json",
        "~/.config/Code - Insiders/User/mcp.json"
    },

    {
        "Cline",
        mcp_cfg_format_t::cline_mcp,
        "%APPDATA%/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
        "~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
        "~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"
    },
    {
        "Kilo Code",
        mcp_cfg_format_t::cline_mcp,
        "%APPDATA%/Code/User/globalStorage/kilocode.kilo-code/settings/mcp_settings.json",
        "~/Library/Application Support/Code/User/globalStorage/kilocode.kilo-code/settings/mcp_settings.json",
        "~/.config/Code/User/globalStorage/kilocode.kilo-code/settings/mcp_settings.json"
    },
    {
        "Roo Code",
        mcp_cfg_format_t::cline_mcp,
        "%APPDATA%/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json",
        "~/Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json",
        "~/.config/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json"
    },

    {
        "Zed",
        mcp_cfg_format_t::zed_context,
        "%APPDATA%/Zed/settings.json",
        "~/Library/Application Support/Zed/settings.json",
        "~/.config/zed/settings.json"
    },

    {
        "Codex",
        mcp_cfg_format_t::codex_toml,
        "~/.codex/config.toml",
        "~/.codex/config.toml",
        "~/.codex/config.toml"
    },

    {
        "Claude Code",
        mcp_cfg_format_t::claude_code_json,
        "~/.claude.json",
        "~/.claude.json",
        "~/.claude.json"
    },

#ifdef __APPLE__
    {
        "BoltAI",
        mcp_cfg_format_t::mcpservers_url,
        nullptr,
        "~/Library/Application Support/BoltAI/config.json",
        nullptr
    },
    {
        "Perplexity",
        mcp_cfg_format_t::mcpservers_url,
        nullptr,
        "~/Library/Application Support/Perplexity/mcp_config.json",
        nullptr
    },
#endif
};

static const std::string MCP_SERVER_NAME       = std::string("aida-ida-mcp");
static const std::string MCP_AGGREGATOR_NAME    = std::string("aida-ida-mcp");
static const std::string MCP_OLD_SERVER_NAME   = std::string("AiDA-IDA-MCP");
static const std::string MCP_OLD_PRO_PREFIX    = std::string("AiDA-Pro-MCP");
static const std::string MCP_INSTANCE_PREFIX    = std::string("AiDA-IDA-MCP-");
static const std::string MCP_OLD_INSTANCE_PREFIX = std::string("aida-ida-");

struct mcp_entry_t
{
    std::string name;
    std::string http_url;
    std::string sse_url;
    std::string description;
};

static bool mcp_is_aida_managed_key(const std::string& key)
{
    if (key == MCP_SERVER_NAME)
        return true;
    if (key == MCP_AGGREGATOR_NAME)
        return true;
    if (key == MCP_OLD_SERVER_NAME)
        return true;
    if (key == MCP_OLD_PRO_PREFIX)
        return true;
    if (key == std::string("aida-ida-all"))
        return true;
    if (key == std::string("camoufox-reverse-mcp"))
        return true;
    if (key == std::string("camoufox_reverse_mcp"))
        return true;
    if (key == std::string("camoufox-reverse"))
        return true;
    if (key.size() >= MCP_INSTANCE_PREFIX.size()
        && key.compare(0, MCP_INSTANCE_PREFIX.size(), MCP_INSTANCE_PREFIX) == 0)
        return true;
    if (key.size() >= MCP_OLD_INSTANCE_PREFIX.size()
        && key.compare(0, MCP_OLD_INSTANCE_PREFIX.size(), MCP_OLD_INSTANCE_PREFIX) == 0)
        return true;
    return false;
}

static std::vector<std::string> mcp_collect_managed_keys(const json& obj)
{
    std::vector<std::string> out;
    if (!obj.is_object())
        return out;
    for (auto it = obj.begin(); it != obj.end(); ++it)
    {
        if (mcp_is_aida_managed_key(it.key()))
            out.push_back(it.key());
    }
    return out;
}

static std::string mcp_get_home_dir()
{
    qstring buf;
#ifdef _WIN32
    if (qgetenv("USERPROFILE", &buf) && !buf.empty())
        return std::string(buf.c_str());
    qstring drive, hpath;
    if (qgetenv("HOMEDRIVE", &drive) && qgetenv("HOMEPATH", &hpath))
        return std::string(drive.c_str()) + std::string(hpath.c_str());
#else
    if (qgetenv("HOME", &buf) && !buf.empty())
        return std::string(buf.c_str());
#endif
    return std::string();
}

static std::string mcp_get_appdata_dir()
{
#ifdef _WIN32
    qstring buf;
    if (qgetenv("APPDATA", &buf) && !buf.empty())
        return std::string(buf.c_str());
    return std::string();
#elif defined(__APPLE__)
    std::string home = mcp_get_home_dir();
    if (home.empty()) return std::string();
    return home + "/Library/Application Support";
#else
    std::string home = mcp_get_home_dir();
    if (home.empty()) return std::string();
    return home + "/.config";
#endif
}

static std::string mcp_normalize_separators(const std::string& path)
{
    std::string result = path;
#ifdef _WIN32
    for (auto& c : result)
    {
        if (c == '/')
            c = '\\';
    }
#endif
    return result;
}

static std::string mcp_expand_path(const char* path_template)
{
    if (!path_template || !*path_template)
        return std::string();

    std::string path(path_template);

    if (path.size() >= 1 && path[0] == '~')
    {
        std::string home = mcp_get_home_dir();
        if (home.empty())
            return std::string();
        if (path.size() >= 2 && (path[1] == '/' || path[1] == '\\'))
            path = home + path.substr(1);
        else if (path.size() == 1)
            path = home;
    }

    size_t pos = path.find("%APPDATA%");
    if (pos != std::string::npos)
    {
#ifdef _WIN32
        qstring appdata;
        if (!qgetenv("APPDATA", &appdata) || appdata.empty())
            return std::string();
        path.replace(pos, 9, appdata.c_str());
#else
        std::string appdata = mcp_get_appdata_dir();
        if (appdata.empty())
            return std::string();
        path.replace(pos, 9, appdata);
#endif
    }

    return mcp_normalize_separators(path);
}

static bool mcp_ensure_dir_recursive(const std::string& dir_path)
{
    if (dir_path.empty())
        return false;
    if (qisdir(dir_path.c_str()))
        return true;

    size_t sep = dir_path.find_last_of("/\\");
    if (sep != std::string::npos && sep > 0)
    {
        std::string parent = dir_path.substr(0, sep);
        if (!mcp_ensure_dir_recursive(parent))
            return false;
    }

    int rc = qmkdir(dir_path.c_str(), 0755);
    return rc == 0 || qisdir(dir_path.c_str());
}

static bool mcp_ensure_parent_dir(const std::string& file_path)
{
    size_t sep = file_path.find_last_of("/\\");
    if (sep == std::string::npos || sep == 0)
        return true;
    return mcp_ensure_dir_recursive(file_path.substr(0, sep));
}

static bool mcp_read_file_contents(const std::string& path, std::string& out)
{
    FILE* fp = qfopen(path.c_str(), "rb");
    if (!fp)
        return false;
    file_janitor_t fj(fp);
    uint64 size = qfsize(fp);
    if (size == 0 || size > 50ULL * 1024 * 1024)
        return false;
    out.resize(static_cast<size_t>(size));
    return qfread(fp, &out[0], out.size()) == static_cast<ssize_t>(out.size());
}

static bool mcp_parse_json_file(const std::string& path, json& out, bool allow_jsonc);
static bool mcp_write_json_file(const std::string& path, const json& data);

static bool mcp_write_file_contents(const std::string& path, const std::string& content)
{
    if (!mcp_ensure_parent_dir(path))
        return false;

    std::string tmp = path + ".aida-tmp";
    {
        FILE* fp = qfopen(tmp.c_str(), "wb");
        if (!fp)
            return false;
        file_janitor_t fj(fp);
        if (qfwrite(fp, content.c_str(), content.size()) != static_cast<ssize_t>(content.size()))
            return false;
    }

#ifdef _WIN32
    if (MoveFileExA(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING) == 0)
    {
        qunlink(tmp.c_str());
        return false;
    }
#else
    if (::rename(tmp.c_str(), path.c_str()) != 0)
    {
        qunlink(tmp.c_str());
        return false;
    }
#endif
    return true;
}

static std::string mcp_strip_jsonc(const std::string& input)
{
    std::string result;
    result.reserve(input.size());

    bool in_string = false;
    bool in_line_comment = false;
    bool in_block_comment = false;

    for (size_t i = 0; i < input.size(); ++i)
    {
        char c = input[i];

        if (in_line_comment)
        {
            if (c == '\n')
            {
                in_line_comment = false;
                result += '\n';
            }
            continue;
        }

        if (in_block_comment)
        {
            if (c == '*' && i + 1 < input.size() && input[i + 1] == '/')
            {
                in_block_comment = false;
                ++i;
            }
            continue;
        }

        if (in_string)
        {
            result += c;
            if (c == '\\' && i + 1 < input.size())
                result += input[++i];
            else if (c == '"')
                in_string = false;
            continue;
        }

        if (c == '"')
        {
            in_string = true;
            result += c;
            continue;
        }

        if (c == '/' && i + 1 < input.size())
        {
            if (input[i + 1] == '/')
            {
                in_line_comment = true;
                ++i;
                continue;
            }
            if (input[i + 1] == '*')
            {
                in_block_comment = true;
                ++i;
                continue;
            }
        }

        if (c == ',')
        {
            size_t j = i + 1;
            while (j < input.size()
                && (input[j] == ' ' || input[j] == '\t'
                    || input[j] == '\n' || input[j] == '\r'))
                ++j;
            if (j < input.size() && (input[j] == '}' || input[j] == ']'))
                continue;
        }

        result += c;
    }

    return result;
}

static bool mcp_parse_json_file(const std::string& path, json& out, bool allow_jsonc)
{
    std::string raw;
    if (!mcp_read_file_contents(path, raw))
        return false;

    try
    {
        out = json::parse(raw);
        return true;
    }
    catch (const json::parse_error&)
    {
        if (!allow_jsonc)
            return false;
    }

    try
    {
        std::string stripped = mcp_strip_jsonc(raw);
        out = json::parse(stripped);
        return true;
    }
    catch (const json::parse_error&)
    {
        return false;
    }
}

static bool mcp_write_json_file(const std::string& path, const json& data)
{
    std::string content = json_dump_safe(data, 2);
    content += "\n";
    return mcp_write_file_contents(path, content);
}

static bool mcp_write_mcpservers_url(
    const std::string& path,
    const std::vector<mcp_entry_t>& entries,
    const char* url_key)
{
    json config;
    if (qfileexist(path.c_str()))
    {
        if (!mcp_parse_json_file(path, config, false))
            config = json::object();
    }
    if (!config.is_object())
        config = json::object();

    if (!config.contains("mcpServers") || !config["mcpServers"].is_object())
        config["mcpServers"] = json::object();

    auto& root = config["mcpServers"];
    for (const auto& key : mcp_collect_managed_keys(root))
        root.erase(key);

    for (const auto& e : entries)
    {
        json entry = json::object();
        entry["type"] = "http";
        entry[url_key] = e.http_url;
        root[e.name] = entry;
    }

    return mcp_write_json_file(path, config);
}

static bool mcp_write_opencode_json(const std::string& path,
                                    const std::vector<mcp_entry_t>& entries)
{
    json config;
    if (qfileexist(path.c_str()))
    {
        if (!mcp_parse_json_file(path, config, true))
            config = json::object();
    }
    if (!config.is_object())
        config = json::object();

    if (!config.contains("mcp") || !config["mcp"].is_object())
        config["mcp"] = json::object();

    auto& root = config["mcp"];
    for (const auto& key : mcp_collect_managed_keys(root))
        root.erase(key);

    for (const auto& e : entries)
    {
        json entry;
        entry["type"] = "remote";
        entry["url"] = e.http_url;
        root[e.name] = entry;
    }

    return mcp_write_json_file(path, config);
}

static bool mcp_write_cline_config(const std::string& path,
                                   const std::vector<mcp_entry_t>& entries)
{
    json config;
    if (qfileexist(path.c_str()))
    {
        if (!mcp_parse_json_file(path, config, false))
            config = json::object();
    }
    if (!config.is_object())
        config = json::object();

    if (!config.contains("mcpServers") || !config["mcpServers"].is_object())
        config["mcpServers"] = json::object();

    auto& root = config["mcpServers"];

    for (const auto& key : mcp_collect_managed_keys(root))
        root.erase(key);

    for (const auto& e : entries)
    {
        json entry;
        entry["type"] = "http";
        entry["url"] = e.http_url;
        root[e.name] = entry;
    }

    return mcp_write_json_file(path, config);
}

static bool mcp_write_vscode_settings(const std::string& path,
                                      const std::vector<mcp_entry_t>& entries)
{
    json config;
    if (qfileexist(path.c_str()))
    {
        if (!mcp_parse_json_file(path, config, true))
            config = json::object();
    }
    if (!config.is_object())
        config = json::object();

    if (!config.contains("mcp") || !config["mcp"].is_object())
        config["mcp"] = json::object();
    if (!config["mcp"].contains("servers") || !config["mcp"]["servers"].is_object())
        config["mcp"]["servers"] = json::object();

    auto& root = config["mcp"]["servers"];
    for (const auto& key : mcp_collect_managed_keys(root))
        root.erase(key);

    for (const auto& e : entries)
    {
        json entry;
        entry["type"] = "http";
        entry["url"] = e.http_url;
        root[e.name] = entry;
    }

    return mcp_write_json_file(path, config);
}

static bool mcp_write_vscode_mcp_json(const std::string& path,
                                      const std::vector<mcp_entry_t>& entries)
{
    json config;
    if (qfileexist(path.c_str()))
    {
        if (!mcp_parse_json_file(path, config, true))
            config = json::object();
    }
    if (!config.is_object())
        config = json::object();

    if (!config.contains("servers") || !config["servers"].is_object())
        config["servers"] = json::object();

    auto& root = config["servers"];
    for (const auto& key : mcp_collect_managed_keys(root))
        root.erase(key);

    for (const auto& e : entries)
    {
        json entry;
        entry["type"] = "http";
        entry["url"] = e.http_url;
        root[e.name] = entry;
    }

    return mcp_write_json_file(path, config);
}

static bool mcp_write_zed_settings(const std::string& path,
                                   const std::vector<mcp_entry_t>& entries)
{
    json config;
    if (qfileexist(path.c_str()))
    {
        if (!mcp_parse_json_file(path, config, true))
            config = json::object();
    }
    if (!config.is_object())
        config = json::object();

    if (!config.contains("context_servers") || !config["context_servers"].is_object())
        config["context_servers"] = json::object();

    auto& root = config["context_servers"];
    for (const auto& key : mcp_collect_managed_keys(root))
        root.erase(key);

    for (const auto& e : entries)
    {
        json entry;
        entry["settings"] = json::object();
        entry["settings"]["url"] = e.http_url;
        root[e.name] = entry;
    }

    return mcp_write_json_file(path, config);
}

static bool mcp_write_codex_toml(const std::string& path,
                                 const std::vector<mcp_entry_t>& entries)
{
    std::string content;
    if (qfileexist(path.c_str()))
        mcp_read_file_contents(path, content);

    auto strip_section = [](std::string& doc, const std::string& marker) {
        size_t pos = doc.find(marker);
        while (pos != std::string::npos)
        {
            size_t end = doc.find("\n[", pos + marker.size());
            if (end == std::string::npos)
                end = doc.size();
            else
                end += 1;
            doc.erase(pos, end - pos);
            pos = doc.find(marker);
        }
    };

    {
        const std::vector<std::string> names = {
            std::string("AiDA-Pro-MCP"),
            std::string("aida-ida-all"),
            std::string("camoufox-reverse-mcp"),
            std::string("camoufox_reverse_mcp"),
            std::string("camoufox-reverse"),
            MCP_OLD_SERVER_NAME,
            MCP_SERVER_NAME,
            MCP_AGGREGATOR_NAME
        };
        for (const auto& name : names)
            strip_section(content, std::string("[mcp_servers.") + name + "]");
    }

    {
        const std::string instance_marker_prefix = std::string("[mcp_servers.") + MCP_INSTANCE_PREFIX;
        size_t pos = content.find(instance_marker_prefix);
        while (pos != std::string::npos)
        {
            size_t end = content.find("\n[", pos + instance_marker_prefix.size());
            if (end == std::string::npos)
                end = content.size();
            else
                end += 1;
            content.erase(pos, end - pos);
            pos = content.find(instance_marker_prefix);
        }
    }

    {
        const std::string instance_marker_prefix = std::string("[mcp_servers.") + MCP_OLD_INSTANCE_PREFIX;
        size_t pos = content.find(instance_marker_prefix);
        while (pos != std::string::npos)
        {
            size_t end = content.find("\n[", pos + instance_marker_prefix.size());
            if (end == std::string::npos)
                end = content.size();
            else
                end += 1;
            content.erase(pos, end - pos);
            pos = content.find(instance_marker_prefix);
        }
    }

    if (!content.empty() && content.back() != '\n')
        content += "\n";

    for (const auto& e : entries)
    {
        std::string section = "\n[mcp_servers." + e.name + "]\n"
            "url = \"" + e.http_url + "\"\n";
        content += section;
    }

    return mcp_write_file_contents(path, content);
}

static bool mcp_write_claude_code_json(const std::string& path,
                                       const std::vector<mcp_entry_t>& entries)
{
    json config;
    if (qfileexist(path.c_str()))
    {
        if (!mcp_parse_json_file(path, config, false))
            config = json::object();
    }
    if (!config.is_object())
        config = json::object();

    if (!config.contains("mcpServers") || !config["mcpServers"].is_object())
        config["mcpServers"] = json::object();

    auto& root = config["mcpServers"];
    for (const auto& key : mcp_collect_managed_keys(root))
        root.erase(key);

    for (const auto& e : entries)
    {
        json entry;
        entry["type"] = "http";
        entry["url"] = e.http_url;
        root[e.name] = entry;
    }

    return mcp_write_json_file(path, config);
}

static bool mcp_write_single_client(
    const mcp_client_def_t& def,
    const std::string& path,
    const std::vector<mcp_entry_t>& entries)
{
    switch (def.format)
    {
    case mcp_cfg_format_t::mcpservers_url:
        return mcp_write_mcpservers_url(path, entries, "url");

    case mcp_cfg_format_t::mcpservers_serverurl:
        return mcp_write_mcpservers_url(path, entries, "serverUrl");

    case mcp_cfg_format_t::opencode_json:
        return mcp_write_opencode_json(path, entries);

    case mcp_cfg_format_t::vscode_mcp:
        return mcp_write_vscode_settings(path, entries);

    case mcp_cfg_format_t::vscode_mcp_json:
        return mcp_write_vscode_mcp_json(path, entries);

    case mcp_cfg_format_t::cline_mcp:
        return mcp_write_cline_config(path, entries);

    case mcp_cfg_format_t::zed_context:
        return mcp_write_zed_settings(path, entries);

    case mcp_cfg_format_t::codex_toml:
        return mcp_write_codex_toml(path, entries);

    case mcp_cfg_format_t::claude_code_json:
        return mcp_write_claude_code_json(path, entries);

    }
    return false;
}

static void mcp_write_reference_config(
    const std::vector<mcp_entry_t>& entries,
    const ida_instance_record_t& self_rec)
{
    json config;
    config["_comment"] = std::string("MCP Server - Auto-configured endpoint. aida-ida-mcp is the IDA plugin entry and coexists with aida-standalone-mcp.");
    config["_version"] = AIDA_VERSION;
    config["self"] = {
        {"instance_id",       self_rec.instance_id},
        {"port",              self_rec.port},
        {"base_url",          self_rec.base_url},
        {"mcp_url",           self_rec.mcp_url},
        {"sse_url",           self_rec.sse_url},
        {"input_file",        self_rec.input_file},
        {"display_name",      self_rec.display_name},
        {"config_entry_name", self_rec.config_entry_name}
    };

    json arr = json::array();
    for (const auto& e : entries)
    {
        json o;
        o["name"]     = e.name;
        o["http_url"] = e.http_url;
        o["sse_url"]  = e.sse_url;
        o["description"] = e.description;
        arr.push_back(o);
    }
    config["entries"] = arr;

    qstring config_file = get_user_idadir();
    config_file.append("/aida_mcp_config.json");

    try
    {
        std::string json_str = json_dump_safe(config, 2) + "\n";
        FILE* fp = qfopen(config_file.c_str(), "wb");
        if (fp)
        {
            file_janitor_t fj(fp);
            qfwrite(fp, json_str.c_str(), json_str.length());
        }
    }
    catch (...)
    {
        msg("AiDA MCP: Warning - could not write reference config file.\n");
    }
}

void mcp_server_t::write_mcp_client_configs() const
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("ida_mcp_write_configs_enter running=%d registry=%d",
                               _running.load() ? 1 : 0, _registry ? 1 : 0);
#endif
    if (!_running.load())
        return;
    if (!_registry || !_registry->is_running())
        return;

    auto self_rec = _registry->self_record();
    auto live = _registry->all_live_instances();

    std::vector<mcp_entry_t> entries;
    entries.reserve(1);

    {
        mcp_entry_t agg;
        agg.name = MCP_AGGREGATOR_NAME;
        agg.http_url = self_rec.mcp_url.empty() ? (self_rec.base_url + "/mcp") : self_rec.mcp_url;
        agg.sse_url  = self_rec.sse_url.empty() ? (self_rec.base_url + "/sse") : self_rec.sse_url;
        agg.description = "AiDA aggregator (any one live IDA; routes via list_ida_instances/query_all_instances)";
        entries.push_back(std::move(agg));
    }

    mcp_write_reference_config(entries, self_rec);

    std::set<std::string> written_paths;
    int configured_count = 0;
    int skipped_count = 0;
    int failed_count = 0;

    const size_t num_clients = sizeof(g_mcp_client_defs) / sizeof(g_mcp_client_defs[0]);
    for (size_t i = 0; i < num_clients; ++i)
    {
        const auto& def = g_mcp_client_defs[i];

        const char* path_template = nullptr;
#if defined(_WIN32)
        path_template = def.win_path;
#elif defined(__APPLE__)
        path_template = def.mac_path;
#else
        path_template = def.linux_path;
#endif

        if (!path_template || !*path_template)
        {
            ++skipped_count;
            continue;
        }

        std::string expanded = mcp_expand_path(path_template);
        if (expanded.empty())
        {
            ++skipped_count;
            continue;
        }

        if (written_paths.count(expanded))
            continue;

        if (expanded.find("globalStorage") != std::string::npos)
        {
            size_t sep = expanded.find_last_of("/\\");
            if (sep != std::string::npos)
            {
                std::string parent = expanded.substr(0, sep);
                if (!qisdir(parent.c_str()))
                {
                    ++skipped_count;
                    continue;
                }
            }
        }

        if (mcp_write_single_client(def, expanded, entries))
        {
            written_paths.insert(expanded);
            ++configured_count;
            msg("AiDA MCP: [OK] %s -> %s (%zu entries)\n",
                def.name, expanded.c_str(), entries.size());
        }
        else
        {
            ++failed_count;
            msg("AiDA MCP: [FAIL] %s -> %s\n", def.name, expanded.c_str());
        }
    }

    qstring ref_file = get_user_idadir();
    ref_file.append("/aida_mcp_config.json");

    msg("\n");
    msg("============================================================\n");
    msg("  AiDA MCP Server - Multi-Instance Configuration Summary\n");
    msg("============================================================\n");
    msg("  Self port            : %d\n", self_rec.port);
    msg("  Self instance_id     : %s\n", self_rec.instance_id.c_str());
    msg("  Self entry name      : %s\n", self_rec.config_entry_name.c_str());
    msg("  Live IDA instances   : %zu\n", live.size());
    for (const auto& r : live)
    {
        msg("    - %s | %s | %s%s\n",
            r.config_entry_name.c_str(),
            r.input_file.empty() ? "(no input)" : r.input_file.c_str(),
            r.base_url.c_str(),
            r.is_self ? "  [self]" : "");
    }
    msg("------------------------------------------------------------\n");
    msg("  Aggregator entry      : %s -> %s\n",
        MCP_AGGREGATOR_NAME.c_str(),
        (self_rec.mcp_url.empty() ? (self_rec.base_url + "/mcp").c_str() : self_rec.mcp_url.c_str()));
    msg("  Clients configured    : %d\n", configured_count);
    msg("  Clients skipped       : %d (not installed or unavailable)\n", skipped_count);
    if (failed_count > 0)
        msg("  Clients failed        : %d\n", failed_count);
    msg("------------------------------------------------------------\n");
    msg("  Client config exposes one IDA MCP server entry: %s.\n", MCP_AGGREGATOR_NAME.c_str());
    msg("  Use list_ida_instances, query_all_instances, instance_id,\n");
    msg("  or pid routing through that single entry for live IDA targets.\n");
    msg("------------------------------------------------------------\n");
    msg("  Reference config      : %s\n", ref_file.c_str());
    msg("============================================================\n\n");
}
