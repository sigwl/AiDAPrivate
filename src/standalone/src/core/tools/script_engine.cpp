#include "script_engine.hpp"
#include "../../helpers/diag_log.hpp"

#define SOL_ALL_SAFETIES_ON 1
#include <sol/sol.hpp>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <utility>
#include <vector>

namespace script_engine {

extern "C" int aida_lua_abi_release(void);
extern "C" int aida_lua_registry_index(void);
extern "C" size_t aida_lua_number_sizes(void);

static_assert(LUA_VERSION_RELEASE_NUM == 50408);
static_assert(LUA_REGISTRYINDEX == -1001000);

static std::mutex                    g_mutex;
static std::unique_ptr<sol::state>   g_lua;
static std::atomic<bool>             g_initialized{false};
static std::atomic<bool>             g_initializing{false};
static std::map<std::string, script_info> g_scripts;
static std::deque<log_entry>         g_log;
static constexpr size_t              MAX_LOG_ENTRIES = 4096;
static bool                          g_init_logged = false;
static std::array<size_t, static_cast<size_t>(hook_type::COUNT)> g_hook_counts{};


static uint64_t now_ms() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

static uint64_t wall_now_seconds() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}


static void add_log(const std::string& script, log_level level,
                    const std::string& msg) {
    if (!g_log.empty()) {
        log_entry& last = g_log.back();
        if (last.level == level && last.script_name == script && last.message == msg) {
            if (last.repeat_count < 0xFFFFFFFFu) last.repeat_count++;
            last.timestamp    = now_ms();
            last.wall_seconds = wall_now_seconds();
            return;
        }
    }
    log_entry e;
    e.timestamp    = now_ms();
    e.wall_seconds = wall_now_seconds();
    e.script_name  = script;
    e.level        = level;
    e.message      = msg;
    e.repeat_count = 1;
    g_log.push_back(std::move(e));
    while (g_log.size() > MAX_LOG_ENTRIES) g_log.pop_front();
}


static std::string current_script_context;

static void lua_log_info(const std::string& msg) {
    add_log(current_script_context, log_level::info, msg);
}

static void lua_log_warn(const std::string& msg) {
    add_log(current_script_context, log_level::warn, msg);
}

static void lua_log_error(const std::string& msg) {
    add_log(current_script_context, log_level::error, msg);
}

static void lua_log_debug(const std::string& msg) {
    add_log(current_script_context, log_level::debug, msg);
}

static void lua_log_output(const std::string& msg) {
    add_log(current_script_context, log_level::output, msg);
}


static std::string lua_base64_encode(const std::string& input) {
    auto result = decoder_pipeline::apply_single("base64_encode",
        std::vector<uint8_t>(input.begin(), input.end()));
    if (!result.success) return "";
    return std::string(result.data.begin(), result.data.end());
}

static std::string lua_base64_decode(const std::string& input) {
    auto result = decoder_pipeline::apply_single("base64_decode",
        std::vector<uint8_t>(input.begin(), input.end()));
    if (!result.success) return "";
    return std::string(result.data.begin(), result.data.end());
}

static std::string lua_hex_encode(const std::string& input) {
    auto result = decoder_pipeline::apply_single("hex_encode",
        std::vector<uint8_t>(input.begin(), input.end()));
    if (!result.success) return "";
    return std::string(result.data.begin(), result.data.end());
}

static std::string lua_hex_decode(const std::string& input) {
    auto result = decoder_pipeline::apply_single("hex_decode",
        std::vector<uint8_t>(input.begin(), input.end()));
    if (!result.success) return "";
    return std::string(result.data.begin(), result.data.end());
}

static std::string lua_url_encode(const std::string& input) {
    auto result = decoder_pipeline::apply_single("url_encode",
        std::vector<uint8_t>(input.begin(), input.end()));
    if (!result.success) return "";
    return std::string(result.data.begin(), result.data.end());
}

static std::string lua_url_decode(const std::string& input) {
    auto result = decoder_pipeline::apply_single("url_decode",
        std::vector<uint8_t>(input.begin(), input.end()));
    if (!result.success) return "";
    return std::string(result.data.begin(), result.data.end());
}

static std::string lua_md5(const std::string& input) {
    auto result = decoder_pipeline::apply_single("md5",
        std::vector<uint8_t>(input.begin(), input.end()));
    if (!result.success) return "";
    return std::string(result.data.begin(), result.data.end());
}

static std::string lua_sha256(const std::string& input) {
    auto result = decoder_pipeline::apply_single("sha256",
        std::vector<uint8_t>(input.begin(), input.end()));
    if (!result.success) return "";
    return std::string(result.data.begin(), result.data.end());
}

static std::string lua_gzip_decompress(const std::string& input) {
    auto result = decoder_pipeline::apply_single("gzip_decompress",
        std::vector<uint8_t>(input.begin(), input.end()));
    if (!result.success) return "";
    return std::string(result.data.begin(), result.data.end());
}

static std::string lua_gzip_compress(const std::string& input) {
    auto result = decoder_pipeline::apply_single("gzip_compress",
        std::vector<uint8_t>(input.begin(), input.end()));
    if (!result.success) return "";
    return std::string(result.data.begin(), result.data.end());
}

static std::string lua_xor_bytes(const std::string& data, const std::string& key_hex) {
    std::map<std::string, std::string> params = { {"key", key_hex} };
    auto result = decoder_pipeline::apply_single("xor",
        std::vector<uint8_t>(data.begin(), data.end()), params);
    if (!result.success) return "";
    return std::string(result.data.begin(), result.data.end());
}

static std::string lua_json_beautify(const std::string& input) {
    auto result = decoder_pipeline::apply_single("json_beautify",
        std::vector<uint8_t>(input.begin(), input.end()));
    if (!result.success) return "";
    return std::string(result.data.begin(), result.data.end());
}

static bool lua_regex_match(const std::string& text, const std::string& pattern) {
    if (!g_lua) return false;
    sol::state_view lua(*g_lua);
    sol::protected_function match_fn = lua["string"]["match"];
    if (!match_fn.valid()) return false;
    sol::protected_function_result result = match_fn(text, pattern);
    if (!result.valid()) return false;
    return result.get_type() != sol::type::lua_nil;
}

static sol::table lua_regex_find(const std::string& text, const std::string& pattern) {
    sol::state_view lua(*g_lua);
    sol::table results = lua.create_table();
    sol::protected_function gmatch_fn = lua["string"]["gmatch"];
    if (!gmatch_fn.valid()) return results;
    sol::protected_function_result gmatch_result = gmatch_fn(text, pattern);
    if (!gmatch_result.valid()) return results;
    if (gmatch_result.get_type() != sol::type::function) return results;
    sol::protected_function iter = gmatch_result;
    int idx = 1;
    while (true) {
        sol::protected_function_result match_result = iter();
        if (!match_result.valid()) break;
        if (match_result.get_type() == sol::type::lua_nil) break;
        sol::optional<std::string> captured = match_result;
        if (!captured) break;
        results[idx++] = *captured;
    }
    return results;
}


static void register_usertypes(sol::state& lua) {

    lua.new_usertype<hook_request_data>("Request",
        "method",   &hook_request_data::method,
        "uri",      &hook_request_data::uri,
        "host",     &hook_request_data::host,
        "port",     &hook_request_data::port,
        "is_tls",   &hook_request_data::is_tls,
        "headers",  sol::property(
            [](hook_request_data& self, sol::this_state s) -> sol::table {
                sol::state_view lua(s);
                sol::table t = lua.create_table();
                for (const auto& kv : self.headers) t[kv.first] = kv.second;
                return t;
            },
            [](hook_request_data& self, sol::table t) {
                self.headers.clear();
                for (const auto& kv : t) {
                    if (kv.first.get_type() != sol::type::string || kv.second.get_type() != sol::type::string)
                        continue;
                    sol::optional<std::string> k = kv.first.as<sol::optional<std::string>>();
                    sol::optional<std::string> v = kv.second.as<sol::optional<std::string>>();
                    if (k && v)
                        self.headers[*k] = *v;
                }
            }
        ),
        "body",     &hook_request_data::body,
        "modified", &hook_request_data::modified,
        "dropped",  &hook_request_data::dropped,
        "get_header", [](hook_request_data& self, const std::string& name) -> std::string {
            auto it = self.headers.find(name);
            return (it != self.headers.end()) ? it->second : "";
        },
        "set_header", [](hook_request_data& self, const std::string& name, const std::string& value) {
            self.headers[name] = value;
            self.modified = true;
        },
        "remove_header", [](hook_request_data& self, const std::string& name) {
            self.headers.erase(name);
            self.modified = true;
        },
        "get_body_string", [](hook_request_data& self) -> std::string {
            return std::string(self.body.begin(), self.body.end());
        },
        "set_body", [](hook_request_data& self, const std::string& body) {
            self.body.assign(body.begin(), body.end());
            self.modified = true;
        },
        "drop", [](hook_request_data& self) { self.dropped = true; }
    );


    lua.new_usertype<hook_response_data>("Response",
        "status_code", &hook_response_data::status_code,
        "reason",      &hook_response_data::reason,
        "headers",     sol::property(
            [](hook_response_data& self, sol::this_state s) -> sol::table {
                sol::state_view lua(s);
                sol::table t = lua.create_table();
                for (const auto& kv : self.headers) t[kv.first] = kv.second;
                return t;
            },
            [](hook_response_data& self, sol::table t) {
                self.headers.clear();
                for (const auto& kv : t) {
                    if (kv.first.get_type() != sol::type::string || kv.second.get_type() != sol::type::string)
                        continue;
                    sol::optional<std::string> k = kv.first.as<sol::optional<std::string>>();
                    sol::optional<std::string> v = kv.second.as<sol::optional<std::string>>();
                    if (k && v)
                        self.headers[*k] = *v;
                }
            }
        ),
        "body",        &hook_response_data::body,
        "latency_ms",  &hook_response_data::latency_ms,
        "modified",    &hook_response_data::modified,
        "dropped",     &hook_response_data::dropped,
        "get_header", [](hook_response_data& self, const std::string& name) -> std::string {
            auto it = self.headers.find(name);
            return (it != self.headers.end()) ? it->second : "";
        },
        "set_header", [](hook_response_data& self, const std::string& name, const std::string& value) {
            self.headers[name] = value;
            self.modified = true;
        },
        "get_body_string", [](hook_response_data& self) -> std::string {
            return std::string(self.body.begin(), self.body.end());
        },
        "set_body", [](hook_response_data& self, const std::string& body) {
            self.body.assign(body.begin(), body.end());
            self.modified = true;
        },
        "drop", [](hook_response_data& self) { self.dropped = true; }
    );


    lua.new_usertype<hook_ws_frame_data>("WebSocketFrame",
        "opcode",      &hook_ws_frame_data::opcode,
        "from_server", &hook_ws_frame_data::from_server,
        "payload",     &hook_ws_frame_data::payload,
        "host",        &hook_ws_frame_data::host,
        "modified",    &hook_ws_frame_data::modified,
        "dropped",     &hook_ws_frame_data::dropped,
        "get_text", [](hook_ws_frame_data& self) -> std::string {
            return std::string(self.payload.begin(), self.payload.end());
        },
        "set_payload", [](hook_ws_frame_data& self, const std::string& data) {
            self.payload.assign(data.begin(), data.end());
            self.modified = true;
        },
        "drop", [](hook_ws_frame_data& self) { self.dropped = true; }
    );


    lua.new_usertype<hook_packet_data>("Packet",
        "pid",       &hook_packet_data::pid,
        "protocol",  &hook_packet_data::protocol,
        "direction", &hook_packet_data::direction,
        "src_port",  &hook_packet_data::src_port,
        "dst_port",  &hook_packet_data::dst_port,
        "src_addr",  &hook_packet_data::src_addr,
        "dst_addr",  &hook_packet_data::dst_addr,
        "payload",   &hook_packet_data::payload,
        "dropped",   &hook_packet_data::dropped,
        "get_data", [](hook_packet_data& self) -> std::string {
            return std::string(self.payload.begin(), self.payload.end());
        },
        "drop", [](hook_packet_data& self) { self.dropped = true; }
    );


    lua.new_usertype<hook_dns_data>("DnsQuery",
        "pid",           &hook_dns_data::pid,
        "domain",        &hook_dns_data::domain,
        "query_type",    &hook_dns_data::query_type,
        "resolved_addr", &hook_dns_data::resolved_addr,
        "response_code", &hook_dns_data::response_code,
        "blocked",       &hook_dns_data::blocked,
        "spoof_addr",    &hook_dns_data::spoof_addr,
        "block", [](hook_dns_data& self) { self.blocked = true; },
        "spoof", [](hook_dns_data& self, const std::string& addr) {
            self.spoof_addr = addr;
        }
    );


    lua.new_usertype<hook_connection_data>("Connection",
        "pid",          &hook_connection_data::pid,
        "process_name", &hook_connection_data::process_name,
        "local_addr",   &hook_connection_data::local_addr,
        "local_port",   &hook_connection_data::local_port,
        "remote_addr",  &hook_connection_data::remote_addr,
        "remote_port",  &hook_connection_data::remote_port,
        "protocol",     &hook_connection_data::protocol,
        "is_tls",       &hook_connection_data::is_tls,
        "blocked",      &hook_connection_data::blocked,
        "block", [](hook_connection_data& self) { self.blocked = true; }
    );

    lua.new_usertype<protobuf_message_t>("ProtobufMessage",

        "fields_count", [](const protobuf_message_t& self) -> int {
            return static_cast<int>(self.fields.size());
        },

        "field_at", [](const protobuf_message_t& self, int i) -> sol::optional<sol::table> {
            if (!g_lua) return sol::nullopt;
            if (i < 1 || i > static_cast<int>(self.fields.size())) return sol::nullopt;
            auto& f = self.fields[static_cast<size_t>(i - 1)];
            sol::table t = g_lua->create_table();
            t["field_number"] = f.field_number;
            t["wire_type"]    = f.wire_type;
            switch (f.wire_type) {
                case 0: t["value"] = std::to_string(f.varint_value); break;
                case 1: t["value"] = std::to_string(f.varint_value); break;
                case 2: t["value"] = std::string(f.bytes_value.begin(), f.bytes_value.end()); break;
                case 5: t["value"] = std::to_string(static_cast<uint32_t>(f.varint_value & 0xFFFFFFFF)); break;
                default: t["value"] = std::string(); break;
            }
            return t;
        },

        "get", [](const protobuf_message_t& self, uint32_t field_num) -> sol::optional<std::string> {
            for (auto& f : self.fields) {
                if (f.field_number != field_num) continue;
                switch (f.wire_type) {
                    case 0: return std::to_string(f.varint_value);
                    case 1: return std::to_string(f.varint_value);
                    case 2: return std::string(f.bytes_value.begin(), f.bytes_value.end());
                    case 5: return std::to_string(static_cast<uint32_t>(f.varint_value & 0xFFFFFFFF));
                    default: return std::string();
                }
            }
            return sol::nullopt;
        },

        "set", [](protobuf_message_t& self, uint32_t field_num, const std::string& val) {
            for (auto& f : self.fields) {
                if (f.field_number != field_num) continue;
                switch (f.wire_type) {
                    case 0: case 1: case 5: {
                        char* endp = nullptr;
                        errno = 0;
                        unsigned long long parsed = strtoull(val.c_str(), &endp, 0);
                        if (errno == 0 && endp && *endp == '\0' && endp != val.c_str())
                            f.varint_value = static_cast<uint64_t>(parsed);
                        return;
                    }
                    case 2:
                        f.bytes_value.assign(val.begin(), val.end());
                        return;
                    default:
                        return;
                }
            }

            decoder_pipeline::protobuf_field nf;
            nf.field_number = field_num;
            nf.wire_type    = 2;
            nf.bytes_value.assign(val.begin(), val.end());
            self.fields.push_back(std::move(nf));
        },

        "add_varint", [](protobuf_message_t& self, uint32_t field_num, uint64_t val) {
            decoder_pipeline::protobuf_field f;
            f.field_number  = field_num;
            f.wire_type     = 0;
            f.varint_value  = val;
            self.fields.push_back(std::move(f));
        },

        "add_bytes", [](protobuf_message_t& self, uint32_t field_num, const std::string& val) {
            decoder_pipeline::protobuf_field f;
            f.field_number = field_num;
            f.wire_type    = 2;
            f.bytes_value.assign(val.begin(), val.end());
            self.fields.push_back(std::move(f));
        },

        "encode", [](const protobuf_message_t& self) -> std::string {
            auto bytes = decoder_pipeline::protobuf_encode(self.fields);
            return std::string(bytes.begin(), bytes.end());
        },

        "grpc_frame", [](const protobuf_message_t& self) -> std::string {
            auto proto = decoder_pipeline::protobuf_encode(self.fields);
            auto framed = decoder_pipeline::grpc_encode(proto);
            return std::string(framed.begin(), framed.end());
        },

        "text", [](const protobuf_message_t& self) -> std::string {
            return decoder_pipeline::protobuf_to_text(self.fields);
        }
    );
}


static std::string format_lua_number(double value) {
    double rounded = std::floor(value);
    if (rounded == value && value >= -9.007199254740992e15 &&
        value <= 9.007199254740992e15) {
        char buf[32];
        snprintf(buf, sizeof(buf), "%lld", static_cast<long long>(value));
        return std::string(buf);
    }
    char buf[64];
    snprintf(buf, sizeof(buf), "%.14g", value);
    return std::string(buf);
}

static std::string lua_escape_string(const char* data, size_t len) {
    std::string out;
    out.reserve(len + 2);
    out.push_back('"');
    for (size_t i = 0; i < len; ++i) {
        unsigned char ch = static_cast<unsigned char>(data[i]);
        switch (ch) {
            case '\\': out += "\\\\"; break;
            case '"':  out += "\\\""; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            default:
                if (ch < 0x20) {
                    char buf[5];
                    snprintf(buf, sizeof(buf), "\\x%02X", static_cast<unsigned int>(ch));
                    out += buf;
                } else {
                    out.push_back(static_cast<char>(ch));
                }
                break;
        }
    }
    out.push_back('"');
    return out;
}

static bool lua_simple_key(const char* data, size_t len) {
    if (!data || len == 0)
        return false;
    unsigned char first = static_cast<unsigned char>(data[0]);
    if (!(std::isalpha(first) || first == '_'))
        return false;
    for (size_t i = 1; i < len; ++i) {
        unsigned char ch = static_cast<unsigned char>(data[i]);
        if (!(std::isalnum(ch) || ch == '_'))
            return false;
    }
    return true;
}

static const char* lua_type_name(lua_State* L, int index) {
    const char* name = lua_typename(L, lua_type(L, index));
    return name ? name : "unknown";
}

static std::string lua_value_to_string_at(lua_State* L, int index, int depth,
                                          std::vector<const void*>& seen,
                                          bool quote_strings);

static std::string lua_key_to_string_at(lua_State* L, int index, int depth,
                                        std::vector<const void*>& seen) {
    int type = lua_type(L, index);
    if (type == LUA_TSTRING) {
        size_t len = 0;
        const char* data = lua_tolstring(L, index, &len);
        if (lua_simple_key(data, len))
            return std::string(data, len);
        return "[" + lua_escape_string(data ? data : "", len) + "]";
    }
    return "[" + lua_value_to_string_at(L, index, depth, seen, true) + "]";
}

static std::string lua_table_to_string_at(lua_State* L, int index, int depth,
                                          std::vector<const void*>& seen) {
    if (depth >= 6)
        return "{...}";
    int abs_index = lua_absindex(L, index);
    const void* ptr = lua_topointer(L, abs_index);
    if (ptr) {
        if (std::find(seen.begin(), seen.end(), ptr) != seen.end())
            return "{...}";
        seen.push_back(ptr);
    }
    std::string out = "{";
    bool first = true;
    int emitted = 0;
    lua_pushnil(L);
    while (lua_next(L, abs_index) != 0) {
        if (emitted >= 64) {
            if (!first)
                out += ", ";
            out += "...";
            lua_pop(L, 2);
            break;
        }
        int key_index = lua_absindex(L, -2);
        int value_index = lua_absindex(L, -1);
        if (!first)
            out += ", ";
        out += lua_key_to_string_at(L, key_index, depth + 1, seen);
        out += "=";
        out += lua_value_to_string_at(L, value_index, depth + 1, seen, true);
        first = false;
        ++emitted;
        lua_pop(L, 1);
    }
    if (ptr)
        seen.pop_back();
    out += "}";
    return out;
}

static std::string lua_value_to_string_at(lua_State* L, int index, int depth,
                                          std::vector<const void*>& seen,
                                          bool quote_strings) {
    switch (lua_type(L, index)) {
        case LUA_TSTRING: {
            size_t len = 0;
            const char* data = lua_tolstring(L, index, &len);
            if (!data)
                return std::string();
            return quote_strings ? lua_escape_string(data, len) : std::string(data, len);
        }
        case LUA_TNUMBER:
            if (lua_isinteger(L, index)) {
                char buf[32];
                snprintf(buf, sizeof(buf), "%lld", static_cast<long long>(lua_tointeger(L, index)));
                return std::string(buf);
            }
            return format_lua_number(static_cast<double>(lua_tonumber(L, index)));
        case LUA_TBOOLEAN:
            return lua_toboolean(L, index) ? std::string("true") : std::string("false");
        case LUA_TNIL:
        case LUA_TNONE:
            return std::string("nil");
        case LUA_TTABLE:
            return lua_table_to_string_at(L, index, depth, seen);
        case LUA_TFUNCTION:
            return std::string("function");
        case LUA_TTHREAD:
            return std::string("thread");
        case LUA_TUSERDATA:
        case LUA_TLIGHTUSERDATA:
            return std::string("userdata");
        default:
            return std::string(lua_type_name(L, index));
    }
}

template <typename LuaValue>
static std::string lua_value_to_string(const LuaValue& v) {
    lua_State* L = v.lua_state();
    if (!L)
        return std::string("nil");
    int pushed = v.push();
    std::vector<const void*> seen;
    std::string out = lua_value_to_string_at(L, -1, 0, seen, false);
    lua_pop(L, pushed);
    return out;
}

static int hook_type_index(const std::string& name) {
    for (int i = 0; i < static_cast<int>(hook_type::COUNT); ++i) {
        if (name == hook_type_name(static_cast<hook_type>(i)))
            return i;
    }
    return -1;
}

static void reset_hook_table() {
    if (!g_lua) return;
    (*g_lua)["_hooks"] = g_lua->create_table();
    g_hook_counts.fill(0);
}

static bool register_hook_named(const std::string& hook_name,
                                const sol::protected_function& fn) {
    if (!g_lua) return false;
    if (!fn.valid()) {
        add_log(current_script_context, log_level::error,
                "register_hook('" + hook_name + "') ignored: callback is not a function");
        return false;
    }
    int idx = hook_type_index(hook_name);
    if (idx < 0) {
        add_log(current_script_context, log_level::error,
                "register_hook('" + hook_name + "') ignored: unknown hook name");
        return false;
    }
    sol::table hooks = (*g_lua)["_hooks"];
    if (!hooks.valid()) {
        reset_hook_table();
        hooks = (*g_lua)["_hooks"];
    }
    sol::object list_obj = hooks[hook_name];
    sol::table hook_list;
    if (list_obj.valid() && list_obj.get_type() == sol::type::table) {
        hook_list = list_obj.as<sol::table>();
    } else {
        hook_list = g_lua->create_table();
        hooks[hook_name] = hook_list;
    }
    hook_list[hook_list.size() + 1] = fn;
    g_hook_counts[static_cast<size_t>(idx)]++;
    add_log(current_script_context, log_level::debug,
            "Registered " + hook_name + " hook");
    return true;
}


static void register_api(sol::state& lua) {

    lua.set_function("log",   lua_log_info);
    lua.set_function("warn",  lua_log_warn);
    lua.set_function("error_log", lua_log_error);
    lua.set_function("debug_log", lua_log_debug);


    lua.set_function("print", [](sol::variadic_args va) {
        std::string msg;
        for (auto v : va) {
            if (!msg.empty()) msg += "\t";
            msg += lua_value_to_string(v);
        }
        lua_log_output(msg);
    });


    lua.set_function("base64_encode",  lua_base64_encode);
    lua.set_function("base64_decode",  lua_base64_decode);
    lua.set_function("hex_encode",     lua_hex_encode);
    lua.set_function("hex_decode",     lua_hex_decode);
    lua.set_function("url_encode",     lua_url_encode);
    lua.set_function("url_decode",     lua_url_decode);
    lua.set_function("json_beautify",  lua_json_beautify);


    lua.set_function("md5",    lua_md5);
    lua.set_function("sha256", lua_sha256);


    lua.set_function("gzip",   lua_gzip_compress);
    lua.set_function("gunzip", lua_gzip_decompress);


    lua.set_function("xor_bytes", lua_xor_bytes);


    lua.set_function("regex_match", lua_regex_match);
    lua.set_function("regex_find",  lua_regex_find);


    lua.set_function("bytes_to_string", [](const std::vector<uint8_t>& bytes) -> std::string {
        return std::string(bytes.begin(), bytes.end());
    });

    lua.set_function("string_to_bytes", [](const std::string& s) -> std::vector<uint8_t> {
        return std::vector<uint8_t>(s.begin(), s.end());
    });


    lua.set_function("decode", [](const std::string& transform_id,
                                  const std::string& input,
                                  sol::optional<sol::table> params_table) -> std::string {
        std::map<std::string, std::string> params;
        if (params_table) {
            for (auto& [k, v] : *params_table) {
                sol::optional<std::string> ks = k.as<sol::optional<std::string>>();
                sol::optional<std::string> vs = v.as<sol::optional<std::string>>();
                if (ks && vs)
                    params[*ks] = *vs;
            }
        }
        auto result = decoder_pipeline::apply_single(transform_id,
            std::vector<uint8_t>(input.begin(), input.end()), params);
        if (!result.success) return std::string("[error: " + result.error + "]");
        return std::string(result.data.begin(), result.data.end());
    });


    lua.set_function("time_ms", now_ms);


    lua.set_function("proto_parse", [](const std::string& data) -> protobuf_message_t {
        protobuf_message_t msg;
        msg.fields = decoder_pipeline::decode_protobuf_wire(
            reinterpret_cast<const uint8_t*>(data.data()), data.size());
        return msg;
    });


    lua.set_function("proto_build", []() -> protobuf_message_t {
        return protobuf_message_t{};
    });


    lua.set_function("grpc_parse", [](const std::string& data) -> protobuf_message_t {
        protobuf_message_t msg;

        if (data.size() < 5) return msg;

        if (static_cast<uint8_t>(data[0]) != 0x00) return msg;
        uint32_t len = (static_cast<uint8_t>(data[1]) << 24) |
                       (static_cast<uint8_t>(data[2]) << 16) |
                       (static_cast<uint8_t>(data[3]) <<  8) |
                        static_cast<uint8_t>(data[4]);
        if (data.size() < 5 + len) return msg;
        msg.fields = decoder_pipeline::decode_protobuf_wire(
            reinterpret_cast<const uint8_t*>(data.data() + 5), len);
        return msg;
    });


    lua.set_function("grpc_build", []() -> protobuf_message_t {
        return protobuf_message_t{};
    });


    lua["_hooks"] = lua.create_table();

    lua.set_function("register_hook", [](const std::string& hook_name,
                                         sol::protected_function fn) -> bool {
        return register_hook_named(hook_name, fn);
    });


    for (int i = 0; i < static_cast<int>(hook_type::COUNT); ++i) {
        auto ht = static_cast<hook_type>(i);
        std::string name = hook_type_name(ht);
        lua.set_function(name, [name](sol::protected_function fn) -> bool {
            return register_hook_named(name, fn);
        });
    }
}


static void apply_sandbox(sol::state& lua) {

    lua["io"]        = sol::lua_nil;
    lua["os"]["execute"] = sol::lua_nil;
    lua["os"]["exit"]    = sol::lua_nil;
    lua["os"]["remove"]  = sol::lua_nil;
    lua["os"]["rename"]  = sol::lua_nil;
    lua["os"]["tmpname"] = sol::lua_nil;
    lua["os"]["getenv"]  = sol::lua_nil;
    lua["loadfile"]  = sol::lua_nil;
    lua["dofile"]    = sol::lua_nil;


    lua_sethook(lua.lua_state(), [](lua_State* L, lua_Debug*) {
        luaL_error(L, "Script exceeded instruction limit (possible infinite loop)");
    }, LUA_MASKCOUNT, 10'000'000);
}


static void rebuild_hook_table_locked() {
    diag::log_tagged_fmt("script_eng", "rebuild_hook_table scripts=%zu", g_scripts.size());
    if (!g_lua) return;
    reset_hook_table();
    std::string saved_context = current_script_context;
    for (auto& kv : g_scripts) {
        script_info& sinfo = kv.second;
        if (!sinfo.enabled || !sinfo.loaded) continue;
        diag::log_tagged_fmt("script_eng", "rebuild_hook_table re-exec name='%s'", sinfo.name.c_str());
        current_script_context = sinfo.name;
        sol::protected_function_result result =
            g_lua->safe_script(sinfo.source, sol::script_pass_on_error);
        if (!result.valid()) {
            sol::error err = result;
            sinfo.last_error = err.what();
            sinfo.loaded = false;
            diag::log_tagged_fmt("script_eng", "rebuild_hook_table fail name='%s' err='%s'",
                sinfo.name.c_str(), sinfo.last_error.c_str());
            add_log(sinfo.name, log_level::error,
                    "Rebuild failed: " + sinfo.last_error);
        }
    }
    current_script_context = saved_context;
    diag::log_tagged_fmt("script_eng", "rebuild_hook_table done");
}


bool initialize() {
    const uint64_t started = now_ms();
    const DWORD tid = GetCurrentThreadId();
    diag::log_tagged_fmt("script_eng", "initialize entry tid=%lu initialized=%d initializing=%d",
        tid,
        g_initialized.load(std::memory_order_acquire) ? 1 : 0,
        g_initializing.load(std::memory_order_acquire) ? 1 : 0);
    if (g_initialized.load(std::memory_order_acquire))
    {
        diag::log_tagged_fmt("script_eng", "initialize already done tid=%lu elapsed_ms=%llu",
            tid,
            static_cast<unsigned long long>(now_ms() - started));
        return true;
    }

    bool expected = false;
    if (!g_initializing.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
    {
        diag::log_tagged_fmt("script_eng", "initialize already in progress tid=%lu elapsed_ms=%llu",
            tid,
            static_cast<unsigned long long>(now_ms() - started));
        for (int attempt = 0; attempt < 40; ++attempt) {
            if (g_initialized.load(std::memory_order_acquire)) {
                diag::log_tagged_fmt("script_eng", "initialize observed complete tid=%lu wait_ms=%llu attempts=%d",
                    tid,
                    static_cast<unsigned long long>(now_ms() - started),
                    attempt + 1);
                return true;
            }
            Sleep(25);
        }
        diag::log_tagged_fmt("script_eng", "initialize still in progress tid=%lu wait_ms=%llu initialized=%d",
            tid,
            static_cast<unsigned long long>(now_ms() - started),
            g_initialized.load(std::memory_order_acquire) ? 1 : 0);
        return g_initialized.load(std::memory_order_acquire);
    }

    const char* phase = "abi_check";
    std::unique_ptr<sol::state> local_lua;
    void* published_lua_state = nullptr;
    try {
        diag::log_tagged_fmt("script_eng", "initialize_phase_pre phase=%s tid=%lu elapsed_ms=%llu",
            phase,
            tid,
            static_cast<unsigned long long>(now_ms() - started));
        const int linked_release = aida_lua_abi_release();
        const int linked_registry_index = aida_lua_registry_index();
        const size_t linked_number_sizes = aida_lua_number_sizes();
        diag::log_tagged_fmt("script_eng",
            "initialize_lua_abi header_release=%d linked_release=%d header_registry=%d linked_registry=%d header_number_sizes=%zu linked_number_sizes=%zu",
            LUA_VERSION_RELEASE_NUM,
            linked_release,
            LUA_REGISTRYINDEX,
            linked_registry_index,
            static_cast<size_t>(LUAL_NUMSIZES),
            linked_number_sizes);
        if (linked_release != LUA_VERSION_RELEASE_NUM ||
            linked_registry_index != LUA_REGISTRYINDEX ||
            linked_number_sizes != static_cast<size_t>(LUAL_NUMSIZES)) {
            throw std::runtime_error("Lua static library ABI does not match its public headers");
        }
        diag::log_tagged_fmt("script_eng", "initialize_phase_post phase=%s tid=%lu elapsed_ms=%llu",
            phase,
            tid,
            static_cast<unsigned long long>(now_ms() - started));

        phase = "local_alloc";
        diag::log_tagged_fmt("script_eng", "initialize_phase_pre phase=%s tid=%lu elapsed_ms=%llu",
            phase,
            tid,
            static_cast<unsigned long long>(now_ms() - started));
        local_lua = std::make_unique<sol::state>();
        diag::log_tagged_fmt("script_eng", "initialize_phase_post phase=%s tid=%lu lua_state=%p elapsed_ms=%llu",
            phase,
            tid,
            local_lua ? (void*)local_lua->lua_state() : nullptr,
            static_cast<unsigned long long>(now_ms() - started));

        phase = "open_libraries";
        diag::log_tagged_fmt("script_eng", "initialize_phase_pre phase=%s tid=%lu elapsed_ms=%llu",
            phase,
            tid,
            static_cast<unsigned long long>(now_ms() - started));
        local_lua->open_libraries(
            sol::lib::base,
            sol::lib::string,
            sol::lib::table,
            sol::lib::math,
            sol::lib::utf8,
            sol::lib::os
        );
        diag::log_tagged_fmt("script_eng", "initialize_phase_post phase=%s tid=%lu elapsed_ms=%llu",
            phase,
            tid,
            static_cast<unsigned long long>(now_ms() - started));

        phase = "register_usertypes";
        diag::log_tagged_fmt("script_eng", "initialize_phase_pre phase=%s tid=%lu elapsed_ms=%llu",
            phase,
            tid,
            static_cast<unsigned long long>(now_ms() - started));
        register_usertypes(*local_lua);
        diag::log_tagged_fmt("script_eng", "initialize_phase_post phase=%s tid=%lu elapsed_ms=%llu",
            phase,
            tid,
            static_cast<unsigned long long>(now_ms() - started));

        phase = "register_api";
        diag::log_tagged_fmt("script_eng", "initialize_phase_pre phase=%s tid=%lu elapsed_ms=%llu",
            phase,
            tid,
            static_cast<unsigned long long>(now_ms() - started));
        register_api(*local_lua);
        diag::log_tagged_fmt("script_eng", "initialize_phase_post phase=%s tid=%lu elapsed_ms=%llu",
            phase,
            tid,
            static_cast<unsigned long long>(now_ms() - started));

        phase = "apply_sandbox";
        diag::log_tagged_fmt("script_eng", "initialize_phase_pre phase=%s tid=%lu elapsed_ms=%llu",
            phase,
            tid,
            static_cast<unsigned long long>(now_ms() - started));
        apply_sandbox(*local_lua);
        diag::log_tagged_fmt("script_eng", "initialize_phase_post phase=%s tid=%lu elapsed_ms=%llu",
            phase,
            tid,
            static_cast<unsigned long long>(now_ms() - started));

        phase = "reset_hook_table";
        diag::log_tagged_fmt("script_eng", "initialize_phase_pre phase=%s tid=%lu elapsed_ms=%llu",
            phase,
            tid,
            static_cast<unsigned long long>(now_ms() - started));
        (*local_lua)["_hooks"] = local_lua->create_table();
        diag::log_tagged_fmt("script_eng", "initialize_phase_post phase=%s tid=%lu elapsed_ms=%llu",
            phase,
            tid,
            static_cast<unsigned long long>(now_ms() - started));

        phase = "publish_wait";
        diag::log_tagged_fmt("script_eng", "initialize_phase_pre phase=%s tid=%lu elapsed_ms=%llu",
            phase,
            tid,
            static_cast<unsigned long long>(now_ms() - started));
        std::unique_lock<std::mutex> lock(g_mutex);
        diag::log_tagged_fmt("script_eng", "initialize_phase_post phase=%s tid=%lu elapsed_ms=%llu",
            phase,
            tid,
            static_cast<unsigned long long>(now_ms() - started));
        if (g_initialized.load(std::memory_order_acquire))
        {
            g_initializing.store(false, std::memory_order_release);
            diag::log_tagged_fmt("script_eng", "initialize publish skipped already_initialized tid=%lu elapsed_ms=%llu",
                tid,
                static_cast<unsigned long long>(now_ms() - started));
            return true;
        }

        phase = "publish_state";
        diag::log_tagged_fmt("script_eng", "initialize_phase_pre phase=%s tid=%lu elapsed_ms=%llu",
            phase,
            tid,
            static_cast<unsigned long long>(now_ms() - started));
        g_lua = std::move(local_lua);
        g_hook_counts.fill(0);
        g_initialized.store(true, std::memory_order_release);
        published_lua_state = g_lua ? (void*)g_lua->lua_state() : nullptr;
        diag::log_tagged_fmt("script_eng", "initialize_phase_post phase=%s tid=%lu lua_state=%p elapsed_ms=%llu",
            phase,
            tid,
            published_lua_state,
            static_cast<unsigned long long>(now_ms() - started));

        phase = "add_log";
        diag::log_tagged_fmt("script_eng", "initialize_phase_pre phase=%s tid=%lu elapsed_ms=%llu",
            phase,
            tid,
            static_cast<unsigned long long>(now_ms() - started));
        if (!g_init_logged) {
            add_log("engine", log_level::info, "Script engine initialized (Lua 5.4 + sol2)");
            g_init_logged = true;
        }
        diag::log_tagged_fmt("script_eng", "initialize_phase_post phase=%s tid=%lu elapsed_ms=%llu",
            phase,
            tid,
            static_cast<unsigned long long>(now_ms() - started));
    } catch (const std::exception& e) {
        g_initializing.store(false, std::memory_order_release);
        diag::log_tagged_fmt("script_eng", "initialize_exception phase=%s tid=%lu elapsed_ms=%llu what=%.160s",
            phase,
            tid,
            static_cast<unsigned long long>(now_ms() - started),
            e.what());
        return false;
    } catch (...) {
        g_initializing.store(false, std::memory_order_release);
        diag::log_tagged_fmt("script_eng", "initialize_exception phase=%s tid=%lu elapsed_ms=%llu what=<unknown>",
            phase,
            tid,
            static_cast<unsigned long long>(now_ms() - started));
        return false;
    }

    g_initializing.store(false, std::memory_order_release);
    diag::log_tagged_fmt("script_eng", "initialize done tid=%lu lua_state=%p elapsed_ms=%llu",
        tid,
        published_lua_state,
        static_cast<unsigned long long>(now_ms() - started));
    return true;
}

void shutdown() {
    diag::log_tagged_fmt("script_eng", "shutdown entry scripts=%zu", g_scripts.size());
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_initialized.load())
    {
        diag::log_tagged_fmt("script_eng", "shutdown not initialized");
        return;
    }

    g_scripts.clear();
    g_log.clear();
    g_hook_counts.fill(0);
    g_init_logged = false;
    g_lua.reset();
    g_initialized.store(false);
    diag::log_tagged_fmt("script_eng", "shutdown done");
}

bool is_initialized() {
    return g_initialized.load(std::memory_order_acquire);
}

static bool install_script_locked(const std::string& name, const std::string& path,
                                  const std::string& source, const std::string& origin) {
    diag::log_tagged_fmt("script_eng", "install_script name='%s' origin='%s' bytes=%zu",
        name.c_str(), origin.c_str(), source.size());
    if (!g_lua)
    {
        diag::log_tagged_fmt("script_eng", "install_script no lua state");
        return false;
    }

    if (g_scripts.find(name) != g_scripts.end())
        add_log(name, log_level::info, "Reloading existing script");

    script_info info;
    info.name      = name;
    info.path      = path;
    info.source    = source;
    info.enabled   = true;
    info.loaded    = true;
    info.load_time = now_ms();
    g_scripts[name] = std::move(info);

    rebuild_hook_table_locked();

    script_info& stored = g_scripts[name];
    if (!stored.loaded) {
        diag::log_tagged_fmt("script_eng", "install_script load fail name='%s' err='%s'",
            name.c_str(), stored.last_error.c_str());
        add_log(name, log_level::error,
                "Failed to load: " + stored.last_error);
        return false;
    }
    diag::log_tagged_fmt("script_eng", "install_script ok name='%s'", name.c_str());
    add_log(name, log_level::info, "Loaded from " + origin);
    return true;
}

bool load_script(const std::string& path) {
    diag::log_tagged_fmt("script_eng", "load_script path='%.120s'", path.c_str());
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_lua)
    {
        diag::log_tagged_fmt("script_eng", "load_script no lua state");
        return false;
    }

    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        diag::log_tagged_fmt("script_eng", "load_script cannot open path='%.120s'", path.c_str());
        std::filesystem::path fp(path);
        add_log(fp.stem().string(), log_level::error,
                "Cannot open file: " + path);
        return false;
    }
    std::string source((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
    file.close();

    std::filesystem::path p(path);
    std::string name = p.stem().string();
    return install_script_locked(name, path, source, path);
}

bool load_script_source(const std::string& name, const std::string& source) {
    diag::log_tagged_fmt("script_eng", "load_script_source name='%s' bytes=%zu",
        name.c_str(), source.size());
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_lua)
    {
        diag::log_tagged_fmt("script_eng", "load_script_source no lua state");
        return false;
    }
    return install_script_locked(name, std::string(), source, "source");
}

bool unload_script(const std::string& name) {
    diag::log_tagged_fmt("script_eng", "unload_script name='%s'", name.c_str());
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_lua)
    {
        diag::log_tagged_fmt("script_eng", "unload_script no lua state");
        return false;
    }
    auto it = g_scripts.find(name);
    if (it == g_scripts.end())
    {
        diag::log_tagged_fmt("script_eng", "unload_script not found name='%s'", name.c_str());
        return false;
    }

    g_scripts.erase(it);
    rebuild_hook_table_locked();

    diag::log_tagged_fmt("script_eng", "unload_script ok name='%s'", name.c_str());
    add_log(name, log_level::info, "Unloaded");
    return true;
}

bool reload_script(const std::string& name) {
    diag::log_tagged_fmt("script_eng", "reload_script name='%s'", name.c_str());
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_lua)
    {
        diag::log_tagged_fmt("script_eng", "reload_script no lua state");
        return false;
    }
    auto it = g_scripts.find(name);
    if (it == g_scripts.end())
    {
        diag::log_tagged_fmt("script_eng", "reload_script not found name='%s'", name.c_str());
        return false;
    }

    script_info& info = it->second;

    if (!info.path.empty()) {
        std::ifstream file(info.path, std::ios::binary);
        if (file.is_open()) {
            info.source = std::string((std::istreambuf_iterator<char>(file)),
                                       std::istreambuf_iterator<char>());
            file.close();
        } else {
            add_log(name, log_level::warn,
                    "Reload could not reopen file, using cached source");
        }
    }

    info.loaded = true;
    info.last_error.clear();
    info.load_time = now_ms();

    rebuild_hook_table_locked();

    if (!info.loaded) {
        diag::log_tagged_fmt("script_eng", "reload_script fail name='%s' err='%s'",
            name.c_str(), info.last_error.c_str());
        add_log(name, log_level::error, "Reload failed: " + info.last_error);
        return false;
    }
    diag::log_tagged_fmt("script_eng", "reload_script ok name='%s'", name.c_str());
    add_log(name, log_level::info, "Reloaded");
    return true;
}

void set_script_enabled(const std::string& name, bool enabled) {
    diag::log_tagged_fmt("script_eng", "set_script_enabled name='%s' enabled=%d",
        name.c_str(), (int)enabled);
    std::lock_guard<std::mutex> lock(g_mutex);
    auto it = g_scripts.find(name);
    if (it == g_scripts.end())
    {
        diag::log_tagged_fmt("script_eng", "set_script_enabled not found name='%s'", name.c_str());
        return;
    }
    if (it->second.enabled == enabled) return;
    it->second.enabled = enabled;

    rebuild_hook_table_locked();
    diag::log_tagged_fmt("script_eng", "set_script_enabled done name='%s' enabled=%d",
        name.c_str(), (int)enabled);
    add_log(name, log_level::info, enabled ? "Enabled" : "Paused");
}

std::vector<script_info> get_scripts() {
    std::lock_guard<std::mutex> lock(g_mutex);
    std::vector<script_info> result;
    result.reserve(g_scripts.size());
    for (auto& [name, info] : g_scripts) result.push_back(info);
    return result;
}

const script_info* find_script(const std::string& name) {

    auto it = g_scripts.find(name);
    return (it != g_scripts.end()) ? &it->second : nullptr;
}


template <typename T>
static bool invoke_hook_impl(hook_type type, T& data) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_lua || !g_initialized.load()) return false;
    if (type < hook_type::on_request || type >= hook_type::COUNT) return false;

    std::string hook_name = hook_type_name(type);
    diag::log_tagged_fmt("script_eng", "invoke_hook hook='%s'", hook_name.c_str());
    sol::object hooks_obj = (*g_lua)["_hooks"];
    if (!hooks_obj.valid() || hooks_obj.get_type() != sol::type::table)
        return false;
    sol::table hooks = hooks_obj.as<sol::table>();

    sol::object hook_list_obj = hooks[hook_name];
    if (!hook_list_obj.valid() || hook_list_obj.get_type() != sol::type::table)
        return false;

    sol::table hook_list = hook_list_obj.as<sol::table>();

    std::string saved_context = current_script_context;
    bool invoked_any = false;

    for (auto& kv : hook_list) {
        if (kv.second.get_type() != sol::type::function) continue;
        sol::protected_function fn = kv.second.as<sol::protected_function>();
        if (!fn.valid()) continue;

        current_script_context = hook_name;
        invoked_any = true;

        sol::protected_function_result result = fn(std::ref(data));
        if (!result.valid()) {
            sol::error err = result;
            diag::log_tagged_fmt("script_eng", "invoke_hook error hook='%s' err='%.120s'",
                hook_name.c_str(), err.what());
            add_log(hook_name, log_level::error,
                    "Hook error: " + std::string(err.what()));
        }
    }

    diag::log_tagged_fmt("script_eng", "invoke_hook done hook='%s' invoked=%d",
        hook_name.c_str(), (int)invoked_any);
    current_script_context = saved_context;
    return invoked_any;
}

bool invoke_hook(hook_type type, hook_request_data& data)    { return invoke_hook_impl(type, data); }
bool invoke_hook(hook_type type, hook_response_data& data)   { return invoke_hook_impl(type, data); }
bool invoke_hook(hook_type type, hook_ws_frame_data& data)   { return invoke_hook_impl(type, data); }
bool invoke_hook(hook_type type, hook_packet_data& data)     { return invoke_hook_impl(type, data); }
bool invoke_hook(hook_type type, hook_dns_data& data)        { return invoke_hook_impl(type, data); }
bool invoke_hook(hook_type type, hook_connection_data& data) { return invoke_hook_impl(type, data); }

bool dispatch_request(hook_request_data& data) {
    return invoke_hook_impl(hook_type::on_request, data);
}
bool dispatch_response(hook_response_data& data) {
    return invoke_hook_impl(hook_type::on_response, data);
}
bool dispatch_websocket_frame(hook_ws_frame_data& data) {
    return invoke_hook_impl(hook_type::on_websocket_frame, data);
}
bool dispatch_packet(hook_packet_data& data) {
    return invoke_hook_impl(hook_type::on_packet, data);
}
bool dispatch_dns(hook_dns_data& data) {
    return invoke_hook_impl(hook_type::on_dns, data);
}
bool dispatch_connection(hook_connection_data& data) {
    return invoke_hook_impl(hook_type::on_connection, data);
}
bool dispatch_connection_close(hook_connection_data& data) {
    return invoke_hook_impl(hook_type::on_connection_close, data);
}

size_t registered_hook_count(hook_type type) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (type < hook_type::on_request || type >= hook_type::COUNT) return 0;
    return g_hook_counts[static_cast<size_t>(type)];
}

size_t registered_hook_count() {
    std::lock_guard<std::mutex> lock(g_mutex);
    size_t total = 0;
    for (size_t c : g_hook_counts) total += c;
    return total;
}


static bool starts_with_lua_return_keyword(const std::string& text) {
    if (text.size() < 6 || text.compare(0, 6, "return") != 0)
        return false;
    if (text.size() == 6)
        return true;
    unsigned char next = static_cast<unsigned char>(text[6]);
    return !(std::isalnum(next) || next == '_');
}

struct lua_console_result {
    bool ok = false;
    bool load_error = false;
    int return_count = 0;
    std::string first_type;
    std::string output;
    std::string error;
};

static std::string lua_error_to_string(lua_State* L, int index) {
    size_t len = 0;
    const char* data = lua_tolstring(L, index, &len);
    if (data)
        return std::string(data, len);
    return std::string(lua_type_name(L, index));
}

static lua_console_result execute_lua_chunk(sol::state& lua, const std::string& chunk) {
    lua_console_result result;
    lua_State* L = lua.lua_state();
    if (!L) {
        result.error = "engine not initialized";
        return result;
    }

    int base = lua_gettop(L);
    try {
        int load_status = luaL_loadbufferx(L, chunk.data(), chunk.size(), "=(console)", "t");
        if (load_status != LUA_OK) {
            result.load_error = true;
            result.error = lua_error_to_string(L, -1);
            lua_settop(L, base);
            return result;
        }

        int call_status = lua_pcall(L, 0, LUA_MULTRET, 0);
        if (call_status != LUA_OK) {
            result.error = lua_error_to_string(L, -1);
            lua_settop(L, base);
            return result;
        }

        int top = lua_gettop(L);
        result.return_count = top - base;
        if (result.return_count > 0)
            result.first_type = lua_type_name(L, base + 1);

        std::vector<const void*> seen;
        for (int i = 0; i < result.return_count; ++i) {
            if (i > 0)
                result.output += "\t";
            result.output += lua_value_to_string_at(L, base + 1 + i, 0, seen, false);
        }
        lua_settop(L, base);
        result.ok = true;
        return result;
    } catch (const std::exception& ex) {
        lua_settop(L, base);
        result.error = ex.what();
        return result;
    } catch (...) {
        lua_settop(L, base);
        result.error = "unknown C++ exception during script execution";
        return result;
    }
}

std::string execute(const std::string& code) {
    diag::log_tagged_fmt("script_eng", "execute code_len=%zu code='%.80s'",
        code.size(), code.c_str());
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_lua)
    {
        diag::log_tagged_fmt("script_eng", "execute no lua state");
        return "[error: engine not initialized]";
    }

    std::string trimmed = code;
    size_t first = trimmed.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return std::string();
    size_t last = trimmed.find_last_not_of(" \t\r\n");
    trimmed = trimmed.substr(first, last - first + 1);

    std::string saved_context = current_script_context;
    current_script_context = "console";
    add_log("console", log_level::command, trimmed);

    lua_console_result result;
    if (starts_with_lua_return_keyword(trimmed)) {
        result = execute_lua_chunk(*g_lua, trimmed);
    } else {
        lua_console_result expr_result = execute_lua_chunk(*g_lua, "return " + trimmed);
        if (expr_result.ok || !expr_result.load_error) {
            result = std::move(expr_result);
        } else {
            result = execute_lua_chunk(*g_lua, trimmed);
        }
    }

    if (!result.ok) {
        std::string msg = std::string("[error: ") + result.error + "]";
        add_log("console", log_level::error, msg);
        current_script_context = saved_context;
        return msg;
    }

    std::string out = result.output;
    if (!out.empty())
        add_log("console", log_level::output, out);

    diag::log_tagged_fmt("script_eng", "execute ok returns=%d first_type=%s out_len=%zu",
        result.return_count, result.first_type.c_str(), out.size());
    current_script_context = saved_context;
    return out;
}


std::vector<log_entry> get_log(size_t max_count) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (max_count == 0 || max_count >= g_log.size())
        return std::vector<log_entry>(g_log.begin(), g_log.end());
    return std::vector<log_entry>(g_log.end() - max_count, g_log.end());
}

void clear_log() {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_log.clear();
}


std::vector<api_function> get_api_listing() {
    return {
        { "log",            "log(msg)",                         "Log an info message" },
        { "warn",           "warn(msg)",                        "Log a warning message" },
        { "error_log",      "error_log(msg)",                   "Log an error message" },
        { "debug_log",      "debug_log(msg)",                   "Log a debug message" },
        { "print",          "print(...)",                       "Print values (goes to engine log)" },
        { "base64_encode",  "base64_encode(str) -> str",        "Base64 encode a string" },
        { "base64_decode",  "base64_decode(str) -> str",        "Base64 decode a string" },
        { "hex_encode",     "hex_encode(str) -> str",           "Hex encode bytes" },
        { "hex_decode",     "hex_decode(str) -> str",           "Hex decode a string" },
        { "url_encode",     "url_encode(str) -> str",           "URL percent-encode" },
        { "url_decode",     "url_decode(str) -> str",           "URL percent-decode" },
        { "md5",            "md5(str) -> str",                  "MD5 hash (hex output)" },
        { "sha256",         "sha256(str) -> str",               "SHA-256 hash (hex output)" },
        { "gzip",           "gzip(str) -> str",                 "Gzip compress" },
        { "gunzip",         "gunzip(str) -> str",               "Gzip decompress" },
        { "xor_bytes",      "xor_bytes(data, key_hex) -> str",  "XOR with hex key" },
        { "json_beautify",  "json_beautify(str) -> str",        "Pretty-print JSON" },
        { "regex_match",    "regex_match(text, pattern) -> bool","Lua pattern match" },
        { "regex_find",     "regex_find(text, pattern) -> table","Find all matches" },
        { "bytes_to_string","bytes_to_string(bytes) -> str",    "Convert byte array to string" },
        { "string_to_bytes","string_to_bytes(str) -> bytes",    "Convert string to byte array" },
        { "decode",         "decode(id, input, params?) -> str", "Run decoder pipeline transform" },
        { "time_ms",        "time_ms() -> number",              "Current time in milliseconds" },
        { "register_hook",  "register_hook(name, fn) -> bool",  "Register a hook callback by name" },
        { "on_request",     "on_request(fn(req)) -> bool",      "Hook: HTTP request intercepted" },
        { "on_response",    "on_response(fn(resp)) -> bool",    "Hook: HTTP response received" },
        { "on_websocket_frame","on_websocket_frame(fn(frame)) -> bool", "Hook: WebSocket frame" },
        { "on_packet",      "on_packet(fn(pkt)) -> bool",       "Hook: Raw packet captured" },
        { "on_dns",         "on_dns(fn(dns)) -> bool",          "Hook: DNS query/response" },
        { "on_connection",  "on_connection(fn(conn)) -> bool",  "Hook: New connection" },
        { "on_connection_close","on_connection_close(fn(conn)) -> bool", "Hook: Connection closed" },
    };
}

}
