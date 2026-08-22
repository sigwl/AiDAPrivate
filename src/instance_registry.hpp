#pragma once

#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>
#include <functional>
#include <nlohmann/json.hpp>

struct ida_instance_record_t
{
    std::string instance_id;
    uint64_t    pid = 0;
    int         port = 0;
    std::string base_url;
    std::string mcp_url;
    std::string sse_url;
    std::string idb_path;
    std::string input_file;
    std::string input_basename;
    std::string display_name;
    std::string config_entry_name;
    std::string file_md5;
    std::string file_sha256;
    std::string module_id;
    std::string index_generation;
    std::string image_base;
    std::string image_min_ea;
    std::string image_max_ea;
    std::string processor;
    int         bitness = 0;
    std::string hostname;
    std::string ida_version;
    uint64_t    started_at_ms = 0;
    uint64_t    last_heartbeat_ms = 0;
    bool        is_self = false;

    nlohmann::json to_json() const;
    static ida_instance_record_t from_json(const nlohmann::json& j);
};

struct ida_peer_authentication_t
{
    std::string instance_id;
    std::string lifecycle_generation;
    uint64_t    pid = 0;
    uint64_t    started_at_ms = 0;
    std::string capability;
};

class instance_registry_t
{
public:
    instance_registry_t();
    ~instance_registry_t();

    bool start(int port, const std::string& base_url,
               const std::string& mcp_url, const std::string& sse_url);
    void stop();

    bool is_running() const { return _running.load(); }

    const std::string& self_instance_id() const { return _self.instance_id; }
    const std::string& self_config_entry_name() const { return _self.config_entry_name; }
    int self_port() const { return _self.port; }

    ida_instance_record_t self_record() const;
    std::vector<ida_instance_record_t> live_peers() const;
    std::vector<ida_instance_record_t> all_live_instances() const;
    bool find_instance(const std::string& instance_id, ida_instance_record_t& out) const;
    bool find_instance_by_pid(uint64_t pid, ida_instance_record_t& out) const;
    bool self_peer_authentication(ida_peer_authentication_t& out) const;
    bool load_peer_authentication(const std::string& instance_id,
                                  ida_peer_authentication_t& out) const;
    bool authenticate_peer(const ida_peer_authentication_t& presented) const;

    void on_peer_set_changed(std::function<void()> cb);

    static std::string registry_dir();
    static uint64_t now_ms();

private:
    void heartbeat_thread_func();
    void write_self_file();
    void delete_self_file();
    bool load_record(const std::string& path, ida_instance_record_t& out) const;
    std::vector<ida_instance_record_t> scan_locked() const;
    void prune_stale_locked() const;
    bool is_pid_alive(uint64_t pid) const;
    void compute_self_identity(int port, const std::string& base_url,
                               const std::string& mcp_url, const std::string& sse_url);
    bool create_self_authentication();
    bool write_self_authentication_file();
    void delete_self_authentication_file();
    std::string auth_file_path(const std::string& instance_id) const;
    bool load_authentication_file(const std::string& path,
                                  ida_peer_authentication_t& out) const;
    std::string compute_config_entry_name(const std::string& base);
    uint64_t hash_string(const std::string& s) const;
    std::string self_file_path() const;

    mutable std::mutex _mtx;
    ida_instance_record_t _self;
    std::atomic<bool>     _running{false};
    std::atomic<bool>     _stop_requested{false};
    std::thread           _heartbeat_thread;
    std::function<void()> _peer_change_cb;
    mutable std::vector<std::string> _last_known_peer_ids;
    ida_peer_authentication_t _self_auth;
};
