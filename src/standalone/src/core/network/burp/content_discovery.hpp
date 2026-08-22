#pragma once

#include <atomic>
#include <cstdint>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace content_discovery {

struct config_t
{
    std::string              target_url;
    std::string              wordlist_id;
    std::string              wordlist_file;
    std::vector<std::string> extensions;
    int                      concurrency = 25;
    int                      delay_ms = 0;
    int                      request_timeout_ms = 8000;
    std::vector<int>         match_status;
    std::vector<int>         filter_status;
    size_t                   filter_size_min = 0;
    size_t                   filter_size_max = 0;
    std::string              filter_words_regex;
    bool                     recurse = false;
    int                      recurse_depth = 1;
    std::string              method = "GET";
    std::vector<std::pair<std::string, std::string>> extra_headers;
    std::string              cookie_header;
    std::string              user_agent = "AiDA-ContentDiscovery/1.0";
    bool                     follow_redirects = false;
    bool                     auto_calibrate = true;
};

enum class disc_phase_t : int
{
    pending = 0,
    calibrating = 1,
    running = 2,
    stopping = 3,
    complete = 4,
    error = 5
};

struct hit_t
{
    std::string url;
    std::string payload;
    int         status = 0;
    size_t      body_bytes = 0;
    uint64_t    latency_ms = 0;
    std::string content_type;
    std::string redirect_to;
    int         depth = 0;
};

struct disc_status_t
{
    uint64_t            id = 0;
    disc_phase_t        phase = disc_phase_t::pending;
    int                 attempts = 0;
    int                 total = 0;
    int                 hits = 0;
    int                 filtered = 0;
    int                 errors = 0;
    uint64_t            started_unix_ms = 0;
    uint64_t            finished_unix_ms = 0;
    bool                finished = false;
    bool                cancelled = false;
    size_t              calibrated_size_lo = 0;
    size_t              calibrated_size_hi = 0;
    std::string         last_error;
    std::string         last_url;
    config_t            config;
    std::vector<hit_t>  hits_list;
};

bool                            initialize();
void                            shutdown();

uint64_t                        start(const config_t& cfg);
bool                            stop(uint64_t id);
disc_status_t                   status(uint64_t id);
std::vector<disc_status_t>      list();
std::vector<hit_t>              results(uint64_t id);
bool                            remove(uint64_t id);

std::string                     last_error();

}
}
}
