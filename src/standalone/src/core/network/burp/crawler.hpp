#pragma once

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace crawler {

struct crawl_config_t
{
    std::vector<std::string> start_urls;
    int                      max_depth = 3;
    bool                     same_host_only = true;
    bool                     scope_only = false;
    bool                     respect_robots_txt = true;
    bool                     parse_js = true;
    int                      max_pages = 500;
    int                      concurrency = 8;
    int                      rate_per_host = 10;
    int                      request_timeout_ms = 8000;
    std::string              user_agent = "AiDA-Crawler/1.0";
    std::vector<std::string> exclude_extensions;
    std::vector<std::string> exclude_patterns;
};

enum class crawl_status_phase_t : int
{
    pending = 0,
    running = 1,
    stopping = 2,
    complete = 3,
    error = 4
};

struct discovered_url_t
{
    std::string url;
    int         status = 0;
    size_t      body_bytes = 0;
    std::string content_type;
    int         depth = 0;
    std::string source_url;
    uint64_t    fetched_unix_ms = 0;
};

struct crawl_status_t
{
    uint64_t                       id = 0;
    crawl_status_phase_t           phase = crawl_status_phase_t::pending;
    int                            queue_depth = 0;
    int                            pages_visited = 0;
    int                            pages_failed = 0;
    int                            urls_found = 0;
    uint64_t                       started_unix_ms = 0;
    uint64_t                       finished_unix_ms = 0;
    uint64_t                       last_progress_unix_ms = 0;
    double                         pages_per_sec = 0.0;
    int                            in_flight = 0;
    bool                           finished = false;
    bool                           cancelled = false;
    std::string                    last_url;
    std::string                    last_error;
    crawl_config_t                 config;
    std::vector<discovered_url_t>  discovered;
    std::vector<std::string>       log;
};

bool                       initialize();
void                       shutdown();

uint64_t                   start(const crawl_config_t& config);
bool                       stop(uint64_t crawl_id);
crawl_status_t             status(uint64_t crawl_id);
std::vector<crawl_status_t> list();
bool                       remove(uint64_t crawl_id);

std::string                last_error();

}
}
}
