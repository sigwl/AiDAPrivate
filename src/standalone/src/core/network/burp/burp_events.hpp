#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "../../infra/event_bus.hpp"

namespace aida {
namespace burp {

struct exchange_observed_t
{
    uint64_t                                          id = 0;
    uint64_t                                          timestamp_ms = 0;
    std::string                                       method;
    std::string                                       scheme;
    std::string                                       host;
    uint16_t                                          port = 0;
    std::string                                       path;
    std::string                                       query;
    std::vector<std::pair<std::string, std::string>>  req_headers;
    std::vector<uint8_t>                              req_body;
    int                                               status_code = 0;
    std::string                                       reason_phrase;
    std::vector<std::pair<std::string, std::string>>  resp_headers;
    std::vector<uint8_t>                              resp_body;
    uint64_t                                          latency_ms = 0;
    bool                                              is_websocket = false;
    bool                                              is_h2 = false;
    std::string                                       tls_version;
    std::string                                       alpn;
    std::string                                       client_addr;
    uint16_t                                          client_port = 0;
    std::string                                       source;
};

struct send_to_action_t
{
    uint64_t    exchange_id = 0;
    std::string target;
    std::string source_view;
};

struct scope_changed_t
{
    uint64_t    rule_id = 0;
    std::string action;
    bool        rule_is_exclude = false;
};

struct cookie_changed_t
{
    std::string host;
    std::string name;
    std::string action;
};

struct job_state_changed_t
{
    std::string job_type;
    uint64_t    job_id = 0;
    std::string phase;
    std::string reason;
    uint64_t    timestamp_ms = 0;
    bool        cancelled = false;
    bool        terminal = false;
};

inline constexpr aida::events::event_def_t<exchange_observed_t> kExchangeObservedEvent{"burp.exchange_observed"};
inline constexpr aida::events::event_def_t<send_to_action_t>    kSendToActionEvent{"burp.send_to_action"};
inline constexpr aida::events::event_def_t<scope_changed_t>     kScopeChangedEvent{"burp.scope_changed"};
inline constexpr aida::events::event_def_t<cookie_changed_t>    kCookieChangedEvent{"burp.cookie_changed"};
inline constexpr aida::events::event_def_t<job_state_changed_t> kJobStateChangedEvent{"burp.job_state_changed"};

}
}
