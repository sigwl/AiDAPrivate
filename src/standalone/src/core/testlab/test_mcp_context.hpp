#pragma once

#include <atomic>
#include <functional>
#include <memory>
#include <string>

namespace test_all_features {

struct mcp_run_fixture_context_t;

struct mcp_phase_context_t {
    std::atomic<int>* passed = nullptr;
    std::atomic<int>* failed = nullptr;
    std::atomic<int>* skipped = nullptr;
    std::function<bool()> cancelled;
    mcp_run_fixture_context_t* fixture = nullptr;

    bool validate(std::string& reason) const {
        if (passed == nullptr) reason = "passed counter missing";
        else if (failed == nullptr) reason = "failed counter missing";
        else if (skipped == nullptr) reason = "skipped counter missing";
        else if (!cancelled) reason = "cancellation callback missing";
        else if (fixture == nullptr) reason = "fixture context missing";
        else return true;
        return false;
    }
};

struct mcp_fixture_cleanup_receipt_t {
    bool attempted = false;
    bool completed = false;
    std::string reason;
};

struct mcp_run_fixture_context_t {
    std::shared_ptr<void> burp_http_fixture_owner;
    std::string burp_fixture_base_url;
    std::string burp_fixture_wordlist_path;
    std::string cert_thumbprint;
    bool cert_inject_validate_only = false;
    mcp_fixture_cleanup_receipt_t burp_http_cleanup;
    mcp_fixture_cleanup_receipt_t certificate_cleanup;
};

}
