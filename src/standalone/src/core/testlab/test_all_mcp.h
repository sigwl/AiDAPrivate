#pragma once
#include <Windows.h>
#include <atomic>

#include "test_mcp_context.hpp"

namespace test_all_features {
    void phase_mcp_tests(HANDLE hf, const mcp_phase_context_t& context);
}
