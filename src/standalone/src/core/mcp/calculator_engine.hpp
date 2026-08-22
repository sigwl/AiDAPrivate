#pragma once

#include "calculator_tool.hpp"

namespace mcp_standalone::ida_compat
{
    tool_result_t calculate_engine(const json& params, const workspace_request_context_t& context);
}
