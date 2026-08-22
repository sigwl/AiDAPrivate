#include "calculator_tool.hpp"

#include "calculator_engine.hpp"

namespace mcp_standalone::ida_compat
{
    tool_result_t tool_calculate(const json& params, const workspace_request_context_t& context)
    {
        return calculate_engine(params, context);
    }
}
