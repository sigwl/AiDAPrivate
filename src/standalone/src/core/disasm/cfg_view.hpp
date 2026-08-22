#pragma once

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#include "cfg_layout.hpp"
#include "disasm_theme.hpp"
#include "../ui/analysis_context_menu.hpp"
#include "../ui/application_view_registry.hpp"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "function_index.hpp"
#include "standalone_driver.hpp"
#include "symbol_classifier.hpp"
#include "zydis_disasm.hpp"
#include "../debugger/debugger_engine.hpp"
#include "ui_anim.hpp"
#include "../analysis/pdb_events.hpp"
#include "../analysis/symbol_store.hpp"
#include "../infra/executor.hpp"
#include "../infra/event_bus.hpp"
#include "../ui/motion.hpp"
#include "../ui/clock.hpp"
#include "../ui/transition.hpp"
#include "../ui/components.hpp"
#include "../ui/blur_layer.hpp"
#include "../ui/empty_state.hpp"
#include "../ui/skeleton.hpp"
#include "../ui/fonts.hpp"
#else
#include "../../preview/debugger_preview_runtime.hpp"
#include "../../preview/studio_semantics.hpp"
#include "ui_anim.hpp"
#include "../ui/motion.hpp"
#include "../ui/clock.hpp"
#include "../ui/transition.hpp"
#include "../ui/components.hpp"
#include "../ui/blur_layer.hpp"
#include "../ui/empty_state.hpp"
#include "../ui/skeleton.hpp"
#include "../ui/fonts.hpp"
#endif
#include "disasm_view.hpp"
#include "comment_dialog.hpp"
#include "pseudocode_view.hpp"
#include "rename_dialog.hpp"
#include "../analysis/types_hub_view_api.hpp"
#include "../analysis/xref_db_view.hpp"
#include "../debugger/debugger_view.hpp"
#include "../ai/standalone_chat.hpp"
#include "../ui/theme.hpp"
#include "../settings/settings_persistence_service.hpp"
#include "../settings/standalone_settings.hpp"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../helpers/diag_log.hpp"
#endif

namespace cfg_view {

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
namespace preview_support {
enum class injection_t { function_banner, attributes_line, prototype_line, proc_header, var_decl, proc_endp, endp_separator, label_line, spacer_line, noreturn_separator };
struct injection_row_t { injection_t kind = injection_t::spacer_line; std::string text; uint64_t addr = 0; };
}
}
namespace function_index {
using injection_t = cfg_view::preview_support::injection_t;
using injection_row_t = cfg_view::preview_support::injection_row_t;
}
namespace symbol_classifier {
enum class kind_t { unknown, external_import };
template <typename... T> inline kind_t classify(T&&...) { return kind_t::unknown; }
}
namespace cfg_view {
#endif

struct instruction_line_t {
	uint64_t    addr = 0;
	std::string text;
};

struct basic_block_t {
	uint64_t                       start_addr = 0;
	uint64_t                       end_addr = 0;
	std::vector<instruction_line_t> instructions;
	std::vector<int>               successors;
	bool                           is_entry = false;
	bool                           has_breakpoint = false;
};

struct block_motion_t {
	float current_x = 0.f;
	float current_y = 0.f;
	float vel_x = 0.f;
	float vel_y = 0.f;
	float entrance = 0.f;
	float hover = 0.f;
	float hover_vel = 0.f;
	bool  initialized = false;
};

struct cfg_model_snapshot_t {
	std::vector<basic_block_t> blocks;
	cfg_layout::graph_t graph;
	uint64_t entry_addr = 0;
	uint64_t current_rip = 0;
	std::unordered_map<int, std::size_t> node_lookup;
	std::map<int, std::vector<function_index::injection_row_t>> entry_injections;
	std::uint64_t generation = 0;
};

struct cfg_state_t {
	std::shared_ptr<const cfg_model_snapshot_t> model;
	std::atomic<std::uint64_t> next_model_generation{1};
	std::uint64_t              displayed_model_generation = 0;
	uint64_t                   last_cursor_addr = 0;
	float                      pan_x = 0.f;
	float                      pan_y = 0.f;
	float                      target_pan_x = 0.f;
	float                      target_pan_y = 0.f;
	float                      pan_vel_x = 0.f;
	float                      pan_vel_y = 0.f;
	float                      zoom = 1.f;
	float                      target_zoom = 1.f;
	float                      zoom_vel = 0.f;
	int                        selected_block = -1;
	float                      rebuild_anim = 1.f;
	bool                       fit_request = false;
	std::unordered_map<int, block_motion_t> block_motion;
	bool                       minimap_dragging = false;
	int                        text_sel_block = -1;
	int                        text_sel_line_anchor = -1;
	int                        text_sel_line_extent = -1;
	bool                       text_sel_dragging = false;
	int                        text_ctx_block = -1;
	int                        text_ctx_line  = -1;
	int                        sel_log_frame = -1;
	std::mutex                 mutex;
	std::atomic<bool>          building{false};
};

inline cfg_state_t g_state;

inline std::shared_ptr<const cfg_model_snapshot_t> capture_model()
{
	std::lock_guard<std::mutex> lock(g_state.mutex);
	return g_state.model;
}

inline void publish_model(std::shared_ptr<const cfg_model_snapshot_t> model)
{
	std::lock_guard<std::mutex> lock(g_state.mutex);
	g_state.model = std::move(model);
}

inline void build_cfg(uint64_t entry_address);
inline void build_cfg(const disasm_view::workspace_context_t& context,
                      uint64_t entry_address);

namespace detail {

inline float estimate_text_width_for_cfg(const char* text, float font_size)
{
	if (!text || font_size <= 0.f)
		return 0.f;
	float width = 0.f;
	for (const unsigned char* p = reinterpret_cast<const unsigned char*>(text); *p; ++p) {
		const unsigned char c = *p;
		if (c == '\t') {
			width += font_size * 2.0f;
		} else if (c == ' ') {
			width += font_size * 0.35f;
		} else if (std::strchr("ilI.,:;!|'", c)) {
			width += font_size * 0.34f;
		} else if (std::strchr("mwMW@#%&", c)) {
			width += font_size * 0.86f;
		} else {
			width += font_size * 0.58f;
		}
	}
	return width;
}

inline float estimate_text_width_for_cfg(const std::string& text, float font_size)
{
	return estimate_text_width_for_cfg(text.c_str(), font_size);
}

inline bool safe_decode_for_cfg(const uint8_t* code, int avail, uint64_t va,
                               bool is_64bit, AsmInstr& out)
{
#if defined(_MSC_VER)
	__try {
		out = zydis_decode_one(code, avail, va, is_64bit);
		return true;
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		std::snprintf(out.mnem, sizeof(out.mnem), "db");
		std::snprintf(out.ops, sizeof(out.ops), "0x%02X", (code && avail > 0) ? code[0] : 0);
		out.addr = va;
		out.len = 1;
		if (code && avail > 0)
			out.raw[0] = code[0];
		return false;
	}
#else
	out = zydis_decode_one(code, avail, va, is_64bit);
	return true;
#endif
}

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
inline std::atomic<bool>&                    pdb_subscription_armed_flag()
{
	static std::atomic<bool> armed{false};
	return armed;
}

inline aida::events::subscription_handle_t& pdb_subscription_slot()
{
	static aida::events::subscription_handle_t slot;
	return slot;
}

inline void rebuild_on_pdb_load(const aida::events::event_pdb_loaded& ev)
{
	if (!ev.success) return;
	const auto model = capture_model();
	const uint64_t entry = model ? model->entry_addr : 0;
	if (entry == 0) return;
	build_cfg(entry);
}

inline void ensure_pdb_subscription()
{
	auto& armed = pdb_subscription_armed_flag();
	if (armed.load(std::memory_order_acquire)) return;
	bool expected = false;
	if (!armed.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) return;
	pdb_subscription_slot() = aida::events::subscribe(
		aida::events::event_pdb_loaded_def,
		[](const aida::events::event_pdb_loaded& ev) {
			rebuild_on_pdb_load(ev);
		});
	if (!pdb_subscription_slot().valid()) {
		armed.store(false, std::memory_order_release);
	}
}
#else
inline void ensure_pdb_subscription() {}
#endif

}

inline void clear()
{
	publish_model({});
	g_state.displayed_model_generation = 0;
	g_state.selected_block = -1;
	g_state.block_motion.clear();
	g_state.rebuild_anim = 1.f;
	g_state.text_sel_block = -1;
	g_state.text_sel_line_anchor = -1;
	g_state.text_sel_line_extent = -1;
	g_state.text_sel_dragging = false;
	g_state.text_ctx_block = -1;
	g_state.text_ctx_line = -1;
	g_state.sel_log_frame = -1;
}

namespace detail {

inline int find_or_create_block(std::map<uint64_t, int>& addr_to_block,
								std::vector<basic_block_t>& blocks, uint64_t addr)
{
	auto it = addr_to_block.find(addr);
	if (it != addr_to_block.end())
		return it->second;
	int idx = static_cast<int>(blocks.size());
	blocks.emplace_back();
	blocks.back().start_addr = addr;
	addr_to_block[addr] = idx;
	return idx;
}

inline ImVec2 bezier_point(ImVec2 p1, ImVec2 p2, ImVec2 p3, ImVec2 p4, float t)
{
	float u = 1.f - t;
	float w0 = u * u * u;
	float w1 = 3.f * u * u * t;
	float w2 = 3.f * u * t * t;
	float w3 = t * t * t;
	return ImVec2(w0 * p1.x + w1 * p2.x + w2 * p3.x + w3 * p4.x,
	              w0 * p1.y + w1 * p2.y + w2 * p3.y + w3 * p4.y);
}

inline void compute_world_bounds(const cfg_layout::graph_t& g, float& min_x, float& min_y,
                                 float& max_x, float& max_y)
{
	min_x = min_y = 1e9f;
	max_x = max_y = -1e9f;
	for (const auto& n : g.nodes) {
		float lx = n.x - n.width * 0.5f;
		float rx = n.x + n.width * 0.5f;
		float ty = n.y;
		float by = n.y + n.height;
		if (lx < min_x) min_x = lx;
		if (rx > max_x) max_x = rx;
		if (ty < min_y) min_y = ty;
		if (by > max_y) max_y = by;
	}
	if (min_x > max_x) { min_x = -100.f; max_x = 100.f; }
	if (min_y > max_y) { min_y = -100.f; max_y = 100.f; }
}

inline float render_colored_insn(ImDrawList* dl, float x, float y,
                                  const char* text, const aida::ui::theme_t& tk,
                                  float alpha, float clip_right,
                                  ImFont* font, float font_size)
{
	if (!text || !*text) return x;
	if (!font) font = ImGui::GetFont();

	ImU32 col_mnem  = aida::ui::with_alpha(tk.accent_u32,    alpha);
	ImU32 col_reg   = aida::ui::with_alpha(tk.info,          alpha);
	ImU32 col_imm   = aida::ui::with_alpha(tk.warning,       alpha);
	ImU32 col_mem   = aida::ui::with_alpha(tk.success,       alpha);
	ImU32 col_punct = aida::ui::with_alpha(tk.text_secondary, alpha);
	ImU32 col_def   = aida::ui::with_alpha(tk.text_primary,  alpha);

	const char* p = text;
	float cur_x = x;

	while (*p && static_cast<unsigned char>(*p) <= 0x20) ++p;
	const char* mnem_start = p;
	while (*p && static_cast<unsigned char>(*p) > 0x20) ++p;
	if (p > mnem_start) {
		if (cur_x < clip_right) {
			dl->AddText(font, font_size, ImVec2(cur_x, y), col_mnem, mnem_start, p);
		}
		ImVec2 ms = font->CalcTextSizeA(font_size, FLT_MAX, 0.f, mnem_start, p);
		cur_x += ms.x;
	}

	while (*p) {
		if (cur_x >= clip_right) break;

		if (static_cast<unsigned char>(*p) <= 0x20) {
			const char* ws = p;
			while (*p && static_cast<unsigned char>(*p) <= 0x20) ++p;
			ImVec2 ss = font->CalcTextSizeA(font_size, FLT_MAX, 0.f, ws, p);
			cur_x += ss.x;
			continue;
		}

		const char* tok = p;
		ImU32 col;

		if (*p == '[') {
			int depth = 0;
			while (*p) {
				if (*p == '[') ++depth;
				else if (*p == ']') {
					++p; --depth;
					if (depth <= 0) break;
					continue;
				}
				++p;
			}
			col = col_mem;
		} else if (*p == '0' && (*(p + 1) == 'x' || *(p + 1) == 'X')) {
			p += 2;
			while (*p && ((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F')))
				++p;
			col = col_imm;
		} else if (*p >= '0' && *p <= '9') {
			while (*p && *p >= '0' && *p <= '9') ++p;
			col = col_imm;
		} else if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || *p == '_') {
			while (*p && ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
			              (*p >= '0' && *p <= '9') || *p == '_'))
				++p;
			col = col_reg;
		} else if (*p == ',' || *p == '+' || *p == '-' || *p == '*' || *p == ':' || *p == '.') {
			++p;
			col = col_punct;
		} else {
			++p;
			col = col_def;
		}

		dl->AddText(font, font_size, ImVec2(cur_x, y), col, tok, p);
		ImVec2 ts = font->CalcTextSizeA(font_size, FLT_MAX, 0.f, tok, p);
		cur_x += ts.x;
	}

	return cur_x;
}

inline std::string resolve_branch_symbol_for_cfg(
	const disasm_view::workspace_context_t& context, uint64_t target)
{
	if (target == 0) return std::string();
	const auto address = disasm_view::typed_address(context, target);
	std::string sym = address ? disasm_view::resolve_name(context, *address) : std::string();
	if (!sym.empty()) {
		auto bang = sym.find('!');
		if (bang != std::string::npos) sym = sym.substr(bang + 1);
		return sym;
	}
	return std::string();
}

inline std::string resolve_branch_symbol_for_cfg(uint64_t target)
{
	return resolve_branch_symbol_for_cfg(disasm_view::capture_selected_workspace(), target);
}

inline ImU32 injection_color_for_kind(function_index::injection_t kind)
{
	switch (kind) {
		case function_index::injection_t::function_banner:
		case function_index::injection_t::endp_separator:
			return disasm_theme::banner();
		case function_index::injection_t::attributes_line:
		case function_index::injection_t::prototype_line:
			return disasm_theme::comment();
		case function_index::injection_t::var_decl:
			return disasm_theme::var_decl();
		case function_index::injection_t::label_line:
			return disasm_theme::loc_label();
		case function_index::injection_t::proc_header:
		case function_index::injection_t::proc_endp:
			return disasm_theme::sub_label();
		case function_index::injection_t::spacer_line:
		case function_index::injection_t::noreturn_separator:
		default:
			return disasm_theme::comment();
	}
}

inline std::string substitute_branch_operand(
	const disasm_view::workspace_context_t& context,
	const std::string& ops, uint64_t target)
{
	if (target == 0) return ops;
	std::string sym = resolve_branch_symbol_for_cfg(context, target);
	if (sym.empty()) return ops;
	const auto address = disasm_view::typed_address(context, target);
	symbol_classifier::kind_t k = address
		? symbol_classifier::classify(context.workspace, *address)
		: symbol_classifier::kind_t::unknown;
	if (k == symbol_classifier::kind_t::external_import) {
		if (sym.compare(0, 6, "__imp_") != 0)
			sym = "__imp_" + sym;
	}
	char hex_buf[32];
	std::snprintf(hex_buf, sizeof(hex_buf), "0x%llX", static_cast<unsigned long long>(target));
	std::size_t pos = ops.find(hex_buf);
	if (pos == std::string::npos) {
		std::snprintf(hex_buf, sizeof(hex_buf), "0x%llx", static_cast<unsigned long long>(target));
		pos = ops.find(hex_buf);
	}
	if (pos == std::string::npos) {
		std::snprintf(hex_buf, sizeof(hex_buf), "%llXh", static_cast<unsigned long long>(target));
		pos = ops.find(hex_buf);
	}
	if (pos == std::string::npos) return ops;
	std::string out = ops.substr(0, pos) + sym + ops.substr(pos + std::strlen(hex_buf));
	return out;
}

}

inline void fit_to_view(float view_width, float view_height)
{
	const auto model = capture_model();
	if (!model || model->graph.nodes.empty())
		return;

	float min_x, min_y, max_x, max_y;
	detail::compute_world_bounds(model->graph, min_x, min_y, max_x, max_y);
	float ww = max_x - min_x;
	float wh = max_y - min_y;
	if (ww < 1.f) ww = 1.f;
	if (wh < 1.f) wh = 1.f;

	const float pad = 60.f;
	float zx = (view_width - pad * 2.f) / ww;
	float zy = (view_height - pad * 2.f) / wh;
	float z = zx < zy ? zx : zy;
	if (z < 0.1f) z = 0.1f;
	if (z > 5.f) z = 5.f;

	float cx = (min_x + max_x) * 0.5f;
	float cy = (min_y + max_y) * 0.5f;

	g_state.target_zoom = z;
	g_state.target_pan_x = -cx;
	g_state.target_pan_y = -cy;
}

inline void center_on_address(uint64_t addr)
{
	const auto model = capture_model();
	if (!model)
		return;
	for (std::size_t i = 0; i < model->blocks.size(); ++i) {
		const auto& b = model->blocks[i];
		if (addr >= b.start_addr && addr < b.end_addr) {
			const auto found = model->node_lookup.find(static_cast<int>(i));
			if (found != model->node_lookup.end() && found->second < model->graph.nodes.size()) {
				const auto& n = model->graph.nodes[found->second];
				g_state.target_pan_x = -n.x;
				g_state.target_pan_y = -(n.y + n.height * 0.5f);
				g_state.selected_block = static_cast<int>(i);
			}
			return;
		}
	}
}

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
inline void build_cfg(const disasm_view::workspace_context_t& workspace_context,
                      uint64_t entry_address)
{
	detail::ensure_pdb_subscription();

	if (g_state.building.load()) {
		diag::log_tagged_fmt("cfg", "build_cfg skipped already_building entry=0x%llX",
			static_cast<unsigned long long>(entry_address));
		return;
	}

	const uint32_t target_pid = workspace_context.workspace &&
		workspace_context.workspace->identity().process()
		? workspace_context.workspace->identity().process()->pid : 0;
	diag::log_tagged_fmt("cfg", "build_cfg START entry=0x%llX pid=%u",
		static_cast<unsigned long long>(entry_address), target_pid);

	g_state.building.store(true);
	g_state.rebuild_anim = 0.f;

	try {
		aida::infra::executor::submission_t sub;
		sub.owner_subsystem = "disasm";
		sub.label = "disasm.cfg.build";
		sub.thread_class = "bounded_task";
		sub.domain = aida::infra::executor::domain_t::feature_worker;
		sub.priority = 2;
		const uint32_t target_pid = driver_bridge::attached_pid();
		sub.target_pid = target_pid;
		sub.body = [entry_address, workspace_context, target_pid]() {
		try {
		struct build_guard_t {
			~build_guard_t()
			{
				g_state.building.store(false);
			}
		} build_guard;

		auto t_start = std::chrono::steady_clock::now();
		const std::size_t max_bytes = 0x10000;
		const std::size_t max_insns = 4096;

		std::vector<uint8_t> mem;
		bool have_data = false;

		if (workspace_context) {
			const auto address = disasm_view::typed_address(workspace_context, entry_address);
			if (address) {
				auto bytes = disasm_view::read_bytes(workspace_context, *address, max_bytes);
				if (bytes) {
					mem = bytes.take_value();
					have_data = !mem.empty();
				}
			}
		} else if (target_pid != 0) {
			have_data = driver_bridge::read_memory_for(target_pid, entry_address, max_bytes, mem);
		}

		if (mem.empty()) {
			diag::log_tagged_fmt("cfg", "build_cfg FAILED no_memory_data entry=0x%llX have_data=%d",
				static_cast<unsigned long long>(entry_address), static_cast<int>(have_data));
			g_state.building.store(false);
			return;
		}
		diag::log_tagged_fmt("cfg", "build_cfg memory_read %zu bytes from 0x%llX",
			mem.size(), static_cast<unsigned long long>(entry_address));

		struct decoded_insn_t {
			AsmInstr    ins;
			uint64_t    branch_target = 0;
			bool        has_target = false;
		};

		std::vector<decoded_insn_t> all_insns;
		all_insns.reserve(max_insns);

		const uint8_t* data = mem.data();
		const std::size_t sz = mem.size();
		std::size_t pos = 0;

		while (pos < sz && all_insns.size() < max_insns) {
			int avail = static_cast<int>((std::min)(std::size_t{15}, sz - pos));
			uint64_t va = entry_address + static_cast<uint64_t>(pos);
			AsmInstr ins = {};
			const bool is_64bit = !workspace_context.image ||
				workspace_context.image->architecture() == aida::analysis::architecture_id_t::x86_64;
			if (!detail::safe_decode_for_cfg(data + pos, avail, va, is_64bit, ins)) {
				diag::log_tagged_fmt("cfg", "build_cfg decode_seh addr=0x%llX",
					static_cast<unsigned long long>(va));
			}
			if (ins.len <= 0) {
				ins.addr = va;
				ins.len = 1;
				std::snprintf(ins.mnem, sizeof(ins.mnem), "db");
				std::snprintf(ins.ops, sizeof(ins.ops), "0x%02X", data[pos]);
				ins.raw[0] = data[pos];
			}

			decoded_insn_t d;
			d.ins = ins;

			if ((ins.is_call || ins.is_branch) && ins.branch_target != 0) {
				d.branch_target = ins.branch_target;
				d.has_target = true;
			}

			all_insns.push_back(d);

			if (ins.is_ret)
				break;

			pos += static_cast<std::size_t>(ins.len);
		}

		if (all_insns.empty()) {
			g_state.building.store(false);
			return;
		}

		uint64_t decoded_lo = all_insns.front().ins.addr;
		uint64_t decoded_hi = all_insns.back().ins.addr + static_cast<uint64_t>(all_insns.back().ins.len);

		std::map<uint64_t, bool> leaders;
		leaders[entry_address] = true;

		for (auto& d : all_insns) {
			if (d.has_target && !d.ins.is_call) {
				if (d.branch_target >= decoded_lo && d.branch_target < decoded_hi)
					leaders[d.branch_target] = true;
				uint64_t fallthrough = d.ins.addr + d.ins.len;
				leaders[fallthrough] = true;
			}
			if (d.ins.is_ret) {
				uint64_t next = d.ins.addr + d.ins.len;
				leaders[next] = true;
			}
		}

		std::vector<basic_block_t> blocks;
		std::map<uint64_t, int> addr_to_block;

		int cur_block = -1;
		for (auto& d : all_insns) {
			if (leaders.count(d.ins.addr)) {
				cur_block = detail::find_or_create_block(addr_to_block, blocks, d.ins.addr);
				if (d.ins.addr == entry_address)
					blocks[static_cast<std::size_t>(cur_block)].is_entry = true;
			}
			if (cur_block < 0)
				cur_block = detail::find_or_create_block(addr_to_block, blocks, d.ins.addr);

			instruction_line_t line;
			line.addr = d.ins.addr;
			std::string ops_text = d.ins.ops;
			if ((d.ins.is_branch || d.ins.is_call) && d.ins.branch_target != 0) {
				ops_text = detail::substitute_branch_operand(
					workspace_context, ops_text, d.ins.branch_target);
			}
			line.text.reserve(std::strlen(d.ins.mnem) + 1 + ops_text.size());
			line.text.assign(d.ins.mnem);
			line.text.push_back(' ');
			line.text.append(ops_text);
			blocks[static_cast<std::size_t>(cur_block)].instructions.push_back(std::move(line));
			blocks[static_cast<std::size_t>(cur_block)].end_addr = d.ins.addr + d.ins.len;

			if (d.ins.is_ret)
				continue;

			if (d.has_target && !d.ins.is_call) {
				bool target_in_range = (d.branch_target >= decoded_lo && d.branch_target < decoded_hi);
				if (target_in_range) {
					auto it_target = addr_to_block.find(d.branch_target);
					if (it_target != addr_to_block.end())
						blocks[static_cast<std::size_t>(cur_block)].successors.push_back(it_target->second);
					else {
						int tidx = detail::find_or_create_block(addr_to_block, blocks, d.branch_target);
						blocks[static_cast<std::size_t>(cur_block)].successors.push_back(tidx);
					}
				}

				bool is_unconditional = (std::strcmp(d.ins.mnem, "jmp") == 0);
				if (!is_unconditional) {
					uint64_t fall = d.ins.addr + d.ins.len;
					auto it_fall = addr_to_block.find(fall);
					if (it_fall != addr_to_block.end())
						blocks[static_cast<std::size_t>(cur_block)].successors.push_back(it_fall->second);
					else {
						int fidx = detail::find_or_create_block(addr_to_block, blocks, fall);
						blocks[static_cast<std::size_t>(cur_block)].successors.push_back(fidx);
					}
				}

				uint64_t next_addr = d.ins.addr + d.ins.len;
				if (leaders.count(next_addr)) {
					cur_block = -1;
				}
			}
		}

		if (!workspace_context) {
			auto& bps = debugger_engine::g_state.breakpoints;
			std::lock_guard<std::mutex> bp_lk(debugger_engine::g_state.bp_mutex);
			for (auto& b : blocks) {
				for (auto& bp : bps) {
					if (bp.address >= b.start_addr && bp.address < b.end_addr) {
						b.has_breakpoint = true;
						break;
					}
				}
			}
		}

		const float code_base = 13.f;
		const float ui_base = 13.f;

		const float line_gap = 5.f;
		const float line_h = code_base + line_gap;
		const float padding = 14.f;
		const float header_h = ui_base + 12.f;
		const float addr_gap = 14.f;
		const float text_slack = 24.f;
		const float min_node_w = 380.f;
		const float max_node_w = 1200.f;

		std::map<int, std::vector<function_index::injection_row_t>> entry_injections;
		for (std::size_t bi = 0; bi < blocks.size(); ++bi) {
			const int block_id = static_cast<int>(bi);
			if (!blocks[bi].is_entry) continue;
			std::vector<function_index::injection_row_t> rows;
			if (workspace_context) {
				const auto address = disasm_view::typed_address(
					workspace_context, blocks[bi].start_addr);
				if (address) {
					rows = function_index::rows_before(
						workspace_context.workspace, *address);
				}
			}
			if (!rows.empty()) {
				char log_buf[160];
				std::snprintf(log_buf, sizeof(log_buf),
					"[cfg] entry block=%d addr=0x%llX inj_rows=%zu",
					block_id,
					static_cast<unsigned long long>(blocks[bi].start_addr),
					rows.size());
				diag::log_tagged("cfg_view", log_buf);
				entry_injections.emplace(block_id, std::move(rows));
			}
		}

		cfg_layout::graph_t graph;
		graph.nodes.reserve(blocks.size());
		for (std::size_t i = 0; i < blocks.size(); ++i) {
			const int block_id = static_cast<int>(i);
			cfg_layout::node_t n;
			n.id = block_id;
			n.is_entry = blocks[i].is_entry;

			float addr_w = 0.f;
			float text_w = 0.f;
			for (auto& ln : blocks[i].instructions) {
				char ab[24];
				std::snprintf(ab, sizeof(ab), "%llX",
					static_cast<unsigned long long>(ln.addr));
				float aw = detail::estimate_text_width_for_cfg(ab, code_base);
				if (aw > addr_w) addr_w = aw;
				if (!ln.text.empty()) {
					float tw = detail::estimate_text_width_for_cfg(ln.text, code_base);
					if (tw > text_w) text_w = tw;
				}
			}

			std::size_t inj_lines = 0;
			auto it_inj = entry_injections.find(block_id);
			if (it_inj != entry_injections.end()) {
				inj_lines = it_inj->second.size();
				for (const auto& r : it_inj->second) {
					if (r.text.empty()) continue;
					float tw = detail::estimate_text_width_for_cfg(r.text, code_base);
					if (tw > text_w) text_w = tw;
				}
			}

			char header_buf[160];
			const char* kind = blocks[i].is_entry
				? "ENTRY"
				: (blocks[i].successors.empty() && !blocks[i].is_entry ? "EXIT" : "BLOCK");
			if (blocks[i].is_entry) {
				std::string fname = detail::resolve_branch_symbol_for_cfg(
					workspace_context, entry_address);
				if (fname.empty() && entry_address != blocks[i].start_addr)
					fname = detail::resolve_branch_symbol_for_cfg(
						workspace_context, blocks[i].start_addr);
				if (!fname.empty()) {
					std::size_t avail = sizeof(header_buf) - 12;
					std::string fn_short = fname.size() > avail
						? fname.substr(0, avail - 2) + ".." : fname;
					std::snprintf(header_buf, sizeof(header_buf), "%s  %s",
						kind, fn_short.c_str());
				} else {
					std::snprintf(header_buf, sizeof(header_buf), "%s  %llX",
						kind, static_cast<unsigned long long>(blocks[i].start_addr));
				}
			} else {
				std::snprintf(header_buf, sizeof(header_buf), "%s  %llX",
					kind, static_cast<unsigned long long>(blocks[i].start_addr));
			}
			float header_w = detail::estimate_text_width_for_cfg(header_buf, ui_base);

			n.addr_col_w = addr_w + addr_gap;

			float body_w = n.addr_col_w + text_w + padding * 2.f + text_slack;
			float head_w = header_w + padding * 2.f + 20.f;
			float w = body_w > head_w ? body_w : head_w;
			if (w < min_node_w) w = min_node_w;
			if (w > max_node_w) w = max_node_w;
			n.width = w;

			std::size_t total_lines = blocks[i].instructions.size() + inj_lines;
			n.height = header_h + padding * 2.f + static_cast<float>(total_lines) * line_h;
			float min_h = header_h + line_h + padding * 2.f;
			if (n.height < min_h) n.height = min_h;
			graph.nodes.push_back(n);
		}

		for (std::size_t i = 0; i < blocks.size(); ++i) {
			const int block_id = static_cast<int>(i);
			auto& succs = blocks[i].successors;
			for (std::size_t j = 0; j < succs.size(); ++j) {
				cfg_layout::edge_t e;
				e.from = block_id;
				e.to = succs[j];
				e.is_true_branch = (j == 0 && succs.size() > 1);
				graph.edges.push_back(e);
			}
		}

		cfg_layout::layout(graph, 60.f, 60.f);

		const std::size_t block_count = blocks.size();
		const std::size_t node_count = graph.nodes.size();
		const std::size_t edge_count = graph.edges.size();
		if (workspace_context &&
			(workspace_context.workspace->closed() ||
			 workspace_context.workspace->generation() != workspace_context.publication->generation ||
			 workspace_context.workspace->analysis_revision() !=
				workspace_context.publication->analysis_revision))
			return;

		auto model = std::make_shared<cfg_model_snapshot_t>();
		model->blocks = std::move(blocks);
		model->graph = std::move(graph);
		model->entry_addr = entry_address;
		model->current_rip = debugger_engine::cached_registers().rip;
		model->entry_injections = std::move(entry_injections);
		model->node_lookup.reserve(model->graph.nodes.size());
		for (std::size_t node_index = 0; node_index < model->graph.nodes.size(); ++node_index)
			model->node_lookup.emplace(model->graph.nodes[node_index].id, node_index);
		model->generation = g_state.next_model_generation.fetch_add(1,
			std::memory_order_acq_rel);
		publish_model(std::move(model));

		auto t_end = std::chrono::steady_clock::now();
		uint64_t dur_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t_end - t_start).count();
		diag::log_tagged_fmt("cfg", "build_cfg DONE entry=0x%llX blocks=%zu nodes=%zu edges=%zu duration_ms=%llu",
			static_cast<unsigned long long>(entry_address),
			block_count,
			node_count,
			edge_count,
			static_cast<unsigned long long>(dur_ms));
		} catch (const std::exception& ex) {
			diag::log_tagged_fmt("cfg", "build_cfg exception entry=0x%llX err='%s'",
				static_cast<unsigned long long>(entry_address), ex.what());
			g_state.building.store(false);
		} catch (...) {
			diag::log_tagged_fmt("cfg", "build_cfg exception entry=0x%llX err='<unknown>'",
				static_cast<unsigned long long>(entry_address));
			g_state.building.store(false);
		}
	};
		if (!aida::infra::executor::submit(std::move(sub)).submitted) {
			diag::log_tagged_fmt("cfg", "build_cfg worker_post_failed entry=0x%llX",
				static_cast<unsigned long long>(entry_address));
			g_state.building.store(false);
		}
	} catch (const std::exception& ex) {
		diag::log_tagged_fmt("cfg", "build_cfg worker_create_failed entry=0x%llX err='%s'",
			static_cast<unsigned long long>(entry_address), ex.what());
		g_state.building.store(false);
	} catch (...) {
		diag::log_tagged_fmt("cfg", "build_cfg worker_create_failed entry=0x%llX err='<unknown>'",
			static_cast<unsigned long long>(entry_address));
		g_state.building.store(false);
	}
}

inline void build_cfg(uint64_t entry_address)
{
	build_cfg(disasm_view::capture_selected_workspace(), entry_address);
}
#else
inline void build_cfg(const disasm_view::workspace_context_t&, uint64_t entry_address)
{
	auto model = std::make_shared<cfg_model_snapshot_t>();
	model->entry_addr = entry_address ? entry_address : 0x00007FF7A4C16A10;
	model->current_rip = debugger_engine::cached_registers().rip;
	model->blocks = {
		{model->entry_addr, model->entry_addr + 0x0D, {{model->entry_addr, "mov rax, qword ptr [rbx+18h]"}, {model->entry_addr + 4, "test rax, rax"}, {model->entry_addr + 7, "je loc_7FF7A4C16A32"}}, {1, 2}, true, false},
		{model->entry_addr + 0x10, model->entry_addr + 0x1D, {{model->entry_addr + 0x10, "call decrypt_stage"}, {model->entry_addr + 0x15, "test al, al"}, {model->entry_addr + 0x17, "jne loc_7FF7A4C16A48"}}, {3, 2}, false, false},
		{model->entry_addr + 0x22, model->entry_addr + 0x28, {{model->entry_addr + 0x22, "xor eax, eax"}, {model->entry_addr + 0x24, "jmp loc_7FF7A4C16A52"}}, {4}, false, true},
		{model->entry_addr + 0x38, model->entry_addr + 0x42, {{model->entry_addr + 0x38, "mov eax, 1"}, {model->entry_addr + 0x3D, "mov [rdi+40h], al"}}, {4}, false, false},
		{model->entry_addr + 0x48, model->entry_addr + 0x4D, {{model->entry_addr + 0x48, "add rsp, 30h"}, {model->entry_addr + 0x4C, "ret"}}, {}, false, false}
	};
	for (std::size_t i = 0; i < model->blocks.size(); ++i) {
		const int block_id = static_cast<int>(i);
		cfg_layout::node_t node;
		node.id = block_id;
		node.width = 286.f;
		node.height = 72.f + static_cast<float>(model->blocks[i].instructions.size()) * 20.f;
		node.addr_col_w = 116.f;
		node.is_entry = i == 0;
		model->graph.nodes.push_back(node);
		for (int successor : model->blocks[i].successors)
			model->graph.edges.push_back({block_id, successor, i == 0 && successor == 1});
	}
	cfg_layout::layout(model->graph, 92.f, 76.f);
	model->node_lookup.reserve(model->graph.nodes.size());
	for (std::size_t node_index = 0; node_index < model->graph.nodes.size(); ++node_index)
		model->node_lookup.emplace(model->graph.nodes[node_index].id, node_index);
	model->entry_injections[0] = {{function_index::injection_t::function_banner, "; validate_license", model->entry_addr}, {function_index::injection_t::prototype_line, "bool __fastcall validate_license(session_t* session)", model->entry_addr}};
	model->generation = g_state.next_model_generation.fetch_add(1, std::memory_order_acq_rel);
	const auto logged_entry = model->entry_addr;
	publish_model(std::move(model));
	aida::preview::debugger::record("build_cfg", std::to_string(logged_entry));
}

inline void build_cfg(uint64_t entry_address)
{
	build_cfg(disasm_view::capture_selected_workspace(), entry_address);
}
#endif

inline bool handle_view_keys(float view_width, float view_height)
{
	const auto model = capture_model();
	if (g_state.fit_request && model && !model->graph.nodes.empty()) {
		g_state.fit_request = false;
		fit_to_view(view_width, view_height);
	}

	ImGuiIO& key_io = ImGui::GetIO();
	bool key_text_lock = key_io.WantTextInput
		|| ImGui::IsAnyItemActive();

	if (key_text_lock || key_io.KeyCtrl || key_io.KeyAlt)
		return false;

	if (ImGui::IsKeyPressed(ImGuiKey_Escape, false)) {
		if (g_state.text_sel_block >= 0
			|| g_state.text_sel_line_anchor >= 0
			|| g_state.text_sel_line_extent >= 0)
		{
			g_state.text_sel_block = -1;
			g_state.text_sel_line_anchor = -1;
			g_state.text_sel_line_extent = -1;
			g_state.text_sel_dragging = false;
			return true;
		}
		uint64_t back_addr = g_state.last_cursor_addr != 0
			? g_state.last_cursor_addr
			: (model ? model->entry_addr : 0);
		aida::ui::application_views::open_or_focus(
			aida::ui::stable_view_id_t("document.disassembly"));
		if (back_addr != 0)
			disasm_view::goto_address(back_addr, disasm_view::capture_selected_workspace());
		return true;
	}
	return false;
}

inline void render(float pos_x, float pos_y, float width, float height,
				   float alpha, float accent_r, float accent_g, float accent_b)
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	if (!capture_model())
		build_cfg(debugger_engine::cached_registers().rip);
#endif
	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImVec2 clip_min(pos_x, pos_y);
	ImVec2 clip_max(pos_x + width, pos_y + height);
	dl->PushClipRect(clip_min, clip_max, true);

	const auto& tk = aida::ui::resolved();
	const auto _ta = [alpha](ImU32 c) -> ImU32 {
		return aida::ui::with_alpha(c, alpha);
	};
	float dt = aida::ui::clock::dt();

	dl->AddRectFilled(clip_min, clip_max, _ta(tk.bg_base));

	handle_view_keys(width, height);

	if (g_state.building.load()) {
		float panel_w = width * 0.55f;
		if (panel_w > 480.f) panel_w = 480.f;
		float panel_h = 180.f;
		float px = pos_x + (width - panel_w) * 0.5f;
		float py = pos_y + (height - panel_h) * 0.5f;
		ImVec2 a(px, py);
		ImVec2 b(px + panel_w, py + panel_h);
		aida::ui::blur::render_drop_shadow(dl, a, b, 14.f, 4, 0.30f * alpha);
		aida::ui::blur::render_glass_fill(dl, a, b, 14.f, alpha);
		aida::ui::blur::render_glass_border(dl, a, b, 14.f, alpha);

		float row_y = py + 22.f;
		ImFont* ft = aida::ui::fonts::body_em();
		dl->AddText(ft, 14.f, ImVec2(px + 22.f, row_y),
		            _ta(tk.text_primary), "Building CFG...");
		row_y += 26.f;
		aida::ui::skeleton::render_text_line(dl, ImVec2(px + 22.f, row_y), panel_w - 44.f, 12.f);
		row_y += 18.f;
		aida::ui::skeleton::render_text_line(dl, ImVec2(px + 22.f, row_y), (panel_w - 44.f) * 0.78f, 12.f);
		row_y += 18.f;
		aida::ui::skeleton::render_text_line(dl, ImVec2(px + 22.f, row_y), (panel_w - 44.f) * 0.62f, 12.f);

		float bar_y = py + panel_h - 26.f;
		aida::ui::components::render_progress_bar(ImVec2(px + 22.f, bar_y),
		                                          panel_w - 44.f, 4.f, 0.f, true, true);
		dl->PopClipRect();
		return;
	}

	const auto model = capture_model();
	if (!model || model->blocks.empty()) {
		aida::ui::empty_state::config_t cfg;
		cfg.glyph = aida::ui::empty_state::glyph_t::flow;
		cfg.title = "No CFG built";
		cfg.body  = "Place the cursor on an address in the disassembly view, then press Space to build a control-flow graph.";
		cfg.hints = { { "Space" }, { "Esc" } };
		aida::ui::empty_state::render(ImVec2(pos_x, pos_y), ImVec2(width, height), cfg);
		dl->PopClipRect();
		return;
	}
	if (g_state.displayed_model_generation != model->generation) {
		g_state.displayed_model_generation = model->generation;
		g_state.selected_block = -1;
		g_state.target_pan_x = 0.f;
		g_state.target_pan_y = 0.f;
		g_state.pan_x = 0.f;
		g_state.pan_y = 0.f;
		g_state.target_zoom = 1.f;
		g_state.zoom = 1.f;
		g_state.block_motion.clear();
		g_state.rebuild_anim = 0.f;
		g_state.fit_request = true;
		g_state.text_sel_block = -1;
		g_state.text_sel_line_anchor = -1;
		g_state.text_sel_line_extent = -1;
		g_state.text_sel_dragging = false;
		g_state.text_ctx_block = -1;
		g_state.text_ctx_line = -1;
		g_state.sel_log_frame = -1;
	}

	g_state.rebuild_anim = aida::motion::smooth_lerp(g_state.rebuild_anim, 1.f, 4.f, dt);

	ImGuiIO& io = ImGui::GetIO();
	bool hovered = ImGui::IsMouseHoveringRect(clip_min, clip_max, false);

	if (hovered && ImGui::IsMouseDragging(ImGuiMouseButton_Middle, 0.f)) {
		g_state.target_pan_x += io.MouseDelta.x / g_state.zoom;
		g_state.target_pan_y += io.MouseDelta.y / g_state.zoom;
	}

	if (hovered && io.MouseWheel != 0.f) {
		if (io.KeyCtrl) {
			float old_zoom = g_state.target_zoom;
			g_state.target_zoom *= (io.MouseWheel > 0) ? 1.1f : 0.9f;
			if (g_state.target_zoom < 0.1f) g_state.target_zoom = 0.1f;
			if (g_state.target_zoom > 5.f) g_state.target_zoom = 5.f;

			float mx = io.MousePos.x - pos_x - width * 0.5f;
			float my = io.MousePos.y - pos_y - height * 0.5f;
			float scale_change = g_state.target_zoom / old_zoom;
			g_state.target_pan_x -= mx * (1.f - 1.f / scale_change) / g_state.target_zoom;
			g_state.target_pan_y -= my * (1.f - 1.f / scale_change) / g_state.target_zoom;
		} else {
			g_state.target_pan_y += io.MouseWheel * 40.f / g_state.zoom;
		}
	}

	g_state.pan_x = aida::motion::spring_step(g_state.pan_x, g_state.target_pan_x,
	                                           g_state.pan_vel_x, aida::motion::spring::balanced, dt);
	g_state.pan_y = aida::motion::spring_step(g_state.pan_y, g_state.target_pan_y,
	                                           g_state.pan_vel_y, aida::motion::spring::balanced, dt);
	g_state.zoom = aida::motion::spring_step(g_state.zoom, g_state.target_zoom,
	                                          g_state.zoom_vel, aida::motion::spring::balanced, dt);

	float center_x = pos_x + width * 0.5f;
	float center_y = pos_y + height * 0.5f;
	float z = g_state.zoom;

	auto world_to_screen = [&](float wx, float wy) -> ImVec2 {
		return ImVec2(center_x + (wx + g_state.pan_x) * z,
					  center_y + (wy + g_state.pan_y) * z);
	};

	{
		const float grid_step = 40.f;
		float inv_z = z > 0.0001f ? 1.f / z : 1.f;
		float w_left   = -g_state.pan_x - (width  * 0.5f) * inv_z;
		float w_right  = -g_state.pan_x + (width  * 0.5f) * inv_z;
		float w_top    = -g_state.pan_y - (height * 0.5f) * inv_z;
		float w_bottom = -g_state.pan_y + (height * 0.5f) * inv_z;
		float span_x = w_right - w_left;
		float span_y = w_bottom - w_top;
		if (span_x > 0.f && span_y > 0.f) {
			float est_cols = span_x / grid_step;
			float est_rows = span_y / grid_step;
			if (est_cols * est_rows <= 4000.f) {
				float gx0 = std::floor(w_left  / grid_step) * grid_step;
				float gy0 = std::floor(w_top   / grid_step) * grid_step;
				float gx1 = std::ceil (w_right / grid_step) * grid_step;
				float gy1 = std::ceil (w_bottom / grid_step) * grid_step;
				ImU32 dot_col = aida::ui::with_alpha(tk.border_subtle, alpha * 0.6f);
				for (float gy = gy0; gy <= gy1; gy += grid_step) {
					for (float gx = gx0; gx <= gx1; gx += grid_step) {
						ImVec2 sp = world_to_screen(gx, gy);
						if (sp.x < pos_x - 2.f || sp.x > pos_x + width + 2.f) continue;
						if (sp.y < pos_y - 2.f || sp.y > pos_y + height + 2.f) continue;
						dl->AddCircleFilled(sp, 0.9f, dot_col, 6);
					}
				}
			}
		}
	}

	const auto& nodes = model->graph.nodes;
	const auto& edges = model->graph.edges;
	const auto& blocks = model->blocks;

	for (const auto& n : nodes) {
		auto& m = g_state.block_motion[n.id];
		if (!m.initialized) {
			m.current_x = n.x;
			m.current_y = n.y;
			m.initialized = true;
			m.entrance = 0.f;
		}
		m.current_x = aida::motion::spring_step(m.current_x, n.x, m.vel_x, aida::motion::spring::gentle, dt);
		m.current_y = aida::motion::spring_step(m.current_y, n.y, m.vel_y, aida::motion::spring::gentle, dt);
	}

	for (const auto& e : edges) {
		const auto from_found = model->node_lookup.find(e.from);
		const auto to_found = model->node_lookup.find(e.to);
		if (from_found == model->node_lookup.end() || to_found == model->node_lookup.end()) continue;
		const std::size_t from_idx = from_found->second;
		const std::size_t to_idx = to_found->second;

		const auto& fn = nodes[from_idx];
		const auto& tn = nodes[to_idx];
		auto& fm = g_state.block_motion[fn.id];
		auto& tm = g_state.block_motion[tn.id];

		float arrow_sz = std::max(5.f, 7.f * z);
		ImVec2 p1 = world_to_screen(fm.current_x, fm.current_y + fn.height);
		ImVec2 p_tip = world_to_screen(tm.current_x, tm.current_y);
		ImVec2 p4(p_tip.x, p_tip.y - arrow_sz);
		float mid_y = (p1.y + p4.y) * 0.5f;
		ImVec2 p2(p1.x, mid_y);
		ImVec2 p3(p4.x, mid_y);
		const float edge_min_x = (std::min)(p1.x, p4.x);
		const float edge_max_x = (std::max)(p1.x, p4.x);
		const float edge_min_y = (std::min)(p1.y, p4.y);
		const float edge_max_y = (std::max)(p1.y, p4.y);
		if (edge_max_x < pos_x || edge_min_x > pos_x + width ||
			edge_max_y < pos_y || edge_min_y > pos_y + height)
			continue;

		bool two_succ = e.from >= 0 && static_cast<std::size_t>(e.from) < blocks.size()
			&& blocks[static_cast<std::size_t>(e.from)].successors.size() > 1;
		ImU32 edge_col;
		if (two_succ) {
			edge_col = e.is_true_branch
				? aida::ui::with_alpha(tk.success, alpha)
				: aida::ui::with_alpha(tk.error,   alpha);
		} else {
			edge_col = aida::ui::with_alpha(aida::ui::lighten(tk.text_secondary, 10), alpha);
		}

		float halo_thick = std::max(3.5f, 5.5f * z);
		float line_thick = std::max(1.5f, 2.0f * z);
		ImU32 halo = aida::ui::with_alpha(edge_col, 0.18f);
		dl->AddBezierCubic(p1, p2, p3, p4, halo, halo_thick);
		dl->AddBezierCubic(p1, p2, p3, p4, edge_col, line_thick);

		ImVec2 dir(p_tip.x - p3.x, p_tip.y - p3.y);
		float dir_len = std::sqrt(dir.x * dir.x + dir.y * dir.y);
		if (dir_len > 0.001f) {
			dir.x /= dir_len;
			dir.y /= dir_len;
			ImVec2 perp(-dir.y, dir.x);
			ImVec2 a1(p_tip.x - dir.x * arrow_sz + perp.x * arrow_sz * 0.5f,
					   p_tip.y - dir.y * arrow_sz + perp.y * arrow_sz * 0.5f);
			ImVec2 a2(p_tip.x - dir.x * arrow_sz - perp.x * arrow_sz * 0.5f,
					   p_tip.y - dir.y * arrow_sz - perp.y * arrow_sz * 0.5f);
			dl->AddTriangleFilled(p_tip, a1, a2, edge_col);
		}

		if (two_succ) {
			const char* label = e.is_true_branch ? "T" : "F";
			ImVec2 lts = ImGui::CalcTextSize(label);
			float lx = (p1.x + p4.x) * 0.5f + 6.f;
			float ly = (p1.y + p4.y) * 0.5f - lts.y * 0.5f;
			float pad_x = 4.f;
			float pad_y = 1.f;
			ImVec2 box_a(lx - pad_x, ly - pad_y);
			ImVec2 box_b(lx + lts.x + pad_x, ly + lts.y + pad_y);
			dl->AddRectFilled(box_a, box_b,
				aida::ui::with_alpha(aida::ui::resolved().bg_base, 0.94f * alpha), 3.f);
			dl->AddRect(box_a, box_b, edge_col, 3.f, 0, 1.f);
			dl->AddText(ImVec2(lx, ly), edge_col, label);
		}
	}

	float card_font_scale = z;
	if (card_font_scale < 0.30f) card_font_scale = 0.30f;
	if (card_font_scale > 3.00f) card_font_scale = 3.00f;
	ImFont* header_font = aida::ui::fonts::body_em();
	if (!header_font) header_font = ImGui::GetFont();
	float header_base = aida::ui::fonts::size_or(header_font, 13.f);
	const float header_strip_h = (header_base + 8.f) * card_font_scale;

	{
		ImFont* log_font = aida::ui::fonts::code();
		if (!log_font) log_font = ImGui::GetFont();
		float log_base = aida::ui::fonts::size_or(log_font, ImGui::GetFontSize());
		if (log_base <= 0.f) log_base = 13.f;
		float log_raw = log_base * z;
		float log_final = log_raw < 6.f ? 6.f : log_raw;
		bool  log_skip = log_raw < 6.f;
		static double s_last_log_time = -1e9;
		double now_log = ImGui::GetTime();
		if (now_log - s_last_log_time >= 2.0) {
			s_last_log_time = now_log;
			char log_msg[160];
			std::snprintf(log_msg, sizeof(log_msg),
				"node_render font=disasm_code base_size=%.2f zoom=%.3f final_size=%.2f skip_text=%d",
				log_base, z, log_final, log_skip ? 1 : 0);
			diag::log_tagged("cfg", log_msg);
		}
	}

	bool typed_context_requested = false;
	for (std::size_t ni = 0; ni < nodes.size(); ++ni) {
		auto& n = nodes[ni];
		if (n.id < 0 || static_cast<std::size_t>(n.id) >= blocks.size())
			continue;

		auto& blk = blocks[static_cast<std::size_t>(n.id)];
		auto& mm = g_state.block_motion[n.id];

		float nw = n.width * z;
		float nh = n.height * z;
		ImVec2 base_tl = world_to_screen(mm.current_x - n.width * 0.5f, mm.current_y);
		ImVec2 base_br(base_tl.x + nw, base_tl.y + nh);

		bool block_hov = ImGui::IsMouseHoveringRect(base_tl, base_br, false) && hovered;
		mm.hover = aida::motion::spring_step(mm.hover, block_hov ? 1.f : 0.f, mm.hover_vel,
		                                      aida::motion::spring::snappy, dt);
		float lift = mm.hover * 2.f;

		ImVec2 tl(base_tl.x, base_tl.y - lift);
		ImVec2 br(base_br.x, base_br.y - lift);

		float entrance = mm.entrance;
		if (entrance < 1.f) {
			float fy = (1.f - entrance) * 8.f;
			tl.y += fy; br.y += fy;
		}
		float row_alpha = alpha * (entrance < 1.f ? entrance : 1.f);

		if (br.x < pos_x || tl.x > pos_x + width || br.y < pos_y || tl.y > pos_y + height)
			continue;

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		const std::string legacy_node_identity = std::to_string(blk.start_addr) + ":" +
			std::to_string(blk.end_addr);
		const std::string legacy_node_semantic = aida::preview::semantics::stable_id(
			aida::preview::semantics::stable_id("aida.graph-node", "legacy"),
			aida::preview::semantics::entity_token(legacy_node_identity));
		static_cast<void>(aida::preview::semantics::register_region(legacy_node_semantic,
			"graph-node", ImGui::GetID(legacy_node_semantic.c_str()), tl, br));
#endif

		bool is_rip_block = (model->current_rip >= blk.start_addr && model->current_rip < blk.end_addr);
		bool is_selected = (n.id == g_state.selected_block);
		bool is_exit = blk.successors.empty() && !blk.is_entry;

		char header_buf[160];
		const char* kind = blk.is_entry ? "ENTRY" : (is_exit ? "EXIT" : "BLOCK");
		if (blk.is_entry) {
			std::string fname = detail::resolve_branch_symbol_for_cfg(model->entry_addr);
			if (fname.empty() && model->entry_addr != blk.start_addr)
				fname = detail::resolve_branch_symbol_for_cfg(blk.start_addr);
			if (!fname.empty()) {
				std::size_t avail = sizeof(header_buf) - 12;
				std::string fn_short = fname.size() > avail
					? fname.substr(0, avail - 2) + ".." : fname;
				snprintf(header_buf, sizeof(header_buf), "%s  %s",
				         kind, fn_short.c_str());
			} else {
				snprintf(header_buf, sizeof(header_buf), "%s  %llX",
				         kind, static_cast<unsigned long long>(blk.start_addr));
			}
		} else {
			snprintf(header_buf, sizeof(header_buf), "%s  %llX",
			         kind, static_cast<unsigned long long>(blk.start_addr));
		}

		ui_anim::render_graph_node_card(dl, tl.x, tl.y, nw, nh,
		                                 header_buf, blk.is_entry, is_selected,
		                                 accent_r, accent_g, accent_b, row_alpha,
		                                 aida::ui::clock::seconds(), card_font_scale);

		if (is_exit) {
			dl->AddRect(tl, br,
			            aida::ui::with_alpha(tk.warning, row_alpha * 0.75f),
			            7.f, 0, 1.5f * z);
		}
		if (is_rip_block) {
			float pulse = aida::ui::clock::pulse(1.4f, 0.55f, 1.f);
			dl->AddRect(tl, br,
			            aida::ui::with_alpha(tk.accent_u32, row_alpha * pulse),
			            7.f, 0, 2.f * z);
		}

		if (mm.hover > 0.001f) {
			ImU32 wash = aida::ui::with_alpha(tk.hover_wash, row_alpha * mm.hover);
			dl->AddRectFilled(ImVec2(tl.x + 1.f, tl.y + header_strip_h + 1.f),
			                  ImVec2(br.x - 1.f, br.y - 1.f), wash, 6.f);
		}

		if (blk.has_breakpoint) {
			dl->AddRectFilled(ImVec2(tl.x, tl.y + header_strip_h),
			                  ImVec2(tl.x + 3.f * z, br.y),
			                  aida::ui::with_alpha(tk.error, row_alpha));
		}

		int hovered_line_idx = -1;
		float body_top_y = tl.y + header_strip_h;
		float body_bottom_y = br.y - 1.f;

		{
			ImVec2 body_clip_a(tl.x + 1.f, tl.y + header_strip_h);
			ImVec2 body_clip_b(br.x - 1.f, br.y - 1.f);
			dl->PushClipRect(body_clip_a, body_clip_b, true);

			ImFont* node_font = aida::ui::fonts::code();
			if (!node_font) node_font = ImGui::GetFont();
			float base_font_size = aida::ui::fonts::size_or(node_font, ImGui::GetFontSize());
			if (base_font_size <= 0.f) base_font_size = 13.f;

			float raw_size = base_font_size * z;
			float node_font_size = raw_size;
			if (node_font_size < 7.5f) node_font_size = 7.5f;
			const float size_ratio = node_font_size / base_font_size;
			const bool  skip_text = raw_size < 3.f;

			const float scaled_line_h   = (base_font_size + 4.f) * size_ratio;
			const float scaled_padding  =  8.f * size_ratio;
			const float scaled_addr_col = n.addr_col_w * size_ratio;
			const float row_text_dy     = (scaled_line_h - node_font_size) * 0.5f;

			int sel_lo = -1, sel_hi = -1;
			if (g_state.text_sel_block == n.id
				&& g_state.text_sel_line_anchor >= 0
				&& g_state.text_sel_line_extent >= 0)
			{
				sel_lo = g_state.text_sel_line_anchor < g_state.text_sel_line_extent
					? g_state.text_sel_line_anchor : g_state.text_sel_line_extent;
				sel_hi = g_state.text_sel_line_anchor > g_state.text_sel_line_extent
					? g_state.text_sel_line_anchor : g_state.text_sel_line_extent;
			}

			const std::vector<function_index::injection_row_t>* injs = nullptr;
			if (blk.is_entry) {
				auto it_inj = model->entry_injections.find(n.id);
				if (it_inj != model->entry_injections.end() && !it_inj->second.empty())
					injs = &it_inj->second;
			}
			std::size_t inj_count = injs ? injs->size() : 0;

			float inj_y = body_top_y;
			for (std::size_t ii = 0; ii < inj_count; ++ii) {
				if (inj_y + scaled_line_h > br.y - 2.f) break;
				const auto& r = (*injs)[ii];
				float inj_text_y = inj_y + row_text_dy;
				if (!(inj_y + scaled_line_h < pos_y || inj_y > pos_y + height)) {
					if (!skip_text && r.kind != function_index::injection_t::spacer_line && !r.text.empty()) {
						if (r.kind == function_index::injection_t::proc_header
							|| r.kind == function_index::injection_t::proc_endp)
						{
							ImU32 name_base = disasm_theme::sub_label();
							symbol_classifier::kind_t sk = symbol_classifier::classify(r.addr);
							if (sk != symbol_classifier::kind_t::unknown)
								name_base = disasm_theme::color_for_kind(static_cast<int>(sk));
							const std::string& t = r.text;
							std::size_t name_end = 0;
							while (name_end < t.size()
								&& t[name_end] != ' ' && t[name_end] != '\t') ++name_end;
							std::string name_part = t.substr(0, name_end);
							std::string tail_part = t.substr(name_end);
							ImU32 name_col = aida::ui::with_alpha(name_base, row_alpha);
							dl->AddText(node_font, node_font_size,
								ImVec2(tl.x + scaled_padding, inj_text_y),
								name_col, name_part.c_str());
							if (!tail_part.empty()) {
								float name_w = node_font->CalcTextSizeA(node_font_size, FLT_MAX, 0.f,
									name_part.c_str()).x;
								ImU32 tail_col = aida::ui::with_alpha(
									disasm_theme::keyword(), row_alpha);
								dl->AddText(node_font, node_font_size,
									ImVec2(tl.x + scaled_padding + name_w, inj_text_y),
									tail_col, tail_part.c_str());
							}
						} else {
							ImU32 inj_col_base = detail::injection_color_for_kind(r.kind);
							ImU32 inj_col = aida::ui::with_alpha(inj_col_base, row_alpha);
							dl->AddText(node_font, node_font_size,
								ImVec2(tl.x + scaled_padding, inj_text_y),
								inj_col, r.text.c_str());
						}
					}
				}
				inj_y += scaled_line_h;
			}

			float instr_top_y = body_top_y + static_cast<float>(inj_count) * scaled_line_h;

			for (std::size_t li = 0; li < blk.instructions.size(); ++li) {
				const int line_index = static_cast<int>(li);
				auto& line = blk.instructions[li];
				float line_y = instr_top_y + scaled_line_h * static_cast<float>(li);
				float line_bottom = line_y + scaled_line_h;
				if (line_bottom > br.y - 2.f) break;
				if (line_y > pos_y + height) break;
				if (line_bottom < pos_y) continue;

				ImVec2 line_a(tl.x + 2.f, line_y);
				ImVec2 line_b(br.x - 2.f, line_bottom);

				if (block_hov && io.MousePos.x >= line_a.x && io.MousePos.x <= line_b.x
					&& io.MousePos.y >= line_a.y && io.MousePos.y <= line_b.y)
				{
					hovered_line_idx = line_index;
				}

				bool line_selected = sel_lo >= 0 && line_index >= sel_lo && line_index <= sel_hi;

				char addr_buf[24];
				snprintf(addr_buf, sizeof(addr_buf), "%llX", static_cast<unsigned long long>(line.addr));

				ImU32 addr_col = aida::ui::with_alpha(tk.text_address, row_alpha * 0.85f);

				if (line.addr == model->current_rip) {
					dl->AddRectFilled(line_a, line_b,
									  aida::ui::with_alpha(tk.accent_glow, row_alpha));
				}

				if (line_selected) {
					dl->AddRectFilled(line_a, line_b,
									  aida::ui::with_alpha(tk.accent_u32, row_alpha * 0.32f));
					dl->AddLine(ImVec2(line_a.x, line_a.y),
								ImVec2(line_a.x, line_b.y),
								aida::ui::with_alpha(tk.accent_u32, row_alpha), 1.5f);
				}

				if (!skip_text) {
					float text_y = line_y + row_text_dy;
					dl->AddText(node_font, node_font_size,
						ImVec2(tl.x + scaled_padding, text_y), addr_col, addr_buf);
					detail::render_colored_insn(dl,
						tl.x + scaled_padding + scaled_addr_col, text_y,
						line.text.c_str(), tk, row_alpha, br.x - scaled_padding,
						node_font, node_font_size);
				}
			}

			dl->PopClipRect();
		}

		if (block_hov) {
			bool in_body = io.MousePos.y >= body_top_y && io.MousePos.y <= body_bottom_y;

			if (ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
				g_state.selected_block = n.id;
				g_state.last_cursor_addr = blk.start_addr;
				if (in_body && hovered_line_idx >= 0) {
					if (static_cast<std::size_t>(hovered_line_idx) < blk.instructions.size())
					{
						g_state.last_cursor_addr = blk.instructions[static_cast<std::size_t>(hovered_line_idx)].addr;
					}
					g_state.text_sel_block = n.id;
					if (io.KeyShift && g_state.text_sel_block == n.id
						&& g_state.text_sel_line_anchor >= 0)
					{
						g_state.text_sel_line_extent = hovered_line_idx;
					} else {
						g_state.text_sel_line_anchor = hovered_line_idx;
						g_state.text_sel_line_extent = hovered_line_idx;
					}
					g_state.text_sel_dragging = true;
					int cur_frame = ImGui::GetFrameCount();
					if (g_state.sel_log_frame != cur_frame) {
						g_state.sel_log_frame = cur_frame;
						char log_buf[96];
						std::snprintf(log_buf, sizeof(log_buf),
							"[cfg] sel block=%d line=%d y=%.1f",
							n.id, hovered_line_idx, io.MousePos.y);
						diag::log_tagged("cfg_view", log_buf);
					}
				} else {
					g_state.text_sel_block = -1;
					g_state.text_sel_line_anchor = -1;
					g_state.text_sel_line_extent = -1;
					g_state.text_sel_dragging = false;
				}
				disasm_view::select_address(g_state.last_cursor_addr,
					disasm_view::capture_selected_workspace());
			}
			if (g_state.text_sel_dragging && g_state.text_sel_block == n.id
				&& ImGui::IsMouseDown(ImGuiMouseButton_Left)
				&& hovered_line_idx >= 0)
			{
				g_state.text_sel_line_extent = hovered_line_idx;
			}
			if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
				uint64_t go_addr = blk.start_addr;
				if (in_body && hovered_line_idx >= 0
					&& static_cast<std::size_t>(hovered_line_idx) < blk.instructions.size())
				{
					go_addr = blk.instructions[static_cast<std::size_t>(hovered_line_idx)].addr;
				}
				g_state.last_cursor_addr = go_addr;
				aida::ui::application_views::open_or_focus(
					aida::ui::stable_view_id_t("document.disassembly"));
				disasm_view::goto_address(go_addr, disasm_view::capture_selected_workspace());
			}
			if (ImGui::IsMouseClicked(ImGuiMouseButton_Right)
				&& in_body && hovered_line_idx >= 0)
			{
				g_state.text_ctx_block = n.id;
				g_state.text_ctx_line  = hovered_line_idx;
				if (g_state.text_sel_block != n.id
					|| g_state.text_sel_line_anchor < 0
					|| hovered_line_idx < (g_state.text_sel_line_anchor < g_state.text_sel_line_extent
						? g_state.text_sel_line_anchor : g_state.text_sel_line_extent)
					|| hovered_line_idx > (g_state.text_sel_line_anchor > g_state.text_sel_line_extent
						? g_state.text_sel_line_anchor : g_state.text_sel_line_extent))
				{
					g_state.text_sel_block = n.id;
					g_state.text_sel_line_anchor = hovered_line_idx;
					g_state.text_sel_line_extent = hovered_line_idx;
				}
				typed_context_requested = true;
			}
		}

		if (mm.entrance < 1.f) mm.entrance += dt * 3.5f;
		if (mm.entrance > 1.f) mm.entrance = 1.f;
	}

	if (g_state.text_sel_dragging && ImGui::IsMouseReleased(ImGuiMouseButton_Left)) {
		g_state.text_sel_dragging = false;
	}

	auto build_sel_text = [&](bool include_address) -> std::string {
		if (g_state.text_sel_block < 0
			|| g_state.text_sel_line_anchor < 0
			|| g_state.text_sel_line_extent < 0)
			return std::string();
		if (static_cast<std::size_t>(g_state.text_sel_block) >= model->blocks.size())
			return std::string();
		const auto& sblk = model->blocks[static_cast<std::size_t>(g_state.text_sel_block)];
		int lo = g_state.text_sel_line_anchor < g_state.text_sel_line_extent
			? g_state.text_sel_line_anchor : g_state.text_sel_line_extent;
		int hi = g_state.text_sel_line_anchor > g_state.text_sel_line_extent
			? g_state.text_sel_line_anchor : g_state.text_sel_line_extent;
		if (lo < 0) lo = 0;
		if (static_cast<std::size_t>(hi) >= sblk.instructions.size())
			hi = static_cast<int>(sblk.instructions.size()) - 1;
		std::string out;
		out.reserve(static_cast<std::size_t>(hi - lo + 1) * 64);
		char buf[256];
		for (int i = lo; i <= hi; ++i) {
			const auto& ln = sblk.instructions[static_cast<std::size_t>(i)];
			if (include_address) {
				snprintf(buf, sizeof(buf), ".text:%016llX  %s\n",
					static_cast<unsigned long long>(ln.addr), ln.text.c_str());
			} else {
				snprintf(buf, sizeof(buf), "%s\n", ln.text.c_str());
			}
			out += buf;
		}
		if (!out.empty() && out.back() == '\n') out.pop_back();
		return out;
	};
	aida::ui::analysis_context_menu::render();
	aida::ui::context_menu_open_origin_t legacy_graph_origin{};
	const bool legacy_pointer_context_requested = typed_context_requested;
	if (hovered && aida::ui::analysis_context_menu::keyboard_request(legacy_graph_origin))
		typed_context_requested = g_state.last_cursor_addr != 0;
	const auto make_legacy_graph_context = [&](int action_block) {
		using namespace aida::ui::analysis_context_menu;
		using aida::ui::action_handler_result_t;
		context_t menu;
		menu.kind = menu_kind_t::graph;
		menu.entity_id = "legacy-graph:" + std::to_string(g_state.selected_block) + ":" +
			std::to_string(g_state.last_cursor_addr) + ":" +
			std::to_string(g_state.text_sel_block) + ":" +
			std::to_string(g_state.text_sel_line_anchor) + ":" +
			std::to_string(g_state.text_sel_line_extent);
		menu.generation = model->generation;
		menu.live_generation = []() {
			const auto current = capture_model();
			return current ? current->generation : 0;
		};
		const auto address = g_state.last_cursor_addr;
		const auto selected_block = g_state.selected_block;
		const auto selection_block = g_state.text_sel_block;
		const auto selection_anchor = g_state.text_sel_line_anchor;
		const auto selection_extent = g_state.text_sel_line_extent;
		menu.validate_identity = [address, selected_block, selection_block,
			selection_anchor, selection_extent]() {
			return g_state.last_cursor_addr == address &&
				g_state.selected_block == selected_block &&
				g_state.text_sel_block == selection_block &&
				g_state.text_sel_line_anchor == selection_anchor &&
				g_state.text_sel_line_extent == selection_extent
				? aida::ui::capability_state_t::available()
				: aida::ui::capability_state_t::unavailable(
					"The selected graph entity changed");
		};
		menu.actions["analysis.navigate.disassembly"].invoke = [address]() {
			aida::ui::application_views::open_or_focus(
				aida::ui::stable_view_id_t("document.disassembly"));
			disasm_view::goto_address(address, disasm_view::capture_selected_workspace());
			return action_handler_result_t::completed();
		};
		char address_text[32]{};
		std::snprintf(address_text, sizeof(address_text), "%016llX",
			static_cast<unsigned long long>(address));
		menu.actions["analysis.copy.address"].invoke = [value = std::string(address_text)]() {
			ImGui::SetClipboardText(value.c_str());
			return action_handler_result_t::completed();
		};
		const auto text = build_sel_text(false);
		const auto addressed = build_sel_text(true);
		if (!text.empty()) {
			menu.actions["analysis.copy.block"].invoke = [text]() {
				ImGui::SetClipboardText(text.c_str());
				return action_handler_result_t::completed();
			};
			menu.actions["analysis.copy.block_addressed"].invoke = [addressed]() {
				ImGui::SetClipboardText(addressed.c_str());
				return action_handler_result_t::completed();
			};
		}
		menu.actions["analysis.graph.fit"].invoke = []() {
			g_state.fit_request = true;
			return action_handler_result_t::completed();
		};
		menu.actions["analysis.graph.zoom_in"].invoke = []() {
			g_state.target_zoom = (std::min)(5.0f, g_state.target_zoom * 1.18f);
			return action_handler_result_t::completed();
		};
		menu.actions["analysis.graph.zoom_out"].invoke = []() {
			g_state.target_zoom = (std::max)(0.1f, g_state.target_zoom * 0.85f);
			return action_handler_result_t::completed();
		};
		if (action_block >= 0 &&
			static_cast<std::size_t>(action_block) < model->blocks.size()) {
			const int context_block = action_block;
			menu.actions["analysis.graph.select_block"].invoke = [model, context_block]() {
				const auto& block = model->blocks[static_cast<std::size_t>(context_block)];
				g_state.text_sel_block = context_block;
				g_state.text_sel_line_anchor = 0;
				g_state.text_sel_line_extent = static_cast<int>(block.instructions.size()) - 1;
				return action_handler_result_t::completed();
			};
		}
		if (!text.empty()) {
			menu.actions["analysis.graph.clear_selection"].invoke = []() {
				g_state.text_sel_block = -1;
				g_state.text_sel_line_anchor = -1;
				g_state.text_sel_line_extent = -1;
				return action_handler_result_t::completed();
			};
		}
		return menu;
	};
	if (typed_context_requested) {
		const int action_block = g_state.text_ctx_block >= 0
			? g_state.text_ctx_block : g_state.selected_block;
		aida::ui::analysis_context_menu::open(
			make_legacy_graph_context(action_block), legacy_pointer_context_requested
				? aida::ui::context_menu_open_origin_t::pointer : legacy_graph_origin);
	}

	if (hovered && !io.WantTextInput && !io.WantCaptureKeyboard
		&& io.KeyCtrl && (ImGui::IsKeyPressed(ImGuiKey_C, false) ||
			ImGui::IsKeyPressed(ImGuiKey_Insert, false)))
	{
		if (!build_sel_text(true).empty())
			aida::ui::analysis_context_menu::execute_shortcut(
				make_legacy_graph_context(g_state.selected_block),
				"analysis.copy.block_addressed");
	}
	if (hovered && !io.WantTextInput && !io.WantCaptureKeyboard
		&& io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_A, false))
	{
		if (g_state.selected_block >= 0 &&
			static_cast<std::size_t>(g_state.selected_block) < model->blocks.size())
			aida::ui::analysis_context_menu::execute_shortcut(
				make_legacy_graph_context(g_state.selected_block),
				"analysis.graph.select_block");
	}
	if (!io.WantTextInput && !ImGui::IsAnyItemActive() &&
		!io.KeyCtrl && !io.KeyAlt && ImGui::IsKeyPressed(ImGuiKey_F, false))
		aida::ui::analysis_context_menu::execute_shortcut(
			make_legacy_graph_context(g_state.selected_block),
			"analysis.graph.fit");

	{
		float zoom_w = 220.f;
		float zoom_h = 32.f;
		float zx = pos_x + 14.f;
		float zy = pos_y + height - zoom_h - 14.f;
		ImVec2 za(zx, zy);
		ImVec2 zb(zx + zoom_w, zy + zoom_h);
		aida::ui::blur::render_drop_shadow(dl, za, zb, zoom_h * 0.5f, 4, 0.30f * alpha);
		aida::ui::blur::render_glass_fill(dl, za, zb, zoom_h * 0.5f, alpha);
		aida::ui::blur::render_glass_border(dl, za, zb, zoom_h * 0.5f, alpha);

		float btn_sz = zoom_h - 6.f;
		float by = zy + 3.f;

		float minus_x = zx + 4.f;
		ImVec2 minus_a(minus_x, by);
		ImVec2 minus_b(minus_x + btn_sz, by + btn_sz);
		bool minus_hov = ImGui::IsMouseHoveringRect(minus_a, minus_b, false);
		if (minus_hov) {
			dl->AddRectFilled(minus_a, minus_b,
			                  aida::ui::with_alpha(tk.hover_wash, alpha), btn_sz * 0.5f);
		}
		ImVec2 mc((minus_a.x + minus_b.x) * 0.5f, (minus_a.y + minus_b.y) * 0.5f);
		dl->AddLine(ImVec2(mc.x - 6.f, mc.y), ImVec2(mc.x + 6.f, mc.y),
		            minus_hov ? aida::ui::with_alpha(tk.accent_u32, alpha)
		                      : aida::ui::with_alpha(tk.text_secondary, alpha), 2.f);

		float text_box_w = 56.f;
		float plus_x = minus_b.x + text_box_w;
		ImVec2 plus_a(plus_x, by);
		ImVec2 plus_b(plus_x + btn_sz, by + btn_sz);
		bool plus_hov = ImGui::IsMouseHoveringRect(plus_a, plus_b, false);
		if (plus_hov) {
			dl->AddRectFilled(plus_a, plus_b,
			                  aida::ui::with_alpha(tk.hover_wash, alpha), btn_sz * 0.5f);
		}
		ImVec2 pc((plus_a.x + plus_b.x) * 0.5f, (plus_a.y + plus_b.y) * 0.5f);
		dl->AddLine(ImVec2(pc.x - 6.f, pc.y), ImVec2(pc.x + 6.f, pc.y),
		            plus_hov ? aida::ui::with_alpha(tk.accent_u32, alpha)
		                     : aida::ui::with_alpha(tk.text_secondary, alpha), 2.f);
		dl->AddLine(ImVec2(pc.x, pc.y - 6.f), ImVec2(pc.x, pc.y + 6.f),
		            plus_hov ? aida::ui::with_alpha(tk.accent_u32, alpha)
		                     : aida::ui::with_alpha(tk.text_secondary, alpha), 2.f);

		char zoom_buf[16];
		snprintf(zoom_buf, sizeof(zoom_buf), "%.0f%%", g_state.zoom * 100.f);
		ImVec2 zts = ImGui::CalcTextSize(zoom_buf);
		float zoom_text_x = (minus_b.x + plus_a.x - zts.x) * 0.5f;
		float zoom_text_y = zy + (zoom_h - zts.y) * 0.5f;
		dl->AddText(ImVec2(zoom_text_x, zoom_text_y),
		            aida::ui::with_alpha(tk.text_primary, alpha), zoom_buf);

		float sep_x = plus_b.x + 6.f;
		dl->AddLine(ImVec2(sep_x, zy + 6.f),
		            ImVec2(sep_x, zy + zoom_h - 6.f),
		            aida::ui::with_alpha(tk.border_subtle, alpha), 1.f);

		float fit_x = sep_x + 6.f;
		ImVec2 fit_a(fit_x, by);
		ImVec2 fit_b(fit_x + btn_sz, by + btn_sz);
		bool fit_hov = ImGui::IsMouseHoveringRect(fit_a, fit_b, false);
		if (fit_hov) {
			dl->AddRectFilled(fit_a, fit_b,
			                  aida::ui::with_alpha(tk.hover_wash, alpha), btn_sz * 0.5f);
		}
		{
			ImU32 fit_col = fit_hov ? aida::ui::with_alpha(tk.accent_u32, alpha)
			                        : aida::ui::with_alpha(tk.text_secondary, alpha);
			float fcx = (fit_a.x + fit_b.x) * 0.5f;
			float fcy = (fit_a.y + fit_b.y) * 0.5f;
			float rw = 12.f * 0.5f;
			float rh = 8.f * 0.5f;
			float tick = 3.f;
			ImVec2 r_tl(fcx - rw, fcy - rh);
			ImVec2 r_tr(fcx + rw, fcy - rh);
			ImVec2 r_bl(fcx - rw, fcy + rh);
			ImVec2 r_br(fcx + rw, fcy + rh);
			dl->AddLine(r_tl, ImVec2(r_tl.x + tick, r_tl.y), fit_col, 1.6f);
			dl->AddLine(r_tl, ImVec2(r_tl.x, r_tl.y + tick), fit_col, 1.6f);
			dl->AddLine(r_tr, ImVec2(r_tr.x - tick, r_tr.y), fit_col, 1.6f);
			dl->AddLine(r_tr, ImVec2(r_tr.x, r_tr.y + tick), fit_col, 1.6f);
			dl->AddLine(r_bl, ImVec2(r_bl.x + tick, r_bl.y), fit_col, 1.6f);
			dl->AddLine(r_bl, ImVec2(r_bl.x, r_bl.y - tick), fit_col, 1.6f);
			dl->AddLine(r_br, ImVec2(r_br.x - tick, r_br.y), fit_col, 1.6f);
			dl->AddLine(r_br, ImVec2(r_br.x, r_br.y - tick), fit_col, 1.6f);
		}

		float home_x = fit_b.x + 4.f;
		ImVec2 home_a(home_x, by);
		ImVec2 home_b(home_x + btn_sz, by + btn_sz);
		bool home_hov = ImGui::IsMouseHoveringRect(home_a, home_b, false);
		if (home_hov) {
			dl->AddRectFilled(home_a, home_b,
			                  aida::ui::with_alpha(tk.hover_wash, alpha), btn_sz * 0.5f);
		}
		{
			ImU32 home_col = home_hov ? aida::ui::with_alpha(tk.accent_u32, alpha)
			                          : aida::ui::with_alpha(tk.text_secondary, alpha);
			float hcx = (home_a.x + home_b.x) * 0.5f;
			float hcy = (home_a.y + home_b.y) * 0.5f;
			float arm = 7.f;
			dl->AddLine(ImVec2(hcx - arm, hcy), ImVec2(hcx + arm, hcy), home_col, 1.4f);
			dl->AddLine(ImVec2(hcx, hcy - arm), ImVec2(hcx, hcy + arm), home_col, 1.4f);
			dl->AddCircle(ImVec2(hcx, hcy), 4.f, home_col, 16, 1.4f);
			dl->AddCircleFilled(ImVec2(hcx, hcy), 1.6f, home_col, 8);
		}

		if (minus_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			g_state.target_zoom *= 0.85f;
			if (g_state.target_zoom < 0.1f) g_state.target_zoom = 0.1f;
		}
		if (plus_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			g_state.target_zoom *= 1.18f;
			if (g_state.target_zoom > 5.f) g_state.target_zoom = 5.f;
		}
		if (fit_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			g_state.fit_request = true;
		}
		if (home_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			if (model->entry_addr != 0) {
				for (std::size_t i = 0; i < model->blocks.size(); ++i) {
					const auto& block = model->blocks[i];
					if (model->entry_addr >= block.start_addr && model->entry_addr < block.end_addr) {
						const auto found = model->node_lookup.find(static_cast<int>(i));
						if (found != model->node_lookup.end() &&
							found->second < model->graph.nodes.size()) {
							const auto& nd = model->graph.nodes[found->second];
							g_state.target_pan_x = -nd.x;
							g_state.target_pan_y = -(nd.y + nd.height * 0.5f);
							g_state.selected_block = static_cast<int>(i);
						}
						break;
					}
				}
			}
		}
	}

	{
		float mw = 220.f;
		float mh = 140.f;
		float mx = pos_x + width - mw - 14.f;
		float my = pos_y + height - mh - 14.f;
		ImVec2 ma(mx, my);
		ImVec2 mb(mx + mw, my + mh);

		aida::ui::blur::render_drop_shadow(dl, ma, mb, 10.f, 4, 0.32f * alpha);
		aida::ui::blur::render_glass_fill(dl, ma, mb, 10.f, alpha);
		aida::ui::blur::render_glass_border(dl, ma, mb, 10.f, alpha);

		dl->PushClipRect(ma, mb, true);

		{
			const char* mm_label = "Overview";
			ImFont* cap = aida::ui::fonts::caption();
			float lbl_size = 10.f;
			dl->AddText(cap, lbl_size,
			            ImVec2(mx + 8.f, my + 4.f),
			            aida::ui::with_alpha(tk.text_dim, alpha),
			            mm_label);
		}

		float wmin_x, wmin_y, wmax_x, wmax_y;
		detail::compute_world_bounds(model->graph, wmin_x, wmin_y, wmax_x, wmax_y);
		float ww = wmax_x - wmin_x;
		float wh = wmax_y - wmin_y;
		if (ww < 1.f) ww = 1.f;
		if (wh < 1.f) wh = 1.f;

		float pad = 10.f;
		float top_pad = 18.f;
		float scale_x = (mw - pad * 2.f) / ww;
		float scale_y = (mh - top_pad - pad) / wh;
		float scale = scale_x < scale_y ? scale_x : scale_y;

		float ox = mx + pad + ((mw - pad * 2.f) - ww * scale) * 0.5f;
		float oy = my + top_pad + ((mh - top_pad - pad) - wh * scale) * 0.5f;

		auto wts = [&](float wx, float wy) -> ImVec2 {
			return ImVec2(ox + (wx - wmin_x) * scale,
			              oy + (wy - wmin_y) * scale);
		};

		for (std::size_t ni = 0; ni < model->graph.nodes.size(); ++ni) {
			const auto& n = model->graph.nodes[ni];
			if (n.id < 0 || static_cast<std::size_t>(n.id) >= model->blocks.size()) continue;
			const auto& blk = model->blocks[static_cast<std::size_t>(n.id)];

			ImVec2 t1 = wts(n.x - n.width * 0.5f, n.y);
			ImVec2 t2 = wts(n.x + n.width * 0.5f, n.y + n.height);

			ImU32 nc;
			if (model->current_rip >= blk.start_addr && model->current_rip < blk.end_addr)
				nc = aida::ui::with_alpha(tk.accent_u32, alpha);
			else if (blk.is_entry)
				nc = aida::ui::with_alpha(tk.accent_dim, alpha);
			else if (n.id == g_state.selected_block)
				nc = aida::ui::with_alpha(tk.accent_hover, alpha);
			else
				nc = aida::ui::with_alpha(tk.text_secondary, alpha * 0.6f);

			dl->AddRectFilled(t1, t2, nc, 1.5f);
		}

		float view_world_w = width / z;
		float view_world_h = height / z;
		float view_world_x = -g_state.pan_x - view_world_w * 0.5f;
		float view_world_y = -g_state.pan_y - view_world_h * 0.5f;

		ImVec2 v1 = wts(view_world_x, view_world_y);
		ImVec2 v2 = wts(view_world_x + view_world_w, view_world_y + view_world_h);
		dl->AddRect(v1, v2, aida::ui::with_alpha(tk.accent_u32, alpha), 2.f, 0, 1.5f);
		dl->AddRectFilled(v1, v2, aida::ui::with_alpha(tk.accent_glow, alpha * 0.7f), 2.f);

		{
			ImU32 br_col = aida::ui::with_alpha(tk.accent_hover, alpha);
			float bo = 2.f;
			float bl = 6.f;
			float bt = 1.5f;
			ImVec2 c_tl(v1.x - bo, v1.y - bo);
			ImVec2 c_tr(v2.x + bo, v1.y - bo);
			ImVec2 c_bl(v1.x - bo, v2.y + bo);
			ImVec2 c_br(v2.x + bo, v2.y + bo);
			dl->AddLine(c_tl, ImVec2(c_tl.x + bl, c_tl.y), br_col, bt);
			dl->AddLine(c_tl, ImVec2(c_tl.x, c_tl.y + bl), br_col, bt);
			dl->AddLine(c_tr, ImVec2(c_tr.x - bl, c_tr.y), br_col, bt);
			dl->AddLine(c_tr, ImVec2(c_tr.x, c_tr.y + bl), br_col, bt);
			dl->AddLine(c_bl, ImVec2(c_bl.x + bl, c_bl.y), br_col, bt);
			dl->AddLine(c_bl, ImVec2(c_bl.x, c_bl.y - bl), br_col, bt);
			dl->AddLine(c_br, ImVec2(c_br.x - bl, c_br.y), br_col, bt);
			dl->AddLine(c_br, ImVec2(c_br.x, c_br.y - bl), br_col, bt);
		}

		dl->PopClipRect();

		bool minimap_hov = ImGui::IsMouseHoveringRect(ma, mb, false);
		if (minimap_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
			g_state.minimap_dragging = true;
		if (g_state.minimap_dragging) {
			if (ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
				ImVec2 mp = ImGui::GetMousePos();
				float wx = wmin_x + (mp.x - ox) / scale;
				float wy = wmin_y + (mp.y - oy) / scale;
				g_state.target_pan_x = -wx;
				g_state.target_pan_y = -wy;
			} else {
				g_state.minimap_dragging = false;
			}
		}
	}

	dl->PopClipRect();
}

struct workspace_graph_block_key_t {
	std::uint8_t function_space = 0;
	std::uint64_t function_value = 0;
	std::uint8_t block_space = 0;
	std::uint64_t block_value = 0;

	friend bool operator==(const workspace_graph_block_key_t& left,
		const workspace_graph_block_key_t& right) noexcept
	{
		return left.function_space == right.function_space &&
			left.function_value == right.function_value &&
			left.block_space == right.block_space &&
			left.block_value == right.block_value;
	}
};

struct workspace_graph_block_key_hash_t {
	std::size_t operator()(const workspace_graph_block_key_t& value) const noexcept
	{
		std::uint64_t hash = value.function_value;
		hash ^= value.block_value + 0x9E3779B97F4A7C15ull + (hash << 6u) + (hash >> 2u);
		hash ^= static_cast<std::uint64_t>(value.function_space) << 56u;
		hash ^= static_cast<std::uint64_t>(value.block_space) << 48u;
		return static_cast<std::size_t>(hash ^ (hash >> 32u));
	}
};

struct workspace_graph_layout_key_t {
	std::uint8_t function_space = 0;
	std::uint64_t function_value = 0;
	std::uint8_t page_space = 0;
	std::uint64_t page_value = 0;

	friend bool operator==(const workspace_graph_layout_key_t& left,
		const workspace_graph_layout_key_t& right) noexcept
	{
		return left.function_space == right.function_space &&
			left.function_value == right.function_value &&
			left.page_space == right.page_space &&
			left.page_value == right.page_value;
	}

	friend bool operator!=(const workspace_graph_layout_key_t& left,
		const workspace_graph_layout_key_t& right) noexcept
	{
		return !(left == right);
	}
};

struct workspace_graph_layout_key_hash_t {
	std::size_t operator()(const workspace_graph_layout_key_t& value) const noexcept
	{
		std::uint64_t hash = value.function_value;
		hash ^= value.page_value + 0x9E3779B97F4A7C15ull + (hash << 6u) + (hash >> 2u);
		hash ^= static_cast<std::uint64_t>(value.function_space) << 56u;
		hash ^= static_cast<std::uint64_t>(value.page_space) << 48u;
		return static_cast<std::size_t>(hash ^ (hash >> 32u));
	}
};

struct workspace_graph_layout_node_key_t {
	workspace_graph_layout_key_t layout;
	workspace_graph_block_key_t block;

	friend bool operator==(const workspace_graph_layout_node_key_t& left,
		const workspace_graph_layout_node_key_t& right) noexcept
	{
		return left.layout == right.layout && left.block == right.block;
	}
};

struct workspace_graph_layout_node_key_hash_t {
	std::size_t operator()(const workspace_graph_layout_node_key_t& value) const noexcept
	{
		const auto left = workspace_graph_layout_key_hash_t{}(value.layout);
		const auto right = workspace_graph_block_key_hash_t{}(value.block);
		return left ^ (right + static_cast<std::size_t>(0x9E3779B97F4A7C15ull) +
			(left << 6u) + (left >> 2u));
	}
};

struct workspace_graph_edge_key_t {
	aida::analysis::entity_id_t source = 0;
	aida::analysis::entity_id_t target = 0;
	aida::analysis::edge_kind_t kind = aida::analysis::edge_kind_t::fallthrough;

	friend bool operator==(const workspace_graph_edge_key_t& left,
		const workspace_graph_edge_key_t& right) noexcept
	{
		return left.source == right.source && left.target == right.target &&
			left.kind == right.kind;
	}
};

struct workspace_graph_edge_key_hash_t {
	std::size_t operator()(const workspace_graph_edge_key_t& value) const noexcept
	{
		std::uint64_t hash = value.source;
		hash ^= value.target + 0x9E3779B97F4A7C15ull + (hash << 6u) + (hash >> 2u);
		hash ^= static_cast<std::uint64_t>(value.kind) << 56u;
		return static_cast<std::size_t>(hash ^ (hash >> 32u));
	}
};

inline workspace_graph_block_key_t workspace_graph_block_key(
	const aida::analysis::function_record_t& function,
	const aida::analysis::basic_block_record_t& block) noexcept
{
	return {static_cast<std::uint8_t>(function.start.space), function.start.value,
		static_cast<std::uint8_t>(block.start.space), block.start.value};
}

inline workspace_graph_layout_key_t workspace_graph_layout_key(
	const aida::analysis::function_record_t& function,
	const aida::analysis::basic_block_record_t& page_anchor) noexcept
{
	return {static_cast<std::uint8_t>(function.start.space), function.start.value,
		static_cast<std::uint8_t>(page_anchor.start.space), page_anchor.start.value};
}

struct workspace_graph_view_state_t {
	std::size_t block_page = 0;
	float pan_x = 0.0f;
	float pan_y = 0.0f;
	float zoom = 1.0f;
	float target_zoom = 1.0f;
	bool fit_request = true;
	bool minimap_dragging = false;
	std::uint64_t layout_signature = 0;
	cfg_layout::graph_t layout;
	std::vector<std::size_t> block_indices;
	struct edge_t {
		int from = 0;
		int to = 0;
		aida::analysis::edge_kind_t kind = aida::analysis::edge_kind_t::fallthrough;
	};
	std::vector<edge_t> edges;
	bool edge_set_truncated = false;
	std::vector<int> outgoing;
	std::unordered_map<aida::analysis::entity_id_t, std::size_t> node_by_entity;
	std::unordered_map<aida::analysis::entity_id_t,
		std::vector<aida::analysis::entity_id_t>> successors;
	std::unordered_map<aida::analysis::entity_id_t,
		std::vector<aida::analysis::entity_id_t>> predecessors;
	std::unordered_map<aida::analysis::entity_id_t, std::size_t> page_block_by_entity;
	std::optional<aida::analysis::entity_id_t> selected_block;
	std::optional<aida::analysis::entity_id_t> selected_instruction;
	std::uint64_t selected_address = 0;
	std::unordered_set<workspace_graph_block_key_t, workspace_graph_block_key_hash_t>
		collapsed_reachable_roots;
	std::unordered_map<workspace_graph_block_key_t, ImVec2,
		workspace_graph_block_key_hash_t> pinned_node_positions;
	std::unordered_set<workspace_graph_layout_key_t, workspace_graph_layout_key_hash_t>
		pinned_layouts;
	std::unordered_map<workspace_graph_layout_node_key_t, ImVec2,
		workspace_graph_layout_node_key_hash_t> pinned_layout_positions;
	std::optional<workspace_graph_layout_key_t> current_layout;
	bool persisted_state_dirty = false;
	std::uint32_t persisted_state_version = 3;
};

inline constexpr std::size_t k_workspace_graph_persisted_entry_limit = 32;
inline constexpr std::size_t k_workspace_graph_persisted_item_limit = 256;
inline constexpr std::size_t k_workspace_graph_edge_candidate_limit = 65536;
inline constexpr std::size_t k_workspace_graph_edge_limit = 4096;

inline void workspace_graph_load_persisted(const disasm_view::workspace_context_t& context,
	workspace_graph_view_state_t& view)
{
	if (!context.workspace || g_sa_settings.workspace.graph_state_json.empty())
		return;
	const auto root = nlohmann::json::parse(g_sa_settings.workspace.graph_state_json,
		nullptr, false);
	const auto version = root.is_object() ? root.find("version") : root.end();
	const auto entries = root.is_object() ? root.find("entries") : root.end();
	const std::uint64_t root_version = version != root.end() && version->is_number_unsigned()
		? version->get<std::uint64_t>() : 0U;
	if (root.is_discarded() || !root.is_object() || version == root.end() ||
		!version->is_number_unsigned() || (root_version != 2U && root_version != 3U) ||
		entries == root.end() || !entries->is_array()) {
		view.persisted_state_version = 0;
		return;
	}
	const std::string binary_id = context.workspace->identity().binary_id().to_hex();
	std::size_t inspected_entries = 0;
	for (const auto& entry : *entries) {
		if (inspected_entries++ >= k_workspace_graph_persisted_entry_limit)
			break;
		const auto entry_binary = entry.is_object() ? entry.find("binary_id") : entry.end();
		if (!entry.is_object() || entry_binary == entry.end() ||
			!entry_binary->is_string() || entry_binary->get<std::string>() != binary_id)
			continue;
		const auto entry_version = entry.find("version");
		const std::uint64_t entry_version_value = entry_version != entry.end() &&
			entry_version->is_number_unsigned()
			? entry_version->get<std::uint64_t>() : 0U;
		if ((entry_version_value != 2U && entry_version_value != 3U) ||
			entry_version_value != root_version) {
			view.persisted_state_version = 0;
			return;
		}
		view.persisted_state_version = static_cast<std::uint32_t>(entry_version_value);
		view.persisted_state_dirty = view.persisted_state_version == 2U;
		if (entry.contains("collapsed") && entry["collapsed"].is_array()) {
			std::size_t inspected_collapsed = 0;
			for (const auto& value : entry["collapsed"]) {
				if (inspected_collapsed++ >= k_workspace_graph_persisted_item_limit)
					break;
				if (!value.is_object())
					continue;
				const auto function_space = value.find("function_space");
				const auto function_value = value.find("function_value");
				const auto block_space = value.find("block_space");
				const auto block_value = value.find("block_value");
				if (function_space == value.end() || function_value == value.end() ||
					block_space == value.end() || block_value == value.end() ||
					!function_space->is_number_unsigned() ||
					function_space->get<std::uint64_t>() > 3U ||
					!function_value->is_number_unsigned() ||
					!block_space->is_number_unsigned() ||
					block_space->get<std::uint64_t>() > 3U ||
					!block_value->is_number_unsigned())
					continue;
				view.collapsed_reachable_roots.insert({
					static_cast<std::uint8_t>(function_space->get<std::uint64_t>()),
					function_value->get<std::uint64_t>(),
					static_cast<std::uint8_t>(block_space->get<std::uint64_t>()),
					block_value->get<std::uint64_t>()});
			}
		}
		if (entry.contains("pins") && entry["pins"].is_array()) {
			std::size_t inspected_pins = 0;
			for (const auto& pin : entry["pins"]) {
				if (inspected_pins++ >= k_workspace_graph_persisted_item_limit)
					break;
				if (!pin.is_object())
					continue;
				const auto function_space = pin.find("function_space");
				const auto function_value = pin.find("function_value");
				const auto block_space = pin.find("block_space");
				const auto block_value = pin.find("block_value");
				const auto x_value = pin.find("x");
				const auto y_value = pin.find("y");
				if (function_space == pin.end() || function_value == pin.end() ||
					block_space == pin.end() || block_value == pin.end() ||
					x_value == pin.end() || y_value == pin.end() ||
					!function_space->is_number_unsigned() ||
					function_space->get<std::uint64_t>() > 3U ||
					!function_value->is_number_unsigned() ||
					!block_space->is_number_unsigned() ||
					block_space->get<std::uint64_t>() > 3U ||
					!block_value->is_number_unsigned() ||
					!x_value->is_number() || !y_value->is_number())
					continue;
				const float x = x_value->get<float>();
				const float y = y_value->get<float>();
				if (!std::isfinite(x) || !std::isfinite(y) ||
					std::abs(x) > 1000000.0f || std::abs(y) > 1000000.0f)
					continue;
				view.pinned_node_positions.emplace(workspace_graph_block_key_t{
					static_cast<std::uint8_t>(function_space->get<std::uint64_t>()),
					function_value->get<std::uint64_t>(),
					static_cast<std::uint8_t>(block_space->get<std::uint64_t>()),
					block_value->get<std::uint64_t>()}, ImVec2(x, y));
			}
		}
		if (view.persisted_state_version == 3U && entry.contains("layout_pins") &&
			entry["layout_pins"].is_array()) {
			std::size_t inspected_layout_pins = 0;
			for (const auto& pin : entry["layout_pins"]) {
				if (inspected_layout_pins++ >= k_workspace_graph_persisted_item_limit)
					break;
				if (!pin.is_object())
					continue;
				const auto fs = pin.find("function_space");
				const auto fv = pin.find("function_value");
				const auto ps = pin.find("page_space");
				const auto pv = pin.find("page_value");
				const auto bs = pin.find("block_space");
				const auto bv = pin.find("block_value");
				const auto x = pin.find("x");
				const auto y = pin.find("y");
				if (fs == pin.end() || fv == pin.end() || ps == pin.end() ||
					pv == pin.end() || bs == pin.end() || bv == pin.end() ||
					x == pin.end() || y == pin.end() || !fs->is_number_unsigned() ||
					fs->get<std::uint64_t>() > 3U || !fv->is_number_unsigned() ||
					!ps->is_number_unsigned() || ps->get<std::uint64_t>() > 3U ||
					!pv->is_number_unsigned() || !bs->is_number_unsigned() ||
					bs->get<std::uint64_t>() > 3U || !bv->is_number_unsigned() ||
					!x->is_number() || !y->is_number())
					continue;
				const float px = x->get<float>();
				const float py = y->get<float>();
				if (!std::isfinite(px) || !std::isfinite(py) ||
					std::abs(px) > 1000000.0f || std::abs(py) > 1000000.0f)
					continue;
				workspace_graph_layout_node_key_t key{{
					static_cast<std::uint8_t>(fs->get<std::uint64_t>()),
					fv->get<std::uint64_t>(),
					static_cast<std::uint8_t>(ps->get<std::uint64_t>()),
					pv->get<std::uint64_t>()}, {
					static_cast<std::uint8_t>(fs->get<std::uint64_t>()),
					fv->get<std::uint64_t>(),
					static_cast<std::uint8_t>(bs->get<std::uint64_t>()),
					bv->get<std::uint64_t>()}};
				view.pinned_layouts.insert(key.layout);
				view.pinned_layout_positions.emplace(key, ImVec2(px, py));
			}
		}
		view.fit_request = view.pinned_layouts.empty();
		return;
	}
	if (root_version == 2U) {
		view.persisted_state_version = 2;
		view.persisted_state_dirty = true;
	}
}

inline bool workspace_graph_save_persisted(const disasm_view::workspace_context_t& context,
	const workspace_graph_view_state_t& view)
{
	if (!context.workspace ||
		view.collapsed_reachable_roots.size() > k_workspace_graph_persisted_item_limit ||
		view.pinned_node_positions.size() > k_workspace_graph_persisted_item_limit ||
		view.pinned_layout_positions.size() > k_workspace_graph_persisted_item_limit ||
		view.pinned_layouts.size() > k_workspace_graph_persisted_item_limit)
		return false;
	nlohmann::json root = nlohmann::json::parse(g_sa_settings.workspace.graph_state_json,
		nullptr, false);
	const auto version = root.is_object() ? root.find("version") : root.end();
	const std::uint64_t root_version = version != root.end() && version->is_number_unsigned()
		? version->get<std::uint64_t>() : 0U;
	if (root.is_discarded() || !root.is_object() || version == root.end() ||
		!version->is_number_unsigned() || (root_version != 2U && root_version != 3U))
		root = nlohmann::json{{"version", 3U}, {"entries", nlohmann::json::array()}};
	else if (root_version == 2U) {
		root["version"] = 3U;
		if (root.contains("entries") && root["entries"].is_array()) {
			for (auto& entry : root["entries"]) {
				if (!entry.is_object())
					continue;
				entry["version"] = 3U;
				entry.erase("layout_pinned");
				entry["layout_pins"] = nlohmann::json::array();
			}
		}
	}
	if (!root.contains("entries") || !root["entries"].is_array())
		root["entries"] = nlohmann::json::array();
	const std::string binary_id = context.workspace->identity().binary_id().to_hex();
	auto& entries = root["entries"];
	for (auto iterator = entries.begin(); iterator != entries.end();) {
		const auto entry_binary = iterator->is_object()
			? iterator->find("binary_id") : iterator->end();
		if (!iterator->is_object() || entry_binary == iterator->end() ||
			!entry_binary->is_string() || entry_binary->get<std::string>() == binary_id)
			iterator = entries.erase(iterator);
		else
			++iterator;
	}
	nlohmann::json collapsed = nlohmann::json::array();
	for (const auto& key : view.collapsed_reachable_roots)
		collapsed.push_back({{"function_space", key.function_space},
			{"function_value", key.function_value}, {"block_space", key.block_space},
			{"block_value", key.block_value}});
	nlohmann::json pins = nlohmann::json::array();
	for (const auto& item : view.pinned_node_positions)
		pins.push_back({{"function_space", item.first.function_space},
			{"function_value", item.first.function_value},
			{"block_space", item.first.block_space}, {"block_value", item.first.block_value},
			{"x", item.second.x}, {"y", item.second.y}});
	nlohmann::json layout_pins = nlohmann::json::array();
	for (const auto& item : view.pinned_layout_positions)
		layout_pins.push_back({{"function_space", item.first.layout.function_space},
			{"function_value", item.first.layout.function_value},
			{"page_space", item.first.layout.page_space},
			{"page_value", item.first.layout.page_value},
			{"block_space", item.first.block.block_space},
			{"block_value", item.first.block.block_value},
			{"x", item.second.x}, {"y", item.second.y}});
	entries.insert(entries.begin(), nlohmann::json{{"version", 3U},
		{"binary_id", binary_id},
		{"collapsed", std::move(collapsed)}, {"pins", std::move(pins)}});
	entries.front()["layout_pins"] = std::move(layout_pins);
	while (entries.size() > k_workspace_graph_persisted_entry_limit)
		entries.erase(entries.end() - 1);
	const std::string encoded = root.dump();
	if (encoded.size() > 256U * 1024U)
		return false;
	const std::string previous = g_sa_settings.workspace.graph_state_json;
	g_sa_settings.workspace.graph_state_json = encoded;
	if (aida::settings_persistence::accepted(
			aida::settings_persistence::request_save(g_sa_settings)))
		return true;
	g_sa_settings.workspace.graph_state_json = previous;
	return false;
}

template <typename Mutator>
inline aida::ui::action_handler_result_t workspace_graph_persist_mutation(
	const disasm_view::workspace_context_t& context,
	const std::shared_ptr<workspace_graph_view_state_t>& view, Mutator&& mutator)
{
	const auto old_collapsed = view->collapsed_reachable_roots;
	const auto old_positions = view->pinned_node_positions;
	const auto old_pinned_layouts = view->pinned_layouts;
	const auto old_layout_positions = view->pinned_layout_positions;
	const auto old_signature = view->layout_signature;
	mutator();
	if (workspace_graph_save_persisted(context, *view))
		return aida::ui::action_handler_result_t::completed();
	view->collapsed_reachable_roots = old_collapsed;
	view->pinned_node_positions = old_positions;
	view->pinned_layouts = old_pinned_layouts;
	view->pinned_layout_positions = old_layout_positions;
	view->layout_signature = old_signature;
	return aida::ui::action_handler_result_t::failed(
		"Graph state persistence rejected the update");
}

inline std::mutex& workspace_graph_registry_mutex()
{
	static std::mutex value;
	return value;
}

struct workspace_graph_registry_entry_t {
	std::shared_ptr<workspace_graph_view_state_t> view;
	std::uint64_t access = 0;
};

inline std::unordered_map<aida::analysis::binary_id_t,
	workspace_graph_registry_entry_t,
	aida::analysis::binary_id_hash_t>& workspace_graph_registry()
{
	static std::unordered_map<aida::analysis::binary_id_t,
		workspace_graph_registry_entry_t,
		aida::analysis::binary_id_hash_t> value;
	return value;
}

inline std::uint64_t& workspace_graph_registry_clock()
{
	static std::uint64_t value = 0;
	return value;
}

inline std::shared_ptr<workspace_graph_view_state_t> workspace_graph_state(
	const disasm_view::workspace_context_t& context)
{
	if (!context.workspace)
		return {};
	std::lock_guard<std::mutex> lock(workspace_graph_registry_mutex());
	auto& registry = workspace_graph_registry();
	const auto id = context.workspace->identity().binary_id();
	auto found = registry.find(id);
	if (found != registry.end()) {
		found->second.access = ++workspace_graph_registry_clock();
		return found->second.view;
	}
	if (registry.size() >= k_workspace_graph_persisted_entry_limit) {
		const auto oldest = std::min_element(registry.begin(), registry.end(),
			[](const auto& left, const auto& right) {
				return left.second.access < right.second.access;
			});
		if (oldest != registry.end())
			registry.erase(oldest);
	}
	auto created = std::make_shared<workspace_graph_view_state_t>();
	workspace_graph_load_persisted(context, *created);
	registry.emplace(id, workspace_graph_registry_entry_t{
		created, ++workspace_graph_registry_clock()});
	return created;
}

inline const aida::analysis::function_record_t* workspace_graph_function(
	const disasm_view::workspace_context_t& context)
{
	if (!context.publication || !context.publication->snapshot ||
		context.publication->snapshot->functions.empty())
		return nullptr;
	const auto& functions = context.publication->snapshot->functions;
	const auto selection = context.workspace->view_state().selection;
	if (!selection)
		return &functions.front();
	auto found = std::upper_bound(functions.begin(), functions.end(), *selection,
		[](const aida::analysis::address_t& address,
		   const aida::analysis::function_record_t& function) {
			return address < function.start;
		});
	if (found == functions.begin())
		return &functions.front();
	--found;
	if (found->start.space == selection->space &&
		selection->value >= found->start.value && selection->value < found->end.value)
		return &*found;
	return &functions.front();
}

inline std::uint64_t workspace_graph_generation(
	const disasm_view::workspace_context_t& context)
{
	const auto generation = context.workspace->generation();
	const auto revision = context.workspace->analysis_revision();
	return generation ^ (revision + 0x9E3779B97F4A7C15ull +
		(generation << 6u) + (generation >> 2u));
}

inline std::uint64_t workspace_graph_layout_signature(
	const disasm_view::workspace_context_t& context,
	const aida::analysis::function_record_t& function,
	std::size_t page)
{
	std::uint64_t value = workspace_graph_generation(context);
	value ^= function.id + 0x9E3779B97F4A7C15ull + (value << 6u) + (value >> 2u);
	value ^= static_cast<std::uint64_t>(page) + 0x9E3779B97F4A7C15ull +
		(value << 6u) + (value >> 2u);
	return value == 0 ? 1 : value;
}

inline std::uint64_t workspace_graph_evidence_hash(const std::string& value)
{
	std::uint64_t hash = 1469598103934665603ull;
	for (const char character : value) {
		hash ^= static_cast<unsigned char>(character);
		hash *= 1099511628211ull;
	}
	return hash == 0 ? 1 : hash;
}

inline bool workspace_graph_cfg_edge_kind(aida::analysis::edge_kind_t kind) noexcept
{
	switch (kind) {
	case aida::analysis::edge_kind_t::fallthrough:
	case aida::analysis::edge_kind_t::conditional_taken:
	case aida::analysis::edge_kind_t::unconditional:
	case aida::analysis::edge_kind_t::exception_edge:
	case aida::analysis::edge_kind_t::indirect:
		return true;
	case aida::analysis::edge_kind_t::call:
	case aida::analysis::edge_kind_t::tail_call:
	case aida::analysis::edge_kind_t::return_edge:
		return false;
	}
	return false;
}

inline const char* workspace_graph_edge_label(aida::analysis::edge_kind_t kind,
	bool branching)
{
	switch (kind) {
	case aida::analysis::edge_kind_t::fallthrough: return branching ? "F" : nullptr;
	case aida::analysis::edge_kind_t::conditional_taken: return "T";
	case aida::analysis::edge_kind_t::unconditional: return "J";
	case aida::analysis::edge_kind_t::call: return "CALL";
	case aida::analysis::edge_kind_t::tail_call: return "TAIL";
	case aida::analysis::edge_kind_t::return_edge: return "RET";
	case aida::analysis::edge_kind_t::exception_edge: return "EX";
	case aida::analysis::edge_kind_t::indirect: return "IND";
	}
	return nullptr;
}

inline ImU32 workspace_graph_edge_color(aida::analysis::edge_kind_t kind,
	const aida::ui::theme_t& theme, float alpha, bool branching = false)
{
	ImU32 color = theme.text_secondary;
	switch (kind) {
	case aida::analysis::edge_kind_t::fallthrough:
		color = branching ? theme.error : theme.text_secondary;
		break;
	case aida::analysis::edge_kind_t::conditional_taken: color = theme.success; break;
	case aida::analysis::edge_kind_t::unconditional: color = theme.info; break;
	case aida::analysis::edge_kind_t::call: color = theme.accent_hover; break;
	case aida::analysis::edge_kind_t::tail_call: color = theme.warning; break;
	case aida::analysis::edge_kind_t::return_edge: color = theme.error; break;
	case aida::analysis::edge_kind_t::exception_edge: color = theme.warning; break;
	case aida::analysis::edge_kind_t::indirect: color = theme.syn_keyword; break;
	}
	return aida::ui::with_alpha(color, alpha);
}

inline bool workspace_graph_contains_block_key(
	const aida::analysis::analysis_snapshot_t& snapshot,
	const workspace_graph_block_key_t& key)
{
	const auto function = std::lower_bound(snapshot.functions.begin(), snapshot.functions.end(), key,
		[](const aida::analysis::function_record_t& candidate,
		   const workspace_graph_block_key_t& value) {
			const auto space = static_cast<std::uint8_t>(candidate.start.space);
			return space < value.function_space ||
				(space == value.function_space && candidate.start.value < value.function_value);
		});
	if (function == snapshot.functions.end() ||
		static_cast<std::uint8_t>(function->start.space) != key.function_space ||
		function->start.value != key.function_value)
		return false;
	const std::size_t begin = function->first_block;
	if (begin > snapshot.blocks.size())
		return false;
	const std::size_t available = begin <= snapshot.blocks.size()
		? snapshot.blocks.size() - begin : 0;
	const std::size_t count = (std::min)(
		static_cast<std::size_t>(function->block_count), available);
	const auto first = snapshot.blocks.begin() + static_cast<std::ptrdiff_t>(begin);
	const auto last = first + static_cast<std::ptrdiff_t>(count);
	const auto block = std::lower_bound(first, last, key,
		[](const aida::analysis::basic_block_record_t& candidate,
		   const workspace_graph_block_key_t& value) {
			const auto space = static_cast<std::uint8_t>(candidate.start.space);
			return space < value.block_space ||
				(space == value.block_space && candidate.start.value < value.block_value);
		});
	return block != last && block->function_id == function->id &&
		static_cast<std::uint8_t>(block->start.space) == key.block_space &&
		block->start.value == key.block_value;
}

inline bool workspace_graph_contains_layout_key(
	const aida::analysis::analysis_snapshot_t& snapshot,
	const workspace_graph_layout_key_t& key)
{
	return workspace_graph_contains_block_key(snapshot, {
		key.function_space, key.function_value, key.page_space, key.page_value});
}

inline void workspace_graph_rebuild_layout(
	workspace_graph_view_state_t& view,
	const disasm_view::workspace_context_t& context,
	const aida::analysis::function_record_t& function,
	std::size_t page_begin, std::size_t page_end)
{
	const auto& snapshot = *context.publication->snapshot;
	const auto old_collapsed = view.collapsed_reachable_roots;
	const auto old_positions = view.pinned_node_positions;
	const auto old_pinned_layouts = view.pinned_layouts;
	const auto old_layout_positions = view.pinned_layout_positions;
	const auto old_persisted_version = view.persisted_state_version;
	bool persisted_state_changed = view.persisted_state_dirty;
	if (view.persisted_state_version != 3) {
		if (view.persisted_state_version != 2) {
			view.collapsed_reachable_roots.clear();
			view.pinned_node_positions.clear();
		}
		view.pinned_layouts.clear();
		view.pinned_layout_positions.clear();
		view.persisted_state_version = 3;
		persisted_state_changed = true;
	}
	std::unordered_set<workspace_graph_block_key_t, workspace_graph_block_key_hash_t>
		persisted_keys;
	persisted_keys.reserve(view.collapsed_reachable_roots.size() +
		view.pinned_node_positions.size());
	for (const auto& key : view.collapsed_reachable_roots) persisted_keys.insert(key);
	for (const auto& item : view.pinned_node_positions) persisted_keys.insert(item.first);
	for (const auto& item : view.pinned_layout_positions) persisted_keys.insert(item.first.block);
	std::unordered_set<workspace_graph_layout_key_t, workspace_graph_layout_key_hash_t>
		valid_layout_keys;
	valid_layout_keys.reserve(view.pinned_layouts.size());
	std::unordered_set<workspace_graph_block_key_t, workspace_graph_block_key_hash_t>
		valid_persisted_keys;
	valid_persisted_keys.reserve(persisted_keys.size());
	for (const auto& key : persisted_keys)
		if (workspace_graph_contains_block_key(snapshot, key))
			valid_persisted_keys.insert(key);
	for (const auto& key : view.pinned_layouts)
		if (workspace_graph_contains_layout_key(snapshot, key))
			valid_layout_keys.insert(key);
	for (auto iterator = view.collapsed_reachable_roots.begin();
		iterator != view.collapsed_reachable_roots.end();) {
		if (valid_persisted_keys.count(*iterator) == 0) {
			iterator = view.collapsed_reachable_roots.erase(iterator);
			persisted_state_changed = true;
		}
		else ++iterator;
	}
	for (auto iterator = view.pinned_node_positions.begin();
		iterator != view.pinned_node_positions.end();) {
		if (valid_persisted_keys.count(iterator->first) == 0) {
			iterator = view.pinned_node_positions.erase(iterator);
			persisted_state_changed = true;
		}
		else ++iterator;
	}
	for (auto iterator = view.pinned_layouts.begin(); iterator != view.pinned_layouts.end();) {
		if (valid_layout_keys.count(*iterator) == 0) {
			iterator = view.pinned_layouts.erase(iterator);
			persisted_state_changed = true;
		} else ++iterator;
	}
	for (auto iterator = view.pinned_layout_positions.begin();
		iterator != view.pinned_layout_positions.end();) {
		if (valid_layout_keys.count(iterator->first.layout) == 0 ||
			valid_persisted_keys.count(iterator->first.block) == 0) {
			iterator = view.pinned_layout_positions.erase(iterator);
			persisted_state_changed = true;
		} else ++iterator;
	}
	if (persisted_state_changed && !workspace_graph_save_persisted(context, view)) {
		view.collapsed_reachable_roots = old_collapsed;
		view.pinned_node_positions = old_positions;
		view.pinned_layouts = old_pinned_layouts;
		view.pinned_layout_positions = old_layout_positions;
		view.persisted_state_version = old_persisted_version;
		view.persisted_state_dirty = true;
		view.layout_signature = 0;
	} else if (persisted_state_changed) {
		view.persisted_state_dirty = false;
	}
	view.layout = {};
	view.block_indices.clear();
	view.edges.clear();
	view.edge_set_truncated = false;
	view.outgoing.clear();
	view.node_by_entity.clear();
	view.successors.clear();
	view.predecessors.clear();
	view.page_block_by_entity.clear();
	view.block_indices.reserve(page_end - page_begin);
	view.layout.nodes.reserve(page_end - page_begin);
	std::vector<std::size_t> page_block_indices;
	page_block_indices.reserve(page_end - page_begin);
	std::unordered_set<aida::analysis::entity_id_t> page_block_ids;
	page_block_ids.reserve(page_end - page_begin);
	std::unordered_map<aida::analysis::entity_id_t, workspace_graph_block_key_t>
		page_block_keys;
	page_block_keys.reserve(page_end - page_begin);
	view.page_block_by_entity.reserve(page_end - page_begin);
	for (std::size_t local = page_begin; local < page_end; ++local) {
		const std::size_t index = static_cast<std::size_t>(function.first_block) + local;
		if (index >= snapshot.blocks.size())
			break;
		const auto& block = snapshot.blocks[index];
		page_block_indices.push_back(index);
		page_block_ids.insert(block.id);
		page_block_keys.emplace(block.id, workspace_graph_block_key(function, block));
		view.page_block_by_entity.emplace(block.id, index);
	}
	view.current_layout = page_block_indices.empty() ?
		std::optional<workspace_graph_layout_key_t>{} :
		std::optional<workspace_graph_layout_key_t>{workspace_graph_layout_key(
			function, snapshot.blocks[page_block_indices.front()])};
	std::vector<const aida::analysis::edge_record_t*> page_cfg_edges;
	page_cfg_edges.reserve((std::min)(k_workspace_graph_edge_limit,
		page_block_indices.size() * 4U));
	if (!page_block_indices.empty()) {
		auto range_begin = snapshot.blocks[page_block_indices.front()].start;
		auto range_end = snapshot.blocks[page_block_indices.front()].end;
		for (const auto index : page_block_indices) {
			range_begin = (std::min)(range_begin, snapshot.blocks[index].start);
			range_end = (std::max)(range_end, snapshot.blocks[index].end);
		}
		auto edge = std::lower_bound(snapshot.edges.begin(), snapshot.edges.end(), range_begin,
			[](const aida::analysis::edge_record_t& candidate,
			   const aida::analysis::address_t& address) {
				return candidate.source < address;
			});
		std::unordered_set<workspace_graph_edge_key_t, workspace_graph_edge_key_hash_t>
			deduplicated;
		deduplicated.reserve((std::min)(k_workspace_graph_edge_limit,
			page_block_indices.size() * 4U));
		std::size_t inspected = 0;
		for (; edge != snapshot.edges.end() && edge->source < range_end &&
			inspected < k_workspace_graph_edge_candidate_limit; ++edge, ++inspected) {
			if (!edge->target_entity || !workspace_graph_cfg_edge_kind(edge->kind) ||
				page_block_ids.count(edge->source_entity) == 0 ||
				page_block_ids.count(*edge->target_entity) == 0)
				continue;
			const workspace_graph_edge_key_t key{edge->source_entity,
				*edge->target_entity, edge->kind};
			if (!deduplicated.insert(key).second)
				continue;
			if (page_cfg_edges.size() >= k_workspace_graph_edge_limit) {
				view.edge_set_truncated = true;
				break;
			}
			page_cfg_edges.push_back(&*edge);
		}
		if (inspected >= k_workspace_graph_edge_candidate_limit &&
			edge != snapshot.edges.end() && edge->source < range_end)
			view.edge_set_truncated = true;
	}
	view.successors.reserve(page_block_ids.size());
	view.predecessors.reserve(page_block_ids.size());
	for (const auto* edge : page_cfg_edges) {
		view.successors[edge->source_entity].push_back(*edge->target_entity);
		view.predecessors[*edge->target_entity].push_back(edge->source_entity);
	}
	std::unordered_set<aida::analysis::entity_id_t> hidden;
	std::unordered_set<aida::analysis::entity_id_t> protected_roots;
	std::vector<aida::analysis::entity_id_t> frontier;
	for (const auto& item : page_block_keys) {
		if (view.collapsed_reachable_roots.count(item.second) != 0) {
			protected_roots.insert(item.first);
			frontier.push_back(item.first);
		}
	}
	std::unordered_set<aida::analysis::entity_id_t> visited = protected_roots;
	for (std::size_t cursor = 0; cursor < frontier.size(); ++cursor) {
		const auto adjacent = view.successors.find(frontier[cursor]);
		if (adjacent == view.successors.end())
			continue;
		for (const auto target : adjacent->second) {
			if (protected_roots.count(target) == 0)
				hidden.insert(target);
			if (visited.insert(target).second)
				frontier.push_back(target);
		}
	}
	for (const auto index : page_block_indices) {
		const auto& block = snapshot.blocks[index];
		if (hidden.count(block.id) != 0)
			continue;
		const int node_id = static_cast<int>(view.layout.nodes.size());
		const std::size_t shown = (std::min)(static_cast<std::size_t>(block.instruction_count),
			static_cast<std::size_t>(14));
		cfg_layout::node_t node;
		node.id = node_id;
		node.width = 410.0f;
		node.height = 43.0f + static_cast<float>(shown) * 19.0f +
			(block.instruction_count > shown ? 20.0f : 8.0f);
		node.addr_col_w = 112.0f;
		node.is_entry = index == static_cast<std::size_t>(function.first_block);
		view.node_by_entity.emplace(block.id, view.layout.nodes.size());
		view.block_indices.push_back(index);
		view.layout.nodes.push_back(node);
	}
	for (const auto* edge : page_cfg_edges) {
		const auto from = view.node_by_entity.find(edge->source_entity);
		const auto to = view.node_by_entity.find(*edge->target_entity);
		if (from == view.node_by_entity.end() || to == view.node_by_entity.end())
			continue;
		workspace_graph_view_state_t::edge_t visual;
		visual.from = static_cast<int>(from->second);
		visual.to = static_cast<int>(to->second);
		visual.kind = edge->kind;
		view.edges.push_back(visual);
		if (visual.to > visual.from) {
			cfg_layout::edge_t layout_edge;
			layout_edge.from = visual.from;
			layout_edge.to = visual.to;
			layout_edge.is_true_branch = edge->kind ==
				aida::analysis::edge_kind_t::conditional_taken;
			view.layout.edges.push_back(layout_edge);
		}
	}
	view.outgoing.assign(view.layout.nodes.size(), 0);
	for (const auto& edge : view.edges) {
		if (edge.from >= 0 && static_cast<std::size_t>(edge.from) < view.outgoing.size())
			++view.outgoing[static_cast<std::size_t>(edge.from)];
	}
	cfg_layout::layout(view.layout, 82.0f, 94.0f);
	for (std::size_t index = 0; index < view.block_indices.size(); ++index) {
		const auto& block = snapshot.blocks[view.block_indices[index]];
		const auto block_key = workspace_graph_block_key(function, block);
		const auto pinned = view.pinned_node_positions.find(block_key);
		if (pinned != view.pinned_node_positions.end()) {
			view.layout.nodes[index].x = pinned->second.x;
			view.layout.nodes[index].y = pinned->second.y;
		} else if (view.current_layout &&
			view.pinned_layouts.count(*view.current_layout) != 0) {
			const auto layout_pinned = view.pinned_layout_positions.find(
				workspace_graph_layout_node_key_t{*view.current_layout, block_key});
			if (layout_pinned != view.pinned_layout_positions.end()) {
				view.layout.nodes[index].x = layout_pinned->second.x;
				view.layout.nodes[index].y = layout_pinned->second.y;
			}
		}
	}
	if (view.selected_block &&
		view.node_by_entity.find(*view.selected_block) == view.node_by_entity.end()) {
		view.selected_block.reset();
		view.selected_instruction.reset();
		view.selected_address = 0;
	}
	view.fit_request = true;
}

inline std::optional<std::uint64_t> workspace_graph_direct_target(
	const disasm_view::workspace_context_t& context,
	const aida::analysis::instruction_record_t& instruction)
{
	if (!context.publication || !context.publication->snapshot ||
		instruction.target_fact_count == 0)
		return std::nullopt;
	const auto& facts = context.publication->snapshot->target_facts;
	const std::size_t begin = instruction.target_fact_begin;
	const std::size_t end = (std::min)(facts.size(),
		begin + static_cast<std::size_t>(instruction.target_fact_count));
	for (std::size_t index = begin; index < end; ++index) {
		if (!facts[index].direct)
			continue;
		return disasm_view::runtime_address(context, facts[index].target).value_or(
			facts[index].target.value);
	}
	return std::nullopt;
}

inline const aida::analysis::instruction_record_t* workspace_graph_selected_instruction(
	const workspace_graph_view_state_t& view,
	const aida::analysis::analysis_snapshot_t& snapshot)
{
	if (!view.selected_instruction)
		return nullptr;
	const auto found = std::find_if(snapshot.instructions.begin(), snapshot.instructions.end(),
		[&](const aida::analysis::instruction_record_t& instruction) {
			return instruction.id == *view.selected_instruction;
		});
	return found == snapshot.instructions.end() ? nullptr : &*found;
}

inline void workspace_graph_open_disassembly(
	const disasm_view::workspace_context_t& context, std::uint64_t address)
{
	disasm_view::goto_address(address, context);
	aida::ui::application_views::open_or_focus(
		aida::ui::stable_view_id_t("document.disassembly"));
}

inline void workspace_graph_open_pseudocode(
	const disasm_view::workspace_context_t& context, std::uint64_t address)
{
	const auto function = disasm_view::enclosing_function_start(address, context);
	if (function == 0)
		return;
	pseudocode_view::request_decompile(context, function, false);
	aida::ui::application_views::open_or_focus(
		aida::ui::stable_view_id_t("document.pseudocode"));
}

inline void render(float, float, float width, float height,
	float alpha, float, float, float,
	const disasm_view::workspace_context_t& context)
{
	if (!context || !context.publication || !context.publication->snapshot) {
		ImGui::BeginChild("##workspace_cfg_empty", ImVec2(width, height), false);
		aida::ui::compact_empty_state("workspace_cfg_empty", "Graph is not ready",
			"Open a binary and wait for function recovery to publish a control-flow snapshot.",
			nullptr, ImVec2(0.0f, (std::max)(160.0f, height)));
		ImGui::EndChild();
		return;
	}
	const auto* function = workspace_graph_function(context);
	if (!function) {
		ImGui::BeginChild("##workspace_cfg_no_function", ImVec2(width, height), false);
		aida::ui::compact_empty_state("workspace_cfg_no_function", "No recovered function",
			"Select an instruction inside a recovered function, then return to Graph.",
			nullptr, ImVec2(0.0f, (std::max)(160.0f, height)));
		ImGui::EndChild();
		return;
	}
	auto view = workspace_graph_state(context);
	if (!view)
		return;
	const auto& snapshot = *context.publication->snapshot;
	const std::size_t first = function->first_block;
	const std::size_t available = first <= snapshot.blocks.size()
		? snapshot.blocks.size() - first : 0;
	const std::size_t total = (std::min)(static_cast<std::size_t>(function->block_count), available);
	constexpr std::size_t blocks_per_page = 256;
	const std::size_t page_count = total == 0 ? 1 : (total + blocks_per_page - 1) / blocks_per_page;
	if (view->block_page >= page_count)
		view->block_page = page_count - 1;
	const std::size_t page_begin = view->block_page * blocks_per_page;
	const std::size_t page_end = (std::min)(total, page_begin + blocks_per_page);
	const auto signature = workspace_graph_layout_signature(context, *function, view->block_page);
	if (view->layout_signature != signature) {
		view->layout_signature = signature;
		workspace_graph_rebuild_layout(*view, context, *function, page_begin, page_end);
	}
	const std::string id = context.workspace->identity().binary_id().to_hex();
	const auto function_address = disasm_view::runtime_address(context, function->start).value_or(
		function->start.value);
	const std::string function_name = disasm_view::resolve_name(context, function->start);
	ImGui::PushID(id.c_str());
	ImGui::BeginChild("##workspace_cfg", ImVec2(width, height), false,
		ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
	const auto& theme = aida::ui::resolved();
	ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(6.0f, 5.0f));
	ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(theme.text_primary));
	ImGui::TextUnformatted(function_name.empty() ? "Recovered function" : function_name.c_str());
	ImGui::SameLine();
	ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(theme.text_address),
		"%016llX", static_cast<unsigned long long>(function_address));
	ImGui::SameLine();
	ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(theme.text_dim),
		"%zu/%zu page blocks visible  %zu visible edges%s  %zu function blocks",
		view->layout.nodes.size(), page_end - page_begin, view->edges.size(),
		view->edge_set_truncated ? "  bounded" : "", total);
	ImGui::SameLine();
	if (ImGui::SmallButton("Disassembly  Space"))
		workspace_graph_open_disassembly(context,
			view->selected_address != 0 ? view->selected_address : function_address);
	ImGui::SameLine();
	if (ImGui::SmallButton("Pseudocode  F5"))
		workspace_graph_open_pseudocode(context,
			view->selected_address != 0 ? view->selected_address : function_address);
	ImGui::SameLine();
	if (ImGui::SmallButton("Fit  F"))
		view->fit_request = true;
	ImGui::SameLine();
	if (ImGui::SmallButton("-"))
		view->target_zoom = (std::max)(0.16f, view->target_zoom * 0.85f);
	ImGui::SameLine();
	if (ImGui::SmallButton("100%")) {
		view->zoom = 1.0f;
		view->target_zoom = 1.0f;
		view->pan_x = 0.0f;
		view->pan_y = 0.0f;
	}
	ImGui::SameLine();
	if (ImGui::SmallButton("+"))
		view->target_zoom = (std::min)(2.5f, view->target_zoom * 1.18f);
	if (page_count > 1) {
		ImGui::SameLine();
		if (ImGui::SmallButton("Previous") && view->block_page != 0) {
			--view->block_page;
			view->layout_signature = 0;
		}
		ImGui::SameLine();
		ImGui::Text("Page %zu/%zu", view->block_page + 1, page_count);
		ImGui::SameLine();
		if (ImGui::SmallButton("Next") && view->block_page + 1 < page_count) {
			++view->block_page;
			view->layout_signature = 0;
		}
	}
	ImGui::PopStyleColor();
	ImGui::PopStyleVar();
	ImGui::Separator();
	if (total == 0) {
		aida::ui::compact_empty_state("workspace_cfg_zero_blocks", "No control-flow blocks",
			"Function recovery published this function without a displayable block graph.",
			nullptr, ImVec2(0.0f, (std::max)(160.0f, height - 34.0f)));
		ImGui::EndChild();
		ImGui::PopID();
		return;
	}
	ImGui::BeginChild("##workspace_cfg_canvas", ImVec2(0.0f, 0.0f), false,
		ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
	ImDrawList* draw = ImGui::GetWindowDrawList();
	const ImVec2 canvas = ImGui::GetWindowPos();
	const ImVec2 canvas_size = ImGui::GetWindowSize();
	const ImVec2 canvas_max(canvas.x + canvas_size.x, canvas.y + canvas_size.y);
	draw->AddRectFilled(canvas, canvas_max, aida::ui::with_alpha(theme.bg_base, alpha));
	const bool canvas_hovered = ImGui::IsWindowHovered(ImGuiHoveredFlags_AllowWhenBlockedByActiveItem);
	ImGuiIO& io = ImGui::GetIO();
	if (canvas_hovered && ImGui::IsMouseDragging(ImGuiMouseButton_Middle, 0.0f)) {
		view->pan_x += io.MouseDelta.x / (std::max)(view->zoom, 0.01f);
		view->pan_y += io.MouseDelta.y / (std::max)(view->zoom, 0.01f);
	}
	if (canvas_hovered && io.MouseWheel != 0.0f) {
		if (io.KeyCtrl) {
			const float old_zoom = view->target_zoom;
			const float new_zoom = (std::clamp)(old_zoom * (io.MouseWheel > 0.0f ? 1.12f : 0.89f),
				0.16f, 2.5f);
			const ImVec2 center(canvas.x + canvas_size.x * 0.5f,
				canvas.y + canvas_size.y * 0.5f);
			const float world_x = (io.MousePos.x - center.x) / old_zoom - view->pan_x;
			const float world_y = (io.MousePos.y - center.y) / old_zoom - view->pan_y;
			view->pan_x = (io.MousePos.x - center.x) / new_zoom - world_x;
			view->pan_y = (io.MousePos.y - center.y) / new_zoom - world_y;
			view->target_zoom = new_zoom;
		} else {
			view->pan_y += io.MouseWheel * 46.0f / (std::max)(view->zoom, 0.01f);
		}
	}
	view->zoom += (view->target_zoom - view->zoom) *
		(1.0f - std::pow(0.001f, (std::min)(ImGui::GetIO().DeltaTime, 0.05f)));
	float min_x, min_y, max_x, max_y;
	detail::compute_world_bounds(view->layout, min_x, min_y, max_x, max_y);
	if (view->fit_request && !view->layout.nodes.empty() &&
		canvas_size.x > 80.0f && canvas_size.y > 80.0f) {
		view->fit_request = false;
		const float graph_width = (std::max)(1.0f, max_x - min_x);
		const float graph_height = (std::max)(1.0f, max_y - min_y);
		view->target_zoom = (std::clamp)((std::min)(
			(canvas_size.x - 88.0f) / graph_width,
			(canvas_size.y - 88.0f) / graph_height), 0.16f, 1.35f);
		view->zoom = view->target_zoom;
		view->pan_x = -(min_x + max_x) * 0.5f;
		view->pan_y = -(min_y + max_y) * 0.5f;
	}
	const ImVec2 center(canvas.x + canvas_size.x * 0.5f,
		canvas.y + canvas_size.y * 0.5f);
	auto world_to_screen = [&](float x, float y) {
		return ImVec2(center.x + (x + view->pan_x) * view->zoom,
			center.y + (y + view->pan_y) * view->zoom);
	};
	const float grid_world = 40.0f;
	const float visible_left = -view->pan_x - canvas_size.x * 0.5f / view->zoom;
	const float visible_right = -view->pan_x + canvas_size.x * 0.5f / view->zoom;
	const float visible_top = -view->pan_y - canvas_size.y * 0.5f / view->zoom;
	const float visible_bottom = -view->pan_y + canvas_size.y * 0.5f / view->zoom;
	if ((visible_right - visible_left) * (visible_bottom - visible_top) /
		(grid_world * grid_world) < 5000.0f) {
		const ImU32 grid_color = aida::ui::with_alpha(theme.border_subtle, alpha * 0.42f);
		for (float y = std::floor(visible_top / grid_world) * grid_world;
			y <= visible_bottom; y += grid_world) {
			for (float x = std::floor(visible_left / grid_world) * grid_world;
				x <= visible_right; x += grid_world) {
				draw->AddCircleFilled(world_to_screen(x, y), 0.8f, grid_color, 4);
			}
		}
	}
	const auto& outgoing = view->outgoing;
	for (const auto& edge : view->edges) {
		if (edge.from < 0 || edge.to < 0 ||
			static_cast<std::size_t>(edge.from) >= view->layout.nodes.size() ||
			static_cast<std::size_t>(edge.to) >= view->layout.nodes.size())
			continue;
		const auto& from = view->layout.nodes[static_cast<std::size_t>(edge.from)];
		const auto& to = view->layout.nodes[static_cast<std::size_t>(edge.to)];
		ImVec2 p1;
		ImVec2 p4;
		ImVec2 p2;
		ImVec2 p3;
		if (to.y > from.y + from.height * 0.25f) {
			p1 = world_to_screen(from.x, from.y + from.height);
			p4 = world_to_screen(to.x, to.y);
			const float middle = (p1.y + p4.y) * 0.5f;
			p2 = ImVec2(p1.x, middle);
			p3 = ImVec2(p4.x, middle);
		} else {
			p1 = world_to_screen(from.x + from.width * 0.5f, from.y + from.height * 0.5f);
			p4 = world_to_screen(to.x + to.width * 0.5f, to.y + to.height * 0.5f);
			const float route_x = (std::max)(p1.x, p4.x) + 54.0f * view->zoom;
			p2 = ImVec2(route_x, p1.y);
			p3 = ImVec2(route_x, p4.y);
		}
		const float minimum_x = (std::min)((std::min)(p1.x, p2.x), (std::min)(p3.x, p4.x));
		const float maximum_x = (std::max)((std::max)(p1.x, p2.x), (std::max)(p3.x, p4.x));
		const float minimum_y = (std::min)((std::min)(p1.y, p2.y), (std::min)(p3.y, p4.y));
		const float maximum_y = (std::max)((std::max)(p1.y, p2.y), (std::max)(p3.y, p4.y));
		if (maximum_x < canvas.x || minimum_x > canvas_max.x ||
			maximum_y < canvas.y || minimum_y > canvas_max.y)
			continue;
		const bool branching = outgoing[static_cast<std::size_t>(edge.from)] > 1;
		const ImU32 edge_color = workspace_graph_edge_color(edge.kind, theme,
			alpha * 0.92f, branching);
		draw->AddBezierCubic(p1, p2, p3, p4,
			aida::ui::with_alpha(edge_color, 0.18f), (std::max)(3.0f, 5.0f * view->zoom));
		draw->AddBezierCubic(p1, p2, p3, p4, edge_color,
			(std::max)(1.25f, 1.9f * view->zoom));
		ImVec2 direction(p4.x - p3.x, p4.y - p3.y);
		float length = std::sqrt(direction.x * direction.x + direction.y * direction.y);
		if (length > 0.001f) {
			direction.x /= length;
			direction.y /= length;
			const ImVec2 perpendicular(-direction.y, direction.x);
			const float arrow = (std::max)(5.0f, 7.0f * view->zoom);
			draw->AddTriangleFilled(p4,
				ImVec2(p4.x - direction.x * arrow + perpendicular.x * arrow * 0.52f,
					p4.y - direction.y * arrow + perpendicular.y * arrow * 0.52f),
				ImVec2(p4.x - direction.x * arrow - perpendicular.x * arrow * 0.52f,
					p4.y - direction.y * arrow - perpendicular.y * arrow * 0.52f),
				edge_color);
		}
		const char* label = workspace_graph_edge_label(edge.kind, branching);
		if (label && view->zoom > 0.32f) {
			const ImVec2 text_size = ImGui::CalcTextSize(label);
			const ImVec2 label_position((p1.x + p4.x) * 0.5f + 5.0f,
				(p1.y + p4.y) * 0.5f - text_size.y * 0.5f);
			draw->AddRectFilled(ImVec2(label_position.x - 4.0f, label_position.y - 1.0f),
				ImVec2(label_position.x + text_size.x + 4.0f,
					label_position.y + text_size.y + 1.0f),
				aida::ui::with_alpha(theme.bg_overlay, alpha * 0.96f), 3.0f);
			draw->AddText(label_position, edge_color, label);
		}
	}
	const auto workspace_selection = context.workspace->view_state().selection;
	if (workspace_selection) {
		const auto selection_runtime = disasm_view::runtime_address(context, *workspace_selection).value_or(
			workspace_selection->value);
		if (view->selected_address != selection_runtime) {
			for (std::size_t node_index = 0; node_index < view->block_indices.size(); ++node_index) {
				const auto& block = snapshot.blocks[view->block_indices[node_index]];
				if (workspace_selection->space != block.start.space ||
					workspace_selection->value < block.start.value ||
					workspace_selection->value >= block.end.value)
					continue;
				view->selected_block = block.id;
				view->selected_address = selection_runtime;
				view->selected_instruction.reset();
				const std::size_t begin = block.first_instruction;
				const std::size_t count = (std::min)(static_cast<std::size_t>(block.instruction_count),
					begin <= snapshot.instructions.size() ? snapshot.instructions.size() - begin : 0);
				for (std::size_t row = 0; row < count; ++row) {
					if (snapshot.instructions[begin + row].address == *workspace_selection) {
						view->selected_instruction = snapshot.instructions[begin + row].id;
						break;
					}
				}
				break;
			}
		}
	}
	bool context_requested = false;
	aida::ui::context_menu_open_origin_t context_origin{};
	const aida::analysis::basic_block_record_t* context_block = nullptr;
	for (std::size_t node_index = 0; node_index < view->layout.nodes.size(); ++node_index) {
		if (node_index >= view->block_indices.size())
			break;
		const auto& node = view->layout.nodes[node_index];
		const auto& block = snapshot.blocks[view->block_indices[node_index]];
		const ImVec2 top_left = world_to_screen(node.x - node.width * 0.5f, node.y);
		const ImVec2 bottom_right = world_to_screen(node.x + node.width * 0.5f,
			node.y + node.height);
		if (bottom_right.x < canvas.x || top_left.x > canvas_max.x ||
			bottom_right.y < canvas.y || top_left.y > canvas_max.y)
			continue;
		const bool selected = view->selected_block && *view->selected_block == block.id;
		const bool selection_inside = workspace_selection &&
			workspace_selection->space == block.start.space &&
			workspace_selection->value >= block.start.value &&
			workspace_selection->value < block.end.value;
		const bool entry = node.is_entry;
		const bool terminal = outgoing[node_index] == 0;
		const float rounding = (std::max)(3.0f, 7.0f * view->zoom);
		draw->AddRectFilled(ImVec2(top_left.x + 4.0f, top_left.y + 5.0f),
			ImVec2(bottom_right.x + 4.0f, bottom_right.y + 5.0f),
			aida::ui::with_alpha(IM_COL32(0, 0, 0, 255), alpha * 0.34f), rounding);
		draw->AddRectFilled(top_left, bottom_right,
			aida::ui::with_alpha(selected || selection_inside ? theme.bg_overlay : theme.panel_bg,
				alpha), rounding);
		const float header_height = 34.0f * view->zoom;
		draw->AddRectFilled(top_left, ImVec2(bottom_right.x, top_left.y + header_height),
			aida::ui::with_alpha(entry ? theme.accent_dim : theme.panel_header, alpha), rounding,
			ImDrawFlags_RoundCornersTop);
		const ImU32 border = aida::ui::with_alpha(
			selected || selection_inside ? theme.accent_u32 :
			(terminal ? theme.warning : theme.border_strong), alpha);
		draw->AddRect(top_left, bottom_right, border, rounding, 0,
			selected || selection_inside ? 2.0f : 1.0f);
		const auto block_address = disasm_view::runtime_address(context, block.start).value_or(
			block.start.value);
		const std::string block_name = disasm_view::resolve_name(context, block.start);
		char header[192]{};
		if (!block_name.empty())
			std::snprintf(header, sizeof(header), "%s", block_name.c_str());
		else if (entry)
			std::snprintf(header, sizeof(header), "entry_%llX",
				static_cast<unsigned long long>(block_address));
		else
			std::snprintf(header, sizeof(header), "loc_%llX",
				static_cast<unsigned long long>(block_address));
		ImFont* code_font = aida::ui::fonts::code();
		if (!code_font)
			code_font = ImGui::GetFont();
		const float base_size = aida::ui::fonts::size_or(code_font, ImGui::GetFontSize());
		const float font_size = (std::max)(7.0f, base_size * view->zoom);
		if (view->zoom > 0.22f) {
			draw->AddText(code_font, font_size,
				ImVec2(top_left.x + 10.0f * view->zoom,
					top_left.y + (header_height - font_size) * 0.5f),
				aida::ui::with_alpha(theme.text_primary, alpha), header);
			char confidence[32]{};
			std::snprintf(confidence, sizeof(confidence), "%u%%",
				static_cast<unsigned>(block.confidence));
			const float confidence_width = code_font->CalcTextSizeA(font_size, FLT_MAX, 0.0f,
				confidence).x;
			draw->AddText(code_font, font_size,
				ImVec2(bottom_right.x - confidence_width - 9.0f * view->zoom,
					top_left.y + (header_height - font_size) * 0.5f),
				aida::ui::with_alpha(theme.text_dim, alpha), confidence);
		}
		const std::size_t instruction_begin = block.first_instruction;
		const std::size_t available_instructions = instruction_begin <= snapshot.instructions.size()
			? snapshot.instructions.size() - instruction_begin : 0;
		const std::size_t instruction_total = (std::min)(
			static_cast<std::size_t>(block.instruction_count), available_instructions);
		const std::size_t shown = (std::min)(instruction_total, static_cast<std::size_t>(14));
		disasm_view::request_format_range(context, instruction_begin,
			instruction_begin + instruction_total);
		const float line_height = 19.0f * view->zoom;
		const float body_y = top_left.y + header_height + 4.0f * view->zoom;
		draw->PushClipRect(ImVec2(top_left.x + 1.0f, top_left.y + header_height),
			ImVec2(bottom_right.x - 1.0f, bottom_right.y - 1.0f), true);
		for (std::size_t row = 0; row < shown; ++row) {
			const auto& instruction = snapshot.instructions[instruction_begin + row];
			const auto formatted = disasm_view::formatted_instruction(context, instruction.id);
			const auto address = disasm_view::runtime_address(context, instruction.address).value_or(
				instruction.address.value);
			const float row_y = body_y + static_cast<float>(row) * line_height;
			const bool instruction_selected = view->selected_instruction &&
				*view->selected_instruction == instruction.id;
			if (instruction_selected || (workspace_selection &&
				*workspace_selection == instruction.address)) {
				draw->AddRectFilled(ImVec2(top_left.x + 2.0f, row_y),
					ImVec2(bottom_right.x - 2.0f, row_y + line_height),
					aida::ui::with_alpha(theme.selection, alpha));
				draw->AddRectFilled(ImVec2(top_left.x + 2.0f, row_y),
					ImVec2(top_left.x + 4.0f, row_y + line_height),
					aida::ui::with_alpha(theme.accent_u32, alpha));
			}
			if (view->zoom > 0.22f) {
				char address_text[32]{};
				std::snprintf(address_text, sizeof(address_text), "%016llX",
					static_cast<unsigned long long>(address));
				const float text_y = row_y + (line_height - font_size) * 0.5f;
				draw->AddText(code_font, font_size,
					ImVec2(top_left.x + 8.0f * view->zoom, text_y),
					aida::ui::with_alpha(theme.text_address, alpha * 0.88f), address_text);
				detail::render_colored_insn(draw,
					top_left.x + 126.0f * view->zoom, text_y,
					formatted ? formatted->text.c_str() : "formatting...",
					theme, alpha, bottom_right.x - 8.0f * view->zoom,
					code_font, font_size);
			}
		}
		if (instruction_total > shown && view->zoom > 0.28f) {
			char remainder[48]{};
			std::snprintf(remainder, sizeof(remainder), "+ %zu more instructions",
				instruction_total - shown);
			draw->AddText(code_font, font_size,
				ImVec2(top_left.x + 8.0f * view->zoom,
					body_y + static_cast<float>(shown) * line_height),
				aida::ui::with_alpha(theme.text_dim, alpha), remainder);
		}
		draw->PopClipRect();
		ImGui::SetCursorScreenPos(top_left);
		ImGui::PushID(static_cast<int>(block.id & 0x7FFFFFFF));
		ImGui::InvisibleButton("##workspace_cfg_node",
			ImVec2((std::max)(1.0f, bottom_right.x - top_left.x),
				(std::max)(1.0f, bottom_right.y - top_left.y)));
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		const std::string workspace_node_identity = std::to_string(block_address);
		const std::string workspace_node_semantic = aida::preview::semantics::stable_id(
			aida::preview::semantics::stable_id("aida.graph-node", "workspace"),
			aida::preview::semantics::entity_token(workspace_node_identity));
		static_cast<void>(aida::preview::semantics::register_last_item(
			workspace_node_semantic, "graph-node"));
#endif
		const bool hovered = ImGui::IsItemHovered();
		if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			std::size_t row = 0;
			if (io.MousePos.y >= body_y && shown != 0)
				row = (std::min)(shown - 1, static_cast<std::size_t>(
					(io.MousePos.y - body_y) / (std::max)(line_height, 1.0f)));
			view->selected_block = block.id;
			if (shown != 0) {
				const auto& instruction = snapshot.instructions[instruction_begin + row];
				view->selected_instruction = instruction.id;
				view->selected_address = disasm_view::runtime_address(context,
					instruction.address).value_or(instruction.address.value);
				disasm_view::select_address(instruction.address, context);
			} else {
				view->selected_instruction.reset();
				view->selected_address = block_address;
				disasm_view::select_address(block.start, context);
			}
		}
		if (hovered && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
			const auto* instruction = workspace_graph_selected_instruction(*view, snapshot);
			const auto target = instruction
				? workspace_graph_direct_target(context, *instruction) : std::nullopt;
			if (target) {
				disasm_view::goto_address(*target, context);
				view->selected_address = *target;
			} else {
				workspace_graph_open_disassembly(context,
					view->selected_address != 0 ? view->selected_address : block_address);
			}
		}
		if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
			view->selected_block = block.id;
			std::size_t row = 0;
			if (io.MousePos.y >= body_y && shown != 0)
				row = (std::min)(shown - 1, static_cast<std::size_t>(
					(io.MousePos.y - body_y) / (std::max)(line_height, 1.0f)));
			if (shown != 0) {
				const auto& instruction = snapshot.instructions[instruction_begin + row];
				view->selected_instruction = instruction.id;
				view->selected_address = disasm_view::runtime_address(context,
					instruction.address).value_or(instruction.address.value);
				disasm_view::select_address(instruction.address, context);
			} else {
				view->selected_instruction.reset();
				view->selected_address = block_address;
				disasm_view::select_address(block.start, context);
			}
			context_requested = true;
			context_origin = aida::ui::context_menu_open_origin_t::pointer;
			context_block = &block;
		}
		ImGui::PopID();
	}
	if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
		aida::ui::analysis_context_menu::keyboard_request(context_origin)) {
		context_requested = view->selected_block.has_value();
		if (context_requested) {
			const auto found = view->node_by_entity.find(*view->selected_block);
			if (found != view->node_by_entity.end() && found->second < view->block_indices.size())
				context_block = &snapshot.blocks[view->block_indices[found->second]];
		}
	}
	const auto make_workspace_graph_context = [&](const auto& retained_context_block) {
		const auto* context_block = &retained_context_block;
		using namespace aida::ui::analysis_context_menu;
		using aida::ui::action_handler_result_t;
		using aida::ui::capability_state_t;
		context_t menu;
		menu.kind = menu_kind_t::graph;
		const auto retained_block = context_block->id;
		const auto retained_block_key = workspace_graph_block_key(*function, *context_block);
		const auto retained_layout = view->current_layout;
		const auto retained_instruction = view->selected_instruction;
		const auto retained_address = view->selected_address;
		const auto retained_generation = context.publication->generation;
		const auto retained_analysis_revision = context.publication->analysis_revision;
		const auto retained_overlay_revision = context.workspace->overlay_revision();
		menu.entity_id = "graph-block:" + std::to_string(retained_block) + ":" +
			std::to_string(retained_instruction ? *retained_instruction : 0) + ":" +
			std::to_string(retained_address);
		menu.generation = workspace_graph_generation(context);
		menu.live_generation = [context]() { return workspace_graph_generation(context); };
		menu.validate_identity = [view, retained_block, retained_instruction,
			retained_address, retained_layout]() {
			return view->selected_block && *view->selected_block == retained_block &&
				view->selected_instruction == retained_instruction &&
				view->selected_address == retained_address &&
				view->current_layout == retained_layout
				? aida::ui::capability_state_t::available()
				: aida::ui::capability_state_t::unavailable(
					"The selected graph block or instruction changed");
		};
		auto unavailable = [&menu](const char* id, std::string reason) {
			action_slot_t slot;
			slot.capability = capability_state_t::unavailable(reason);
			slot.invoke = [reason = std::move(reason)]() {
				return action_handler_result_t::failed(reason);
			};
			menu.actions.emplace(id, std::move(slot));
		};
		const auto address = view->selected_address != 0 ? view->selected_address :
			disasm_view::runtime_address(context, context_block->start).value_or(
				context_block->start.value);
		const auto typed = disasm_view::typed_address(context, address);
		const auto validate_retained_action = [context, view, retained_block,
			retained_instruction, retained_address, retained_layout, retained_generation,
			retained_analysis_revision, retained_overlay_revision]() -> std::string {
			if (!context.workspace || context.workspace->closed() || !context.publication ||
				!context.publication->snapshot ||
				context.workspace->analysis_publication() != context.publication ||
				context.workspace->generation() != retained_generation ||
				context.workspace->analysis_revision() != retained_analysis_revision ||
				context.workspace->overlay_revision() != retained_overlay_revision ||
				context.publication->generation != retained_generation ||
				context.publication->analysis_revision != retained_analysis_revision)
				return "The graph workspace publication or overlay changed; reopen the context action";
			if (workspace_graph_state(context) != view || !view->selected_block ||
				*view->selected_block != retained_block ||
				view->selected_instruction != retained_instruction ||
				view->selected_address != retained_address ||
				view->current_layout != retained_layout)
				return "The selected graph block or instruction changed; reopen the context action";
			return {};
		};
		menu.actions["analysis.navigate.back"].invoke = [context]() {
			disasm_view::navigate_back(context);
			return action_handler_result_t::completed();
		};
		menu.actions["analysis.navigate.forward"].invoke = [context]() {
			disasm_view::navigate_forward(context);
			return action_handler_result_t::completed();
		};
		menu.actions["analysis.navigate.disassembly"].invoke = [context, address]() {
			workspace_graph_open_disassembly(context, address);
			return action_handler_result_t::completed();
		};
		menu.actions["analysis.navigate.graph"].invoke = []() {
			aida::ui::application_views::open_or_focus(
				aida::ui::stable_view_id_t("document.graph"));
			return action_handler_result_t::completed();
		};
		const auto function_start = disasm_view::enclosing_function_start(address, context);
		if (function_start != 0) {
			auto decompile = [context, function_start]() {
				pseudocode_view::request_decompile(context, function_start, false);
				aida::ui::application_views::open_or_focus(
					aida::ui::stable_view_id_t("document.pseudocode"));
				return action_handler_result_t::completed();
			};
			menu.actions["analysis.navigate.pseudocode"].invoke = decompile;
			menu.actions["analysis.function.decompile"].invoke = std::move(decompile);
		} else {
			unavailable("analysis.navigate.pseudocode", "No recovered function contains this graph selection");
			unavailable("analysis.function.decompile", "No recovered function contains this graph selection");
		}
		menu.actions["analysis.navigate.functions"].invoke = [context, address]() {
			disasm_view::select_address(address, context, false);
			aida::ui::application_views::open_or_focus(
				aida::ui::stable_view_id_t("view.analysis.functions"));
			return action_handler_result_t::completed();
		};
		menu.actions["analysis.navigate.structures"].invoke = [context, address]() {
			disasm_view::select_address(address, context, false);
			aida::ui::application_views::open_or_focus(
				aida::ui::stable_view_id_t("view.types.structures"));
			return action_handler_result_t::completed();
		};
		menu.actions["analysis.navigate.types"].invoke = [context, address]() {
			disasm_view::select_address(address, context, false);
			aida::ui::application_views::open_or_focus(
				aida::ui::stable_view_id_t("view.types.inferred"));
			return action_handler_result_t::completed();
		};
		menu.actions["analysis.navigate.xrefs"].invoke = [context, address]() {
			disasm_view::open_xrefs(address, context);
			return action_handler_result_t::completed();
		};
		menu.actions["analysis.navigate.callers"].invoke = [context, function_start, address]() {
			disasm_view::open_xrefs(function_start != 0 ? function_start : address, context);
			return action_handler_result_t::completed();
		};
		menu.actions["analysis.navigate.xrefs_from"].invoke = [context, address]() {
			disasm_view::select_address(address, context, false);
			aida::ui::application_views::open_or_focus(
				aida::ui::stable_view_id_t("view.analysis.references"));
			return action_handler_result_t::completed();
		};
		menu.actions["analysis.navigate.hex"].invoke = [context, address]() {
			disasm_view::select_address(address, context, false);
			aida::ui::application_views::open_or_focus(
				aida::ui::stable_view_id_t("document.hex"));
			return action_handler_result_t::completed();
		};
		const auto* selected_instruction = workspace_graph_selected_instruction(*view, snapshot);
		const auto direct_target = selected_instruction
			? workspace_graph_direct_target(context, *selected_instruction) : std::nullopt;
		if (direct_target) {
			menu.actions["analysis.navigate.follow"].invoke = [context, target = *direct_target]() {
				disasm_view::goto_address(target, context);
				return action_handler_result_t::completed();
			};
		} else {
			unavailable("analysis.navigate.follow", "The selected graph instruction has no direct resolved target");
		}
		std::optional<std::uint64_t> source_address;
		const auto successor = view->successors.find(retained_block);
		const bool has_reachable_target = successor != view->successors.end() &&
			std::any_of(successor->second.begin(), successor->second.end(),
				[view, retained_block](const auto target) {
					return target != retained_block &&
						view->node_by_entity.count(target) != 0;
				});
		const auto predecessor = view->predecessors.find(retained_block);
		if (predecessor != view->predecessors.end()) {
			const auto visible_source = std::find_if(predecessor->second.begin(),
				predecessor->second.end(), [view](const auto source) {
					return view->node_by_entity.count(source) != 0;
				});
			const auto source = visible_source == predecessor->second.end()
				? view->page_block_by_entity.end()
				: view->page_block_by_entity.find(*visible_source);
			if (source != view->page_block_by_entity.end() &&
				source->second < snapshot.blocks.size()) {
				const auto& source_block = snapshot.blocks[source->second];
				source_address = disasm_view::runtime_address(context, source_block.start)
					.value_or(source_block.start.value);
			}
		}
		if (source_address) {
			menu.actions["analysis.graph.navigate_source"].invoke =
				[context, value = *source_address]() {
					disasm_view::goto_address(value, context);
					return action_handler_result_t::completed();
				};
		} else {
			unavailable("analysis.graph.navigate_source",
				"No incoming source block is present in the visible page edge set; it may be on another page or hidden");
		}
		std::optional<std::uint64_t> visible_direct_target;
		if (direct_target) {
			const auto typed_target = disasm_view::typed_address(context, *direct_target);
			if (typed_target && successor != view->successors.end()) {
				for (const auto target_entity : successor->second) {
					if (view->node_by_entity.count(target_entity) == 0)
						continue;
					const auto target = view->page_block_by_entity.find(target_entity);
					if (target == view->page_block_by_entity.end() ||
						target->second >= snapshot.blocks.size())
						continue;
					const auto& block = snapshot.blocks[target->second];
					if (typed_target->space == block.start.space &&
						typed_target->value >= block.start.value &&
						typed_target->value < block.end.value) {
						visible_direct_target = *direct_target;
						break;
					}
				}
			}
		}
		if (visible_direct_target) {
			menu.actions["analysis.graph.navigate_target"].invoke =
				[context, value = *visible_direct_target]() {
					disasm_view::goto_address(value, context);
					return action_handler_result_t::completed();
				};
		} else {
			unavailable("analysis.graph.navigate_target",
				"The selected instruction's direct target is not present in the visible page edge set; it may be on another page or hidden");
		}
		const bool collapsed = view->collapsed_reachable_roots.count(retained_block_key) != 0;
		if (view->edge_set_truncated) {
			const std::string reason =
				"The visible page edge set is bounded; complete reachability is unavailable";
			unavailable("analysis.graph.collapse_reachable", reason);
			unavailable("analysis.graph.expand_reachable", reason);
		} else if (has_reachable_target && !collapsed) {
			unavailable("analysis.graph.expand_reachable",
				"The selected visible-page reachable scope is already expanded");
			menu.actions["analysis.graph.collapse_reachable"].invoke =
				[context, view, retained_block_key]() {
				if (view->collapsed_reachable_roots.size() >=
					k_workspace_graph_persisted_item_limit)
					return action_handler_result_t::failed(
						"The bounded graph collapse-state limit was reached");
				return workspace_graph_persist_mutation(context, view, [&] {
					view->collapsed_reachable_roots.insert(retained_block_key);
					view->layout_signature = 0;
				});
			};
		} else {
			unavailable("analysis.graph.collapse_reachable", collapsed
				? "The selected reachable scope is already collapsed"
				: "The selected block has no reachable target blocks on the visible page");
			if (collapsed) {
				menu.actions["analysis.graph.expand_reachable"].invoke =
					[context, view, retained_block_key]() {
						return workspace_graph_persist_mutation(context, view, [&] {
							view->collapsed_reachable_roots.erase(retained_block_key);
							view->layout_signature = 0;
						});
					};
			} else {
				unavailable("analysis.graph.expand_reachable",
					"The selected visible-page reachable scope is already expanded");
			}
		}
		const bool node_pinned = view->pinned_node_positions.count(retained_block_key) != 0;
		if (node_pinned) {
			unavailable("analysis.graph.pin_node", "The selected node is already pinned");
			menu.actions["analysis.graph.pin_node"].check_state =
				aida::ui::action_check_state_t::checked;
			menu.actions["analysis.graph.unpin_node"].invoke =
				[context, view, retained_block_key]() {
					return workspace_graph_persist_mutation(context, view, [&] {
						view->pinned_node_positions.erase(retained_block_key);
						view->layout_signature = 0;
					});
				};
		} else {
			unavailable("analysis.graph.unpin_node", "The selected node is not pinned");
			if (view->pinned_node_positions.size() >=
				k_workspace_graph_persisted_item_limit) {
				unavailable("analysis.graph.pin_node", "The bounded pinned-node limit was reached");
			} else {
				menu.actions["analysis.graph.pin_node"].invoke =
					[context, view, retained_block, retained_block_key]() {
						const auto found = view->node_by_entity.find(retained_block);
						if (found == view->node_by_entity.end() ||
							found->second >= view->layout.nodes.size())
							return action_handler_result_t::failed("The graph node layout changed");
						const auto& node = view->layout.nodes[found->second];
						return workspace_graph_persist_mutation(context, view, [&] {
							view->pinned_node_positions[retained_block_key] =
								ImVec2(node.x, node.y);
						});
					};
			}
		}
		const bool layout_pinned = retained_layout &&
			view->pinned_layouts.count(*retained_layout) != 0;
		if (!retained_layout) {
			unavailable("analysis.graph.pin_layout", "The current graph page has no layout identity");
			unavailable("analysis.graph.unpin_layout", "The current graph page has no layout identity");
		} else if (layout_pinned) {
			unavailable("analysis.graph.pin_layout", "The current function page layout is already pinned");
			menu.actions["analysis.graph.pin_layout"].check_state =
				aida::ui::action_check_state_t::checked;
			menu.actions["analysis.graph.unpin_layout"].invoke =
				[context, view, retained_layout]() {
					return workspace_graph_persist_mutation(context, view, [&] {
						view->pinned_layouts.erase(*retained_layout);
						for (auto iterator = view->pinned_layout_positions.begin();
							iterator != view->pinned_layout_positions.end();) {
							if (iterator->first.layout == *retained_layout)
								iterator = view->pinned_layout_positions.erase(iterator);
							else ++iterator;
						}
						view->layout_signature = 0;
					});
				};
		} else if (view->node_by_entity.size() > k_workspace_graph_persisted_item_limit ||
			view->pinned_layout_positions.size() + view->node_by_entity.size() >
				k_workspace_graph_persisted_item_limit) {
			const std::string reason =
				"The bounded 256-node pinned-layout position limit was reached";
			unavailable("analysis.graph.pin_layout", reason);
			unavailable("analysis.graph.unpin_layout", "The current function page layout is not pinned");
		} else {
			unavailable("analysis.graph.unpin_layout", "The current function page layout is not pinned");
			menu.actions["analysis.graph.pin_layout"].invoke = [context, view, retained_layout]() {
				const auto* current_function = workspace_graph_function(context);
				if (!current_function || !context.publication ||
					!context.publication->snapshot || view->current_layout != retained_layout)
					return action_handler_result_t::failed(
						"The graph publication changed before the layout could be pinned");
				return workspace_graph_persist_mutation(context, view, [&] {
					view->pinned_layouts.insert(*retained_layout);
					const auto& current_snapshot = *context.publication->snapshot;
					for (const auto& item : view->node_by_entity) {
						if (item.second >= view->layout.nodes.size() ||
							item.second >= view->block_indices.size() ||
							view->block_indices[item.second] >= current_snapshot.blocks.size())
							continue;
						const auto& node = view->layout.nodes[item.second];
						const auto& block = current_snapshot.blocks[view->block_indices[item.second]];
						view->pinned_layout_positions[{*retained_layout,
							workspace_graph_block_key(*current_function, block)}] =
							ImVec2(node.x, node.y);
					}
				});
			};
		}
		char address_text[32]{};
		std::snprintf(address_text, sizeof(address_text), "%016llX",
			static_cast<unsigned long long>(address));
		menu.actions["analysis.copy.address"].invoke = [value = std::string(address_text)]() {
			ImGui::SetClipboardText(value.c_str());
			return action_handler_result_t::completed();
		};
		const auto block_begin = static_cast<std::size_t>(context_block->first_instruction);
		const auto block_count = (std::min)(static_cast<std::size_t>(context_block->instruction_count),
			block_begin <= snapshot.instructions.size() ? snapshot.instructions.size() - block_begin : 0);
		std::string block_text;
		std::string addressed_text;
		bool complete_text = block_count != 0;
		for (std::size_t row = 0; row < block_count; ++row) {
			const auto& instruction = snapshot.instructions[block_begin + row];
			const auto formatted = disasm_view::formatted_instruction(context, instruction.id);
			if (!formatted) {
				complete_text = false;
				continue;
			}
			if (!block_text.empty()) {
				block_text.push_back('\n');
				addressed_text.push_back('\n');
			}
			block_text += formatted->text;
			const auto runtime = disasm_view::runtime_address(context, instruction.address).value_or(
				instruction.address.value);
			char prefix[32]{};
			std::snprintf(prefix, sizeof(prefix), "%016llX  ",
				static_cast<unsigned long long>(runtime));
			addressed_text += prefix;
			addressed_text += formatted->text;
		}
		if (complete_text) {
			const std::string evidence_text = addressed_text;
			const std::string graph_name = disasm_view::resolve_name(context, context_block->start);
			const std::string evidence_label = graph_name.empty()
				? std::string(address_text) : graph_name;
			const std::string evidence_return = std::string(address_text);
			const auto queue_evidence = [context, address, block_id = context_block->id,
				evidence_text, evidence_label, evidence_return](bool agent) {
				aida::automation_ui::evidence_envelope_t envelope;
				envelope.workspace_id = context.workspace->identity().binary_id().to_hex();
				envelope.source_view_id = "document.graph";
				envelope.source_kind = "basic_block";
				envelope.entity_id = "block:" + std::to_string(block_id);
				envelope.display_label = evidence_label;
				envelope.return_target = "address:" + evidence_return;
				envelope.excerpt = evidence_text;
				envelope.address = address;
				envelope.revision = context.publication->analysis_revision;
				envelope.generation = context.publication->generation;
				envelope.snapshot_hash = workspace_graph_generation(context);
				envelope.content_hash = workspace_graph_evidence_hash(evidence_text);
				const auto evidence_id = aida::automation_ui::register_evidence(std::move(envelope));
				if (evidence_id.empty())
					return action_handler_result_t::failed(
						"The bounded evidence registry rejected this graph block");
				std::string error;
				const bool queued = agent
					? aida::automation_ui::queue_evidence_for_agent(evidence_id, error)
					: aida::automation_ui::queue_evidence_for_chat(evidence_id, error);
				return queued ? action_handler_result_t::completed()
					: action_handler_result_t::failed(error);
			};
			menu.actions["analysis.evidence.chat"].invoke = [queue_evidence]() {
				return queue_evidence(false);
			};
			menu.actions["analysis.evidence.agent"].invoke = [queue_evidence]() {
				return queue_evidence(true);
			};
			menu.actions["analysis.copy.block"].invoke = [value = std::move(block_text)]() {
				ImGui::SetClipboardText(value.c_str());
				return action_handler_result_t::completed();
			};
			menu.actions["analysis.copy.block_addressed"].invoke =
				[value = std::move(addressed_text)]() {
					ImGui::SetClipboardText(value.c_str());
					return action_handler_result_t::completed();
				};
		} else {
			unavailable("analysis.copy.block", "Block formatting is still in progress");
			unavailable("analysis.copy.block_addressed", "Block formatting is still in progress");
			unavailable("analysis.evidence.chat", "Block formatting is still in progress");
			unavailable("analysis.evidence.agent", "Block formatting is still in progress");
		}
		if (typed) {
			const bool bookmarked = disasm_view::bookmarked(context, *typed);
			menu.actions["analysis.modify.rename"].invoke = [context, value = *typed]() {
				rename_dialog::open(context, value);
				return action_handler_result_t::completed();
			};
			menu.actions["analysis.modify.comment"].invoke = [context, value = *typed]() {
				comment_dialog::open(context, value);
				return action_handler_result_t::completed();
			};
			if (bookmarked) {
				unavailable("analysis.modify.bookmark", "The selected address is already bookmarked");
				menu.actions["analysis.modify.remove_bookmark"].invoke =
					[context, value = *typed]() {
						return disasm_view::queue_bookmark(context, value, {})
							? action_handler_result_t::completed()
							: action_handler_result_t::failed("The bookmark update was rejected");
					};
			} else {
				menu.actions["analysis.modify.bookmark"].invoke = [context, value = *typed,
					label = std::string(address_text)]() {
					return disasm_view::queue_bookmark(context, value, label)
						? action_handler_result_t::completed()
						: action_handler_result_t::failed("The bookmark update was rejected");
				};
				unavailable("analysis.modify.remove_bookmark", "The selected address is not bookmarked");
			}
		} else {
			unavailable("analysis.modify.rename", "The graph selection has no mapped workspace address");
			unavailable("analysis.modify.comment", "The graph selection has no mapped workspace address");
			unavailable("analysis.modify.bookmark", "The graph selection has no mapped workspace address");
			unavailable("analysis.modify.remove_bookmark", "The graph selection has no mapped workspace address");
		}
		menu.actions["analysis.graph.fit"].invoke = [view]() {
			view->fit_request = true;
			return action_handler_result_t::completed();
		};
		menu.actions["analysis.graph.zoom_in"].invoke = [view]() {
			view->target_zoom = (std::min)(2.5f, view->target_zoom * 1.18f);
			return action_handler_result_t::completed();
		};
		menu.actions["analysis.graph.zoom_out"].invoke = [view]() {
			view->target_zoom = (std::max)(0.16f, view->target_zoom * 0.85f);
			return action_handler_result_t::completed();
		};
		menu.actions["analysis.graph.reset"].invoke = [view]() {
			view->zoom = 1.0f;
			view->target_zoom = 1.0f;
			view->pan_x = 0.0f;
			view->pan_y = 0.0f;
			return action_handler_result_t::completed();
		};
		menu.actions["analysis.graph.select_block"].invoke = [view, id = context_block->id,
			address]() {
			view->selected_block = id;
			view->selected_address = address;
			return action_handler_result_t::completed();
		};
		menu.actions["analysis.graph.clear_selection"].invoke = [view]() {
			view->selected_block.reset();
			view->selected_instruction.reset();
			view->selected_address = 0;
			return action_handler_result_t::completed();
		};
		unavailable("analysis.navigate.disassembly_side",
			"Independent side documents require per-instance disassembly presentation state");
		unavailable("analysis.modify.assemble",
			"No assembler provider is registered; use reviewed Patch Bytes with explicitly assembled bytes");
		if (typed) {
			const auto selected_typed = *typed;
			const auto xrefs = xref_db_view::state_for(context);
			if (xrefs) {
				menu.actions["analysis.navigate.callees"].invoke =
					[context, xrefs, selected_typed, validate_retained_action]() {
						if (const auto reason = validate_retained_action(); !reason.empty())
							return action_handler_result_t::failed(reason);
						if (xrefs->searching.load(std::memory_order_acquire))
							return action_handler_result_t::failed(
								"The bounded References query is still running; cancel or wait before requesting callees");
						const auto opened = aida::ui::application_views::open_or_focus(
							aida::ui::stable_view_id_t("view.analysis.references"));
						if (!opened.ok())
							return action_handler_result_t::failed(opened.detail.empty()
								? "The canonical References view could not be opened" : opened.detail);
						xref_db_view::submit_query(context, xrefs, selected_typed, false);
						std::lock_guard<std::mutex> lock(xrefs->mutex);
						return xrefs->error.empty()
							? action_handler_result_t::completed()
							: action_handler_result_t::failed(xrefs->error);
					};
			} else {
				unavailable("analysis.navigate.callees",
					"The canonical bounded References owner is unavailable for this workspace");
			}
			menu.actions["analysis.modify.retype"].invoke =
				[context, selected_typed, validate_retained_action]() {
					if (const auto reason = validate_retained_action(); !reason.empty())
						return action_handler_result_t::failed(reason);
					const auto opened = aida::ui::application_views::open_or_focus(
						aida::ui::stable_view_id_t("view.types.structures"));
					if (!opened.ok())
						return action_handler_result_t::failed(opened.detail.empty()
							? "The canonical Structures view could not be opened" : opened.detail);
					std::string error;
					if (!types_hub_view::stage_type_application(context, selected_typed, &error))
						return action_handler_result_t::failed(error);
					return action_handler_result_t::completed();
				};
			const auto extent = selected_instruction
				? static_cast<std::uint64_t>(selected_instruction->length) : 0;
			const bool provider_backed = extent != 0 &&
				disasm_view::provider_offset(context, selected_typed).has_value();
			if (provider_backed) {
				menu.actions["analysis.modify.patch"].invoke =
					[context, selected_typed, extent, validate_retained_action]() {
						if (const auto reason = validate_retained_action(); !reason.empty())
							return action_handler_result_t::failed(reason);
						std::string error;
						if (!disasm_view::open_static_patch_review(context, selected_typed, extent,
								disasm_view::static_patch_mode_t::bytes, &error))
							return action_handler_result_t::failed(error);
						return action_handler_result_t::completed();
					};
				menu.actions["analysis.modify.nop"].invoke =
					[context, selected_typed, extent, validate_retained_action]() {
						if (const auto reason = validate_retained_action(); !reason.empty())
							return action_handler_result_t::failed(reason);
						std::string error;
						if (!disasm_view::open_static_patch_review(context, selected_typed, extent,
								disasm_view::static_patch_mode_t::nop_fill, &error))
							return action_handler_result_t::failed(error);
						return action_handler_result_t::completed();
					};
			} else {
				unavailable("analysis.modify.patch",
					"The selected graph instruction has no fully provider-backed byte range");
				unavailable("analysis.modify.nop",
					"The selected graph instruction has no fully provider-backed byte range");
			}
			const auto process = context.workspace->identity().process();
			const auto debugger_mutation_context = debugger_interaction::capture(
				debugger_interaction::kind_t::instruction, address, 0, -1, 0, extent);
			const auto breakpoint_definition_context = debugger_interaction::capture(
				debugger_interaction::kind_t::breakpoint, address);
			const bool debugger_matches_workspace_process = process &&
				process->creation_time_100ns != 0 &&
				driver_bridge::attached_pid() == process->pid &&
				debugger_mutation_context.target_pid == process->pid &&
				debugger_mutation_context.process_creation_time_100ns ==
					process->creation_time_100ns &&
				debugger_interaction::is_current(debugger_mutation_context) &&
				breakpoint_definition_context.target_pid == process->pid &&
				breakpoint_definition_context.process_creation_time_100ns ==
					process->creation_time_100ns &&
				debugger_interaction::is_current(breakpoint_definition_context);
			if (debugger_matches_workspace_process) {
				if (extent != 0) {
					menu.actions["analysis.modify.patch"].invoke =
						[extent, debugger_mutation_context,
						 validate_retained_action]() {
							if (const auto reason = validate_retained_action(); !reason.empty())
								return action_handler_result_t::failed(reason);
							if (!debugger_interaction::is_current(debugger_mutation_context))
								return action_handler_result_t::failed(
									"The graph workspace process identity or debugger stop changed before patch review");
							const auto opened = aida::ui::application_views::open_or_focus(
								aida::ui::stable_view_id_t("view.debug.patches"));
							if (!opened.ok())
								return action_handler_result_t::failed(opened.detail.empty()
									? "The canonical Patches view could not be opened" : opened.detail);
							std::string error;
							if (!debugger_view::stage_patch_review(debugger_mutation_context, extent,
									"Reviewed patch from Graph", &error))
								return action_handler_result_t::failed(error);
							return action_handler_result_t::completed();
						};
					menu.actions["analysis.modify.patch"].capability =
						capability_state_t::available();
					menu.actions["analysis.modify.nop"].invoke =
						[extent, debugger_mutation_context,
						 validate_retained_action]() {
							if (const auto reason = validate_retained_action(); !reason.empty())
								return action_handler_result_t::failed(reason);
							if (!debugger_interaction::is_current(debugger_mutation_context))
								return action_handler_result_t::failed(
									"The graph workspace process identity or debugger stop changed before NOP review");
							const auto opened = aida::ui::application_views::open_or_focus(
								aida::ui::stable_view_id_t("view.debug.patches"));
							if (!opened.ok())
								return action_handler_result_t::failed(opened.detail.empty()
									? "The canonical Patches view could not be opened" : opened.detail);
							std::string error;
							if (!debugger_view::stage_nop_review(
									debugger_mutation_context, extent, &error))
								return action_handler_result_t::failed(error);
							return action_handler_result_t::completed();
						};
					menu.actions["analysis.modify.nop"].capability =
						capability_state_t::available();
				} else {
					unavailable("analysis.modify.patch",
						"The selected graph block has no exact instruction byte range");
					unavailable("analysis.modify.nop",
						"The selected graph block has no exact instruction byte range");
				}
				const auto breakpoint_capability = debugger_view::address_mutation_capability(
					debugger_mutation_context, true);
				if (breakpoint_capability.enabled) {
					menu.actions["analysis.debug.breakpoint"].invoke =
						[breakpoint_definition_context, validate_retained_action]() {
							if (const auto reason = validate_retained_action(); !reason.empty())
								return action_handler_result_t::failed(reason);
							std::string error;
							if (!debugger_view::queue_toggle_breakpoint(
									breakpoint_definition_context, &error))
								return action_handler_result_t::failed(error);
							return action_handler_result_t::completed();
						};
					menu.actions["analysis.debug.hardware_breakpoint"].invoke =
						[breakpoint_definition_context,
						 validate_retained_action]() {
							if (const auto reason = validate_retained_action(); !reason.empty())
								return action_handler_result_t::failed(reason);
							const auto capability = debugger_view::address_mutation_capability(
								breakpoint_definition_context, true);
							if (!capability.enabled)
								return action_handler_result_t::failed(capability.disabled_reason
									? capability.disabled_reason : "Breakpoint staging is unavailable");
							const auto opened = aida::ui::application_views::open_or_focus(
								aida::ui::stable_view_id_t("view.debug.breakpoints"));
							if (!opened.ok())
								return action_handler_result_t::failed(opened.detail.empty()
									? "The canonical Breakpoints view could not be opened" : opened.detail);
							std::string error;
							if (!debugger_view::stage_breakpoint_definition(
									breakpoint_definition_context,
									debugger_view::breakpoint_definition_mode_t::hardware_execute,
									&error))
								return action_handler_result_t::failed(error);
							return action_handler_result_t::completed();
						};
				} else {
					const std::string reason = breakpoint_capability.disabled_reason
						? breakpoint_capability.disabled_reason : "Breakpoint staging is unavailable";
					unavailable("analysis.debug.breakpoint", reason);
					unavailable("analysis.debug.hardware_breakpoint", reason);
				}
			} else {
				const std::string reason = !process
					? "Breakpoint definitions require a process-backed debugger workspace"
					: process->creation_time_100ns == 0
					? "The graph workspace lacks a verified process creation identity"
					: driver_bridge::attached_pid() == process->pid
					? "The attached process reused the graph workspace PID with a different creation identity"
					: "Attach the debugger to PID " + std::to_string(process->pid) +
						" before staging a graph breakpoint";
				unavailable("analysis.debug.breakpoint", reason);
				unavailable("analysis.debug.hardware_breakpoint", reason);
			}
		} else {
			unavailable("analysis.navigate.callees",
				"The graph selection has no mapped workspace address");
			unavailable("analysis.modify.retype",
				"The graph selection has no mapped workspace address");
			unavailable("analysis.modify.patch",
				"The graph selection has no mapped workspace address");
			unavailable("analysis.modify.nop",
				"The graph selection has no mapped workspace address");
			unavailable("analysis.debug.breakpoint",
				"The graph selection has no mapped workspace address");
			unavailable("analysis.debug.hardware_breakpoint",
				"The graph selection has no mapped workspace address");
		}
		return menu;
	};
	const auto make_workspace_graph_canvas_context = [&]() {
		using namespace aida::ui::analysis_context_menu;
		using aida::ui::action_handler_result_t;
		context_t menu;
		menu.kind = menu_kind_t::graph;
		menu.entity_id = "graph-canvas:" +
			context.workspace->identity().binary_id().to_hex();
		menu.generation = workspace_graph_generation(context);
		menu.live_generation = [context]() { return workspace_graph_generation(context); };
		menu.validate_identity = [context, view]() {
			return workspace_graph_state(context) == view
				? aida::ui::capability_state_t::available()
				: aida::ui::capability_state_t::unavailable(
					"The active graph canvas changed");
		};
		menu.actions["analysis.graph.fit"].invoke = [view]() {
			view->fit_request = true;
			return action_handler_result_t::completed();
		};
		return menu;
	};
	if (context_requested && context_block)
		aida::ui::analysis_context_menu::open(
			make_workspace_graph_context(*context_block), context_origin);
	if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
		!io.WantTextInput && !ImGui::IsAnyItemActive()) {
		if (!io.KeyCtrl && !io.KeyAlt && ImGui::IsKeyPressed(ImGuiKey_F, false)) {
			bool executed = false;
			if (view->selected_block) {
				const auto found = view->node_by_entity.find(*view->selected_block);
				if (found != view->node_by_entity.end() &&
					found->second < view->block_indices.size())
					executed = aida::ui::analysis_context_menu::execute_shortcut(
						make_workspace_graph_context(
							snapshot.blocks[view->block_indices[found->second]]),
						"analysis.graph.fit");
			}
			if (!executed)
					aida::ui::analysis_context_menu::execute_shortcut(
						make_workspace_graph_canvas_context(), "analysis.graph.fit");
		}
		if (!io.KeyCtrl && !io.KeyAlt && view->selected_block &&
			(ImGui::IsKeyPressed(ImGuiKey_Enter, false) ||
			 ImGui::IsKeyPressed(ImGuiKey_KeypadEnter, false))) {
			const auto found = view->node_by_entity.find(*view->selected_block);
			if (found != view->node_by_entity.end() &&
				found->second < view->block_indices.size())
				aida::ui::analysis_context_menu::execute_shortcut(
					make_workspace_graph_context(
						snapshot.blocks[view->block_indices[found->second]]),
					"analysis.graph.navigate_target");
		}
	}
	if (!view->layout.nodes.empty() && canvas_size.x >= 320.0f && canvas_size.y >= 220.0f) {
		const float minimap_width = 214.0f;
		const float minimap_height = 132.0f;
		const ImVec2 map_min(canvas_max.x - minimap_width - 12.0f,
			canvas_max.y - minimap_height - 12.0f);
		const ImVec2 map_max(map_min.x + minimap_width, map_min.y + minimap_height);
		draw->AddRectFilled(map_min, map_max,
			aida::ui::with_alpha(theme.bg_overlay, alpha * 0.96f), 6.0f);
		draw->AddRect(map_min, map_max,
			aida::ui::with_alpha(theme.border_strong, alpha), 6.0f);
		draw->AddText(ImVec2(map_min.x + 8.0f, map_min.y + 4.0f),
			aida::ui::with_alpha(theme.text_dim, alpha), "Overview");
		const float map_pad = 9.0f;
		const float map_top = 21.0f;
		const float graph_width = (std::max)(1.0f, max_x - min_x);
		const float graph_height = (std::max)(1.0f, max_y - min_y);
		const float map_scale = (std::min)(
			(minimap_width - map_pad * 2.0f) / graph_width,
			(minimap_height - map_top - map_pad) / graph_height);
		const float map_ox = map_min.x + map_pad +
			((minimap_width - map_pad * 2.0f) - graph_width * map_scale) * 0.5f;
		const float map_oy = map_min.y + map_top +
			((minimap_height - map_top - map_pad) - graph_height * map_scale) * 0.5f;
		auto world_to_map = [&](float x, float y) {
			return ImVec2(map_ox + (x - min_x) * map_scale,
				map_oy + (y - min_y) * map_scale);
		};
		for (const auto& edge : view->edges) {
			const auto& from = view->layout.nodes[static_cast<std::size_t>(edge.from)];
			const auto& to = view->layout.nodes[static_cast<std::size_t>(edge.to)];
			draw->AddLine(world_to_map(from.x, from.y + from.height * 0.5f),
				world_to_map(to.x, to.y + to.height * 0.5f),
				workspace_graph_edge_color(edge.kind, theme, alpha * 0.46f,
					outgoing[static_cast<std::size_t>(edge.from)] > 1), 1.0f);
		}
		for (std::size_t index = 0; index < view->layout.nodes.size(); ++index) {
			const auto& node = view->layout.nodes[index];
			const ImVec2 a = world_to_map(node.x - node.width * 0.5f, node.y);
			const ImVec2 b = world_to_map(node.x + node.width * 0.5f, node.y + node.height);
			const auto& block = snapshot.blocks[view->block_indices[index]];
			const bool selected = view->selected_block && *view->selected_block == block.id;
			draw->AddRectFilled(a, b, aida::ui::with_alpha(
				selected ? theme.accent_u32 : theme.text_secondary, alpha * 0.72f), 1.0f);
		}
		const float world_view_width = canvas_size.x / view->zoom;
		const float world_view_height = canvas_size.y / view->zoom;
		const ImVec2 viewport_min = world_to_map(-view->pan_x - world_view_width * 0.5f,
			-view->pan_y - world_view_height * 0.5f);
		const ImVec2 viewport_max = world_to_map(-view->pan_x + world_view_width * 0.5f,
			-view->pan_y + world_view_height * 0.5f);
		draw->AddRectFilled(viewport_min, viewport_max,
			aida::ui::with_alpha(theme.accent_glow, alpha * 0.8f), 2.0f);
		draw->AddRect(viewport_min, viewport_max,
			aida::ui::with_alpha(theme.accent_u32, alpha), 2.0f, 0, 1.3f);
		const bool minimap_hovered = ImGui::IsMouseHoveringRect(map_min, map_max, false);
		if (minimap_hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
			view->minimap_dragging = true;
		if (view->minimap_dragging) {
			if (ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
				view->pan_x = -(min_x + (io.MousePos.x - map_ox) / map_scale);
				view->pan_y = -(min_y + (io.MousePos.y - map_oy) / map_scale);
			} else {
				view->minimap_dragging = false;
			}
		}
	}
	aida::ui::analysis_context_menu::render();
	comment_dialog::render();
	rename_dialog::render();
	ImGui::EndChild();
	ImGui::EndChild();
	ImGui::PopID();
}

}
