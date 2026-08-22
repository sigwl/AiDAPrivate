#pragma once

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../preview/scan_aob_preview.hpp"
#else

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <exception>
#include <filesystem>
#include <functional>
#include <cmath>
#include <mutex>
#include <memory>
#include <set>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <nlohmann/json.hpp>

#include "../infra/executor.hpp"
#include "standalone_driver.hpp"
#include "zydis_disasm.hpp"
#include "disasm_view.hpp"
#include "../helpers/diag_log.hpp"
#include "../ui/toast_notification.hpp"

#ifdef AIDA_STANDALONE
#include <Zydis/Zydis.h>
#endif

namespace aob_generator {

struct aob_byte_t {
	uint8_t value = 0;
	bool    wildcard = false;
};

struct signature_t {
	uint64_t             id = 0;
	std::string          name;
	uint64_t             address = 0;
	std::vector<aob_byte_t> bytes;
	bool                 unique = false;
	int                  uniqueness_count = 0;
	std::string          module_name;
	float                quality_score = 0.f;
};

struct state_t {
	std::vector<signature_t> saved_signatures;
	std::atomic<std::uint64_t> catalog_generation{1};
	signature_t              current;
	std::mutex               mutex;
	std::atomic<bool>        generating{false};
	std::atomic<bool>        validating{false};
	std::atomic<bool>        batch_generating{false};
	std::atomic<int>         batch_total{0};
	std::atomic<int>         batch_done{0};
	char                     address_input[32] = {};
	char                     name_input[64] = {};
	int                      instruction_count = 16;
	bool                     auto_wildcard = true;
	bool                     validate_uniqueness = true;
	std::string              last_error;
	std::string              pending_clipboard;
	std::atomic<bool>        pending_clipboard_ready{false};
	uint64_t                 last_request_addr = 0;
	int                      last_request_count = 0;
	bool                     last_request_auto_wildcard = true;
	bool                     show_no_address_modal = false;
};

inline state_t g_state;

inline std::mutex& workspace_states_mutex()
{
	static std::mutex mutex;
	return mutex;
}

inline std::unordered_map<std::string, std::shared_ptr<state_t>>& workspace_states()
{
	static std::unordered_map<std::string, std::shared_ptr<state_t>> states;
	return states;
}

inline std::shared_ptr<state_t> state_for(const disasm_view::workspace_context_t& context)
{
	if (!context.workspace) return {};
	const std::string key = context.workspace->identity().binary_id().to_hex();
	std::lock_guard<std::mutex> lock(workspace_states_mutex());
	auto& state = workspace_states()[key];
	if (!state) {
		state = std::make_shared<state_t>();
	}
	return state;
}

inline std::shared_ptr<state_t> legacy_state()
{
	return std::shared_ptr<state_t>(&g_state, [](state_t*) {});
}

inline std::atomic<uint64_t> g_next_signature_id{1};

inline uint64_t allocate_signature_id()
{
	return g_next_signature_id.fetch_add(1, std::memory_order_relaxed);
}

inline std::string format_signature(const signature_t& sig)
{
	std::string result;
	result.reserve(sig.bytes.size() * 3);
	for (size_t i = 0; i < sig.bytes.size(); ++i) {
		if (i > 0) result += ' ';
		if (sig.bytes[i].wildcard) {
			result += "??";
		} else {
			char buf[4];
			std::snprintf(buf, sizeof(buf), "%02X", sig.bytes[i].value);
			result += buf;
		}
	}
	return result;
}

inline std::string format_ida_signature(const signature_t& sig)
{
	std::string result;
	result.reserve(sig.bytes.size() * 4);
	for (size_t i = 0; i < sig.bytes.size(); ++i) {
		if (i > 0) result += ' ';
		if (sig.bytes[i].wildcard) {
			result += '?';
		} else {
			char buf[4];
			std::snprintf(buf, sizeof(buf), "%02X", sig.bytes[i].value);
			result += buf;
		}
	}
	return result;
}

inline std::string format_code_signature(const signature_t& sig)
{
	std::string pattern = "\"";
	std::string mask = "\"";
	for (auto& b : sig.bytes) {
		char buf[8];
		if (b.wildcard) {
			pattern += "\\x00";
			mask += "?";
		} else {
			std::snprintf(buf, sizeof(buf), "\\x%02X", b.value);
			pattern += buf;
			mask += "x";
		}
	}
	pattern += "\"";
	mask += "\"";
	return pattern + ", " + mask;
}

inline std::string format_yara_rule(const signature_t& sig)
{
	std::string safe_name;
	for (char c : sig.name) {
		if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '_')
			safe_name += c;
		else
			safe_name += '_';
	}
	if (safe_name.empty()) safe_name = "unnamed_sig";
	if (safe_name[0] >= '0' && safe_name[0] <= '9') safe_name = "sig_" + safe_name;

	std::string hex_str;
	hex_str.reserve(sig.bytes.size() * 3);
	for (size_t i = 0; i < sig.bytes.size(); ++i) {
		if (i > 0) hex_str += ' ';
		if (sig.bytes[i].wildcard) {
			hex_str += "??";
		} else {
			char buf[4];
			std::snprintf(buf, sizeof(buf), "%02X", sig.bytes[i].value);
			hex_str += buf;
		}
	}

	std::string rule;
	rule += "rule " + safe_name + "\n";
	rule += "{\n";
	rule += "    meta:\n";
	rule += "        address = \"0x";
	char addr_buf[20];
	std::snprintf(addr_buf, sizeof(addr_buf), "%llX", static_cast<unsigned long long>(sig.address));
	rule += addr_buf;
	rule += "\"\n";
	if (!sig.module_name.empty())
		rule += "        module = \"" + sig.module_name + "\"\n";
	char q_buf[16];
	std::snprintf(q_buf, sizeof(q_buf), "%.1f", sig.quality_score);
	rule += "        quality = \"" + std::string(q_buf) + "\"\n";
	rule += "    strings:\n";
	rule += "        $pattern = { " + hex_str + " }\n";
	rule += "    condition:\n";
	rule += "        $pattern\n";
	rule += "}\n";
	return rule;
}

inline std::string format_x64dbg_signature(const signature_t& sig)
{
	std::string result;
	result.reserve(sig.bytes.size() * 3);
	for (size_t i = 0; i < sig.bytes.size(); ++i) {
		if (i > 0) result += ' ';
		if (sig.bytes[i].wildcard) {
			result += "??";
		} else {
			char buf[4];
			std::snprintf(buf, sizeof(buf), "%02x", sig.bytes[i].value);
			result += buf;
		}
	}
	return result;
}

namespace detail {

#ifdef AIDA_STANDALONE

struct decoded_instr_t {
	ZydisDecodedInstruction instr;
	ZydisDecodedOperand     operands[ZYDIS_MAX_OPERAND_COUNT];
	uint64_t                address;
	uint8_t                 raw[15];
	uint8_t                 length;
};

inline bool should_wildcard_operand_bytes(const ZydisDecodedInstruction& instr,
                                           const ZydisDecodedOperand* operands,
                                           size_t op_count)
{
	for (size_t i = 0; i < op_count && i < instr.operand_count; ++i) {
		auto& op = operands[i];
		if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
			if (op.imm.is_relative) return true;
			if (instr.raw.imm[0].size >= 32) return true;
		}
		if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
			if (op.mem.base == ZYDIS_REGISTER_RIP) return true;
			if (op.mem.disp.has_displacement != ZYAN_FALSE && instr.raw.disp.size >= 32) return true;
		}
	}
	return false;
}

inline void wildcard_dynamic_bytes(decoded_instr_t& di, std::vector<aob_byte_t>& out)
{
	bool needs_wildcard = should_wildcard_operand_bytes(di.instr, di.operands, ZYDIS_MAX_OPERAND_COUNT);

	for (uint8_t b = 0; b < di.length; ++b) {
		aob_byte_t ab;
		ab.value = di.raw[b];
		ab.wildcard = false;

		if (needs_wildcard) {
			if (di.instr.raw.disp.size > 0) {
				uint8_t disp_off = di.instr.raw.disp.offset;
				uint8_t disp_sz = static_cast<uint8_t>(di.instr.raw.disp.size / 8);
				if (b >= disp_off && b < disp_off + disp_sz) {
					ab.wildcard = true;
				}
			}
			for (int imm_idx = 0; imm_idx < 2; ++imm_idx) {
				if (di.instr.raw.imm[imm_idx].size > 0) {
					uint8_t imm_off = di.instr.raw.imm[imm_idx].offset;
					uint8_t imm_sz = static_cast<uint8_t>(di.instr.raw.imm[imm_idx].size / 8);
					if (b >= imm_off && b < imm_off + imm_sz) {
						ab.wildcard = true;
					}
				}
			}
		}

		out.push_back(ab);
	}
}

#endif

inline int count_pattern_in_data(const uint8_t* data, size_t data_len,
                                  const std::vector<aob_byte_t>& pattern)
{
	if (pattern.empty() || data_len < pattern.size()) return 0;
	int count = 0;
	size_t limit = data_len - pattern.size();
	for (size_t i = 0; i <= limit; ++i) {
		bool match = true;
		for (size_t j = 0; j < pattern.size(); ++j) {
			if (!pattern[j].wildcard && data[i + j] != pattern[j].value) {
				match = false;
				break;
			}
		}
		if (match) {
			++count;
			if (count > 1) return count;
		}
	}
	return count;
}

}

inline float compute_quality_score(const signature_t& sig)
{
	if (sig.bytes.empty()) return 0.f;

	size_t total = sig.bytes.size();
	size_t wildcards = 0;
	for (auto& b : sig.bytes) {
		if (b.wildcard) ++wildcards;
	}

	float wildcard_ratio = static_cast<float>(wildcards) / static_cast<float>(total);
	float specificity = 1.f - wildcard_ratio;

	float length_score;
	if (total >= 32) length_score = 1.f;
	else if (total >= 16) length_score = 0.7f + 0.3f * (static_cast<float>(total) - 16.f) / 16.f;
	else if (total >= 8) length_score = 0.4f + 0.3f * (static_cast<float>(total) - 8.f) / 8.f;
	else length_score = static_cast<float>(total) / 20.f;

	float uniqueness_bonus = 1.f;
	if (sig.uniqueness_count == 1) uniqueness_bonus = 1.3f;
	else if (sig.uniqueness_count > 1) uniqueness_bonus = 0.5f;

	float raw = specificity * length_score * uniqueness_bonus;
	if (raw > 1.f) raw = 1.f;
	if (raw < 0.f) raw = 0.f;
	return raw;
}

inline const char* score_grade(float score)
{
	if (score >= 0.85f) return "A";
	if (score >= 0.7f) return "B";
	if (score >= 0.5f) return "C";
	if (score >= 0.3f) return "D";
	return "F";
}

inline void generate_from_address_with_state(
	const disasm_view::workspace_context_t& context,
	const std::shared_ptr<state_t>& state,
	uint64_t address,
	int num_instructions,
	bool auto_wildcard)
{
#ifdef AIDA_STANDALONE
	if (!state) return;
	if (!context.workspace || (context.workspace->identity().architecture() !=
		aida::analysis::architecture_id_t::x86 &&
		context.workspace->identity().architecture() !=
		aida::analysis::architecture_id_t::x86_64)) {
		std::lock_guard<std::mutex> lock(state->mutex);
		state->last_error = "AOB instruction signatures require an x86 or x86-64 workspace.";
		return;
	}
	char dbg_buf[256];
	std::snprintf(dbg_buf, sizeof(dbg_buf),
		"generate_from_address called va=0x%llX len=%d auto_wildcard=%d",
		static_cast<unsigned long long>(address), num_instructions, static_cast<int>(auto_wildcard));
	diag::log_tagged("aob", dbg_buf);
	diag::log_tagged("aob", dbg_buf);

	if (num_instructions < 1) num_instructions = 1;
	if (num_instructions > 128) num_instructions = 128;

	if (state->generating.load()) {
		diag::log_tagged("aob", "generate_from_address refused already_generating");
		diag::log_tagged("aob", "refused already_generating");
		{
			std::lock_guard<std::mutex> lk(state->mutex);
			state->last_error = "Generator is already busy with another address.";
		}
		return;
	}
	if (address == 0) {
		std::snprintf(dbg_buf, sizeof(dbg_buf),
			"failed reason=zero_address addr=0x%llX",
			static_cast<unsigned long long>(address));
		diag::log_tagged("aob", dbg_buf);
		diag::log_tagged("aob", dbg_buf);
		{
			std::lock_guard<std::mutex> lk(state->mutex);
			state->last_error = "No address selected. Click an instruction in the disassembly first.";
		}
		return;
	}
	{
		std::lock_guard<std::mutex> lk(state->mutex);
		state->last_request_addr = address;
		state->last_request_count = num_instructions;
		state->last_request_auto_wildcard = auto_wildcard;
		state->last_error.clear();
	}
	const bool workspace_available = static_cast<bool>(context.workspace);
	const bool driver_attached = workspace_available &&
		context.workspace->target_kind() == aida::analysis::target_kind_t::live_snapshot;
	const bool static_pe_available = workspace_available &&
		context.workspace->target_kind() == aida::analysis::target_kind_t::static_file &&
		static_cast<bool>(context.image);
	const uint32_t drv_pid = driver_attached && context.workspace->identity().process()
		? context.workspace->identity().process()->pid : 0;
	const size_t static_section_count = static_pe_available ? context.image->sections().size() : 0;
	const uint64_t static_image_base = static_pe_available ? context.image->image_base() : 0;

	if (driver_attached) {
		std::snprintf(dbg_buf, sizeof(dbg_buf), "source=live attached_pid=%u", drv_pid);
	} else {
		std::snprintf(dbg_buf, sizeof(dbg_buf),
			"source=static_pe loaded=%d sections=%zu image_base=0x%llX",
			static_cast<int>(static_pe_available), static_section_count,
			static_cast<unsigned long long>(static_image_base));
	}
	diag::log_tagged("aob", dbg_buf);
	diag::log_tagged("aob", dbg_buf);

	if (!driver_attached && !static_pe_available) {
		std::snprintf(dbg_buf, sizeof(dbg_buf),
			"failed reason=no_source addr=0x%llX driver_loaded=%d pid=%u static=%d",
			static_cast<unsigned long long>(address),
			static_cast<int>(driver_attached), drv_pid,
			static_cast<int>(static_pe_available));
		diag::log_tagged("aob", dbg_buf);
		diag::log_tagged("aob", dbg_buf);
		{
			std::lock_guard<std::mutex> lk(state->mutex);
			state->last_error = "No data source available. Attach a process or open a PE file.";
		}
		return;
	}
	std::snprintf(dbg_buf, sizeof(dbg_buf),
		"generate_from_address start addr=0x%llX instructions=%d auto_wildcard=%d source=%s",
		static_cast<unsigned long long>(address), num_instructions,
		static_cast<int>(auto_wildcard),
		driver_attached ? "live" : "static_pe");
	diag::log_tagged("aob", dbg_buf);
	diag::log_tagged("aob", dbg_buf);

	state->generating.store(true);

	const std::uint64_t request_generation = context.workspace->generation();
	auto task = [context, state, address, num_instructions, auto_wildcard,
		driver_attached, static_pe_available, drv_pid, request_generation]() {
		try {
		auto t_start = std::chrono::steady_clock::now();
		char lbuf[256];
		std::snprintf(lbuf, sizeof(lbuf),
			"worker enter addr=0x%llX driver_attached=%d static=%d",
			static_cast<unsigned long long>(address),
			static_cast<int>(driver_attached),
			static_cast<int>(static_pe_available));
		diag::log_tagged("aob", lbuf);
		diag::log_tagged("aob", lbuf);

		signature_t sig;
		sig.id = allocate_signature_id();
		sig.address = address;

		uint64_t module_base = 0;
		uint64_t module_size = 0;
		bool got_module = false;
		if (driver_attached && context.workspace->identity().module()) {
			const auto& module = *context.workspace->identity().module();
			if (address >= module.base && address - module.base < module.size) {
				sig.module_name = module.normalized_name;
				module_base = module.base;
				module_size = module.size;
				got_module = true;
			}
			std::snprintf(lbuf, sizeof(lbuf),
				"module_lookup live found=%d module_base=0x%llX module_size=%llu",
				static_cast<int>(got_module),
				static_cast<unsigned long long>(module_base),
				static_cast<unsigned long long>(module_size));
			diag::log_tagged("aob", lbuf);
		}
		if (!got_module && static_pe_available) {
			sig.module_name = context.workspace->identity().bin_name();
		}

		size_t read_size = static_cast<size_t>(num_instructions) * 15;
		std::vector<uint8_t> code;
		bool read_ok = false;
		const char* source_label = "none";

		const auto typed = disasm_view::typed_address(context, address);
		if (typed) {
			if (const auto provider_offset = disasm_view::provider_offset(context, *typed))
				read_size = static_cast<size_t>((std::min)(
					static_cast<std::uint64_t>(read_size),
					context.workspace->provider().size() - *provider_offset));
			auto bytes = disasm_view::read_bytes(context, *typed, read_size);
			if (bytes) {
				code = std::move(bytes.value());
				read_ok = !code.empty();
				source_label = driver_attached ? "live_snapshot" : "static_workspace";
			}
			std::snprintf(lbuf, sizeof(lbuf),
				"read_bytes ok=%d got=%zu requested=%zu source=%s addr=0x%llX sections=%zu",
				static_cast<int>(read_ok), code.size(), read_size, source_label,
				static_cast<unsigned long long>(address),
				static_pe_available ? context.image->sections().size() : 0);
			diag::log_tagged("aob", lbuf);
			diag::log_tagged("aob", lbuf);
		}
		if (!read_ok || code.empty()) {
			std::snprintf(lbuf, sizeof(lbuf),
				"failed reason=read_empty addr=0x%llX size=%zu driver=%d static=%d",
				static_cast<unsigned long long>(address), read_size,
				static_cast<int>(driver_attached),
				static_cast<int>(static_pe_available));
			diag::log_tagged("aob", lbuf);
			diag::log_tagged("aob", lbuf);
			{
				std::lock_guard<std::mutex> lk(state->mutex);
				state->last_error = "Failed to read bytes at the requested address.";
			}
			toast_notification::push(
				"AOB: Failed to read bytes at the requested address.",
				toast_notification::toast_type_t::error, 5.0f);
			state->generating.store(false);
			return;
		}

		ZydisDecoder decoder;
		const bool x64 = context.workspace->identity().architecture() ==
			aida::analysis::architecture_id_t::x86_64;
		ZydisDecoderInit(&decoder,
			x64 ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LEGACY_32,
			x64 ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32);

		std::vector<detail::decoded_instr_t> instrs;
		uint64_t offset = 0;
		int decoded_count = 0;

		while (offset < code.size() && decoded_count < num_instructions) {
			detail::decoded_instr_t di{};
			di.address = address + offset;

			auto status = ZydisDecoderDecodeFull(
				&decoder, code.data() + offset, code.size() - offset,
				&di.instr, di.operands);

			if (!ZYAN_SUCCESS(status)) break;

			di.length = static_cast<uint8_t>(di.instr.length);
			if (di.length == 0 || di.length > 15) break;
			std::memcpy(di.raw, code.data() + offset, di.length);

			instrs.push_back(di);
			offset += di.length;
			++decoded_count;
		}

		std::snprintf(lbuf, sizeof(lbuf),
			"decode result decoded=%zu requested=%d source=%s bytes_consumed=%llu code_size=%zu",
			instrs.size(), num_instructions, source_label,
			static_cast<unsigned long long>(offset), code.size());
		diag::log_tagged("aob", lbuf);

		if (instrs.empty()) {
			std::snprintf(lbuf, sizeof(lbuf),
				"failed reason=decode_error addr=0x%llX bytes=%zu source=%s first_byte=0x%02X",
				static_cast<unsigned long long>(address), code.size(), source_label,
				code.empty() ? 0u : code[0]);
			diag::log_tagged("aob", lbuf);
			diag::log_tagged("aob", lbuf);
			{
				std::lock_guard<std::mutex> lk(state->mutex);
				state->last_error = "Zydis failed to decode any instruction at this address.";
			}
			toast_notification::push(
				"AOB: Decoder couldn't read an instruction at that address.",
				toast_notification::toast_type_t::error, 5.0f);
			state->generating.store(false);
			return;
		}

		std::vector<aob_byte_t> pattern;
		pattern.reserve(static_cast<size_t>(num_instructions) * 8);
		for (auto& di : instrs) {
			if (auto_wildcard) {
				detail::wildcard_dynamic_bytes(di, pattern);
			} else {
				for (uint8_t b = 0; b < di.length; ++b) {
					aob_byte_t ab;
					ab.value = di.raw[b];
					ab.wildcard = false;
					pattern.push_back(ab);
				}
			}
		}

		if (pattern.empty()) {
			std::snprintf(lbuf, sizeof(lbuf),
				"failed reason=empty_pattern addr=0x%llX decoded=%zu",
				static_cast<unsigned long long>(address), instrs.size());
			diag::log_tagged("aob", lbuf);
			diag::log_tagged("aob", lbuf);
			{
				std::lock_guard<std::mutex> lk(state->mutex);
				state->last_error = "Decoded instructions produced no signature bytes.";
			}
			state->generating.store(false);
			return;
		}

		size_t pattern_size = pattern.size();
		size_t decoded_instrs = instrs.size();
		int wildcard_count = 0;
		for (auto& ab : pattern) if (ab.wildcard) ++wildcard_count;
		sig.bytes = std::move(pattern);
		sig.quality_score = compute_quality_score(sig);
		float qs = sig.quality_score;

		std::string copy_payload = format_signature(sig);

		{
			std::lock_guard<std::mutex> lk(state->mutex);
			if (context.workspace->generation() == request_generation) {
				state->current = std::move(sig);
				state->last_error.clear();
				state->pending_clipboard = copy_payload;
				state->pending_clipboard_ready.store(true, std::memory_order_release);
			} else {
				state->last_error = "Workspace generation changed while producing the signature.";
			}
		}

		auto t_end = std::chrono::steady_clock::now();
		uint64_t dur_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t_end - t_start).count();

		std::string preview = copy_payload.size() > 32
			? copy_payload.substr(0, 32) + "..."
			: copy_payload;
		std::snprintf(lbuf, sizeof(lbuf),
			"result sig=\"%s\" ok=1 reason=ok bytes=%zu wildcard=%d source=%s addr=0x%llX decoded=%zu quality=%.2f duration_ms=%llu",
			preview.c_str(), pattern_size, wildcard_count, source_label,
			static_cast<unsigned long long>(address), decoded_instrs,
			static_cast<double>(qs), static_cast<unsigned long long>(dur_ms));
		diag::log_tagged("aob", lbuf);
		diag::log_tagged("aob", lbuf);

		{
			char toast_buf[160];
			std::snprintf(toast_buf, sizeof(toast_buf),
				"AOB generated: %zu bytes, %d wildcards, quality %.0f%%",
				pattern_size, wildcard_count, static_cast<double>(qs) * 100.0);
			toast_notification::push(toast_buf,
				toast_notification::toast_type_t::info, 4.0f);
		}

		state->generating.store(false);
		} catch (const std::exception& ex) {
			diag::log_tagged_fmt("aob", "worker exception err='%s'", ex.what());
			{
				std::lock_guard<std::mutex> lk(state->mutex);
				state->last_error = ex.what();
			}
			state->generating.store(false);
		} catch (...) {
			diag::log_tagged("aob", "worker exception err='<unknown>'");
			{
				std::lock_guard<std::mutex> lk(state->mutex);
				state->last_error = "AOB worker threw an unknown exception.";
			}
			state->generating.store(false);
		}
	};

	aida::infra::executor::submission_t sub;
	sub.owner_subsystem = "scanner";
	sub.label = "scanner.aob_generate_process";
	sub.thread_class = "scanner_aob";
	sub.domain = aida::infra::executor::domain_t::feature_worker;
	sub.priority = 3;
	sub.target_pid = drv_pid;
	sub.body = std::move(task);
	const bool posted = aida::infra::executor::submit(std::move(sub)).submitted;
	if (!posted) {
		diag::log_tagged("aob", "worker_queue_rejected clearing_generating_flag");
		diag::log_tagged("aob", "worker queue rejected");
		state->generating.store(false);
		{
			std::lock_guard<std::mutex> lk(state->mutex);
			state->last_error = "Background worker queue rejected the task. Try again.";
		}
		toast_notification::push("AOB: Background worker queue rejected the task. Try again.",
			toast_notification::toast_type_t::error, 5.0f);
	}
#else
	(void)context;
	(void)state;
	(void)address;
	(void)num_instructions;
	(void)auto_wildcard;
#endif
}

inline void generate_from_address(
	const disasm_view::workspace_context_t& context,
	uint64_t address,
	int num_instructions,
	bool auto_wildcard)
{
	generate_from_address_with_state(context, state_for(context), address,
		num_instructions, auto_wildcard);
}

inline void generate_from_address(uint64_t address, int num_instructions, bool auto_wildcard)
{
	generate_from_address_with_state(disasm_view::capture_selected_workspace(), legacy_state(),
		address, num_instructions, auto_wildcard);
}

inline void regenerate_last()
{
#ifdef AIDA_STANDALONE
	uint64_t addr = 0;
	int count = 0;
	bool aw = true;
	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		addr = g_state.last_request_addr;
		count = g_state.last_request_count > 0 ? g_state.last_request_count : g_state.instruction_count;
		aw = g_state.last_request_auto_wildcard;
	}
	if (addr == 0) {
		std::lock_guard<std::mutex> lk(g_state.mutex);
		g_state.last_error = "No previous request to regenerate.";
		return;
	}
	generate_from_address(addr, count, aw);
#endif
}

inline void regenerate_last(const disasm_view::workspace_context_t& context,
	const std::shared_ptr<state_t>& state)
{
#ifdef AIDA_STANDALONE
	if (!state) return;
	uint64_t address = 0;
	int count = 0;
	bool auto_wildcard = true;
	{
		std::lock_guard<std::mutex> lock(state->mutex);
		address = state->last_request_addr;
		count = state->last_request_count > 0 ? state->last_request_count : state->instruction_count;
		auto_wildcard = state->last_request_auto_wildcard;
	}
	if (address == 0) {
		std::lock_guard<std::mutex> lock(state->mutex);
		state->last_error = "No previous request to regenerate.";
		return;
	}
	generate_from_address_with_state(context, state, address, count, auto_wildcard);
#else
	(void)context;
	(void)state;
#endif
}

inline bool take_pending_clipboard(std::string& out)
{
#ifdef AIDA_STANDALONE
	if (!g_state.pending_clipboard_ready.load(std::memory_order_acquire)) return false;
	std::lock_guard<std::mutex> lk(g_state.mutex);
	out = g_state.pending_clipboard;
	g_state.pending_clipboard.clear();
	g_state.pending_clipboard_ready.store(false, std::memory_order_release);
	return !out.empty();
#else
	(void)out;
	return false;
#endif
}

inline bool take_pending_clipboard(const std::shared_ptr<state_t>& state, std::string& out)
{
#ifdef AIDA_STANDALONE
	if (!state || !state->pending_clipboard_ready.load(std::memory_order_acquire)) return false;
	std::lock_guard<std::mutex> lock(state->mutex);
	out = state->pending_clipboard;
	state->pending_clipboard.clear();
	state->pending_clipboard_ready.store(false, std::memory_order_release);
	return !out.empty();
#else
	(void)state;
	(void)out;
	return false;
#endif
}

inline void generate_from_file(const DisasmFile& file, uint64_t address, int num_instructions, bool auto_wildcard)
{
#ifdef AIDA_STANDALONE
	if (g_state.generating.load()) return;
	g_state.generating.store(true);

	auto file_copy = file;
	aida::infra::executor::submission_t sub;
	sub.owner_subsystem = "scanner";
	sub.label = "scanner.aob_generate_file";
	sub.thread_class = "scanner_aob";
	sub.domain = aida::infra::executor::domain_t::feature_worker;
	sub.priority = 3;
	sub.body = [file_copy, address, num_instructions, auto_wildcard]() {
		signature_t sig;
		sig.id = allocate_signature_id();
		sig.address = address;
		sig.module_name = file_copy.filename;

		const uint8_t* code_data = nullptr;
		size_t code_size = 0;
		uint64_t section_va = 0;
		for (auto& sec : file_copy.sections) {
			uint64_t sec_start = sec.va;
			uint64_t sec_end = sec_start + sec.bytes.size();
			if (address >= sec_start && address < sec_end) {
				code_data = sec.bytes.data() + (address - sec_start);
				code_size = sec.bytes.size() - static_cast<size_t>(address - sec_start);
				section_va = sec.va;
				break;
			}
		}

		if (!code_data || code_size == 0) {
			g_state.generating.store(false);
			return;
		}

		ZydisDecoder decoder;
		ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

		std::vector<detail::decoded_instr_t> instrs;
		uint64_t offset = 0;
		int decoded_count = 0;

		while (offset < code_size && decoded_count < num_instructions) {
			detail::decoded_instr_t di{};
			di.address = address + offset;

			auto status = ZydisDecoderDecodeFull(
				&decoder, code_data + offset, code_size - offset,
				&di.instr, di.operands);

			if (!ZYAN_SUCCESS(status)) break;

			di.length = static_cast<uint8_t>(di.instr.length);
			std::memcpy(di.raw, code_data + offset, di.length);

			instrs.push_back(di);
			offset += di.length;
			++decoded_count;
		}

		std::vector<aob_byte_t> pattern;
		for (auto& di : instrs) {
			if (auto_wildcard) {
				detail::wildcard_dynamic_bytes(di, pattern);
			} else {
				for (uint8_t b = 0; b < di.length; ++b) {
					aob_byte_t ab;
					ab.value = di.raw[b];
					ab.wildcard = false;
					pattern.push_back(ab);
				}
			}
		}

		sig.bytes = std::move(pattern);
		sig.quality_score = compute_quality_score(sig);

		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			g_state.current = std::move(sig);
		}

		g_state.generating.store(false);
	};
	if (!aida::infra::executor::submit(std::move(sub)).submitted) {
		diag::log_tagged("aob", "generate_from_file worker_queue_rejected");
		g_state.generating.store(false);
		std::lock_guard<std::mutex> lk(g_state.mutex);
		g_state.last_error = "AOB file worker queue rejected the task.";
	}
#else
	(void)file;
	(void)address;
	(void)num_instructions;
	(void)auto_wildcard;
#endif
}

inline void validate_uniqueness_process(signature_t& sig)
{
	if (g_state.validating.load()) {
		diag::log_tagged("aob", "validate_uniqueness_process refused already_validating");
		return;
	}
	if (sig.id == 0) sig.id = allocate_signature_id();
	diag::log_tagged_fmt("aob", "validate_uniqueness_process start id=%llu bytes=%zu",
		static_cast<unsigned long long>(sig.id), sig.bytes.size());
	g_state.validating.store(true);

	aida::infra::executor::submission_t sub;
	sub.owner_subsystem = "scanner";
	sub.label = "scanner.aob_validate_uniqueness";
	sub.thread_class = "scanner_sweep";
	sub.domain = aida::infra::executor::domain_t::long_running;
	sub.priority = 2;
	sub.target_pid = driver_bridge::attached_pid();
	const uint32_t target_pid = sub.target_pid;
	sub.body = [sig_copy = sig, target_pid]() mutable {
		int total_count = 0;
		auto regions = driver_bridge::enumerate_memory_regions_for(target_pid, 4096);

		for (auto& region : regions) {
			if (region.state != 0x1000) continue;
			if (region.protect & 0x100) continue;
			uint32_t prot = region.protect & 0xFF;
			if (prot == 0x01 || prot == 0x00) continue;
			if (region.size > 0x10000000) continue;

			std::vector<uint8_t> data;
			if (!driver_bridge::read_memory_for(target_pid, region.base,
				static_cast<size_t>(region.size), data) ||
				data.size() != static_cast<size_t>(region.size)) continue;

			total_count += detail::count_pattern_in_data(data.data(), data.size(), sig_copy.bytes);
			if (total_count > 1) break;
		}

		sig_copy.unique = (total_count == 1);
		sig_copy.uniqueness_count = total_count;
		sig_copy.quality_score = compute_quality_score(sig_copy);
		diag::log_tagged_fmt("aob", "validate_uniqueness_process result id=%llu count=%d unique=%d quality=%.2f",
			static_cast<unsigned long long>(sig_copy.id), total_count,
			static_cast<int>(sig_copy.unique), static_cast<double>(sig_copy.quality_score));

		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			bool written = false;
			for (auto& live : g_state.saved_signatures) {
				if (live.id == sig_copy.id) {
					live.unique = sig_copy.unique;
					live.uniqueness_count = sig_copy.uniqueness_count;
					live.quality_score = sig_copy.quality_score;
					written = true;
					break;
				}
			}
			if (!written && g_state.current.id == sig_copy.id) {
				g_state.current.unique = sig_copy.unique;
				g_state.current.uniqueness_count = sig_copy.uniqueness_count;
				g_state.current.quality_score = sig_copy.quality_score;
			}
		}

		g_state.validating.store(false);
	};
	if (!aida::infra::executor::submit(std::move(sub)).submitted) {
		diag::log_tagged("aob", "validate_uniqueness_process worker_queue_rejected");
		g_state.validating.store(false);
	}
}

inline void validate_uniqueness_file(const DisasmFile& file, signature_t& sig)
{
	int total_count = 0;
	for (auto& sec : file.sections) {
		if (sec.bytes.empty()) continue;
		total_count += detail::count_pattern_in_data(sec.bytes.data(), sec.bytes.size(), sig.bytes);
		if (total_count > 1) break;
	}
	sig.unique = (total_count == 1);
	sig.uniqueness_count = total_count;
	sig.quality_score = compute_quality_score(sig);
}

inline void save_current()
{
	std::lock_guard<std::mutex> lk(g_state.mutex);
	if (g_state.current.bytes.empty()) {
		diag::log_tagged("aob", "save_current refused empty_current");
		return;
	}
	if (g_state.name_input[0])
		g_state.current.name = g_state.name_input;
	else {
		char buf[32];
		std::snprintf(buf, sizeof(buf), "sig_%llX", static_cast<unsigned long long>(g_state.current.address));
		g_state.current.name = buf;
	}
	signature_t copy = g_state.current;
	if (copy.id == 0) copy.id = allocate_signature_id();
	std::string saved_name = copy.name;
	size_t bytes_count = copy.bytes.size();
	g_state.saved_signatures.push_back(std::move(copy));
	g_state.catalog_generation.fetch_add(1, std::memory_order_acq_rel);
	diag::log_tagged_fmt("aob", "save_current saved name='%s' bytes=%zu total_saved=%zu",
		saved_name.c_str(), bytes_count, g_state.saved_signatures.size());
}

inline void save_current(const std::shared_ptr<state_t>& state)
{
	if (!state) return;
	std::lock_guard<std::mutex> lock(state->mutex);
	if (state->current.bytes.empty()) {
		diag::log_tagged("aob", "save_current refused empty_current");
		return;
	}
	if (state->name_input[0])
		state->current.name = state->name_input;
	else {
		char buffer[32];
		std::snprintf(buffer, sizeof(buffer), "sig_%llX",
			static_cast<unsigned long long>(state->current.address));
		state->current.name = buffer;
	}
	signature_t copy = state->current;
	if (copy.id == 0) copy.id = allocate_signature_id();
	const std::string saved_name = copy.name;
	const size_t bytes_count = copy.bytes.size();
	state->saved_signatures.push_back(std::move(copy));
	state->catalog_generation.fetch_add(1, std::memory_order_acq_rel);
	diag::log_tagged_fmt("aob", "save_current saved name='%s' bytes=%zu total_saved=%zu",
		saved_name.c_str(), bytes_count, state->saved_signatures.size());
}

inline void generate_batch(const std::vector<uint64_t>& addresses, int num_instructions, bool auto_wildcard)
{
#ifdef AIDA_STANDALONE
	if (g_state.batch_generating.load()) {
		diag::log_tagged("aob", "generate_batch refused already_running");
		return;
	}
	if (addresses.empty()) {
		diag::log_tagged("aob", "generate_batch refused empty_address_list");
		return;
	}
	diag::log_tagged_fmt("aob", "generate_batch start count=%zu instructions=%d auto_wildcard=%d",
		addresses.size(), num_instructions, static_cast<int>(auto_wildcard));
	g_state.batch_generating.store(true);
	g_state.batch_total.store(static_cast<int>(addresses.size()));
	g_state.batch_done.store(0);

	auto addrs = addresses;
	aida::infra::executor::submission_t sub;
	sub.owner_subsystem = "scanner";
	sub.label = "scanner.aob_generate_batch";
	sub.thread_class = "scanner_aob_batch";
	sub.domain = aida::infra::executor::domain_t::feature_worker;
	sub.priority = 2;
	sub.target_pid = driver_bridge::attached_pid();
	const uint32_t target_pid = sub.target_pid;
	sub.body = [addrs, num_instructions, auto_wildcard, target_pid]() {
		auto t_start = std::chrono::steady_clock::now();
		ZydisDecoder decoder;
		ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

		auto modules = driver_bridge::enumerate_modules_for(target_pid);

		for (size_t ai = 0; ai < addrs.size(); ++ai) {
			uint64_t address = addrs[ai];

			signature_t sig;
			sig.id = allocate_signature_id();
			sig.address = address;

			for (auto& m : modules) {
				if (address >= m.base && address < m.base + m.size) {
					sig.module_name = m.name;
					break;
				}
			}

			size_t read_size = static_cast<size_t>(num_instructions) * 15;
			std::vector<uint8_t> code;
			if (!driver_bridge::read_memory_for(target_pid, address, read_size, code) || code.empty()) {
				g_state.batch_done.fetch_add(1);
				continue;
			}

			std::vector<detail::decoded_instr_t> instrs;
			uint64_t offset = 0;
			int decoded_count = 0;

			while (offset < code.size() && decoded_count < num_instructions) {
				detail::decoded_instr_t di{};
				di.address = address + offset;

				auto status = ZydisDecoderDecodeFull(
					&decoder, code.data() + offset, code.size() - offset,
					&di.instr, di.operands);

				if (!ZYAN_SUCCESS(status)) break;

				di.length = static_cast<uint8_t>(di.instr.length);
				std::memcpy(di.raw, code.data() + offset, di.length);

				instrs.push_back(di);
				offset += di.length;
				++decoded_count;
			}

			std::vector<aob_byte_t> pattern;
			for (auto& di : instrs) {
				if (auto_wildcard) {
					detail::wildcard_dynamic_bytes(di, pattern);
				} else {
					for (uint8_t b = 0; b < di.length; ++b) {
						aob_byte_t ab;
						ab.value = di.raw[b];
						ab.wildcard = false;
						pattern.push_back(ab);
					}
				}
			}

			sig.bytes = std::move(pattern);
			sig.quality_score = compute_quality_score(sig);

			char name_buf[32];
			std::snprintf(name_buf, sizeof(name_buf), "batch_%llX", static_cast<unsigned long long>(address));
			sig.name = name_buf;

			{
				std::lock_guard<std::mutex> lk(g_state.mutex);
				g_state.saved_signatures.push_back(std::move(sig));
				g_state.catalog_generation.fetch_add(1, std::memory_order_acq_rel);
			}

			g_state.batch_done.fetch_add(1);
		}

		auto t_end = std::chrono::steady_clock::now();
		uint64_t dur_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t_end - t_start).count();
		diag::log_tagged_fmt("aob", "generate_batch done total=%zu done=%d duration_ms=%llu",
			addrs.size(), g_state.batch_done.load(), static_cast<unsigned long long>(dur_ms));
		g_state.batch_generating.store(false);
	};
	if (!aida::infra::executor::submit(std::move(sub)).submitted) {
		diag::log_tagged("aob", "generate_batch worker_queue_rejected");
		g_state.batch_generating.store(false);
		g_state.batch_done.store(g_state.batch_total.load());
	}
#else
	(void)addresses;
	(void)num_instructions;
	(void)auto_wildcard;
#endif
}

inline void optimize_signature(std::uint32_t pid, signature_t& sig)
{
#ifdef AIDA_STANDALONE
	if (pid == 0) {
		diag::log_tagged("aob", "optimize_signature refused missing_pid");
		return;
	}
	if (sig.bytes.size() < 4) {
		diag::log_tagged_fmt("aob", "optimize_signature refused too_short bytes=%zu",
			sig.bytes.size());
		return;
	}
	diag::log_tagged_fmt("aob", "optimize_signature start id=%llu bytes=%zu",
		static_cast<unsigned long long>(sig.id), sig.bytes.size());

	std::vector<uint8_t> concrete;
	concrete.reserve(sig.bytes.size());
	for (auto& b : sig.bytes) {
		if (!b.wildcard) concrete.push_back(b.value);
	}
	if (concrete.size() < 4) return;

	auto regions = driver_bridge::enumerate_memory_regions_for(pid, 4096);

	std::vector<uint8_t> all_data;
	std::vector<std::pair<uint64_t, size_t>> region_offsets;
	for (auto& region : regions) {
		if (region.state != 0x1000) continue;
		if (region.protect & 0x100) continue;
		uint32_t prot = region.protect & 0xFF;
		if (prot == 0x01 || prot == 0x00) continue;
		if (region.size > 0x10000000) continue;

		std::vector<uint8_t> data;
		driver_bridge::read_memory_for(pid, region.base, static_cast<size_t>(region.size), data);
		if (data.empty()) continue;

		region_offsets.push_back({region.base, all_data.size()});
		all_data.insert(all_data.end(), data.begin(), data.end());
	}

	if (all_data.empty()) return;

	auto count_matches = [&](const std::vector<aob_byte_t>& pat) -> int {
		return detail::count_pattern_in_data(all_data.data(), all_data.size(), pat);
	};

	int full_count = count_matches(sig.bytes);
	if (full_count != 1) return;

	size_t best_start = 0;
	size_t best_len = sig.bytes.size();

	for (size_t start = 0; start < sig.bytes.size(); ++start) {
		size_t lo = 1;
		size_t hi = sig.bytes.size() - start;
		if (hi < lo) continue;

		bool found_unique = false;
		size_t min_len = hi;
		while (lo <= hi) {
			size_t mid = (lo + hi) / 2;
			std::vector<aob_byte_t> sub(sig.bytes.begin() + start,
										sig.bytes.begin() + start + mid);
			int cnt = count_matches(sub);
			if (cnt == 1) {
				min_len = mid;
				found_unique = true;
				if (mid == 0) break;
				hi = mid - 1;
			} else {
				lo = mid + 1;
			}
		}

		if (found_unique && min_len < best_len) {
			best_len = min_len;
			best_start = start;
		}
	}

	if (best_len < sig.bytes.size()) {
		size_t old_size = sig.bytes.size();
		std::vector<aob_byte_t> optimized(sig.bytes.begin() + best_start,
										  sig.bytes.begin() + best_start + best_len);
		sig.bytes = std::move(optimized);
		sig.unique = true;
		sig.uniqueness_count = 1;
		sig.quality_score = compute_quality_score(sig);
		diag::log_tagged_fmt("aob", "optimize_signature done from=%zu to=%zu start=%zu quality=%.2f",
			old_size, best_len, best_start, static_cast<double>(sig.quality_score));
	} else {
		diag::log_tagged_fmt("aob", "optimize_signature no_improvement keep=%zu", sig.bytes.size());
	}
#else
	(void)pid;
	(void)sig;
#endif
}

inline void optimize_signature(signature_t& sig)
{
#ifdef AIDA_STANDALONE
	optimize_signature(driver_bridge::attached_pid(), sig);
#else
	optimize_signature(0, sig);
#endif
}

inline std::string get_aob_cache_dir()
{
	char* appdata = nullptr;
	size_t len = 0;
	_dupenv_s(&appdata, &len, "APPDATA");
	std::string dir;
	if (appdata) {
		dir = std::string(appdata) + "\\AiDA\\Standalone\\aob_signatures";
		free(appdata);
	}
	return dir;
}

enum class export_format_t : std::uint8_t { json, yara, header };

inline constexpr std::size_t max_catalog_entries = 10000;
inline constexpr std::size_t max_signature_bytes = 4096;
inline constexpr std::size_t max_catalog_bytes = 4ULL * 1024ULL * 1024ULL;
inline constexpr std::size_t max_catalog_file_bytes = 64ULL * 1024ULL * 1024ULL;

inline bool valid_catalog_text(const std::string& value, std::size_t maximum)
{
	if (value.size() > maximum || value.find('\0') != std::string::npos) return false;
	return std::none_of(value.begin(), value.end(), [](unsigned char character) {
		return character < 0x20 && character != '\t';
	});
}

inline bool append_bounded(std::string& output, const std::string& value, std::string& error)
{
	if (value.size() > max_catalog_file_bytes || output.size() > max_catalog_file_bytes - value.size()) {
		error = "AOB serialization exceeds the 64 MiB limit";
		return false;
	}
	output += value;
	return true;
}

inline bool serialize_catalog(const std::vector<signature_t>& signatures, export_format_t format,
	std::string& output, std::string& error,
	const std::shared_ptr<std::atomic<bool>>& cancellation)
{
	output.clear();
	if (signatures.size() > max_catalog_entries) {
		error = "AOB catalog exceeds the 10000-signature limit";
		return false;
	}
	try {
	std::size_t total_bytes = 0;
	if (format == export_format_t::json) {
		nlohmann::json array = nlohmann::json::array();
		for (const auto& signature : signatures) {
			if (cancellation && cancellation->load(std::memory_order_acquire)) {
				error = "AOB serialization cancelled";
				return false;
			}
			if (!valid_catalog_text(signature.name, 256) ||
				!valid_catalog_text(signature.module_name, 512) || signature.bytes.empty() ||
				signature.bytes.size() > max_signature_bytes ||
				total_bytes > max_catalog_bytes - signature.bytes.size()) {
				error = "AOB signature violates catalog field bounds";
				return false;
			}
			total_bytes += signature.bytes.size();
			nlohmann::json object;
			object["id"] = signature.id;
			object["name"] = signature.name;
			object["address"] = signature.address;
			object["module"] = signature.module_name;
			object["quality"] = signature.quality_score;
			object["unique"] = signature.unique;
			object["uniqueness_count"] = signature.uniqueness_count;
			object["pattern"] = format_signature(signature);
			object["ida_pattern"] = format_ida_signature(signature);
			object["bytes"] = nlohmann::json::array();
			for (const auto& byte : signature.bytes)
				object["bytes"].push_back({{"value", byte.value}, {"wildcard", byte.wildcard}});
			array.push_back(std::move(object));
		}
		output = array.dump(2);
		if (output.size() > max_catalog_file_bytes) {
			output.clear();
			error = "AOB JSON serialization exceeds the 64 MiB limit";
			return false;
		}
		return true;
	}
	if (format == export_format_t::header &&
		!append_bounded(output, "#pragma once\n\n#include <cstdint>\n\nnamespace signatures {\n\n", error))
		return false;
	for (const auto& signature : signatures) {
		if (cancellation && cancellation->load(std::memory_order_acquire)) {
			error = "AOB serialization cancelled";
			return false;
		}
		if (!valid_catalog_text(signature.name, 256) || signature.bytes.empty() ||
			signature.bytes.size() > max_signature_bytes) {
			error = "AOB signature violates export field bounds";
			return false;
		}
		if (format == export_format_t::yara) {
			if (!append_bounded(output, format_yara_rule(signature) + "\n", error)) return false;
		} else {
			std::string name;
			for (const char character : signature.name)
				name += std::isalnum(static_cast<unsigned char>(character)) || character == '_'
					? character : '_';
			if (name.empty()) name = "unnamed";
			if (std::isdigit(static_cast<unsigned char>(name.front()))) name = "sig_" + name;
			if (!append_bounded(output, "constexpr auto " + name + "_pattern = " +
				format_code_signature(signature) + ";\n", error)) return false;
		}
	}
	if (format == export_format_t::header)
		return append_bounded(output, "\n}\n", error);
	return true;
	} catch (const std::exception& exception) {
		output.clear();
		error = "AOB serialization failed: " + std::string(exception.what());
		return false;
	}
}

inline bool json_depth_within(const std::string& input, std::size_t maximum)
{
	std::size_t depth = 0;
	bool string = false;
	bool escape = false;
	for (const char character : input) {
		if (string) {
			if (escape) escape = false;
			else if (character == '\\') escape = true;
			else if (character == '"') string = false;
			continue;
		}
		if (character == '"') string = true;
		else if (character == '{' || character == '[') {
			if (++depth > maximum) return false;
		} else if ((character == '}' || character == ']') && depth != 0) --depth;
	}
	return !string && depth == 0;
}

inline bool parse_catalog(const std::string& input, std::vector<signature_t>& staged,
	std::uint64_t& maximum_id, std::string& error,
	const std::shared_ptr<std::atomic<bool>>& cancellation)
{
	staged.clear();
	maximum_id = 0;
	if (input.empty() || input.size() > max_catalog_file_bytes || !json_depth_within(input, 16)) {
		error = "AOB catalog is empty, oversized, malformed, or deeper than 16 levels";
		return false;
	}
	nlohmann::json array;
	try { array = nlohmann::json::parse(input); }
	catch (const std::exception& exception) { error = exception.what(); return false; }
	if (!array.is_array() || array.size() > max_catalog_entries) {
		error = "AOB catalog root must be an array of at most 10000 signatures";
		return false;
	}
	std::set<std::uint64_t> ids;
	std::size_t total_bytes = 0;
	try {
	staged.reserve(array.size());
	for (const auto& object : array) {
		if (cancellation && cancellation->load(std::memory_order_acquire)) {
			error = "AOB catalog import cancelled";
			return false;
		}
		if (!object.is_object() || !object.contains("id") || !object["id"].is_number_unsigned() ||
			!object.contains("name") || !object["name"].is_string() ||
			!object.contains("address") || !object["address"].is_number_unsigned() ||
			!object.contains("module") || !object["module"].is_string() ||
			!object.contains("quality") || !object["quality"].is_number() ||
			!object.contains("unique") || !object["unique"].is_boolean() ||
			!object.contains("uniqueness_count") || !object["uniqueness_count"].is_number_integer() ||
			!object.contains("pattern") || !object["pattern"].is_string() ||
			!object.contains("ida_pattern") || !object["ida_pattern"].is_string() ||
			!object.contains("bytes") || !object["bytes"].is_array()) {
			error = "AOB catalog signature does not match the complete schema";
			return false;
		}
		signature_t signature;
		signature.id = object["id"].get<std::uint64_t>();
		signature.name = object["name"].get<std::string>();
		signature.address = object["address"].get<std::uint64_t>();
		signature.module_name = object["module"].get<std::string>();
		signature.quality_score = object["quality"].get<float>();
		signature.unique = object["unique"].get<bool>();
		signature.uniqueness_count = object["uniqueness_count"].get<int>();
		const std::string pattern = object["pattern"].get<std::string>();
		const std::string ida_pattern = object["ida_pattern"].get<std::string>();
		if (signature.id == 0 || !ids.insert(signature.id).second ||
			!valid_catalog_text(signature.name, 256) || !valid_catalog_text(signature.module_name, 512) ||
			!std::isfinite(signature.quality_score) || signature.quality_score < 0.0f ||
			signature.quality_score > 1.0f || signature.uniqueness_count < 0 ||
			signature.uniqueness_count > 1000000 || object["bytes"].empty() ||
			object["bytes"].size() > max_signature_bytes || pattern.size() > 12288 ||
			ida_pattern.size() > 12288) {
			error = "AOB catalog signature field is invalid or exceeds its bound";
			return false;
		}
		if (total_bytes > max_catalog_bytes - object["bytes"].size()) {
			error = "AOB catalog byte fields exceed the 4 MiB aggregate limit";
			return false;
		}
		for (const auto& byte : object["bytes"]) {
			if (!byte.is_object() || !byte.contains("value") || !byte["value"].is_number_unsigned() ||
				byte["value"].get<std::uint64_t>() > 255 || !byte.contains("wildcard") ||
				!byte["wildcard"].is_boolean()) {
				error = "AOB catalog byte field is invalid";
				return false;
			}
			signature.bytes.push_back({static_cast<std::uint8_t>(byte["value"].get<std::uint64_t>()),
				byte["wildcard"].get<bool>()});
		}
		total_bytes += signature.bytes.size();
		if (pattern != format_signature(signature) || ida_pattern != format_ida_signature(signature)) {
			error = "AOB catalog pattern fields do not match the validated byte fields";
			return false;
		}
		maximum_id = (std::max)(maximum_id, signature.id);
		staged.push_back(std::move(signature));
	}
	return true;
	} catch (const std::exception& exception) {
		staged.clear();
		maximum_id = 0;
		error = "AOB catalog validation failed: " + std::string(exception.what());
		return false;
	}
}

struct comparison_result_t {
	std::string name;
	uint64_t    original_address;
	bool        still_found;
	int         match_count;
	uint64_t    new_address;
};

inline std::vector<comparison_result_t> compare_signatures_against_process(
	std::uint32_t pid, const std::vector<signature_t>& sigs,
	const std::shared_ptr<std::atomic<bool>>& cancellation,
	const std::function<bool()>& still_current, std::string& error)
{
#ifdef AIDA_STANDALONE
	std::vector<comparison_result_t> results;
	if (pid == 0 || sigs.size() > max_catalog_entries) {
		error = pid == 0 ? "AOB comparison requires an exact process ID" :
			"AOB comparison exceeds the 10000-signature limit";
		return results;
	}
	std::size_t signature_bytes = 0;
	for (const auto& signature : sigs) {
		if (signature.bytes.empty() || signature.bytes.size() > max_signature_bytes ||
			signature_bytes > max_catalog_bytes - signature.bytes.size()) {
			error = "AOB comparison signature bytes violate the bounded catalog contract";
			return results;
		}
		signature_bytes += signature.bytes.size();
	}
	auto t_start = std::chrono::steady_clock::now();
	diag::log_tagged_fmt("aob", "compare_signatures_against_process start count=%zu pid=%u",
		sigs.size(), pid);
	if (!driver_bridge::is_loaded()) {
		error = "AOB comparison requires the loaded standalone driver";
		return results;
	}

	auto regions = driver_bridge::enumerate_memory_regions_for(pid, 4096);
	struct captured_region_t {
		std::uint64_t base = 0;
		std::vector<std::uint8_t> bytes;
	};
	std::vector<captured_region_t> captured_regions;
	std::size_t captured_bytes = 0;
	constexpr std::size_t max_process_bytes = 512ULL * 1024ULL * 1024ULL;

	for (auto& region : regions) {
		if ((cancellation && cancellation->load(std::memory_order_acquire)) ||
			(still_current && !still_current())) {
			error = cancellation && cancellation->load(std::memory_order_acquire)
				? "AOB comparison cancelled" : "AOB comparison target or source generation changed";
			return {};
		}
		if (region.state != 0x1000) continue;
		if (region.protect & 0x100) continue;
		uint32_t prot = region.protect & 0xFF;
		if (prot == 0x01 || prot == 0x00) continue;
		if (region.size > 0x10000000 || region.size > max_process_bytes - captured_bytes) continue;

		std::vector<uint8_t> data;
		if (!driver_bridge::read_memory_for(pid, region.base, static_cast<size_t>(region.size), data) ||
			data.size() != static_cast<std::size_t>(region.size)) continue;
		if (data.empty()) continue;
		captured_bytes += data.size();
		captured_regions.push_back({region.base, std::move(data)});
	}
	if (captured_regions.empty()) {
		error = "AOB comparison could not capture any readable region for the exact process";
		return results;
	}

	for (auto& sig : sigs) {
		if ((cancellation && cancellation->load(std::memory_order_acquire)) ||
			(still_current && !still_current())) {
			error = cancellation && cancellation->load(std::memory_order_acquire)
				? "AOB comparison cancelled" : "AOB comparison target or source generation changed";
			return {};
		}
		comparison_result_t cr;
		cr.name = sig.name;
		cr.original_address = sig.address;
		cr.match_count = 0;
		cr.new_address = 0;
		cr.still_found = false;

		for (const auto& region : captured_regions) {
			if (sig.bytes.size() > region.bytes.size()) continue;
			for (size_t i = 0; i <= region.bytes.size() - sig.bytes.size(); ++i) {
				if ((i & 0x3FFFU) == 0 && ((cancellation && cancellation->load(std::memory_order_acquire)) ||
					(still_current && !still_current()))) {
					error = cancellation && cancellation->load(std::memory_order_acquire)
						? "AOB comparison cancelled" : "AOB comparison target or source generation changed";
					return {};
				}
				bool match = true;
				for (size_t j = 0; j < sig.bytes.size(); ++j) {
					if (!sig.bytes[j].wildcard && region.bytes[i + j] != sig.bytes[j].value) {
						match = false;
						break;
					}
				}
				if (match) {
					cr.match_count++;
					if (cr.match_count == 1) {
						cr.new_address = region.base + i;
					}
					if (cr.match_count > 100) break;
				}
			}
			if (cr.match_count > 100) break;
		}

		cr.still_found = (cr.match_count > 0);
		results.push_back(cr);
	}

	auto t_end = std::chrono::steady_clock::now();
	uint64_t dur_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t_end - t_start).count();
	size_t still_found = 0;
	for (auto& r : results) if (r.still_found) ++still_found;
	diag::log_tagged_fmt("aob", "compare_signatures_against_process done total=%zu still_found=%zu duration_ms=%llu",
		results.size(), still_found, static_cast<unsigned long long>(dur_ms));

	return results;
#else
	(void)pid;
	(void)sigs;
	(void)cancellation;
	(void)still_current;
	error = "AOB process comparison is unavailable in this target";
	return {};
#endif
}

}

#endif
