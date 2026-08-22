#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include "../infra/executor.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_set>
#include <utility>
#include <vector>

#include "standalone_driver.hpp"
#include "embedded_resources.hpp"
#include "helpers/diag_log.hpp"
#include "zydis_disasm.hpp"
#include "../analysis/pe_parser.hpp"
#include "../analysis/workspace/analysis_workspace.hpp"
#include "../analysis/decompiler/providers/ghidra_ir_adapter.hpp"
#include "../mcp/downstream_producer_governor.hpp"

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4005 4099 4244 4267 4146 4996 4458 4457 4100 4127 4389)
#endif

#include "ghidra_adapters/aida_ghidra_preamble.hpp"
#include "ghidra_adapters/aida_architecture.hpp"
#include "ghidra_adapters/aida_load_image.hpp"
#include "ghidra_adapters/aida_function_db.hpp"
#include "ghidra_adapters/aida_arch_map.hpp"
#include "ghidra_adapters/aida_code_xml_parse.hpp"
#include "ghidra_adapters/aida_print_c.hpp"
#include "ghidra_adapters/aida_pcode_fixup.hpp"

#include "ghidra_adapters/aida_ghidra_preamble.hpp"

#include "libdecomp.hh"
#include "sleigh_arch.hh"
#include "loadimage.hh"
#include "architecture.hh"
#include "action.hh"
#include "funcdata.hh"
#include "printc.hh"

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#include "../../../workers/native_decompiler/worker_symbol_binder.hpp"

namespace ghidra_decompiler {

enum class ghidra_adapter_error_code_t : uint8_t {
	none = 0,
	cancelled,
	deadline_exceeded,
	result_limit_exceeded,
	invalid_request,
	unsupported_language_family,
	language_family_not_staged,
	adapter_revision_mismatch,
	adapter_cache_key_mismatch,
	function_not_found,
	decompiler_unavailable,
	decompilation_failed,
};

struct ghidra_adapter_error_t {
	ghidra_adapter_error_code_t code = ghidra_adapter_error_code_t::none;
	std::optional<aida::analysis::ghidra_adapter::ghidra_language_family_t> language_family;
	std::string phase;
	std::string message;
};

struct ghidra_decompile_result_limits_t {
	uint64_t max_pseudocode_bytes = 8ULL * 1024ULL * 1024ULL;
	size_t max_annotations = 1U << 20;
	size_t max_line_mappings = 1U << 20;
	size_t max_callees = 65536;
	uint64_t max_result_bytes = 16ULL * 1024ULL * 1024ULL;
	bool capture_printc_evidence = false;
	bool keep_fixateglobals = false;
};

struct ghidra_adapter_decompile_cache_key_t {
	aida::analysis::sha256_digest_t digest;
	std::string workspace_id;
	aida::analysis::binary_id_t workspace_binary_id;
	aida::analysis::sha256_digest_t workspace_load_profile_hash;
	uint64_t generation = 0;
	uint64_t analysis_revision = 0;
	uint64_t overlay_revision = 0;
	uint64_t type_revision = 0;
	aida::analysis::ghidra_adapter::ghidra_adapter_cache_key_t adapter_cache_key;
	aida::analysis::ghidra_adapter::ghidra_entity_address_key_t function;
	std::optional<aida::analysis::decompiler_entity_key_t> typed_entity;
	ghidra_decompile_result_limits_t result_limits;
};

struct ghidra_adapter_decompile_request_t {
	const aida::analysis::workspace_identity_t* workspace_identity = nullptr;
	std::string workspace_id;
	std::shared_ptr<const aida::analysis::normalized_workspace_image_t> normalized_image;
	std::shared_ptr<const aida::analysis::analysis_snapshot_t> analysis_snapshot;
	aida::analysis::ghidra_adapter::ghidra_language_catalog_t language_catalog;
	aida::analysis::ghidra_adapter::ghidra_language_spec_t language;
	aida::analysis::ghidra_adapter::ghidra_adapter_revision_t revision;
	aida::analysis::ghidra_adapter::ghidra_adapter_cache_key_t adapter_cache_key;
	std::shared_ptr<const aida::analysis::ghidra_adapter::ghidra_load_image_t> load_image;
	std::shared_ptr<const aida::analysis::ghidra_adapter::ghidra_function_database_t> function_database;
	aida::analysis::ghidra_adapter::ghidra_entity_address_key_t function;
	std::optional<aida::analysis::decompiler_entity_key_t> typed_entity;
	uint64_t type_revision = 0;
	aida::analysis::cancellation_token_t cancellation;
	std::atomic<bool>* engine_cancel = nullptr;
	std::function<bool()> cancel_check;
	std::optional<std::chrono::steady_clock::time_point> deadline;
	ghidra_decompile_result_limits_t result_limits;
};

struct ghidra_result_t {
	uint64_t function_addr = 0;
	std::string function_name;
	std::optional<std::string> printc_evidence;
	std::vector<aida_ghidra::code_annotation_t> annotations;
	std::vector<std::pair<int, uint64_t>> line_to_address;
	std::vector<std::pair<std::string, uint64_t>> callees;
	std::string sleigh_id;
	bool complete = false;
	bool is_error = false;
	std::string error_text;
	ghidra_adapter_error_t adapter_error;
	std::optional<aida::analysis::ghidra_ir_adapter::typed_artifacts_t> typed_artifacts;
	std::vector<aida::analysis::decompiler_diagnostic_t> typed_diagnostics;
	double elapsed_ms = 0.0;
};

struct ghidra_adapter_decompile_result_t {
	ghidra_result_t result;
	ghidra_adapter_decompile_cache_key_t cache_key;
};

aida::analysis::workspace_result_t<ghidra_adapter_decompile_cache_key_t>
make_ghidra_adapter_decompile_cache_key(
	const ghidra_adapter_decompile_request_t& request,
	const aida::analysis::cancellation_token_t& cancel = {});

aida::analysis::workspace_result_t<ghidra_adapter_decompile_result_t>
decompile_adapter(const ghidra_adapter_decompile_request_t& request);

struct batch_entry_t {
	uint64_t address = 0;
	ghidra_result_t result;
};

struct preload_diagnostics_t {
	uint64_t base = 0;
	size_t requested_size = 0;
	size_t first_attempt_bytes = 0;
	size_t total_read = 0;
	size_t chunks_ok = 0;
	size_t chunks_failed = 0;
	size_t chunks_skipped = 0;
	size_t query_ok = 0;
	size_t query_failed = 0;
	size_t skipped_uncommitted = 0;
	size_t skipped_guard = 0;
	size_t skipped_noaccess = 0;
	uint32_t pe_signature = 0;
	uint16_t pe_machine = 0;
	uint16_t pe_sections = 0;
	uint16_t pe_optional_magic = 0;
	uint32_t pe_size_of_image = 0;
	bool whole_read_ok = false;
	bool whole_read_zero_padding = false;
	bool chunked_read = false;
	bool zero_padding = false;
	bool mz = false;
	bool pe_header_ok = false;
};

struct state_t {
	std::mutex init_mtx;
	std::atomic<bool> initialized{false};
	std::string specs_dir;
	std::string init_detail;
	std::string last_specs_probe;
	std::string last_init_reason;
	std::ostringstream err_stream;
	std::atomic<int> active_decompiles{0};
	std::atomic<bool> shutting_down{false};
	std::atomic<uint64_t> last_loadfill_tick_ms{0};
};

inline state_t g_state;

inline std::string init_diagnostics();

inline bool buffer_is_zero_padding(const std::vector<uint8_t>& bytes)
{
	if (bytes.empty()) return true;
	size_t zero_count = 0;
	size_t longest = 0;
	size_t cur = 0;
	for (uint8_t b : bytes) {
		if (b == 0) {
			++zero_count;
			++cur;
			if (cur > longest) longest = cur;
		} else {
			cur = 0;
		}
	}
	return longest >= 256 || (bytes.size() >= 256 && zero_count * 100 >= bytes.size() * 90);
}

inline bool decompile_protect_executable(uint32_t protect)
{
	switch (protect & 0xFFu) {
	case PAGE_EXECUTE:
	case PAGE_EXECUTE_READ:
	case PAGE_EXECUTE_READWRITE:
	case PAGE_EXECUTE_WRITECOPY:
		return true;
	default:
		return false;
	}
}

inline bool decompile_section_executable(uint32_t characteristics)
{
	return (characteristics & 0x20000000u) != 0 || (characteristics & 0x00000020u) != 0;
}

inline void decompile_zero_window_stats(const std::vector<uint8_t>& bytes,
                                        size_t offset,
                                        size_t size,
                                        size_t& zero_count,
                                        size_t& longest_zero_run)
{
	zero_count = 0;
	longest_zero_run = 0;
	size_t current = 0;
	const size_t end = (std::min)(bytes.size(), offset + size);
	for (size_t i = offset; i < end; ++i) {
		if (bytes[i] == 0) {
			++zero_count;
			++current;
			if (current > longest_zero_run)
				longest_zero_run = current;
		} else {
			current = 0;
		}
	}
}

inline bool profile_pe_image_header(const std::vector<uint8_t>& bytes, preload_diagnostics_t& diag)
{
	diag.mz = bytes.size() >= 2 && bytes[0] == 'M' && bytes[1] == 'Z';
	diag.pe_header_ok = false;
	diag.pe_signature = 0;
	diag.pe_machine = 0;
	diag.pe_sections = 0;
	diag.pe_optional_magic = 0;
	diag.pe_size_of_image = 0;
	if (bytes.size() < sizeof(IMAGE_DOS_HEADER))
		return false;

	IMAGE_DOS_HEADER dos{};
	std::memcpy(&dos, bytes.data(), sizeof(dos));
	if (dos.e_magic != IMAGE_DOS_SIGNATURE)
		return false;
	if (dos.e_lfanew < static_cast<LONG>(sizeof(IMAGE_DOS_HEADER)))
		return false;

	const size_t nt_off = static_cast<size_t>(dos.e_lfanew);
	if (nt_off > bytes.size() || bytes.size() - nt_off < sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER))
		return false;

	std::memcpy(&diag.pe_signature, bytes.data() + nt_off, sizeof(diag.pe_signature));
	if (diag.pe_signature != IMAGE_NT_SIGNATURE)
		return false;

	IMAGE_FILE_HEADER file_header{};
	std::memcpy(&file_header, bytes.data() + nt_off + sizeof(uint32_t), sizeof(file_header));
	diag.pe_machine = file_header.Machine;
	diag.pe_sections = file_header.NumberOfSections;

	const size_t optional_off = nt_off + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER);
	if (optional_off + sizeof(uint16_t) <= bytes.size())
		std::memcpy(&diag.pe_optional_magic, bytes.data() + optional_off, sizeof(diag.pe_optional_magic));

	if (file_header.SizeOfOptionalHeader >= offsetof(IMAGE_OPTIONAL_HEADER64, SizeOfImage) + sizeof(uint32_t) &&
		optional_off + offsetof(IMAGE_OPTIONAL_HEADER64, SizeOfImage) + sizeof(uint32_t) <= bytes.size()) {
		std::memcpy(&diag.pe_size_of_image,
			bytes.data() + optional_off + offsetof(IMAGE_OPTIONAL_HEADER64, SizeOfImage),
			sizeof(diag.pe_size_of_image));
	}

	diag.pe_header_ok = diag.pe_sections != 0 &&
		(diag.pe_optional_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC ||
		 diag.pe_optional_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
	return diag.pe_header_ok;
}

enum class wd_state_t : uint32_t {
	running   = 0,
	completed = 1,
	cancelled = 2
};

struct active_decompile_guard_t {
	bool was_shutting_down = false;
	std::atomic<bool>* cancel_ref = nullptr;
	active_decompile_guard_t(std::atomic<bool>* cancel = nullptr) : cancel_ref(cancel) {
		g_state.active_decompiles.fetch_add(1, std::memory_order_acq_rel);
		if (g_state.shutting_down.load(std::memory_order_acquire)) {
			was_shutting_down = true;
			if (cancel_ref)
				cancel_ref->store(true, std::memory_order_release);
		}
	}
	~active_decompile_guard_t() {
		g_state.active_decompiles.fetch_sub(1, std::memory_order_acq_rel);
	}
	active_decompile_guard_t(const active_decompile_guard_t&) = delete;
	active_decompile_guard_t& operator=(const active_decompile_guard_t&) = delete;
};

inline bool wait_for_active_decompiles(int budget_ms) {
	int elapsed = 0;
	while (g_state.active_decompiles.load(std::memory_order_acquire) > 0) {
		if (elapsed >= budget_ms) return false;
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
		elapsed += 10;
	}
	return true;
}

inline void prepare_shutdown() {
	g_state.shutting_down.store(true, std::memory_order_release);
	wait_for_active_decompiles(2000);
}

namespace detail {

inline std::string get_exe_directory() {
	char path[MAX_PATH] = {};
	GetModuleFileNameA(nullptr, path, MAX_PATH);
	std::string full(path);
	auto pos = full.find_last_of("\\/");
	if (pos != std::string::npos)
		return full.substr(0, pos);
	return ".";
}

inline std::string read_env_var(const char* name)
{
	char buf[32768] = {};
	DWORD n = GetEnvironmentVariableA(name, buf, static_cast<DWORD>(sizeof(buf)));
	if (n == 0 || n >= static_cast<DWORD>(sizeof(buf)))
		return {};
	return std::string(buf, n);
}

inline bool specs_dir_has_required_files(const std::string& dir)
{
	if (dir.empty())
		return false;
	DWORD attr = GetFileAttributesA(dir.c_str());
	if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY))
		return false;
	std::string prefix = dir;
	if (!prefix.empty() && prefix.back() != '\\' && prefix.back() != '/')
		prefix += "\\";
	const char* names[] = {
		"x86-64.sla",
		"x86-64.pspec",
		"x86-64-win.cspec",
		"x86.ldefs"
	};
	for (const char* name : names) {
		const std::string file = prefix + name;
		attr = GetFileAttributesA(file.c_str());
		if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY))
			return false;
	}
	return true;
}

inline size_t count_required_specs_files(const std::string& dir)
{
	if (dir.empty())
		return 0;
	DWORD attr = GetFileAttributesA(dir.c_str());
	if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY))
		return 0;
	std::string prefix = dir;
	if (!prefix.empty() && prefix.back() != '\\' && prefix.back() != '/')
		prefix += "\\";
	const char* names[] = {
		"x86-64.sla",
		"x86-64.pspec",
		"x86-64-win.cspec",
		"x86.ldefs"
	};
	size_t count = 0;
	for (const char* name : names) {
		const std::string file = prefix + name;
		attr = GetFileAttributesA(file.c_str());
		if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY))
			++count;
	}
	return count;
}

inline size_t ghidra_spec_resource_count(size_t& total_bytes)
{
	total_bytes = 0;
	const int ids[] = {
		IDR_GHIDRA_SLA,
		IDR_GHIDRA_PSPEC,
		IDR_GHIDRA_CSPEC,
		IDR_GHIDRA_LDEFS
	};
	size_t count = 0;
	for (int id : ids) {
		HRSRC res = FindResourceW(nullptr, MAKEINTRESOURCEW(id), RT_RCDATA);
		if (!res)
			continue;
		DWORD size = SizeofResource(nullptr, res);
		if (size == 0)
			continue;
		++count;
		total_bytes += static_cast<size_t>(size);
	}
	return count;
}

inline void append_specs_root_candidates(std::vector<std::pair<std::string, std::string>>& out,
                                         const std::string& label,
                                         const std::string& root)
{
	if (root.empty())
		return;
	out.emplace_back(label + "_ghidra_specs", root + "\\ghidra_specs");
	out.emplace_back(label + "_deps_ghidra_specs", root + "\\deps\\ghidra_specs");
}

inline std::vector<std::pair<std::string, std::string>> specs_probe_candidates(const std::string& explicit_dir)
{
	std::vector<std::pair<std::string, std::string>> out;
	if (!explicit_dir.empty())
		out.emplace_back("explicit_attr", explicit_dir);
	const std::string env_specs = read_env_var("AIDA_GHIDRA_SPECS_DIR");
	if (!env_specs.empty())
		out.emplace_back("env_AIDA_GHIDRA_SPECS_DIR", env_specs);
	const std::string env_ghidra_specs = read_env_var("GHIDRA_SPECS_DIR");
	if (!env_ghidra_specs.empty())
		out.emplace_back("env_GHIDRA_SPECS_DIR", env_ghidra_specs);
	append_specs_root_candidates(out, "env_AIDA_PACKAGE_DIR", read_env_var("AIDA_PACKAGE_DIR"));
	const std::string env_deps = read_env_var("AIDA_DEPS_DIR");
	if (!env_deps.empty()) {
		out.emplace_back("env_AIDA_DEPS_DIR_direct", env_deps);
		out.emplace_back("env_AIDA_DEPS_DIR_ghidra_specs", env_deps + "\\ghidra_specs");
	}
	const std::string exe_dir = get_exe_directory();
	append_specs_root_candidates(out, "exe", exe_dir);
	append_specs_root_candidates(out, "parent", exe_dir + "\\..");
#ifdef GHIDRA_SPECS_DIR
#define AIDA_GHIDRA_SPECS_STR_IMPL(x) #x
#define AIDA_GHIDRA_SPECS_STR(x) AIDA_GHIDRA_SPECS_STR_IMPL(x)
	out.emplace_back("cmake_ghidra_specs", AIDA_GHIDRA_SPECS_STR(GHIDRA_SPECS_DIR));
#undef AIDA_GHIDRA_SPECS_STR
#undef AIDA_GHIDRA_SPECS_STR_IMPL
#endif
	return out;
}

inline void append_specs_probe_candidate(std::ostringstream& out,
                                         const char* label,
                                         const std::string& path)
{
	DWORD attr = GetFileAttributesA(path.c_str());
	out << label << "=\"" << path << "\"";
	if (attr == INVALID_FILE_ATTRIBUTES) {
		out << ":missing_gle=" << static_cast<unsigned long>(GetLastError());
	} else {
		const size_t file_count = count_required_specs_files(path);
		out << ":attr=0x" << std::hex << std::uppercase << attr << std::dec
		    << ":dir=" << ((attr & FILE_ATTRIBUTE_DIRECTORY) ? 1 : 0)
		    << ":files=" << file_count << "/4"
		    << ":ready=" << (specs_dir_has_required_files(path) ? 1 : 0);
	}
	out << " ";
}

inline std::string describe_specs_probe(const std::string& explicit_dir)
{
	std::ostringstream out;
	std::string exe_dir = get_exe_directory();
	out << "explicit=\"" << (explicit_dir.empty() ? std::string("<empty>") : explicit_dir) << "\" ";
	out << "exe_dir=\"" << exe_dir << "\" ";
	for (const auto& candidate : specs_probe_candidates(explicit_dir))
		append_specs_probe_candidate(out, candidate.first.c_str(), candidate.second);
#ifndef GHIDRA_SPECS_DIR
	out << "cmake_ghidra_specs=<not_defined> ";
#endif
	return out.str();
}

inline std::string find_specs_dir() {
	for (const auto& candidate : specs_probe_candidates(""))
		if (specs_dir_has_required_files(candidate.second))
			return candidate.second;
	return "";
}

inline std::string active_specs_dir()
{
	std::lock_guard<std::mutex> lock(g_state.init_mtx);
	if (g_state.initialized.load(std::memory_order_acquire) && !g_state.specs_dir.empty())
		return g_state.specs_dir;
	return find_specs_dir();
}

inline aida_ghidra::arch_descriptor_t resolve_arch(const DisasmFile* file) {
	if (file && file->loaded)
		return aida_ghidra::detect_arch_from_pe(*file);
	return aida_ghidra::detect_arch_default_x64();
}

inline pe_parser::pe_info_t* try_parse_pe_info(const DisasmFile* file,
                                                pe_parser::pe_info_t& out_storage)
{
	if (!file || !file->loaded || file->image_base == 0)
		return nullptr;

	out_storage = pe_parser::pe_info_t{};
	out_storage.image_base = file->image_base;
	out_storage.entry_point = file->entry_point;

	for (auto& s : file->sections) {
		if (s.bytes.size() < 0x400)
			continue;
		if (s.va > file->image_base)
			continue;
		uint64_t off = file->image_base - s.va;
		if (off + 0x400 > s.bytes.size())
			continue;
		const uint8_t* p = s.bytes.data() + static_cast<size_t>(off);
		if (p[0] != 'M' || p[1] != 'Z')
			continue;
		uint32_t e_lfanew = 0;
		std::memcpy(&e_lfanew, p + 0x3C, 4);
		if (e_lfanew == 0 || e_lfanew + 0x40 > s.bytes.size() - off)
			continue;
		const uint8_t* nt = p + e_lfanew;
		if (nt[0] != 'P' || nt[1] != 'E' || nt[2] != 0 || nt[3] != 0)
			continue;
		uint16_t magic = 0;
		std::memcpy(&magic, nt + 0x18, 2);
		out_storage.is_64bit = (magic == 0x20B);

		const uint8_t* opt = nt + 0x18;
		uint32_t size_of_image = 0;
		uint32_t timestamp = 0;
		std::memcpy(&timestamp, nt + 8, 4);
		uint32_t opt_size_off = out_storage.is_64bit ? 0x38 : 0x38;
		(void)opt_size_off;
		std::memcpy(&size_of_image, opt + 0x38, 4);
		out_storage.size_of_image = size_of_image;
		out_storage.timestamp = timestamp;

		uint32_t data_dir_off = out_storage.is_64bit ? 0x70 : 0x60;
		const uint8_t* dir = opt + data_dir_off;
		std::memcpy(&out_storage.export_dir_rva, dir + 0 * 8, 4);
		std::memcpy(&out_storage.export_dir_size, dir + 0 * 8 + 4, 4);
		std::memcpy(&out_storage.import_dir_rva, dir + 1 * 8, 4);
		std::memcpy(&out_storage.import_dir_size, dir + 1 * 8 + 4, 4);

		uint16_t num_sections = 0;
		std::memcpy(&num_sections, nt + 6, 2);
		uint16_t opt_size = 0;
		std::memcpy(&opt_size, nt + 0x14, 2);
		const uint8_t* section_table = nt + 0x18 + opt_size;

		size_t section_size_avail = s.bytes.size() - off - (section_table - p);
		size_t can_read = section_size_avail / 40;
		if (num_sections > can_read)
			num_sections = static_cast<uint16_t>(can_read);

		for (uint16_t i = 0; i < num_sections; ++i) {
			const uint8_t* sec = section_table + static_cast<size_t>(i) * 40;
			pe_parser::section_info_t si;
			char name[9] = {};
			std::memcpy(name, sec, 8);
			si.name = name;
			std::memcpy(&si.virtual_size, sec + 8, 4);
			std::memcpy(&si.virtual_address, sec + 12, 4);
			std::memcpy(&si.raw_size, sec + 16, 4);
			std::memcpy(&si.characteristics, sec + 36, 4);
			out_storage.sections.push_back(si);
		}

		break;
	}

	return &out_storage;
}

static constexpr int WATCHDOG_TIMEOUT_MS = 10000;

class session_job_guard_t final {
public:
	session_job_guard_t() = default;
	session_job_guard_t(const session_job_guard_t&) = delete;
	session_job_guard_t& operator=(const session_job_guard_t&) = delete;

	~session_job_guard_t()
	{
		stop();
	}

	bool start(std::atomic<bool>* loader_cancel_sink) noexcept
	{
		if (!loader_cancel_sink || thread_.joinable())
			return false;
		loader_cancel_sink_ = loader_cancel_sink;
		exit_.store(false, std::memory_order_release);
		try {
			thread_ = std::thread([this] { run(); });
		} catch (...) {
			loader_cancel_sink_ = nullptr;
			return false;
		}
		return true;
	}

	void stop() noexcept
	{
		exit_.store(true, std::memory_order_release);
		if (thread_.joinable())
			thread_.join();
		loader_cancel_sink_ = nullptr;
	}

	void arm(std::atomic<bool>* job_cancel,
	         std::chrono::steady_clock::time_point deadline,
	         uint64_t addr) noexcept
	{
		watchdog_fired_elapsed_ms_.store(0, std::memory_order_release);
		watchdog_addr_.store(addr, std::memory_order_release);
		watchdog_deadline_.store(
			std::chrono::duration_cast<std::chrono::milliseconds>(
				deadline.time_since_epoch()).count(),
			std::memory_order_release);
		job_cancel_.store(job_cancel, std::memory_order_release);
		watchdog_armed_.store(true, std::memory_order_release);
		watchdog_state_.store(static_cast<uint32_t>(wd_state_t::running),
			std::memory_order_release);
	}

	void disarm() noexcept
	{
		uint32_t expected = static_cast<uint32_t>(wd_state_t::running);
		watchdog_state_.compare_exchange_strong(expected,
			static_cast<uint32_t>(wd_state_t::completed),
			std::memory_order_acq_rel, std::memory_order_acquire);
		watchdog_armed_.store(false, std::memory_order_release);
		job_cancel_.store(nullptr, std::memory_order_release);
	}

	bool watchdog_fired() const noexcept
	{
		return watchdog_state_.load(std::memory_order_acquire) ==
			static_cast<uint32_t>(wd_state_t::cancelled);
	}

	long long watchdog_fired_elapsed_ms() const noexcept
	{
		return watchdog_fired_elapsed_ms_.load(std::memory_order_acquire);
	}

private:
	void run() noexcept
	{
		auto armed_since = std::chrono::steady_clock::now();
		bool was_armed = false;
		while (!exit_.load(std::memory_order_acquire)) {
			std::atomic<bool>* cancel = job_cancel_.load(std::memory_order_acquire);
			if (cancel && loader_cancel_sink_ &&
				cancel->load(std::memory_order_acquire)) {
				loader_cancel_sink_->store(true, std::memory_order_release);
			}
			const bool armed = watchdog_armed_.load(std::memory_order_acquire);
			if (armed && !was_armed) {
				armed_since = std::chrono::steady_clock::now();
				was_armed = true;
			} else if (!armed) {
				was_armed = false;
			}
			if (armed &&
				watchdog_state_.load(std::memory_order_acquire) ==
					static_cast<uint32_t>(wd_state_t::running)) {
				const long long deadline_ms = watchdog_deadline_.load(std::memory_order_acquire);
				const auto now = std::chrono::steady_clock::now();
				const long long now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
					now.time_since_epoch()).count();
				if (now_ms >= deadline_ms) {
					uint32_t expected = static_cast<uint32_t>(wd_state_t::running);
					if (watchdog_state_.compare_exchange_strong(expected,
						static_cast<uint32_t>(wd_state_t::cancelled),
						std::memory_order_acq_rel, std::memory_order_acquire)) {
						const long long fired_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
							now - armed_since).count();
						watchdog_fired_elapsed_ms_.store(fired_ms, std::memory_order_release);
						if (cancel)
							cancel->store(true, std::memory_order_release);
						diag::log_tagged_critical_fmt("dec",
							"do_decompile_watchdog_fired addr=0x%llx elapsed_ms=%lld",
							static_cast<unsigned long long>(
								watchdog_addr_.load(std::memory_order_acquire)),
							fired_ms);
					}
				}
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(5));
		}
	}

	std::thread thread_;
	std::atomic<bool> exit_{false};
	std::atomic<bool>* loader_cancel_sink_ = nullptr;
	std::atomic<std::atomic<bool>*> job_cancel_{nullptr};
	std::atomic<bool> watchdog_armed_{false};
	std::atomic<uint32_t> watchdog_state_{static_cast<uint32_t>(wd_state_t::completed)};
	std::atomic<long long> watchdog_deadline_{0};
	std::atomic<long long> watchdog_fired_elapsed_ms_{0};
	std::atomic<unsigned long long> watchdog_addr_{0};
};

inline std::vector<std::pair<std::string, uint64_t>>
collect_callees(ghidra::Funcdata* fd, std::size_t max_callees = 65536,
                std::atomic<bool>* cancel = nullptr)
{
	std::vector<std::pair<std::string, uint64_t>> out;
	if (!fd)
		return out;
	int n = fd->numCalls();
	if (n <= 0)
		return out;
	if (static_cast<std::size_t>(n) > max_callees)
		n = static_cast<int>(max_callees);
	out.reserve(static_cast<std::size_t>(n));
	for (int i = 0; i < n; ++i) {
		if (cancel && cancel->load(std::memory_order_acquire))
			break;
		ghidra::FuncCallSpecs* spec = fd->getCallSpecs(i);
		if (!spec)
			continue;
		std::string name = spec->getName();
		uint64_t addr = spec->getEntryAddress().getOffset();
		if (name.empty())
			continue;
		out.emplace_back(std::move(name), addr);
	}
	std::sort(out.begin(), out.end());
	out.erase(std::unique(out.begin(), out.end()), out.end());
	return out;
}

inline bool valid_decompile_result_limits(
	const ghidra_decompile_result_limits_t& limits) noexcept
{
	const auto max_size = static_cast<uint64_t>((std::numeric_limits<std::size_t>::max)());
	return limits.max_pseudocode_bytes != 0 && limits.max_annotations != 0 &&
		limits.max_line_mappings != 0 && limits.max_callees != 0 &&
		limits.max_result_bytes >= limits.max_pseudocode_bytes &&
		limits.max_pseudocode_bytes <= max_size && limits.max_result_bytes <= max_size;
}

inline bool decompile_result_within_limits(
	const ghidra_result_t& result, const ghidra_decompile_result_limits_t& limits) noexcept
{
	if (!valid_decompile_result_limits(limits) ||
		(result.printc_evidence && result.printc_evidence->size() > limits.max_pseudocode_bytes) ||
		result.annotations.size() > limits.max_annotations ||
		result.line_to_address.size() > limits.max_line_mappings ||
		result.callees.size() > limits.max_callees) {
		return false;
	}

	uint64_t total = 0;
	const auto consume = [&total, &limits](uint64_t amount) noexcept {
		if (amount > limits.max_result_bytes - total)
			return false;
		total += amount;
		return true;
	};
	if (!consume(static_cast<uint64_t>(result.function_name.size())) ||
		!consume(static_cast<uint64_t>(result.printc_evidence ? result.printc_evidence->size() : 0)) ||
		!consume(static_cast<uint64_t>(result.sleigh_id.size())) ||
		!consume(static_cast<uint64_t>(result.error_text.size()))) {
		return false;
	}
	for (const auto& annotation : result.annotations) {
		if (!consume(static_cast<uint64_t>(sizeof(annotation))) ||
			!consume(static_cast<uint64_t>(annotation.name.size()))) {
			return false;
		}
	}
	for (const auto& mapping : result.line_to_address) {
		if (!consume(static_cast<uint64_t>(sizeof(mapping))))
			return false;
	}
	for (const auto& callee : result.callees) {
		if (!consume(static_cast<uint64_t>(sizeof(callee))) ||
			!consume(static_cast<uint64_t>(callee.first.size()))) {
			return false;
		}
	}
	return true;
}

inline ghidra_result_t do_decompile(aida_ghidra::architecture_t* arch,
                                    uint64_t entry_addr,
                                    std::atomic<bool>* cancel = nullptr,
                                    std::optional<std::chrono::steady_clock::time_point> request_deadline = {},
                                    const ghidra_decompile_result_limits_t& result_limits = {},
                                    const aida::analysis::ghidra_ir_adapter::capture_request_t* typed_request = nullptr,
                                    session_job_guard_t* job_guard = nullptr,
                                    ghidra::FunctionSymbol** job_symbol_out = nullptr,
                                    uint64_t job_ordinal = 0)
{
	ghidra_result_t result;
	result.function_addr = entry_addr;
	if (!valid_decompile_result_limits(result_limits)) {
		result.is_error = true;
		result.error_text = "decompilation result limits are invalid";
		return result;
	}

	const bool verbose_logs = (job_ordinal == 0) || (job_ordinal <= 256) ||
		((job_ordinal & 0xFFULL) == 0);

	auto start_time = std::chrono::high_resolution_clock::now();

	ghidra::AddrSpace* code_space = arch->translate->getDefaultCodeSpace();
	if (!code_space) {
		result.is_error = true;
		result.error_text = "no default code space available";
		return result;
	}

	ghidra::Address addr(code_space, entry_addr);

	const aida_ghidra::function_db_t& db = arch->symbol_database();
	const aida_ghidra::symbol_record_t* known = db.find_by_address(entry_addr);

	std::string func_name;
	bool known_is_callable = known &&
		(known->kind == aida_ghidra::symbol_kind_t::function ||
		 known->kind == aida_ghidra::symbol_kind_t::export_);
	if (known_is_callable && !known->name.empty() && known->name.size() <= 1024) {
		func_name = known->name;
	} else {
		char name_buf[64];
		std::snprintf(name_buf, sizeof(name_buf), "sub_%llx",
		              static_cast<unsigned long long>(entry_addr));
		func_name = name_buf;
	}

	ghidra::Scope* global_scope = arch->symboltab->getGlobalScope();

	ghidra::Funcdata* fd = global_scope->queryFunction(addr);
	if (fd) {
		if (fd->isProcStarted())
			arch->clearAnalysis(fd);
	} else {
		ghidra::FunctionSymbol* sym = global_scope->addFunction(addr, func_name);
		fd = sym ? sym->getFunction() : nullptr;
	}

	if (!fd) {
		result.is_error = true;
		result.error_text = "failed to materialize function symbol";
		return result;
	}

	if (job_symbol_out)
		*job_symbol_out = fd->getSymbol();

	if (fd->hasNoCode()) {
		result.is_error = true;
		result.error_text = "no code at the specified address";
		return result;
	}

	arch->allacts.getCurrent()->reset(*fd);

	if (verbose_logs) {
		diag::log_tagged_critical_fmt("dec",
			"do_decompile_enter addr=0x%llx tid=%lu",
			static_cast<unsigned long long>(entry_addr),
			static_cast<unsigned long>(GetCurrentThreadId()));
	}

	auto wd_state = std::make_shared<std::atomic<uint32_t>>(
		static_cast<uint32_t>(wd_state_t::running));
	auto watchdog_fired_elapsed_ms = std::make_shared<std::atomic<long long>>(0);

	auto wd_start = std::chrono::steady_clock::now();
	auto wd_deadline = request_deadline.has_value()
		? *request_deadline
		: wd_start + std::chrono::milliseconds(WATCHDOG_TIMEOUT_MS);

	if (job_guard) {
		job_guard->arm(cancel, wd_deadline, entry_addr);
	}
	struct watchdog_release_t {
		session_job_guard_t* guard = nullptr;
		~watchdog_release_t() { if (guard) guard->disarm(); }
	} watchdog_release{job_guard};

	std::atomic<bool>* cancel_for_wd = cancel;
	uint64_t wd_addr = entry_addr;
	if (!job_guard) {
		aida::infra::executor::submission_t watchdog_sub;
		watchdog_sub.owner_subsystem = "disasm";
		watchdog_sub.label = "disasm.ghidra.watchdog";
		watchdog_sub.thread_class = "bounded_task";
		watchdog_sub.domain = aida::infra::executor::domain_t::diagnostics;
		watchdog_sub.priority = 3;
		watchdog_sub.body = [wd_state, watchdog_fired_elapsed_ms,
		                     cancel_for_wd, wd_deadline, wd_start, wd_addr]() {
			while (true) {
				uint32_t cur = wd_state->load(std::memory_order_acquire);
				if (cur != static_cast<uint32_t>(wd_state_t::running))
					return;
				auto now = std::chrono::steady_clock::now();
				if (now >= wd_deadline) {
					uint32_t expected = static_cast<uint32_t>(wd_state_t::running);
					if (!wd_state->compare_exchange_strong(expected,
					    static_cast<uint32_t>(wd_state_t::cancelled),
					    std::memory_order_acq_rel, std::memory_order_acquire)) {
						return;
					}
					long long fired_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
						now - wd_start).count();
					watchdog_fired_elapsed_ms->store(fired_ms, std::memory_order_release);
					if (cancel_for_wd)
						cancel_for_wd->store(true, std::memory_order_release);
					diag::log_tagged_critical_fmt("dec",
						"do_decompile_watchdog_fired addr=0x%llx elapsed_ms=%lld",
						static_cast<unsigned long long>(wd_addr),
						fired_ms);
					return;
				}
				std::this_thread::sleep_for(std::chrono::milliseconds(50));
			}
		};
		if (!aida::infra::executor::submit(std::move(watchdog_sub)).submitted) {
			diag::log_tagged_critical_fmt("dec",
				"do_decompile_watchdog_post_failed addr=0x%llx",
				static_cast<unsigned long long>(wd_addr));
		}
	}

	auto perform_start = std::chrono::steady_clock::now();

	ghidra::int4 perform_res = -1;
	bool perform_threw = false;
	std::string perform_err_text;

	try {
		if (cancel && cancel->load(std::memory_order_acquire))
			throw ghidra::LowlevelError("cancelled");
		if (aida_ghidra::is_x86_family(arch->getTarget())) {
			aida_ghidra::pcode_fixup_preprocessor_t::fixup_shared_return_jump_to_imports(fd, *arch);
		}
		if (cancel && cancel->load(std::memory_order_acquire))
			throw ghidra::LowlevelError("cancelled");
		perform_res = arch->allacts.getCurrent()->perform(*fd);
	}
	catch (ghidra::LowlevelError& e) {
		perform_threw = true;
		perform_err_text = e.explain;
		perform_res = -1;
	}
	catch (ghidra::DecoderError& e) {
		perform_threw = true;
		perform_err_text = e.explain;
		perform_res = -1;
	}
	catch (std::exception& e) {
		perform_threw = true;
		perform_err_text = e.what();
		perform_res = -1;
	}
	catch (...) {
		perform_threw = true;
		perform_err_text = "unknown exception in perform";
		perform_res = -1;
	}

	auto perform_end = std::chrono::steady_clock::now();
	long long perform_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
		perform_end - perform_start).count();

	bool fired = false;
	if (job_guard) {
		fired = job_guard->watchdog_fired();
		if (fired) {
			watchdog_fired_elapsed_ms->store(job_guard->watchdog_fired_elapsed_ms(),
				std::memory_order_release);
		}
	} else {
		uint32_t expected_running = static_cast<uint32_t>(wd_state_t::running);
		bool we_completed_first = wd_state->compare_exchange_strong(expected_running,
			static_cast<uint32_t>(wd_state_t::completed),
			std::memory_order_acq_rel, std::memory_order_acquire);
		fired = !we_completed_first &&
			(static_cast<wd_state_t>(wd_state->load(std::memory_order_acquire)) == wd_state_t::cancelled);
	}
	bool external_cancel = (cancel && cancel->load(std::memory_order_acquire));

	if (fired) {
		result.is_error = true;
		result.error_text = "Decompilation timed out (function too complex or invalid code).";
		auto end_time = std::chrono::high_resolution_clock::now();
		result.elapsed_ms = std::chrono::duration<double, std::milli>(end_time - start_time).count();
		diag::log_tagged_critical_fmt("dec",
			"do_decompile_exit addr=0x%llx outcome=timeout fired_at_ms=%lld total_ms=%.2f",
			static_cast<unsigned long long>(entry_addr),
			watchdog_fired_elapsed_ms->load(std::memory_order_acquire),
			result.elapsed_ms);
		return result;
	}

	if (external_cancel) {
		result.is_error = true;
		result.error_text = "Decompilation cancelled.";
		auto end_time = std::chrono::high_resolution_clock::now();
		result.elapsed_ms = std::chrono::duration<double, std::milli>(end_time - start_time).count();
		return result;
	}

	if (perform_threw) {
		result.is_error = true;
		result.error_text = perform_err_text.empty()
			? std::string("Cannot decompile this function (the address may not contain a valid function).")
			: perform_err_text;
		auto end_time = std::chrono::high_resolution_clock::now();
		result.elapsed_ms = std::chrono::duration<double, std::milli>(end_time - start_time).count();
		return result;
	}

	(void)perform_ms;
	if (perform_res < 0) {
		result.is_error = true;
		result.error_text = "Ghidra action stopped before completion";
		auto end_time = std::chrono::high_resolution_clock::now();
		result.elapsed_ms = std::chrono::duration<double, std::milli>(end_time - start_time).count();
		diag::log_tagged_critical_fmt("dec",
			"do_decompile_exit addr=0x%llx outcome=partial_action total_ms=%.2f",
			static_cast<unsigned long long>(entry_addr),
			result.elapsed_ms);
		return result;
	}

	if (typed_request) {
		auto typed = aida::analysis::ghidra_ir_adapter::extract(*fd, *typed_request);
		result.typed_diagnostics = std::move(typed.diagnostics);
		if (!typed.artifacts) {
			result.is_error = true;
			result.error_text = "Ghidra action completed without canonical typed artifacts";
			auto end_time = std::chrono::high_resolution_clock::now();
			result.elapsed_ms = std::chrono::duration<double, std::milli>(end_time - start_time).count();
			return result;
		}
		result.typed_artifacts = std::move(*typed.artifacts);
	}

	if (result_limits.capture_printc_evidence) {
		std::ostringstream xml_oss;
		bool produced_markup = false;
		try {
			if (cancel && cancel->load(std::memory_order_acquire))
				throw ghidra::LowlevelError("cancelled");
			arch->setPrintLanguage("aida-c-language");
			arch->print->setOutputStream(&xml_oss);
			arch->print->setMarkup(true);
			arch->print->docFunction(fd);
			produced_markup = true;
		}
		catch (...) {
			produced_markup = false;
		}

		if (produced_markup) {
			std::string xml = xml_oss.str();
			aida_ghidra::annotated_code_t parsed;
			if (aida_ghidra::parse_code_xml(fd, xml, parsed,
			                                result_limits.max_annotations,
			                                result_limits.max_line_mappings,
			                                cancel) && !parsed.code.empty()) {
				result.printc_evidence = std::move(parsed.code);
				result.annotations = std::move(parsed.annotations);
				result.line_to_address = std::move(parsed.line_to_address);
			}
		}

		if (!result.printc_evidence) {
			std::ostringstream plain_oss;
			try {
				if (cancel && cancel->load(std::memory_order_acquire))
					throw ghidra::LowlevelError("cancelled");
				arch->print->setMarkup(false);
				arch->print->setOutputStream(&plain_oss);
				arch->print->docFunction(fd);
				const auto plain = plain_oss.str();
				if (!plain.empty())
					result.printc_evidence = plain;
			}
			catch (...) {
			}
		}
	}

	result.function_name = fd->getName();
	result.callees = collect_callees(fd, result_limits.max_callees, cancel);
	result.sleigh_id = arch->getTarget();
	if (!decompile_result_within_limits(result, result_limits)) {
		result.is_error = true;
		result.error_text = "decompilation result exceeds configured limits";
		return result;
	}
	result.complete = true;

	auto end_time = std::chrono::high_resolution_clock::now();
	result.elapsed_ms = std::chrono::duration<double, std::milli>(end_time - start_time).count();

	if (verbose_logs) {
		diag::log_tagged_critical_fmt("dec",
			"do_decompile_exit addr=0x%llx outcome=ok total_ms=%.2f typed=%d printc_evidence_bytes=%zu annot=%zu",
			static_cast<unsigned long long>(entry_addr),
			result.elapsed_ms,
			result.typed_artifacts ? 1 : 0,
			result.printc_evidence ? result.printc_evidence->size() : 0,
			result.annotations.size());
	}

	return result;
}

struct prepared_arch_t {
	std::unique_ptr<aida_ghidra::architecture_t> arch;
	std::ostringstream err;
	double init_ms = 0.0;

	void record_init_ms(std::chrono::steady_clock::time_point started,
	                    const char* sleigh_id,
	                    uint64_t image_bytes)
	{
		init_ms = std::chrono::duration<double, std::milli>(
			std::chrono::steady_clock::now() - started).count();
		diag::log_tagged_fmt("dec",
			"arch_init_ms=%.2f sleigh=%s image_bytes=%llu",
			init_ms,
			(sleigh_id && sleigh_id[0] != '\0') ? sleigh_id : "<unknown>",
			static_cast<unsigned long long>(image_bytes));
	}

	static void apply_execution_mode(
		aida_ghidra::architecture_t& architecture,
		aida::analysis::architecture_mode_t architecture_mode,
		uint64_t context_begin,
		uint64_t context_size)
	{
		if (architecture_mode != aida::analysis::architecture_mode_t::arm_a32 &&
			architecture_mode != aida::analysis::architecture_mode_t::arm_thumb)
			return;
		if (context_size == 0 || context_size > UINT64_MAX - context_begin)
			throw ghidra::LowlevelError("ARM context range is invalid");
		auto* context = architecture.context_database();
		auto* code_space = architecture.getDefaultCodeSpace();
		if (!context || !code_space)
			throw ghidra::LowlevelError("ARM context database is unavailable");
		const ghidra::uintm thumb_mode =
			architecture_mode == aida::analysis::architecture_mode_t::arm_thumb ? 1U : 0U;
		context->setVariableRegion("TMode", ghidra::Address(code_space, context_begin),
			ghidra::Address(code_space, context_begin + context_size), thumb_mode);
		if (context->getVariable("TMode", ghidra::Address(code_space, context_begin)) != thumb_mode)
			throw ghidra::LowlevelError("ARM execution mode context was not applied");
	}

	prepared_arch_t(const uint8_t* data,
	                size_t size,
	                uint64_t base,
	                const DisasmFile* file_fallback,
	                std::atomic<bool>* cancel,
	                const std::string& sleigh_id,
	                std::vector<aida_ghidra::region_t> extra_regions = {},
	                uint64_t total_image_size = 0,
	                aida::analysis::architecture_mode_t architecture_mode =
					aida::analysis::architecture_mode_t::unknown,
	                bool keep_fixateglobals = false)
	{
		const auto init_started = std::chrono::steady_clock::now();
		auto loader = std::make_unique<aida_ghidra::load_image_t>(
			data, size, base, file_fallback, cancel);
		if (total_image_size != 0)
			loader->set_image_size(total_image_size);
		for (auto& reg : extra_regions) {
			if (reg.view)
				loader->add_region_view(reg.start_va, reg.view, reg.view_size, reg.owner);
			else
				loader->add_region(reg.start_va, std::move(reg.data));
		}
		arch = std::make_unique<aida_ghidra::architecture_t>(sleigh_id, &err);
		arch->set_keep_fixateglobals(keep_fixateglobals);
		arch->take_loader(std::move(loader));

		ghidra::DocumentStorage store;
		arch->init(store);
		apply_execution_mode(*arch, architecture_mode, base,
			total_image_size != 0 ? total_image_size : static_cast<uint64_t>(size));
		record_init_ms(init_started, sleigh_id.c_str(),
			total_image_size != 0 ? total_image_size : static_cast<uint64_t>(size));
	}

	prepared_arch_t(const prepared_arch_t&) = delete;
	prepared_arch_t& operator=(const prepared_arch_t&) = delete;

	prepared_arch_t(
		std::shared_ptr<const aida::analysis::byte_provider_t> provider,
		std::shared_ptr<const aida::analysis::pe_image_t> image,
		uint64_t load_base,
		std::function<bool()> cancel_check,
		const std::string& sleigh_id,
		std::vector<aida_ghidra::provider_patch_t> patches = {},
		bool keep_fixateglobals = false)
	{
		const auto init_started = std::chrono::steady_clock::now();
		auto loader = std::make_unique<aida_ghidra::load_image_t>(
			std::move(provider), std::move(image), load_base,
			std::move(cancel_check),
			std::move(patches));
		arch = std::make_unique<aida_ghidra::architecture_t>(sleigh_id, &err);
		arch->set_keep_fixateglobals(keep_fixateglobals);
		arch->take_loader(std::move(loader));

		ghidra::DocumentStorage store;
		arch->init(store);
		record_init_ms(init_started, sleigh_id.c_str(), 0);
	}

	prepared_arch_t(
		std::shared_ptr<const aida::analysis::ghidra_adapter::ghidra_load_image_t> image,
		aida::analysis::address_space_id_t address_space,
		aida::analysis::architecture_mode_t architecture_mode,
		std::function<bool()> cancel_check,
		const std::string& sleigh_id,
		bool keep_fixateglobals = false)
	{
#if defined(AIDA_C03_ISOLATED_NATIVE_DECOMPILER_WORKER)
		static_cast<void>(image);
		static_cast<void>(address_space);
		static_cast<void>(architecture_mode);
		static_cast<void>(cancel_check);
		static_cast<void>(sleigh_id);
		static_cast<void>(keep_fixateglobals);
		throw ghidra::LowlevelError("normalized workspace decompilation is unavailable in the isolated worker");
#else
		if (!image)
			throw ghidra::LowlevelError("normalized workspace load image is unavailable");
		const auto& workspace_image = image->image();
		const uint64_t context_begin =
			(address_space == aida::analysis::address_space_id_t::virtual_address ||
			 address_space == aida::analysis::address_space_id_t::live_virtual)
				? workspace_image.image_base : 0;
		if (workspace_image.image_size == 0 ||
			workspace_image.image_size > UINT64_MAX - context_begin)
			throw ghidra::LowlevelError("normalized workspace context range is invalid");
		const auto init_started = std::chrono::steady_clock::now();
		auto loader = std::make_unique<aida_ghidra::load_image_t>(
			std::move(image), address_space, std::move(cancel_check));
		arch = std::make_unique<aida_ghidra::architecture_t>(sleigh_id, &err);
		arch->set_keep_fixateglobals(keep_fixateglobals);
		arch->take_loader(std::move(loader));

		ghidra::DocumentStorage store;
		arch->init(store);
		apply_execution_mode(*arch, architecture_mode, context_begin,
			workspace_image.image_size);
		record_init_ms(init_started, sleigh_id.c_str(), workspace_image.image_size);
#endif
	}
};

__declspec(noinline) inline DWORD seh_apply_pdb_types(aida_ghidra::architecture_t* arch)
{
	__try {
		arch->apply_pdb_types();
		return 0;
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		return GetExceptionCode();
	}
}

__declspec(noinline) inline DWORD seh_apply_pdb_function_prototypes(aida_ghidra::architecture_t* arch)
{
	__try {
		arch->apply_pdb_function_prototypes();
		return 0;
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		return GetExceptionCode();
	}
}

inline void populate_symbols(aida_ghidra::architecture_t& arch,
                             const uint8_t* data,
                             size_t size,
                             uint64_t base,
                             const DisasmFile* file)
{
	auto& db = arch.symbol_database();
	if (file && file->loaded) {
		pe_parser::pe_info_t storage;
		auto pe = try_parse_pe_info(file, storage);
		aida_ghidra::populate_from_pe(db, *file, pe);
	} else {
		db.clear();
		db.image_base = base;
		db.image_size = size;
		db.is_pe = false;
	}
	aida_ghidra::populate_from_driver(db, base);
	aida_ghidra::populate_from_symbol_store(db);
	aida_ghidra::populate_default_noreturn(db);

	diag::log_tagged_critical("dec_pdb", "populate_symbols_pre_apply_pdb_types");
	DWORD seh_types = seh_apply_pdb_types(&arch);
	if (seh_types != 0) {
		std::string last_name = aida_ghidra::architecture_t::current_apply_pdb_name();
		const char* last_stage = aida_ghidra::architecture_t::current_apply_pdb_stage();
		diag::log_tagged_critical_fmt("dec_pdb",
			"populate_symbols_apply_pdb_types_seh_fault code=0x%08X last_stage=%s last_name=%s",
			seh_types,
			last_stage ? last_stage : "<null>",
			last_name.c_str());
	}

	diag::log_tagged_critical("dec_pdb", "populate_symbols_pre_apply_pdb_function_prototypes");
	DWORD seh_protos = seh_apply_pdb_function_prototypes(&arch);
	if (seh_protos != 0) {
		std::string last_name = aida_ghidra::architecture_t::current_apply_pdb_name();
		const char* last_stage = aida_ghidra::architecture_t::current_apply_pdb_stage();
		diag::log_tagged_critical_fmt("dec_pdb",
			"populate_symbols_apply_pdb_function_prototypes_seh_fault code=0x%08X last_stage=%s last_name=%s",
			seh_protos,
			last_stage ? last_stage : "<null>",
			last_name.c_str());
	}
	diag::log_tagged_critical("dec_pdb", "populate_symbols_exit");
}

}

inline bool init(const std::string& specs_dir = "") {
	diag::log_tagged_critical_fmt("dec", "ghidra_init_enter specs_dir_param=%s",
		specs_dir.empty() ? "<empty>" : specs_dir.c_str());
	std::lock_guard<std::mutex> lk(g_state.init_mtx);
	if (g_state.initialized.load()) {
		diag::log_tagged_critical_fmt("dec", "ghidra_init_exit reason=already_initialized detail=%s",
			g_state.init_detail.empty() ? "<empty>" : g_state.init_detail.c_str());
		return true;
	}
	g_state.err_stream.str("");
	g_state.err_stream.clear();
	g_state.last_init_reason = "starting";
	g_state.last_specs_probe = detail::describe_specs_probe(specs_dir);
	g_state.init_detail = "ghidra init starting; " + g_state.last_specs_probe;
	diag::log_tagged_critical_fmt("dec", "ghidra_init_specs_probe %s", g_state.last_specs_probe.c_str());

	std::string dir = specs_dir;
	if (dir.empty())
		dir = detail::find_specs_dir();
	diag::log_tagged_critical_fmt("dec", "ghidra_init_find_specs_dir result=%s",
		dir.empty() ? "<empty>" : dir.c_str());

	size_t embedded_resource_bytes = 0;
	size_t embedded_resource_count = 0;
	if (dir.empty()) {
		embedded_resource_count = detail::ghidra_spec_resource_count(embedded_resource_bytes);
		diag::log_tagged_critical_fmt("dec",
			"ghidra_init_pre_extract_specs target=temp embedded_resources=%zu/4 embedded_resource_bytes=%zu",
			embedded_resource_count,
			embedded_resource_bytes);
		dir = embedded_resources::extract_ghidra_specs();
		const size_t extracted_file_count = detail::count_required_specs_files(dir);
		diag::log_tagged_critical_fmt("dec",
			"ghidra_init_post_extract_specs result=%s target=%s files=%zu/4 ready=%d embedded_resources=%zu/4 embedded_resource_bytes=%zu",
			dir.empty() ? "<empty>" : dir.c_str(),
			dir.empty() ? "<empty>" : dir.c_str(),
			extracted_file_count,
			detail::specs_dir_has_required_files(dir) ? 1 : 0,
			embedded_resource_count,
			embedded_resource_bytes);
		if (!dir.empty()) {
			static std::string s_temp_specs_dir;
			s_temp_specs_dir = dir;
			std::atexit([]() {
				embedded_resources::delete_specs_dir(s_temp_specs_dir);
			});
		}
	}

	if (dir.empty()) {
		g_state.last_init_reason = "dependency_blocked_no_specs_dir";
		g_state.init_detail = "dependency_blocked=1 reason=no_ghidra_specs_dir embedded_resources=" +
			std::to_string(embedded_resource_count) + "/4 embedded_resource_bytes=" +
			std::to_string(embedded_resource_bytes) + " " + g_state.last_specs_probe;
		g_state.err_stream << g_state.init_detail << "\n";
		diag::log_tagged_critical_fmt("dec", "ghidra_init_exit reason=no_specs_dir detail=%s",
			g_state.init_detail.c_str());
		return false;
	}

	try {
		g_state.specs_dir = dir;
		std::vector<std::string> paths;
		paths.push_back(dir);
		g_state.last_init_reason = "start_library";
		g_state.init_detail = "starting_decompiler_library specs_dir=\"" + dir + "\" " + g_state.last_specs_probe;
		diag::log_tagged_critical_fmt("dec", "ghidra_init_pre_startDecompilerLibrary dir=%s", dir.c_str());
		ghidra::startDecompilerLibrary(paths);
		diag::log_tagged_critical("dec", "ghidra_init_post_startDecompilerLibrary");
		g_state.initialized.store(true);
		g_state.last_init_reason = "ok";
		g_state.init_detail = "initialized specs_dir=\"" + dir + "\" " + g_state.last_specs_probe;
		diag::log_tagged_critical_fmt("dec", "ghidra_init_exit reason=ok detail=%s",
			g_state.init_detail.c_str());
		return true;
	}
	catch (ghidra::LowlevelError& err) {
		g_state.err_stream << "ghidra init error: " << err.explain << "\n";
		g_state.last_init_reason = "lowlevel_error";
		g_state.init_detail = "dependency_blocked=1 reason=lowlevel_error specs_dir=\"" + dir + "\" err=\"" + err.explain + "\" " + g_state.last_specs_probe;
		g_state.err_stream << g_state.init_detail << "\n";
		diag::log_tagged_critical_fmt("dec", "ghidra_init_exit reason=lowlevel_error err=%s detail=%s",
			err.explain.c_str(), g_state.init_detail.c_str());
		return false;
	}
	catch (ghidra::DecoderError& err) {
		g_state.err_stream << "ghidra decoder error: " << err.explain << "\n";
		g_state.last_init_reason = "decoder_error";
		g_state.init_detail = "dependency_blocked=1 reason=decoder_error specs_dir=\"" + dir + "\" err=\"" + err.explain + "\" " + g_state.last_specs_probe;
		g_state.err_stream << g_state.init_detail << "\n";
		diag::log_tagged_critical_fmt("dec", "ghidra_init_exit reason=decoder_error err=%s detail=%s",
			err.explain.c_str(), g_state.init_detail.c_str());
		return false;
	}
	catch (...) {
		g_state.err_stream << "ghidra init: unknown error\n";
		g_state.last_init_reason = "unknown_exception";
		g_state.init_detail = "dependency_blocked=1 reason=unknown_exception specs_dir=\"" + dir + "\" " + g_state.last_specs_probe;
		g_state.err_stream << g_state.init_detail << "\n";
		diag::log_tagged_critical_fmt("dec", "ghidra_init_exit reason=unknown_exception detail=%s",
			g_state.init_detail.c_str());
		return false;
	}
}

inline ghidra_result_t decompile_function(uint64_t entry_addr,
                                          std::atomic<bool>* cancel = nullptr)
{
	active_decompile_guard_t active_guard(cancel);
	ghidra_result_t result;
	result.function_addr = entry_addr;

	if (active_guard.was_shutting_down) {
		result.is_error = true;
		result.error_text = "decompiler is shutting down";
		return result;
	}

	if (!g_state.initialized.load()) {
		if (!init()) {
			result.is_error = true;
			result.error_text = "dependency_blocked: ghidra decompiler not initialized; " + init_diagnostics();
			return result;
		}
	}

	const uint32_t attached_pid = driver_bridge::attached_pid();
	auto modules = attached_pid != 0 ? driver_bridge::enumerate_modules_for(attached_pid) : driver_bridge::enumerate_modules();
	driver_bridge::module_info_t selected_module{};
	bool module_found = false;
	for (const auto& m : modules) {
		const uint64_t end = m.base + static_cast<uint64_t>(m.size);
		if (end <= m.base)
			continue;
		if (entry_addr >= m.base && entry_addr < end) {
			if (!module_found || m.size < selected_module.size) {
				selected_module = m;
				module_found = true;
			}
		}
	}

	pe_parser::pe_info_t pe;
	bool pe_ok = false;
	pe_parser::section_info_t selected_section{};
	bool section_found = false;
	bool section_executable = false;
	uint64_t module_base = module_found ? selected_module.base : 0;
	uint64_t module_size = module_found ? selected_module.size : 0;
	uint64_t section_start = 0;
	uint64_t section_end = 0;
	if (module_found) {
		pe_ok = pe_parser::parse(selected_module.base, pe, false);
		if (pe_ok) {
			const uint64_t rva = entry_addr >= selected_module.base ? entry_addr - selected_module.base : 0;
			for (const auto& s : pe.sections) {
				const uint64_t size = (std::max)(static_cast<uint64_t>(s.virtual_size), static_cast<uint64_t>(s.raw_size));
				if (size == 0)
					continue;
				const uint64_t start = static_cast<uint64_t>(s.virtual_address);
				const uint64_t end = start + size;
				if (end <= start)
					continue;
				if (rva >= start && rva < end) {
					selected_section = s;
					section_found = true;
					section_executable = decompile_section_executable(s.characteristics);
					section_start = selected_module.base + start;
					section_end = selected_module.base + end;
					const uint64_t module_end = selected_module.base + static_cast<uint64_t>(selected_module.size);
					if (module_end > selected_module.base && section_end > module_end)
						section_end = module_end;
					break;
				}
			}
		}
	}

	driver_bridge::memory_region_t region{};
	const bool region_ok = attached_pid != 0
		? driver_bridge::query_memory_for(attached_pid, entry_addr, region)
		: driver_bridge::query_memory(entry_addr, region);
	const bool region_executable = region_ok && decompile_protect_executable(region.protect);
	const bool region_committed = region_ok && region.state == MEM_COMMIT;
	if (!section_found && region_ok) {
		module_base = module_found ? selected_module.base : region.base;
		module_size = module_found ? selected_module.size : region.size;
		section_start = region.base;
		section_end = region.base + region.size;
		section_found = true;
		section_executable = region_executable;
	}

	diag::log_tagged_fmt("ghidra",
		"decompile_function_resolve addr=0x%llX pid=%u module_found=%d module=%s module_base=0x%llX module_size=0x%llX pe_ok=%d section_found=%d section=%s section_start=0x%llX section_end=0x%llX section_exec=%d region_ok=%d region_base=0x%llX region_size=0x%llX region_state=0x%08X region_protect=0x%08X region_type=0x%08X region_exec=%d",
		static_cast<unsigned long long>(entry_addr),
		static_cast<unsigned>(attached_pid),
		module_found ? 1 : 0,
		module_found ? selected_module.name.c_str() : "<none>",
		static_cast<unsigned long long>(module_base),
		static_cast<unsigned long long>(module_size),
		pe_ok ? 1 : 0,
		section_found ? 1 : 0,
		section_found ? selected_section.name.c_str() : "<none>",
		static_cast<unsigned long long>(section_start),
		static_cast<unsigned long long>(section_end),
		section_executable ? 1 : 0,
		region_ok ? 1 : 0,
		static_cast<unsigned long long>(region.base),
		static_cast<unsigned long long>(region.size),
		static_cast<unsigned>(region.state),
		static_cast<unsigned>(region.protect),
		static_cast<unsigned>(region.type),
		region_executable ? 1 : 0);

	if (!section_found || section_end <= section_start || entry_addr < section_start || entry_addr >= section_end) {
		result.is_error = true;
		result.error_text = "failed to resolve an executable module section for the target address";
		return result;
	}
	if (!section_executable) {
		result.is_error = true;
		result.error_text = "target address is not inside an executable section";
		return result;
	}
	if (region_ok) {
		if (!region_committed || (region.protect & PAGE_GUARD) != 0 || (region.protect & PAGE_NOACCESS) != 0) {
			result.is_error = true;
			result.error_text = "target address is not in readable committed executable memory";
			return result;
		}
		const uint64_t region_end = region.base + region.size;
		if (region.base <= entry_addr && region_end > entry_addr) {
			if (section_start < region.base)
				section_start = region.base;
			if (section_end > region_end)
				section_end = region_end;
		}
	}

	constexpr size_t MAX_DECOMPILE_READ = 0x20000;
	uint64_t read_base = section_start;
	if (entry_addr - read_base >= MAX_DECOMPILE_READ) {
		read_base = entry_addr & ~0xFFFULL;
		if (read_base < section_start)
			read_base = section_start;
	}
	uint64_t read_end = section_end;
	if (read_end - read_base > MAX_DECOMPILE_READ)
		read_end = read_base + MAX_DECOMPILE_READ;
	if (entry_addr >= read_end) {
		read_base = entry_addr & ~0xFFFULL;
		if (read_base < section_start)
			read_base = section_start;
		read_end = (std::min)(section_end, read_base + static_cast<uint64_t>(MAX_DECOMPILE_READ));
	}
	const size_t read_size = read_end > read_base ? static_cast<size_t>(read_end - read_base) : 0;
	if (read_size == 0 || entry_addr < read_base || entry_addr >= read_end) {
		result.is_error = true;
		result.error_text = "resolved executable read window does not contain the target address";
		return result;
	}

	std::vector<uint8_t> mem;
	SetLastError(ERROR_SUCCESS);
	const bool read_ok = attached_pid != 0
		? driver_bridge::read_memory_for(attached_pid, read_base, read_size, mem)
		: driver_bridge::read_memory(read_base, read_size, mem);
	const DWORD read_gle = read_ok ? ERROR_SUCCESS : GetLastError();
	if (mem.size() > read_size)
		mem.resize(read_size);
	const size_t entry_offset = entry_addr >= read_base ? static_cast<size_t>(entry_addr - read_base) : mem.size();
	const size_t entry_window = entry_offset < mem.size() ? (std::min)(static_cast<size_t>(256), mem.size() - entry_offset) : 0;
	size_t entry_zero_count = 0;
	size_t entry_longest_zero_run = 0;
	decompile_zero_window_stats(mem, entry_offset, entry_window, entry_zero_count, entry_longest_zero_run);
	const bool entry_window_zero = entry_window == 0 || entry_zero_count == entry_window;
	diag::log_tagged_fmt("ghidra",
		"decompile_function_read addr=0x%llX read_base=0x%llX read_size=%zu read_ok=%d bytes=%zu gle=%lu entry_offset=%zu entry_window=%zu entry_zero=%zu entry_nonzero=%zu entry_longest_zero=%zu module_base=0x%llX module_size=0x%llX section_start=0x%llX section_end=0x%llX region_state=0x%08X region_protect=0x%08X",
		static_cast<unsigned long long>(entry_addr),
		static_cast<unsigned long long>(read_base),
		read_size,
		read_ok ? 1 : 0,
		mem.size(),
		static_cast<unsigned long>(read_gle),
		entry_offset,
		entry_window,
		entry_zero_count,
		entry_window >= entry_zero_count ? entry_window - entry_zero_count : 0,
		entry_longest_zero_run,
		static_cast<unsigned long long>(module_base),
		static_cast<unsigned long long>(module_size),
		static_cast<unsigned long long>(section_start),
		static_cast<unsigned long long>(section_end),
		static_cast<unsigned>(region.state),
		static_cast<unsigned>(region.protect));

	if (!read_ok || mem.empty() || entry_offset >= mem.size()) {
		result.is_error = true;
		result.error_text = "failed to read executable bytes at target address";
		return result;
	}
	if (attached_pid != 0 && driver_bridge::attached_pid() != attached_pid) {
		result.is_error = true;
		result.error_text = "attached target changed while executable bytes were read";
		diag::log_tagged_fmt("ghidra",
			"decompile_function_discard_stale addr=0x%llX expected_pid=%u active_pid=%u",
			static_cast<unsigned long long>(entry_addr), attached_pid,
			driver_bridge::attached_pid());
		return result;
	}
	if (entry_window_zero) {
		result.is_error = true;
		result.error_text = "selected address resolves to zero-filled entry bytes, not executable function bytes";
		return result;
	}

	DisasmFile context;
	context.path = module_found ? selected_module.path : std::string("live://memory_region");
	context.filename = module_found ? selected_module.name : std::string("memory_region");
	context.image_base = module_base;
	context.entry_point = pe_ok ? pe.entry_point : 0;
	context.text_va = read_base;
	context.loaded = true;
	PESection ps;
	ps.va = read_base;
	ps.bytes = mem;
	ps.is_executable = true;
	context.sections.push_back(std::move(ps));

	auto arch_desc = aida_ghidra::detect_arch_default_x64();

	try {
		detail::prepared_arch_t ta(mem.data(), mem.size(), read_base,
		                           &context, cancel,
		                           arch_desc.sleigh_id);
		detail::populate_symbols(*ta.arch, mem.data(), mem.size(), read_base, &context);
		result = detail::do_decompile(ta.arch.get(), entry_addr, cancel);
	}
	catch (ghidra::LowlevelError& err) {
		result.is_error = true;
		result.error_text = err.explain;
	}
	catch (ghidra::DecoderError& err) {
		result.is_error = true;
		result.error_text = err.explain;
	}
	catch (...) {
		result.is_error = true;
		result.error_text = "unknown decompilation error";
	}

	return result;
}

inline ghidra_result_t decompile_buffer(const uint8_t* data, size_t size,
                                         uint64_t base_addr, uint64_t entry_addr,
                                         std::atomic<bool>* cancel = nullptr,
                                         const DisasmFile* file_fallback = nullptr)
{
	active_decompile_guard_t active_guard(cancel);
	ghidra_result_t result;
	result.function_addr = entry_addr;

	if (active_guard.was_shutting_down) {
		result.is_error = true;
		result.error_text = "decompiler is shutting down";
		return result;
	}

	if (!g_state.initialized.load()) {
		if (!init()) {
			result.is_error = true;
			result.error_text = "dependency_blocked: ghidra decompiler not initialized; " + init_diagnostics();
			return result;
		}
	}

	if (cancel && cancel->load(std::memory_order_acquire)) {
		result.is_error = true;
		result.error_text = "cancelled";
		return result;
	}

	auto arch_desc = file_fallback
		? detail::resolve_arch(file_fallback)
		: aida_ghidra::detect_arch_default_x64();

	try {
		detail::prepared_arch_t ta(data, size, base_addr,
		                           file_fallback, cancel,
		                           arch_desc.sleigh_id);
		if (cancel && cancel->load(std::memory_order_acquire))
			throw ghidra::LowlevelError("cancelled");
		detail::populate_symbols(*ta.arch, data, size, base_addr, file_fallback);
		if (cancel && cancel->load(std::memory_order_acquire))
			throw ghidra::LowlevelError("cancelled");
		result = detail::do_decompile(ta.arch.get(), entry_addr, cancel);
	}
	catch (ghidra::LowlevelError& e) {
		result.is_error = true;
		result.error_text = e.explain;
	}
	catch (ghidra::DecoderError& e) {
		result.is_error = true;
		result.error_text = e.explain;
	}
	catch (...) {
		result.is_error = true;
		result.error_text = "unknown decompilation error (buffer mode)";
	}

	return result;
}

namespace detail {

inline bool validate_isolated_region_layout(std::vector<aida_ghidra::region_t>& regions,
                                            uint64_t image_base,
                                            uint64_t image_size,
                                            ghidra_result_t& result)
{
	std::sort(regions.begin(), regions.end(), [](const auto& left, const auto& right) {
		return left.start_va < right.start_va;
	});
	uint64_t prior_end = image_base;
	for (std::size_t index = 0; index < regions.size(); ++index) {
		const auto& region = regions[index];
		const size_t region_size = region.effective_size();
		if (region_size == 0 || region.start_va < image_base ||
			region.start_va < prior_end || region.start_va - image_base >= image_size ||
			region_size > image_size - (region.start_va - image_base)) {
			result.is_error = true;
			result.error_text = "isolated decompiler regions are malformed or overlap";
			return false;
		}
		prior_end = region.start_va + region_size;
	}
	return true;
}

inline std::size_t find_isolated_entry_region(const std::vector<aida_ghidra::region_t>& regions,
                                              uint64_t entry_addr) noexcept
{
	for (std::size_t index = 0; index < regions.size(); ++index) {
		const auto& region = regions[index];
		if (entry_addr >= region.start_va && entry_addr - region.start_va < region.effective_size())
			return index;
	}
	return regions.size();
}

inline void finalize_isolated_result(ghidra_result_t& result,
                                     const ghidra_decompile_result_limits_t& result_limits)
{
	if (!result.is_error && !result.typed_artifacts) {
		result.is_error = true;
		result.complete = false;
		result.error_text = "isolated decompilation completed without typed provider artifacts";
	} else if (!result.is_error && !decompile_result_within_limits(result, result_limits)) {
		result.is_error = true;
		result.complete = false;
		result.error_text = "isolated decompilation result exceeds configured limits";
	}
}

}

inline ghidra_result_t decompile_isolated_buffer(
	const uint8_t* data,
	size_t size,
	uint64_t base_addr,
	uint64_t entry_addr,
	const std::string& sleigh_id,
	std::atomic<bool>* cancel,
	std::optional<std::chrono::steady_clock::time_point> deadline,
	const ghidra_decompile_result_limits_t& result_limits,
	const aida::analysis::ghidra_ir_adapter::capture_request_t& typed_request)
{
	active_decompile_guard_t active_guard(cancel);
	ghidra_result_t result;
	result.function_addr = entry_addr;
	if (active_guard.was_shutting_down) {
		result.is_error = true;
		result.error_text = "decompiler is shutting down";
		return result;
	}
	if (!data || size == 0 || base_addr == 0 || entry_addr < base_addr ||
		entry_addr - base_addr >= size || sleigh_id.empty() ||
		!detail::valid_decompile_result_limits(result_limits) ||
		!aida::analysis::validate_decompiler_entity_key(typed_request.entity).valid()) {
		result.is_error = true;
		result.error_text = "isolated decompiler input violates the typed provider contract";
		return result;
	}
	if (!g_state.initialized.load(std::memory_order_acquire) && !init()) {
		result.is_error = true;
		result.error_text = "dependency_blocked: ghidra decompiler not initialized; " + init_diagnostics();
		return result;
	}
	if ((cancel && cancel->load(std::memory_order_acquire)) ||
		(deadline && std::chrono::steady_clock::now() >= *deadline)) {
		result.is_error = true;
		result.error_text = "cancelled";
		return result;
	}
	try {
		detail::prepared_arch_t prepared(data, size, base_addr, nullptr, cancel, sleigh_id,
			{}, 0, typed_request.language.mode, result_limits.keep_fixateglobals);
		result = detail::do_decompile(prepared.arch.get(), entry_addr, cancel, deadline,
			result_limits, &typed_request);
	} catch (ghidra::LowlevelError& error) {
		result.is_error = true;
		result.error_text = error.explain;
	} catch (ghidra::DecoderError& error) {
		result.is_error = true;
		result.error_text = error.explain;
	} catch (...) {
		result.is_error = true;
		result.error_text = "isolated decompilation failed";
	}
	detail::finalize_isolated_result(result, result_limits);
	return result;
}

inline ghidra_result_t decompile_isolated_regions(
	std::vector<aida_ghidra::region_t> regions,
	uint64_t image_base,
	uint64_t image_size,
	uint64_t entry_addr,
	const std::string& sleigh_id,
	aida::analysis::architecture_mode_t architecture_mode,
	std::atomic<bool>* cancel,
	std::optional<std::chrono::steady_clock::time_point> deadline,
	const ghidra_decompile_result_limits_t& result_limits,
	const aida::analysis::ghidra_ir_adapter::capture_request_t& typed_request)
{
	active_decompile_guard_t active_guard(cancel);
	ghidra_result_t result;
	result.function_addr = entry_addr;
	if (active_guard.was_shutting_down) {
		result.is_error = true;
		result.error_text = "decompiler is shutting down";
		return result;
	}
	if (regions.empty() || image_size == 0 ||
		entry_addr < image_base || entry_addr - image_base >= image_size ||
		sleigh_id.empty() || !detail::valid_decompile_result_limits(result_limits) ||
		!aida::analysis::validate_decompiler_entity_key(typed_request.entity).valid()) {
		result.is_error = true;
		result.error_text = "isolated region decompiler input violates the typed provider contract";
		return result;
	}
	if (!detail::validate_isolated_region_layout(regions, image_base, image_size, result))
		return result;
	const std::size_t entry_region = detail::find_isolated_entry_region(regions, entry_addr);
	if (entry_region == regions.size()) {
		result.is_error = true;
		result.error_text = "isolated decompiler entry is not captured";
		return result;
	}
	if (!g_state.initialized.load(std::memory_order_acquire) && !init()) {
		result.is_error = true;
		result.error_text = "dependency_blocked: ghidra decompiler not initialized; " + init_diagnostics();
		return result;
	}
	if ((cancel && cancel->load(std::memory_order_acquire)) ||
		(deadline && std::chrono::steady_clock::now() >= *deadline)) {
		result.is_error = true;
		result.error_text = "cancelled";
		return result;
	}
	try {
		auto primary = std::move(regions[entry_region]);
		regions.erase(regions.begin() + static_cast<std::ptrdiff_t>(entry_region));
		detail::prepared_arch_t prepared(primary.data.data(), primary.data.size(),
			primary.start_va, nullptr, cancel, sleigh_id, std::move(regions), image_size,
			aida::analysis::architecture_mode_t::unknown, result_limits.keep_fixateglobals);
		detail::prepared_arch_t::apply_execution_mode(*prepared.arch,
			architecture_mode, image_base, image_size);
		result = detail::do_decompile(prepared.arch.get(), entry_addr, cancel, deadline,
			result_limits, &typed_request);
	} catch (ghidra::LowlevelError& error) {
		result.is_error = true;
		result.error_text = error.explain;
	} catch (ghidra::DecoderError& error) {
		result.is_error = true;
		result.error_text = error.explain;
	} catch (...) {
		result.is_error = true;
		result.error_text = "isolated region decompilation failed";
	}
	detail::finalize_isolated_result(result, result_limits);
	return result;
}

struct arch_pool_key_t {
	std::string language_id;
	std::string compiler_spec_id;
	aida::analysis::architecture_mode_t architecture_mode =
		aida::analysis::architecture_mode_t::unknown;
	aida::analysis::endian_t endian = aida::analysis::endian_t::little;
	aida::analysis::sha256_digest_t snapshot_hash;
	bool keep_fixateglobals = false;

	bool matches(const arch_pool_key_t& other) const noexcept
	{
		return language_id == other.language_id &&
			compiler_spec_id == other.compiler_spec_id &&
			architecture_mode == other.architecture_mode && endian == other.endian &&
			snapshot_hash.constant_time_equal(other.snapshot_hash) &&
			keep_fixateglobals == other.keep_fixateglobals;
	}
};

struct arch_session_entry_t {
	arch_pool_key_t key;
	std::unique_ptr<detail::prepared_arch_t> prepared;
	std::atomic<bool> loader_cancel{false};
	std::vector<std::pair<uint64_t, uint64_t>> captured_ranges;
	uint64_t image_base = 0;
	uint64_t image_size = 0;
	uint64_t jobs_completed = 0;
	double arch_init_ms = 0.0;
	std::unordered_set<ghidra::FunctionSymbol*> pinned_symbols;
	ghidra::FunctionSymbol* job_function_symbol = nullptr;
	uint32_t jobs_since_purge = 0;
	detail::session_job_guard_t guard;

	arch_session_entry_t() = default;
	arch_session_entry_t(const arch_session_entry_t&) = delete;
	arch_session_entry_t& operator=(const arch_session_entry_t&) = delete;
	~arch_session_entry_t()
	{
		guard.stop();
	}

	bool captures(uint64_t address) const noexcept
	{
		for (const auto& range : captured_ranges) {
			if (address >= range.first && address < range.second)
				return true;
		}
		return false;
	}
};

namespace detail {

inline constexpr uint32_t k_arch_session_purge_interval_jobs = 512;

inline void reset_arch_session_entry(arch_session_entry_t& entry)
{
	if (!entry.prepared || !entry.prepared->arch)
		return;
	auto& arch = *entry.prepared->arch;
	ghidra::Scope* global_scope = arch.symboltab->getGlobalScope();
	if (!global_scope)
		return;
	std::size_t functions_removed = 0;
	if (entry.job_function_symbol) {
		ghidra::FunctionSymbol* job_symbol = entry.job_function_symbol;
		entry.job_function_symbol = nullptr;
		try {
			if (ghidra::Funcdata* fd = job_symbol->getFunction())
				arch.clearAnalysis(fd);
		} catch (...) {
		}
		if (entry.pinned_symbols.find(job_symbol) == entry.pinned_symbols.end()) {
			try {
				global_scope->removeSymbol(job_symbol);
				++functions_removed;
			} catch (...) {
			}
		}
	}
	if (++entry.jobs_since_purge >= k_arch_session_purge_interval_jobs) {
		entry.jobs_since_purge = 0;
		std::vector<ghidra::FunctionSymbol*> stale;
		for (ghidra::MapIterator it = global_scope->begin(); it != global_scope->end(); ++it) {
			const ghidra::SymbolEntry* sym_entry = *it;
			if (!sym_entry)
				continue;
			if (auto* function_symbol = dynamic_cast<ghidra::FunctionSymbol*>(sym_entry->getSymbol())) {
				if (entry.pinned_symbols.find(function_symbol) == entry.pinned_symbols.end())
					stale.push_back(function_symbol);
			}
		}
		for (auto* function_symbol : stale) {
			try {
				if (ghidra::Funcdata* fd = function_symbol->getFunction())
					arch.clearAnalysis(fd);
			} catch (...) {
			}
			try {
				global_scope->removeSymbol(function_symbol);
				++functions_removed;
			} catch (...) {
			}
		}
	}
	if (functions_removed != 0) {
		diag::log_tagged_fmt("dec",
			"arch_session_reset functions_removed=%zu jobs_completed=%llu pinned=%zu",
			functions_removed,
			static_cast<unsigned long long>(entry.jobs_completed),
			entry.pinned_symbols.size());
	}
}

}

struct arch_session_entry_create_t {
	std::unique_ptr<arch_session_entry_t> entry;
	std::string error_text;
	bool ok = false;
};

inline arch_session_entry_create_t make_arch_session_entry(
	std::vector<aida_ghidra::region_t> regions,
	uint64_t image_base,
	uint64_t image_size,
	arch_pool_key_t key,
	bool keep_fixateglobals,
	const aida::analysis::native_worker::snapshot_sidecar::sidecar_t* sidecar = nullptr)
{
	arch_session_entry_create_t output;
	if (regions.empty() || image_size == 0 || key.language_id.empty()) {
		output.error_text = "isolated region decompiler input violates the typed provider contract";
		return output;
	}
	ghidra_result_t layout_result;
	if (!detail::validate_isolated_region_layout(regions, image_base, image_size, layout_result)) {
		output.error_text = std::move(layout_result.error_text);
		return output;
	}
	if (!g_state.initialized.load(std::memory_order_acquire) && !init()) {
		output.error_text = "dependency_blocked: ghidra decompiler not initialized; " + init_diagnostics();
		return output;
	}
	auto entry = std::make_unique<arch_session_entry_t>();
	entry->key = std::move(key);
	entry->image_base = image_base;
	entry->image_size = image_size;
	entry->captured_ranges.reserve(regions.size());
	for (const auto& region : regions) {
		const size_t region_size = region.effective_size();
		if (region_size > UINT64_MAX - region.start_va)
			continue;
		entry->captured_ranges.emplace_back(region.start_va, region.start_va + region_size);
	}
	try {
		entry->prepared = std::make_unique<detail::prepared_arch_t>(
			nullptr, 0, 0,
			nullptr, &entry->loader_cancel, entry->key.language_id,
			std::move(regions), image_size,
			aida::analysis::architecture_mode_t::unknown, keep_fixateglobals);
		detail::prepared_arch_t::apply_execution_mode(*entry->prepared->arch,
			entry->key.architecture_mode, image_base, image_size);
		entry->arch_init_ms = entry->prepared->init_ms;
	} catch (ghidra::LowlevelError& error) {
		output.error_text = error.explain;
		return output;
	} catch (ghidra::DecoderError& error) {
		output.error_text = error.explain;
		return output;
	} catch (...) {
		output.error_text = "isolated region decompilation failed";
		return output;
	}
	if (sidecar) {
		try {
			auto bind_result = aida::analysis::native_worker::worker_symbol_binder::bind(
				*entry->prepared->arch, *sidecar, image_base, image_size);
			entry->pinned_symbols = std::move(bind_result.pinned);
		} catch (const std::bad_alloc&) {
			output.error_text = "isolated symbol sidecar binding allocation failed";
			return output;
		} catch (...) {
			output.error_text = "isolated symbol sidecar binding failed";
			return output;
		}
	}
	if (!entry->guard.start(&entry->loader_cancel)) {
		output.error_text = "isolated session guard could not be started";
		return output;
	}
	output.entry = std::move(entry);
	output.ok = true;
	return output;
}

inline ghidra_result_t decompile_isolated_regions_reusing(
	arch_session_entry_t& entry,
	uint64_t entry_addr,
	std::atomic<bool>* cancel,
	std::optional<std::chrono::steady_clock::time_point> deadline,
	const ghidra_decompile_result_limits_t& result_limits,
	const aida::analysis::ghidra_ir_adapter::capture_request_t& typed_request)
{
	active_decompile_guard_t active_guard(cancel);
	ghidra_result_t result;
	result.function_addr = entry_addr;
	if (active_guard.was_shutting_down) {
		result.is_error = true;
		result.error_text = "decompiler is shutting down";
		return result;
	}
	if (!entry.prepared || !entry.prepared->arch || entry.image_size == 0 ||
		entry_addr < entry.image_base || entry_addr - entry.image_base >= entry.image_size ||
		entry.key.language_id.empty() ||
		!detail::valid_decompile_result_limits(result_limits) ||
		!aida::analysis::validate_decompiler_entity_key(typed_request.entity).valid()) {
		result.is_error = true;
		result.error_text = "isolated region decompiler input violates the typed provider contract";
		return result;
	}
	if (!entry.captures(entry_addr)) {
		result.is_error = true;
		result.error_text = "isolated decompiler entry is not captured";
		return result;
	}
	if (!g_state.initialized.load(std::memory_order_acquire) && !init()) {
		result.is_error = true;
		result.error_text = "dependency_blocked: ghidra decompiler not initialized; " + init_diagnostics();
		return result;
	}
	if ((cancel && cancel->load(std::memory_order_acquire)) ||
		(deadline && std::chrono::steady_clock::now() >= *deadline)) {
		result.is_error = true;
		result.error_text = "cancelled";
		return result;
	}
	detail::reset_arch_session_entry(entry);
	entry.loader_cancel.store(false, std::memory_order_release);
	const uint64_t job_ordinal = entry.jobs_completed + 1;
	try {
		result = detail::do_decompile(entry.prepared->arch.get(), entry_addr, cancel, deadline,
			result_limits, &typed_request, &entry.guard, &entry.job_function_symbol,
			job_ordinal);
	} catch (ghidra::LowlevelError& error) {
		result.is_error = true;
		result.error_text = error.explain;
	} catch (ghidra::DecoderError& error) {
		result.is_error = true;
		result.error_text = error.explain;
	} catch (...) {
		result.is_error = true;
		result.error_text = "isolated region decompilation failed";
	}
	detail::reset_arch_session_entry(entry);
	++entry.jobs_completed;
	detail::finalize_isolated_result(result, result_limits);
	return result;
}

inline ghidra_result_t decompile_workspace(
	const std::shared_ptr<const aida::analysis::ghidra_adapter::ghidra_load_image_t>& load_image,
	const aida::analysis::workspace_identity_t& identity,
	const std::shared_ptr<const aida::analysis::analysis_snapshot_t>& snapshot,
	uint64_t entry_addr,
	aida::analysis::address_space_id_t address_space,
	std::atomic<bool>* cancel,
	std::function<bool()> cancel_check,
	std::optional<std::chrono::steady_clock::time_point> deadline = {},
	const ghidra_decompile_result_limits_t& result_limits = {},
	const aida::analysis::ghidra_ir_adapter::capture_request_t* typed_request = nullptr)
{
	active_decompile_guard_t active_guard(cancel);
	ghidra_result_t result;
	result.function_addr = entry_addr;

	if (active_guard.was_shutting_down) {
		result.is_error = true;
		result.error_text = "decompiler is shutting down";
		return result;
	}
	if (!load_image) {
		result.is_error = true;
		result.error_text = "normalized workspace load image is unavailable";
		return result;
	}
	if (!g_state.initialized.load(std::memory_order_acquire) && !init()) {
		result.is_error = true;
		result.error_text = "dependency_blocked: ghidra decompiler not initialized; " + init_diagnostics();
		return result;
	}
	if ((cancel && cancel->load(std::memory_order_acquire)) ||
		(cancel_check && cancel_check())) {
		result.is_error = true;
		result.error_text = "cancelled";
		return result;
	}

	auto descriptor = aida_ghidra::detect_arch_from_workspace(identity);
	if (!descriptor) {
		result.is_error = true;
		result.error_text = "unsupported workspace architecture for native decompilation";
		return result;
	}

	try {
		detail::prepared_arch_t prepared(load_image, address_space,
			identity.architecture_mode(), cancel_check, descriptor->sleigh_id,
			result_limits.keep_fixateglobals);
		aida_ghidra::populate_from_workspace(prepared.arch->symbol_database(),
			identity, snapshot ? snapshot->image.get() : nullptr, snapshot.get());
		if ((cancel && cancel->load(std::memory_order_acquire)) ||
			(cancel_check && cancel_check()))
			throw ghidra::LowlevelError("cancelled");
		result = detail::do_decompile(prepared.arch.get(), entry_addr, cancel, deadline,
			result_limits, typed_request);
	}
	catch (ghidra::LowlevelError& error) {
		result.is_error = true;
		result.error_text = error.explain;
	}
	catch (ghidra::DecoderError& error) {
		result.is_error = true;
		result.error_text = error.explain;
	}
	catch (const std::exception& error) {
		result.is_error = true;
		result.error_text = error.what();
	}
	catch (...) {
		result.is_error = true;
		result.error_text = "unknown decompilation error (workspace mode)";
	}

	return result;
}

namespace detail {

inline bool same_ghidra_language(
	const aida::analysis::ghidra_adapter::ghidra_language_spec_t& left,
	const aida::analysis::ghidra_adapter::ghidra_language_spec_t& right) noexcept
{
	return left.family == right.family && left.language_id == right.language_id &&
		left.compiler_spec_id == right.compiler_spec_id && left.language_root == right.language_root;
}

inline bool same_ghidra_adapter_cache_key(
	const aida::analysis::ghidra_adapter::ghidra_adapter_cache_key_t& left,
	const aida::analysis::ghidra_adapter::ghidra_adapter_cache_key_t& right) noexcept
{
	return left.digest.constant_time_equal(right.digest) && left.revision.matches(right.revision) &&
		left.language_id == right.language_id && left.compiler_spec_id == right.compiler_spec_id;
}

inline bool same_ghidra_workspace_image(
	const aida::analysis::workspace_image_t& left,
	const aida::analysis::workspace_image_t& right) noexcept
{
	return left.workspace_binary_id.constant_time_equal(right.workspace_binary_id) &&
		left.provider_content_hash.constant_time_equal(right.provider_content_hash) &&
		left.format == right.format && left.architecture == right.architecture &&
		left.architecture_mode == right.architecture_mode && left.abi == right.abi &&
		left.endian == right.endian && left.address_width_bits == right.address_width_bits &&
		left.image_base == right.image_base && left.image_size == right.image_size &&
		left.header_size == right.header_size && left.provider_size == right.provider_size &&
		left.provider_binding_verified == right.provider_binding_verified;
}

inline aida::analysis::workspace_result_t<void> adapter_stop_requested(
	const ghidra_adapter_decompile_request_t& request,
	const aida::analysis::cancellation_token_t& cancel, const char* phase)
{
	const bool deadline = cancel.deadline_exceeded() || request.cancellation.deadline_exceeded() ||
		(request.deadline && std::chrono::steady_clock::now() >= *request.deadline);
	bool cancelled = cancel.cancellation_requested() || request.cancellation.cancellation_requested() ||
		(request.engine_cancel && request.engine_cancel->load(std::memory_order_acquire));
	if (!cancelled && request.cancel_check) {
		try {
			cancelled = request.cancel_check();
		} catch (...) {
			return aida::analysis::workspace_result_t<void>::failure(
				aida::analysis::make_workspace_error(
					aida::analysis::workspace_error_code_t::invalid_argument,
					"Ghidra adapter cancellation hook raised an exception", phase));
		}
	}
	if (!deadline && !cancelled)
		return aida::analysis::workspace_result_t<void>::success();
	auto error = aida::analysis::make_workspace_error(
		deadline ? aida::analysis::workspace_error_code_t::deadline_exceeded
			: aida::analysis::workspace_error_code_t::cancelled,
		deadline ? "Ghidra adapter decompilation deadline exceeded"
			: "Ghidra adapter decompilation cancelled", phase);
	error.deadline = deadline;
	error.cancellation = !deadline;
	return aida::analysis::workspace_result_t<void>::failure(std::move(error));
}

inline aida::analysis::workspace_result_t<void> validate_ghidra_adapter_request(
	const ghidra_adapter_decompile_request_t& request,
	const aida::analysis::cancellation_token_t& cancel)
{
	auto stopped = adapter_stop_requested(request, cancel, "ghidra.adapter.validate");
	if (!stopped)
		return stopped;
	if (!request.workspace_identity || request.workspace_id.empty() ||
		request.workspace_id.size() > 4096 || request.workspace_id.find('\0') != std::string::npos ||
		!request.normalized_image || !request.analysis_snapshot || !request.load_image ||
		!request.function_database || request.function.entity_id == 0 ||
		!valid_decompile_result_limits(request.result_limits)) {
		return aida::analysis::workspace_result_t<void>::failure(
			aida::analysis::make_workspace_error(
				aida::analysis::workspace_error_code_t::invalid_argument,
				"Ghidra adapter decompile request is incomplete or contains invalid result limits",
				"ghidra.adapter.validate"));
	}
	if (request.typed_entity && !aida::analysis::validate_decompiler_entity_key(*request.typed_entity).valid()) {
		return aida::analysis::workspace_result_t<void>::failure(
			aida::analysis::make_workspace_error(
				aida::analysis::workspace_error_code_t::invalid_argument,
				"Ghidra adapter typed entity does not satisfy the native provider contract",
				"ghidra.adapter.validate"));
	}
	if (request.typed_entity) {
		const auto* function = request.function_database->find_function(request.function);
		const auto* identity = std::get_if<aida::analysis::native_decompiler_entity_identity_t>(
			&request.typed_entity->identity);
		if (!function || request.typed_entity->kind != aida::analysis::decompiler_entity_kind_t::native_function ||
			request.typed_entity->format != request.workspace_identity->format() ||
			request.typed_entity->architecture != request.workspace_identity->architecture() ||
			request.typed_entity->mode != request.workspace_identity->architecture_mode() ||
			request.typed_entity->endian != request.workspace_identity->endian() || !identity ||
			identity->function_id != function->key.entity_id || identity->entry != function->key.address ||
			identity->end != function->end) {
			return aida::analysis::workspace_result_t<void>::failure(
				aida::analysis::make_workspace_error(
					aida::analysis::workspace_error_code_t::provider_binding_mismatch,
					"Ghidra adapter typed entity is not bound to the requested native function",
					"ghidra.adapter.validate"));
		}
	}

	auto image_valid = aida::analysis::validate_workspace_image(
		*request.normalized_image, {}, true, cancel);
	if (!image_valid)
		return image_valid;
	auto snapshot_valid = aida::analysis::validate_analysis_snapshot(
		*request.analysis_snapshot, false, cancel);
	if (!snapshot_valid)
		return snapshot_valid;
	if (!request.analysis_snapshot->normalized_image ||
		!same_ghidra_workspace_image(*request.normalized_image,
			*request.analysis_snapshot->normalized_image)) {
		return aida::analysis::workspace_result_t<void>::failure(
			aida::analysis::make_workspace_error(
				aida::analysis::workspace_error_code_t::target_conflict,
				"Ghidra adapter normalized image does not match the analysis snapshot",
				"ghidra.adapter.validate"));
	}

	auto expected_language = aida::analysis::ghidra_adapter::resolve_ghidra_language(
		*request.normalized_image, cancel);
	if (!expected_language)
		return aida::analysis::workspace_result_t<void>::failure(expected_language.error());
	if (!same_ghidra_language(request.language, expected_language.value())) {
		return aida::analysis::workspace_result_t<void>::failure(
			aida::analysis::make_workspace_error(
				aida::analysis::workspace_error_code_t::target_conflict,
				"Ghidra adapter language does not match the normalized workspace image",
				"ghidra.adapter.validate"));
	}
	auto staged = aida::analysis::ghidra_adapter::require_staged_ghidra_language(
		request.language, request.language_catalog, cancel);
	if (!staged)
		return staged;
	auto staged_files = aida::analysis::ghidra_adapter::require_staged_ghidra_language(
		request.language, active_specs_dir(), cancel);
	if (!staged_files)
		return staged_files;
	auto expected_revision = aida::analysis::ghidra_adapter::make_ghidra_adapter_revision(
		*request.workspace_identity, *request.analysis_snapshot, cancel);
	if (!expected_revision)
		return aida::analysis::workspace_result_t<void>::failure(expected_revision.error());
	if (!request.revision.matches(expected_revision.value())) {
		return aida::analysis::workspace_result_t<void>::failure(
			aida::analysis::make_workspace_error(
				aida::analysis::workspace_error_code_t::revision_conflict,
				"Ghidra adapter revision does not match the workspace analysis revision",
				"ghidra.adapter.validate"));
	}

	auto expected_cache_key = aida::analysis::ghidra_adapter::make_ghidra_adapter_cache_key(
		request.revision, request.language, cancel);
	if (!expected_cache_key)
		return aida::analysis::workspace_result_t<void>::failure(expected_cache_key.error());
	if (!same_ghidra_adapter_cache_key(request.adapter_cache_key, expected_cache_key.value()) ||
		!request.load_image->revision().matches(request.revision) ||
		!request.function_database->revision().matches(request.revision) ||
		!same_ghidra_adapter_cache_key(request.load_image->cache_key(), expected_cache_key.value()) ||
		!same_ghidra_adapter_cache_key(request.function_database->cache_key(), expected_cache_key.value()) ||
		!same_ghidra_language(request.load_image->language(), request.language) ||
		!same_ghidra_language(request.function_database->language(), request.language) ||
		!same_ghidra_workspace_image(request.load_image->image(), *request.normalized_image) ||
		request.load_image->provider().size() != request.normalized_image->provider_size) {
		return aida::analysis::workspace_result_t<void>::failure(
			aida::analysis::make_workspace_error(
				aida::analysis::workspace_error_code_t::revision_conflict,
				"Ghidra adapter load image or function database does not match the request revision",
				"ghidra.adapter.validate"));
	}
	if (!request.function_database->find_function(request.function)) {
		auto error = aida::analysis::make_workspace_error(
			aida::analysis::workspace_error_code_t::target_not_found,
			"Ghidra adapter function identity is not present in the function database",
			"ghidra.adapter.validate");
		error.address = request.function.address;
		return aida::analysis::workspace_result_t<void>::failure(std::move(error));
	}
	return adapter_stop_requested(request, cancel, "ghidra.adapter.validate");
}

inline ghidra_adapter_error_t make_adapter_execution_error(
	const ghidra_adapter_decompile_request_t& request, const ghidra_result_t& result)
{
	ghidra_adapter_error_t error;
	error.language_family = request.language.family;
	error.phase = "ghidra.adapter.execute";
	error.message = result.error_text;
	if (request.cancellation.deadline_exceeded() ||
		(request.deadline && std::chrono::steady_clock::now() >= *request.deadline) ||
		result.error_text == "Decompilation timed out (function too complex or invalid code).") {
		error.code = ghidra_adapter_error_code_t::deadline_exceeded;
	} else if (request.cancellation.cancellation_requested() ||
		(request.engine_cancel && request.engine_cancel->load(std::memory_order_acquire)) ||
		result.error_text == "cancelled" || result.error_text == "Decompilation cancelled.") {
		error.code = ghidra_adapter_error_code_t::cancelled;
	} else if (result.error_text == "decompilation result exceeds configured limits" ||
		result.error_text == "decompilation result limits are invalid") {
		error.code = ghidra_adapter_error_code_t::result_limit_exceeded;
	} else if (result.error_text.find("not initialized") != std::string::npos ||
		result.error_text.find("shutting down") != std::string::npos) {
		error.code = ghidra_adapter_error_code_t::decompiler_unavailable;
	} else {
		error.code = ghidra_adapter_error_code_t::decompilation_failed;
	}
	return error;
}

}

inline aida::analysis::workspace_result_t<ghidra_adapter_decompile_cache_key_t>
make_ghidra_adapter_decompile_cache_key(
	const ghidra_adapter_decompile_request_t& request,
	const aida::analysis::cancellation_token_t& cancel)
{
	auto valid = detail::validate_ghidra_adapter_request(request, cancel);
	if (!valid) {
		return aida::analysis::workspace_result_t<ghidra_adapter_decompile_cache_key_t>::failure(
			std::move(valid.error()));
	}
	try {
		std::string material;
		material.reserve(640 + request.workspace_id.size());
		const auto append_text = [&material](const std::string& value) {
			material.append(std::to_string(value.size()));
			material.push_back(':');
			material.append(value);
			material.push_back('|');
		};
		const auto append_number = [&material](uint64_t value) {
			material.append(std::to_string(value));
			material.push_back('|');
		};
		material.append("aida-ghidra-decompile-v1|");
		append_text(request.workspace_id);
		append_text(request.revision.binary_id.to_hex());
		append_text(request.revision.load_profile_hash.to_hex());
		append_number(request.revision.generation);
		append_number(request.revision.analysis_revision);
		append_number(request.revision.overlay_revision);
		append_number(request.type_revision);
		append_text(request.adapter_cache_key.digest.to_hex());
		append_text(request.adapter_cache_key.language_id);
		append_text(request.adapter_cache_key.compiler_spec_id);
		append_number(request.function.entity_id);
		append_number(static_cast<uint64_t>(request.function.address.space));
		append_number(request.function.address.value);
		append_number(static_cast<uint64_t>(request.function.address.architecture));
		append_number(static_cast<uint64_t>(request.function.address.mode));
		append_text(request.typed_entity
			? aida::analysis::stable_serialization_hash(*request.typed_entity).to_hex()
			: std::string("auto"));
		append_number(request.result_limits.max_pseudocode_bytes);
		append_number(static_cast<uint64_t>(request.result_limits.max_annotations));
		append_number(static_cast<uint64_t>(request.result_limits.max_line_mappings));
		append_number(static_cast<uint64_t>(request.result_limits.max_callees));
		append_number(request.result_limits.max_result_bytes);
		append_number(request.result_limits.capture_printc_evidence ? 1U : 0U);
		append_number(request.result_limits.keep_fixateglobals ? 1U : 0U);
		auto digest = aida::analysis::sha256_text(material, cancel);
		if (!digest) {
			return aida::analysis::workspace_result_t<ghidra_adapter_decompile_cache_key_t>::failure(
				digest.error());
		}
		auto stopped = detail::adapter_stop_requested(request, cancel, "ghidra.adapter.cache_key");
		if (!stopped) {
			return aida::analysis::workspace_result_t<ghidra_adapter_decompile_cache_key_t>::failure(
				std::move(stopped.error()));
		}
		ghidra_adapter_decompile_cache_key_t key;
		key.digest = digest.take_value();
		key.workspace_id = request.workspace_id;
		key.workspace_binary_id = request.revision.binary_id;
		key.workspace_load_profile_hash = request.revision.load_profile_hash;
		key.generation = request.revision.generation;
		key.analysis_revision = request.revision.analysis_revision;
		key.overlay_revision = request.revision.overlay_revision;
		key.type_revision = request.type_revision;
		key.adapter_cache_key = request.adapter_cache_key;
		key.function = request.function;
		key.typed_entity = request.typed_entity;
		key.result_limits = request.result_limits;
		return aida::analysis::workspace_result_t<ghidra_adapter_decompile_cache_key_t>::success(
			std::move(key));
	} catch (const std::bad_alloc&) {
		return aida::analysis::workspace_result_t<ghidra_adapter_decompile_cache_key_t>::failure(
			aida::analysis::make_workspace_error(
				aida::analysis::workspace_error_code_t::limit_exceeded,
				"Ghidra adapter decompile cache-key allocation failed", "ghidra.adapter.cache_key"));
	}
}

inline aida::analysis::ghidra_ir_adapter::capture_request_t
make_typed_capture_request(const ghidra_adapter_decompile_request_t& request,
	const aida::analysis::ghidra_adapter::ghidra_function_record_t& function)
{
	aida::analysis::ghidra_ir_adapter::capture_request_t output;
	output.provider.provider = aida::analysis::decompiler_provider_id_t::ghidra_native;
	output.provider.provider_name = "aida-ghidra-native";
	output.provider.provider_version = "1";
	output.provider.provider_binary_hash = aida::analysis::stable_serialization_hash(
		"aida-ghidra-native-provider-v1");
	output.provider.worker_build_id = "aida-ghidra-native-inprocess-v1";
	output.provider.worker_build_hash = aida::analysis::stable_serialization_hash(
		"aida-ghidra-native-inprocess-build-v1");
	output.language.language_id = request.language.language_id;
	output.language.language_version = "ghidra-staged-v1";
	output.language.compiler_spec_id = request.language.compiler_spec_id;
	output.language.language_spec_hash = aida::analysis::stable_serialization_hash(
		request.language.language_id + "|" + request.language.compiler_spec_id);
	output.language.architecture = request.workspace_identity->architecture();
	output.language.mode = request.workspace_identity->architecture_mode();
	output.language.endian = request.workspace_identity->endian();
	if (request.typed_entity) {
		output.entity = *request.typed_entity;
	} else {
		aida::analysis::native_decompiler_entity_identity_t identity;
		identity.function_id = function.key.entity_id;
		identity.entry = function.key.address;
		identity.end = function.end;
		if (identity.end.value <= identity.entry.value)
			identity.end.value = identity.entry.value + 1U;
		identity.function_bytes_hash = aida::analysis::stable_serialization_hash(
			request.adapter_cache_key.digest.to_hex() + ":" + std::to_string(function.key.entity_id));
		identity.canonical_symbol = function.name.empty()
			? "sub_" + std::to_string(function.key.address.value) : function.name;
		output.entity.kind = aida::analysis::decompiler_entity_kind_t::native_function;
		output.entity.format = request.workspace_identity->format();
		output.entity.architecture = request.workspace_identity->architecture();
		output.entity.mode = request.workspace_identity->architecture_mode();
		output.entity.endian = request.workspace_identity->endian();
		output.entity.identity = std::move(identity);
	}
	output.workspace_generation = request.revision.generation;
	output.type_graph_revision = request.type_revision == 0 ? request.revision.analysis_revision : request.type_revision;
	if (output.type_graph_revision == 0)
		output.type_graph_revision = 1;
	return output;
}

inline aida::analysis::workspace_result_t<ghidra_adapter_decompile_result_t>
decompile_adapter(const ghidra_adapter_decompile_request_t& request)
{
	auto cache_key = make_ghidra_adapter_decompile_cache_key(request, request.cancellation);
	if (!cache_key) {
		return aida::analysis::workspace_result_t<ghidra_adapter_decompile_result_t>::failure(
			cache_key.error());
	}
	const auto* function = request.function_database->find_function(request.function);
	if (!function) {
		return aida::analysis::workspace_result_t<ghidra_adapter_decompile_result_t>::failure(
			aida::analysis::make_workspace_error(
				aida::analysis::workspace_error_code_t::target_not_found,
				"Ghidra adapter function identity is not present in the function database",
				"ghidra.adapter.execute"));
	}

	switch (function->key.address.space) {
	case aida::analysis::address_space_id_t::relative_virtual:
	case aida::analysis::address_space_id_t::virtual_address:
	case aida::analysis::address_space_id_t::live_virtual:
		break;
	default:
		return aida::analysis::workspace_result_t<ghidra_adapter_decompile_result_t>::failure(
			aida::analysis::make_workspace_error(
				aida::analysis::workspace_error_code_t::unsupported_address_space,
				"Ghidra adapter function address is not a native image address",
				"ghidra.adapter.execute"));
	}
	uint64_t entry_addr = function->key.address.value;
	if (function->key.address.space == aida::analysis::address_space_id_t::relative_virtual) {
		const uint64_t load_base = request.workspace_identity->target_kind() ==
			aida::analysis::target_kind_t::live_snapshot && request.workspace_identity->module()
			? request.workspace_identity->module()->base
			: request.workspace_identity->image_base();
		if (entry_addr > (std::numeric_limits<uint64_t>::max)() - load_base) {
			return aida::analysis::workspace_result_t<ghidra_adapter_decompile_result_t>::failure(
				aida::analysis::make_workspace_error(
					aida::analysis::workspace_error_code_t::range_overflow,
					"Ghidra adapter function address overflows the workspace load base",
					"ghidra.adapter.execute"));
		}
		entry_addr += load_base;
	}
	const auto ghidra_address_space = request.workspace_identity->target_kind() ==
		aida::analysis::target_kind_t::live_snapshot
		? aida::analysis::address_space_id_t::live_virtual
		: aida::analysis::address_space_id_t::virtual_address;

	std::atomic<bool> local_cancel{false};
	std::atomic<bool>* native_cancel = request.engine_cancel ? request.engine_cancel : &local_cancel;
	auto deadline = request.deadline;
	if (const auto cancellation_deadline = request.cancellation.deadline();
		cancellation_deadline && (!deadline || *cancellation_deadline < *deadline)) {
		deadline = cancellation_deadline;
	}
	auto cancel_check = [&request, deadline]() noexcept {
		if (request.cancellation.stop_requested() ||
			(request.engine_cancel && request.engine_cancel->load(std::memory_order_acquire)) ||
			(deadline && std::chrono::steady_clock::now() >= *deadline)) {
			return true;
		}
		if (!request.cancel_check)
			return false;
		try {
			return request.cancel_check();
		} catch (...) {
			return true;
		}
	};
	auto typed_request = make_typed_capture_request(request, *function);
	ghidra_result_t result = decompile_workspace(request.load_image,
		*request.workspace_identity, request.analysis_snapshot, entry_addr,
		ghidra_address_space,
		native_cancel, std::move(cancel_check), deadline, request.result_limits,
		&typed_request);
	if (!result.is_error && !result.typed_artifacts) {
		result.is_error = true;
		result.complete = false;
		result.error_text = "Ghidra action completed without canonical typed artifacts";
	}
	if (result.is_error) {
		result.adapter_error = detail::make_adapter_execution_error(request, result);
	} else if (!detail::decompile_result_within_limits(result, request.result_limits)) {
		result.is_error = true;
		result.complete = false;
		result.error_text = "decompilation result exceeds configured limits";
		result.adapter_error = detail::make_adapter_execution_error(request, result);
	} else {
		result.adapter_error = {};
	}
	ghidra_adapter_decompile_result_t output;
	output.result = std::move(result);
	output.cache_key = cache_key.take_value();
	return aida::analysis::workspace_result_t<ghidra_adapter_decompile_result_t>::success(
		std::move(output));
}

inline bool preload_module(uint64_t base, size_t size, std::vector<uint8_t>& out, preload_diagnostics_t* diagnostics = nullptr) {
	preload_diagnostics_t local_diag{};
	preload_diagnostics_t& profile = diagnostics ? *diagnostics : local_diag;
	profile = {};
	profile.base = base;
	profile.requested_size = size;
	out.clear();
	if (size == 0 || size > 0x10000000) {
		diag::log_tagged_fmt("ghidra", "preload_module_reject base=0x%llX size=%zu reason=invalid_size",
			static_cast<unsigned long long>(base), size);
		return false;
	}
	const uint32_t pid = driver_bridge::attached_pid();
	profile.whole_read_ok = pid != 0
		? driver_bridge::read_memory_for(pid, base, size, out)
		: driver_bridge::read_memory(base, size, out);
	profile.first_attempt_bytes = out.size();
	if (profile.whole_read_ok && !out.empty()) {
		profile.whole_read_zero_padding = buffer_is_zero_padding(out);
		profile.total_read = out.size();
		const bool pe_ok = profile_pe_image_header(out, profile);
		if (!profile.whole_read_zero_padding || pe_ok) {
			diag::log_tagged_fmt("ghidra",
				"preload_module_whole_ok base=0x%llX requested=%zu bytes=%zu zero=%d mz=%d pe=%d sections=%u image_size=%u",
				static_cast<unsigned long long>(base),
				size,
				out.size(),
				profile.whole_read_zero_padding ? 1 : 0,
				profile.mz ? 1 : 0,
				pe_ok ? 1 : 0,
				static_cast<unsigned>(profile.pe_sections),
				static_cast<unsigned>(profile.pe_size_of_image));
			return true;
		}
	}

	out.assign(size, 0);
	profile.chunked_read = true;
	profile.total_read = 0;
	const uint64_t end = base + static_cast<uint64_t>(size);

	for (size_t offset = 0; offset < size;) {
		const uint64_t addr = base + static_cast<uint64_t>(offset);
		size_t chunk = (std::min)(static_cast<size_t>(0x10000), size - offset);

		driver_bridge::memory_region_t region{};
		const bool region_ok = pid != 0
			? driver_bridge::query_memory_for(pid, addr, region)
			: driver_bridge::query_memory(addr, region);
		if (region_ok) {
			++profile.query_ok;
			const uint64_t region_end = region.base + region.size;
			if (region.base <= addr && region_end > addr) {
				const uint64_t clipped_end = (std::min)(region_end, end);
				chunk = static_cast<size_t>((std::min<uint64_t>)(clipped_end - addr, static_cast<uint64_t>(chunk)));
				if (chunk == 0)
					chunk = (std::min)(static_cast<size_t>(0x1000), size - offset);
			}
			const bool committed = region.state == MEM_COMMIT;
			const bool guarded = (region.protect & PAGE_GUARD) != 0;
			const bool noaccess = (region.protect & PAGE_NOACCESS) != 0;
			if (!committed || guarded || noaccess) {
				++profile.chunks_skipped;
				if (!committed)
					++profile.skipped_uncommitted;
				if (guarded)
					++profile.skipped_guard;
				if (noaccess)
					++profile.skipped_noaccess;
				offset += chunk;
				continue;
			}
		} else {
			++profile.query_failed;
		}

		std::vector<uint8_t> chunk_data;
		const bool chunk_ok = pid != 0
			? driver_bridge::read_memory_for(pid, addr, chunk, chunk_data)
			: driver_bridge::read_memory(addr, chunk, chunk_data);
		if (chunk_ok && !chunk_data.empty()) {
			const size_t copied = (std::min)(chunk_data.size(), size - offset);
			std::memcpy(out.data() + offset, chunk_data.data(), copied);
			profile.total_read += copied;
			++profile.chunks_ok;
		} else {
			++profile.chunks_failed;
		}
		offset += chunk;
	}

	profile.zero_padding = buffer_is_zero_padding(out);
	const bool pe_ok = profile_pe_image_header(out, profile);
	const bool accept = profile.total_read != 0 && (!profile.zero_padding || pe_ok);
	diag::log_tagged_fmt("ghidra",
		"preload_module_chunked base=0x%llX size=%zu first_attempt_bytes=%zu total_read=%zu chunks_ok=%zu chunks_failed=%zu chunks_skipped=%zu query_ok=%zu query_failed=%zu skipped_uncommitted=%zu skipped_guard=%zu skipped_noaccess=%zu zero=%d mz=%d pe=%d sections=%u image_size=%u accept=%d",
		static_cast<unsigned long long>(base),
		size,
		profile.first_attempt_bytes,
		profile.total_read,
		profile.chunks_ok,
		profile.chunks_failed,
		profile.chunks_skipped,
		profile.query_ok,
		profile.query_failed,
		profile.skipped_uncommitted,
		profile.skipped_guard,
		profile.skipped_noaccess,
		profile.zero_padding ? 1 : 0,
		profile.mz ? 1 : 0,
		pe_ok ? 1 : 0,
		static_cast<unsigned>(profile.pe_sections),
		static_cast<unsigned>(profile.pe_size_of_image),
		accept ? 1 : 0);

	if (!accept) {
		out.clear();
		return false;
	}
	return true;
}

inline void batch_decompile(const uint8_t* buffer, size_t buf_size, uint64_t base,
                            const std::vector<uint64_t>& entries,
                            std::vector<ghidra_result_t>& results,
                            std::atomic<int>* progress = nullptr,
                            std::atomic<bool>* cancel = nullptr,
                            const DisasmFile* file_fallback = nullptr)
{
	const uint64_t batch_start_ms = GetTickCount64();
	diag::log_tagged_fmt("ghidra",
		"batch_decompile_enter base=0x%llX buf_size=%zu entries=%zu progress_ptr=%p cancel_ptr=%p initialized=%d",
		static_cast<unsigned long long>(base),
		buf_size,
		entries.size(),
		static_cast<void*>(progress),
		static_cast<void*>(cancel),
		g_state.initialized.load() ? 1 : 0);
	results.clear();
	results.resize(entries.size());

	if (entries.empty()) {
		diag::log_tagged_fmt("ghidra",
			"batch_decompile_exit reason=empty elapsed_ms=%llu",
			static_cast<unsigned long long>(GetTickCount64() - batch_start_ms));
		return;
	}

	if (!g_state.initialized.load()) {
		if (!init()) {
			const std::string init_diag = init_diagnostics();
			for (auto& r : results) {
				r.is_error = true;
				r.error_text = "dependency_blocked: ghidra decompiler not initialized; " + init_diag;
			}
			diag::log_tagged_fmt("ghidra",
				"batch_decompile_exit reason=init_failed entries=%zu diagnostics=%s elapsed_ms=%llu",
				entries.size(),
				init_diag.c_str(),
				static_cast<unsigned long long>(GetTickCount64() - batch_start_ms));
			return;
		}
	}

	mcp_standalone::downstream::producer_identity_t bd_id;
	bd_id.kind = mcp_standalone::downstream::producer_kind_t::decompiler;
	bd_id.tool_name = "batch_decompile";
	mcp_standalone::downstream::scoped_admission_t bd_admission =
		mcp_standalone::downstream::scoped_admission_t::acquire(bd_id);
	if (!bd_admission.active()) {
		auto rej = mcp_standalone::downstream::governor_t::instance().try_admit(bd_id);
		diag::log_tagged_fmt("ghidra",
			"FEATURE-WORKER-GROUP-REJECT batch_decompile reason=%s quota=%s observed=%zu limit=%zu",
			rej.reason.c_str(), rej.quota_name.c_str(), rej.observed, rej.limit);
		for (auto& r : results) {
			r.is_error = true;
			r.error_text = "decompiler capacity exhausted; batch decompile was not started.";
		}
		return;
	}
	diag::log_tagged_fmt("ghidra",
		"FEATURE-WORKER-GROUP-ADMIT batch_decompile token=%llu",
		static_cast<unsigned long long>(bd_admission.token()));

	const std::size_t dec_wg_size = mcp_standalone::downstream::governor_t::instance().quotas().decompiler_worker_group_size;
	unsigned int num_threads = static_cast<unsigned int>(dec_wg_size);
	if (num_threads == 0)
		num_threads = 2;
	if (num_threads > static_cast<unsigned int>(entries.size()))
		num_threads = static_cast<unsigned int>(entries.size());

	std::vector<std::vector<size_t>> partitions(num_threads);
	for (size_t i = 0; i < entries.size(); ++i)
		partitions[i % num_threads].push_back(i);

	auto arch_desc = file_fallback
		? detail::resolve_arch(file_fallback)
		: aida_ghidra::detect_arch_default_x64();

	std::atomic<unsigned int> workers_remaining{num_threads};
	diag::log_tagged_fmt("ghidra",
		"batch_decompile_workers base=0x%llX entries=%zu workers=%u sleigh=%s",
		static_cast<unsigned long long>(base),
		entries.size(),
		num_threads,
		arch_desc.sleigh_id.c_str());

	for (unsigned int t = 0; t < num_threads; ++t) {
		aida::infra::executor::submission_t worker_sub;
		worker_sub.owner_subsystem = "disasm";
		worker_sub.label = "disasm.ghidra.batch_worker";
		worker_sub.thread_class = "external_tool";
		worker_sub.domain = aida::infra::executor::domain_t::external_tool;
		worker_sub.priority = 2;
		worker_sub.body = [&, t]() {
			const uint64_t worker_start_ms = GetTickCount64();
			auto& my_indices = partitions[t];
			auto finish_worker = [&](const char* reason) {
				const unsigned int before = workers_remaining.fetch_sub(1, std::memory_order_acq_rel);
				diag::log_tagged_fmt("ghidra",
					"batch_worker_exit worker=%u reason=%s assigned=%zu remaining_before=%u remaining_after=%u progress=%d cancel=%d elapsed_ms=%llu",
					t,
					reason,
					my_indices.size(),
					before,
					before == 0 ? 0 : before - 1,
					progress ? progress->load(std::memory_order_relaxed) : -1,
					(cancel && cancel->load(std::memory_order_acquire)) ? 1 : 0,
					static_cast<unsigned long long>(GetTickCount64() - worker_start_ms));
			};
			diag::log_tagged_fmt("ghidra",
				"batch_worker_enter worker=%u assigned=%zu tid=%lu",
				t,
				my_indices.size(),
				GetCurrentThreadId());
			if (my_indices.empty()) {
				finish_worker("empty");
				return;
			}

			std::unique_ptr<detail::prepared_arch_t> ta;
			try {
				ta = std::make_unique<detail::prepared_arch_t>(
					buffer, buf_size, base, file_fallback, cancel,
					arch_desc.sleigh_id);
				detail::populate_symbols(*ta->arch, buffer, buf_size, base, file_fallback);
			}
			catch (...) {
				diag::log_tagged_fmt("ghidra",
					"batch_worker_arch_failed worker=%u assigned=%zu",
					t,
					my_indices.size());
				for (size_t idx : my_indices) {
					results[idx].function_addr = entries[idx];
					results[idx].is_error = true;
					results[idx].error_text = "worker architecture init failed";
				}
				if (progress)
					progress->fetch_add(static_cast<int>(my_indices.size()),
					                    std::memory_order_relaxed);
				finish_worker("arch_init_failed");
				return;
			}

			size_t ok_count = 0;
			size_t error_count = 0;
			for (size_t idx : my_indices) {
				if (cancel && cancel->load(std::memory_order_acquire)) {
					results[idx].function_addr = entries[idx];
					results[idx].is_error = true;
					results[idx].error_text = "cancelled";
					++error_count;
					if (progress)
						progress->fetch_add(1, std::memory_order_relaxed);
					continue;
				}

				try {
					ghidra_decompile_result_limits_t evidence_limits;
					evidence_limits.capture_printc_evidence = true;
					results[idx] = detail::do_decompile(ta->arch.get(), entries[idx], cancel, {}, evidence_limits);
					if (results[idx].complete && !results[idx].is_error && results[idx].printc_evidence &&
						!results[idx].printc_evidence->empty())
						++ok_count;
					else
						++error_count;
				}
				catch (ghidra::LowlevelError& err) {
					results[idx].function_addr = entries[idx];
					results[idx].is_error = true;
					results[idx].error_text = err.explain;
					++error_count;
				}
				catch (ghidra::DecoderError& err) {
					results[idx].function_addr = entries[idx];
					results[idx].is_error = true;
					results[idx].error_text = err.explain;
					++error_count;
				}
				catch (...) {
					results[idx].function_addr = entries[idx];
					results[idx].is_error = true;
					results[idx].error_text = "unknown error";
					++error_count;
				}

				if (progress)
					progress->fetch_add(1, std::memory_order_relaxed);
			}
			diag::log_tagged_fmt("ghidra",
				"batch_worker_counts worker=%u ok=%zu errors=%zu assigned=%zu",
				t,
				ok_count,
				error_count,
				my_indices.size());
			finish_worker((cancel && cancel->load(std::memory_order_acquire)) ? "cancelled_or_done" : "done");
		};
		if (!aida::infra::executor::submit(std::move(worker_sub)).submitted)
		{
			const unsigned int before = workers_remaining.fetch_sub(1, std::memory_order_acq_rel);
			diag::log_tagged_fmt("ghidra",
				"batch_worker_post_failed worker=%u assigned=%zu remaining_before=%u remaining_after=%u",
				t,
				partitions[t].size(),
				before,
				before == 0 ? 0 : before - 1);
		}
	}

	uint64_t next_wait_log_ms = GetTickCount64() + 1000;
	while (workers_remaining.load(std::memory_order_acquire) > 0) {
		const uint64_t now_ms = GetTickCount64();
		if (now_ms >= next_wait_log_ms) {
			diag::log_tagged_fmt("ghidra",
				"batch_decompile_wait remaining=%u progress=%d cancel=%d elapsed_ms=%llu",
				workers_remaining.load(std::memory_order_acquire),
				progress ? progress->load(std::memory_order_relaxed) : -1,
				(cancel && cancel->load(std::memory_order_acquire)) ? 1 : 0,
				static_cast<unsigned long long>(now_ms - batch_start_ms));
			next_wait_log_ms = now_ms + 1000;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}
	int ok_total = 0;
	int err_total = 0;
	for (const auto& r : results) {
		if (r.complete && !r.is_error && r.printc_evidence && !r.printc_evidence->empty())
			++ok_total;
		else
			++err_total;
	}
	diag::log_tagged_fmt("ghidra",
		"batch_decompile_exit reason=done entries=%zu ok=%d errors=%d progress=%d cancel=%d elapsed_ms=%llu",
		entries.size(),
		ok_total,
		err_total,
		progress ? progress->load(std::memory_order_relaxed) : -1,
		(cancel && cancel->load(std::memory_order_acquire)) ? 1 : 0,
		static_cast<unsigned long long>(GetTickCount64() - batch_start_ms));
	if (bd_admission.active()) {
		diag::log_tagged_fmt("ghidra",
			"FEATURE-WORKER-GROUP-RELEASE batch_decompile token=%llu reason=completed",
			static_cast<unsigned long long>(bd_admission.token()));
		bd_admission.release("completed");
	}
}

inline std::string last_error() {
	std::lock_guard<std::mutex> lk(g_state.init_mtx);
	return g_state.err_stream.str();
}

inline std::string init_diagnostics() {
	std::lock_guard<std::mutex> lk(g_state.init_mtx);
	std::ostringstream out;
	out << "initialized=" << (g_state.initialized.load(std::memory_order_acquire) ? 1 : 0);
	out << " last_init_reason=" << (g_state.last_init_reason.empty() ? "<empty>" : g_state.last_init_reason);
	out << " specs_dir=\"" << (g_state.specs_dir.empty() ? std::string("<empty>") : g_state.specs_dir) << "\"";
	if (!g_state.init_detail.empty())
		out << " detail=\"" << g_state.init_detail << "\"";
	std::string err = g_state.err_stream.str();
	if (!err.empty())
		out << " error=\"" << err << "\"";
	return out.str();
}

inline bool is_initialized() {
	return g_state.initialized.load();
}

inline void shutdown() {
	std::lock_guard<std::mutex> lk(g_state.init_mtx);
	if (!g_state.initialized.load())
		return;

	try {
		ghidra::shutdownDecompilerLibrary();
	}
	catch (...) {}

	g_state.initialized.store(false);
}

}
