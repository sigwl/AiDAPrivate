#pragma once

#include <cstddef>
#include <cstdint>

namespace test_all_features {

	bool start_tests();
	bool post_hotkey_trigger(const char* source);
	bool trigger_from_hotkey(const char* source);
	void cancel_tests();
	void cancel_tests_for_shutdown();
	void begin_test_guard(const char* source);
	void end_test_guard(const char* source);
	void render_overlay(float vw, float vh);
	bool is_running();
	bool is_unattended_full_test_active();
	struct overlay_perf_snapshot_t {
		bool visible = false;
		bool running = false;
		bool snapshot_busy = false;
		bool snapshot_changed = false;
		std::uint64_t dirty_version = 0;
		std::uint64_t log_version = 0;
		std::uint64_t progress_version = 0;
		std::uint64_t lock_busy_total = 0;
		std::uint64_t snapshot_changes = 0;
		std::uint64_t render_elapsed_us = 0;
		std::size_t total_log_lines = 0;
		std::size_t cached_log_lines = 0;
		std::size_t rendered_log_rows = 0;
	};
	std::uint64_t overlay_dirty_version();
	overlay_perf_snapshot_t overlay_perf_snapshot();
	void set_progress_step(const char* label);
	void format_debug_snapshot(char* out, std::size_t cap);
	void current_phase_and_step(char* phase, std::size_t phase_cap, char* step, std::size_t step_cap, std::uint64_t* step_start_ms_out);
	void log_external_session_event(const char* source, unsigned msg, std::uintptr_t wparam, std::intptr_t lparam);
	void run_parser_proof_smoke();
	void write_full_test_log_line(void* hf, const char* data, std::size_t size, bool force_flush = false);
	void flush_full_test_log(void* hf);
	void mirror_full_test_log_line(const char* tag, const char* detail, const char* line);

}
