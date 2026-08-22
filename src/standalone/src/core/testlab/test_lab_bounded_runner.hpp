#pragma once

#include "../infra/executor.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <exception>
#include <memory>
#include <mutex>
#include <string>
#include <type_traits>
#include <utility>

namespace test_lab {

enum class bounded_run_status_t {
	completed,
	timed_out,
	saturated,
	post_failed,
	exception
};

struct bounded_run_result_t {
	bounded_run_status_t status = bounded_run_status_t::post_failed;
	std::string error;
	std::uint64_t task_id = 0;
	bool cancellation_requested = false;
	bool worker_started = false;
	bool worker_exited = false;
	bool pending = false;
	bool cancellation_observed = false;
	bool cleanup_complete = false;
	bool worker_exit_pending = false;
	bool operation_quarantined = false;
	std::uint32_t worker_pid = 0;
	std::uint32_t worker_tid = 0;
	std::uint64_t elapsed_ms = 0;
};

struct bounded_run_context_t {
	std::shared_ptr<std::atomic<bool>> cancellation;
	std::shared_ptr<std::atomic<bool>> cancellation_observed_signal;

	bool cancellation_requested() const noexcept {
		const bool requested = cancellation && cancellation->load(std::memory_order_acquire);
		if (requested && cancellation_observed_signal)
			cancellation_observed_signal->store(true, std::memory_order_release);
		return requested;
	}
};

namespace detail {

inline std::string describe_current_exception() {
	try {
		throw;
	} catch (const std::exception& ex) {
		return ex.what();
	} catch (...) {
		return "unknown exception";
	}
}

struct bounded_run_state_t {
	std::mutex mtx;
	std::condition_variable cv;
	bool done = false;
	std::string error;
	std::shared_ptr<std::atomic<bool>> cancellation = std::make_shared<std::atomic<bool>>(false);
	std::shared_ptr<std::atomic<bool>> cancellation_observed_signal = std::make_shared<std::atomic<bool>>(false);
	std::uint64_t receipt_id = 0;
	std::atomic<std::uint64_t> task_id{0};
	std::atomic<bool> worker_started{false};
	std::atomic<bool> worker_exited{false};
	std::atomic<bool> cancellation_requested{false};
	std::atomic<bool> cancellation_observed{false};
	std::atomic<bool> cleanup_complete{false};
	std::atomic<bool> operation_quarantined{false};
	std::atomic<std::uint32_t> worker_pid{0};
	std::atomic<std::uint32_t> worker_tid{0};
	std::atomic<std::uint64_t> started_ms{0};
	std::atomic<std::uint64_t> exited_ms{0};
	std::atomic<std::uint32_t> phase{0};
};

struct bounded_run_lease_t {
	std::shared_ptr<std::atomic<std::uint32_t>> active;
	std::atomic<bool> released{false};

	void release() noexcept {
		if (!released.exchange(true, std::memory_order_acq_rel))
			active->fetch_sub(1u, std::memory_order_acq_rel);
	}

	~bounded_run_lease_t() {
		release();
	}
};

}

class bounded_runner_t {
public:
	explicit bounded_runner_t(std::uint32_t max_active)
		: active_(std::make_shared<std::atomic<std::uint32_t>>(0)),
		  max_active_(max_active == 0 ? 1u : max_active) {
	}

	template <typename Fn>
	bounded_run_result_t run(std::uint32_t timeout_ms, Fn&& fn) {
		const std::uint64_t run_started_ms = GetTickCount64();
		auto active = active_;
		bool active_acquired = false;
		for (;;) {
			std::uint32_t current = active->load(std::memory_order_acquire);
			if (current >= max_active_) {
				bounded_run_result_t result;
				result.status = bounded_run_status_t::saturated;
				result.elapsed_ms = GetTickCount64() - run_started_ms;
				return result;
			}
			if (active->compare_exchange_weak(current, current + 1u, std::memory_order_acq_rel)) {
				active_acquired = true;
				break;
			}
		}

		using fn_t = std::decay_t<Fn>;
		std::shared_ptr<detail::bounded_run_state_t> state;
		std::shared_ptr<detail::bounded_run_lease_t> lease;
		std::shared_ptr<fn_t> task;
		try {
			state = std::make_shared<detail::bounded_run_state_t>();
			state->receipt_id = next_receipt_id();
			lease = std::make_shared<detail::bounded_run_lease_t>();
			lease->active = active;
			active_acquired = false;
			task = std::make_shared<fn_t>(std::forward<Fn>(fn));
		} catch (...) {
			if (active_acquired)
				active->fetch_sub(1u, std::memory_order_acq_rel);
			bounded_run_result_t result;
			result.status = bounded_run_status_t::post_failed;
			result.error = detail::describe_current_exception();
			result.cleanup_complete = true;
			result.elapsed_ms = GetTickCount64() - run_started_ms;
			return result;
		}

		bool posted = false;
		std::uint64_t task_id = 0;
		try {
		aida::infra::executor::submission_t submission;
			submission.owner_subsystem = "test_lab";
			submission.label = "test_lab.bounded_runner";
			submission.thread_class = "testlab_bounded_runner";
			submission.domain = aida::infra::executor::domain_t::feature_worker;
			submission.priority = 2;
			submission.failure_policy = "reject_not_started";
			submission.cancel_hook = [state, lease]() mutable {
				state->cancellation->store(true, std::memory_order_release);
				state->cancellation_requested.store(true, std::memory_order_release);
				std::uint32_t queued = 0;
				if (state->phase.compare_exchange_strong(queued, 2u, std::memory_order_acq_rel)) {
					lease->release();
					state->cleanup_complete.store(true, std::memory_order_release);
					{
						std::lock_guard<std::mutex> lk(state->mtx);
						state->done = true;
					}
				}
				state->cv.notify_all();
			};
			submission.body = [state, task, lease]() mutable {
				std::uint32_t queued = 0;
				if (!state->phase.compare_exchange_strong(queued, 1u, std::memory_order_acq_rel))
					return;
				std::string error;
				const auto worker_pid = static_cast<std::uint32_t>(GetCurrentProcessId());
				const auto worker_tid = static_cast<std::uint32_t>(GetCurrentThreadId());
				try {
					state->worker_pid.store(worker_pid, std::memory_order_release);
					state->worker_tid.store(worker_tid, std::memory_order_release);
					state->started_ms.store(GetTickCount64(), std::memory_order_release);
					state->worker_started.store(true, std::memory_order_release);
					diag::log_tagged_fmt("test_lab.bounded_runner", "worker_enter receipt_id=%llu task_id=%llu pid=%u tid=%u cancellation_requested=%d",
						static_cast<unsigned long long>(state->receipt_id),
						static_cast<unsigned long long>(state->task_id.load(std::memory_order_acquire)),
						static_cast<unsigned>(worker_pid), static_cast<unsigned>(worker_tid),
						state->cancellation->load(std::memory_order_acquire) ? 1 : 0);
					if constexpr (std::is_invocable_v<fn_t&, bounded_run_context_t>)
						(*task)(bounded_run_context_t{ state->cancellation, state->cancellation_observed_signal });
					else
						(*task)();
				} catch (...) {
					error = detail::describe_current_exception();
				}
				const bool cancellation_observed = state->cancellation_observed_signal->load(std::memory_order_acquire);
				state->cancellation_observed.store(cancellation_observed, std::memory_order_release);
				state->worker_exited.store(true, std::memory_order_release);
				state->exited_ms.store(GetTickCount64(), std::memory_order_release);
				state->phase.store(2u, std::memory_order_release);
				lease->release();
				state->cleanup_complete.store(true, std::memory_order_release);
				{
					std::lock_guard<std::mutex> lk(state->mtx);
					state->error = std::move(error);
					state->done = true;
				}
				state->cv.notify_all();
				diag::log_tagged_fmt("test_lab.bounded_runner", "worker_exit receipt_id=%llu task_id=%llu pid=%u tid=%u elapsed_ms=%llu cancellation_observed=%d cleanup_complete=1 worker_exit_pending=0",
					static_cast<unsigned long long>(state->receipt_id),
					static_cast<unsigned long long>(state->task_id.load(std::memory_order_acquire)),
					static_cast<unsigned>(worker_pid), static_cast<unsigned>(worker_tid),
					static_cast<unsigned long long>(state->exited_ms.load(std::memory_order_acquire) - state->started_ms.load(std::memory_order_acquire)),
					cancellation_observed ? 1 : 0);
			};
			auto submit_result = aida::infra::executor::submit(std::move(submission));
			posted = submit_result.submitted;
			task_id = submit_result.task_id;
			state->task_id.store(task_id, std::memory_order_release);
			if (posted) {
				diag::log_tagged_fmt("test_lab.bounded_runner", "submitted receipt_id=%llu task_id=%llu timeout_ms=%u caller_pid=%u caller_tid=%u",
					static_cast<unsigned long long>(state->receipt_id), static_cast<unsigned long long>(task_id),
					static_cast<unsigned>(timeout_ms), static_cast<unsigned>(GetCurrentProcessId()),
					static_cast<unsigned>(GetCurrentThreadId()));
			} else {
				state->error = submit_result.reject_reason;
				diag::log_tagged_fmt("test_lab.bounded_runner", "rejected receipt_id=%llu reason=%s caller_pid=%u caller_tid=%u",
					static_cast<unsigned long long>(state->receipt_id), state->error.c_str(),
					static_cast<unsigned>(GetCurrentProcessId()), static_cast<unsigned>(GetCurrentThreadId()));
			}
		} catch (...) {
			lease.reset();
			bounded_run_result_t result;
			result.status = bounded_run_status_t::post_failed;
			result.error = detail::describe_current_exception();
			result.task_id = task_id;
			result.elapsed_ms = GetTickCount64() - run_started_ms;
			return result;
		}

		if (!posted) {
			lease.reset();
			bounded_run_result_t result;
			result.status = bounded_run_status_t::post_failed;
			result.error = state->error;
			result.task_id = task_id;
			result.cleanup_complete = true;
			result.elapsed_ms = GetTickCount64() - run_started_ms;
			return result;
		}

		std::unique_lock<std::mutex> lk(state->mtx);
		if (!state->cv.wait_for(lk, std::chrono::milliseconds(timeout_ms), [&state]() { return state->done; })) {
			state->cancellation->store(true, std::memory_order_release);
			state->cancellation_requested.store(true, std::memory_order_release);
			state->operation_quarantined.store(true, std::memory_order_release);
			lk.unlock();
			diag::log_tagged_fmt("test_lab.bounded_runner", "cancellation_requested receipt_id=%llu task_id=%llu timeout_ms=%u elapsed_ms=%llu",
				static_cast<unsigned long long>(state->receipt_id), static_cast<unsigned long long>(task_id),
				static_cast<unsigned>(timeout_ms), static_cast<unsigned long long>(GetTickCount64() - run_started_ms));
			if (task_id != 0)
				aida::infra::executor::cancel(task_id);
			lk.lock();
			state->cv.wait_for(lk, std::chrono::milliseconds(250u), [&state]() { return state->done; });
			const bool worker_started = state->worker_started.load(std::memory_order_acquire);
			const bool worker_exited = state->worker_exited.load(std::memory_order_acquire);
			const bool cleanup_complete = state->cleanup_complete.load(std::memory_order_acquire);
			bounded_run_result_t result;
			result.status = bounded_run_status_t::timed_out;
			result.task_id = task_id;
			result.cancellation_requested = true;
			result.worker_started = worker_started;
			result.worker_exited = worker_exited;
			result.pending = !cleanup_complete;
			result.cancellation_observed = state->cancellation_observed.load(std::memory_order_acquire);
			result.cleanup_complete = cleanup_complete;
			result.worker_exit_pending = worker_started && !worker_exited;
			result.operation_quarantined = state->operation_quarantined.load(std::memory_order_acquire);
			result.worker_pid = state->worker_pid.load(std::memory_order_acquire);
			result.worker_tid = state->worker_tid.load(std::memory_order_acquire);
			result.elapsed_ms = GetTickCount64() - run_started_ms;
			lk.unlock();
			diag::log_tagged_fmt("test_lab.bounded_runner", "bounded_drain receipt_id=%llu task_id=%llu cancellation_requested=1 cancellation_observed=%d cleanup_complete=%d operation_quarantined=%d worker_exit_pending=%d worker_started=%d worker_exited=%d worker_pid=%u worker_tid=%u elapsed_ms=%llu",
				static_cast<unsigned long long>(state->receipt_id), static_cast<unsigned long long>(task_id),
				result.cancellation_observed ? 1 : 0, result.cleanup_complete ? 1 : 0,
				result.operation_quarantined ? 1 : 0,
				result.worker_exit_pending ? 1 : 0, result.worker_started ? 1 : 0, result.worker_exited ? 1 : 0,
				static_cast<unsigned>(result.worker_pid), static_cast<unsigned>(result.worker_tid),
				static_cast<unsigned long long>(result.elapsed_ms));
			return result;
		}

		if (!state->error.empty())
		{
			bounded_run_result_t result;
			result.status = bounded_run_status_t::exception;
			result.error = state->error;
			result.task_id = task_id;
			result.cancellation_requested = state->cancellation->load(std::memory_order_acquire);
			result.worker_started = state->worker_started.load(std::memory_order_acquire);
			result.worker_exited = state->worker_exited.load(std::memory_order_acquire);
			result.cancellation_observed = state->cancellation_observed.load(std::memory_order_acquire);
			result.cleanup_complete = state->cleanup_complete.load(std::memory_order_acquire);
			result.worker_pid = state->worker_pid.load(std::memory_order_acquire);
			result.worker_tid = state->worker_tid.load(std::memory_order_acquire);
			result.elapsed_ms = GetTickCount64() - run_started_ms;
			return result;
		}

		bounded_run_result_t result;
		result.status = bounded_run_status_t::completed;
		result.task_id = task_id;
		result.cancellation_requested = state->cancellation->load(std::memory_order_acquire);
		result.worker_started = state->worker_started.load(std::memory_order_acquire);
		result.worker_exited = state->worker_exited.load(std::memory_order_acquire);
		result.cancellation_observed = state->cancellation_observed.load(std::memory_order_acquire);
		result.cleanup_complete = state->cleanup_complete.load(std::memory_order_acquire);
		result.worker_pid = state->worker_pid.load(std::memory_order_acquire);
		result.worker_tid = state->worker_tid.load(std::memory_order_acquire);
		result.elapsed_ms = GetTickCount64() - run_started_ms;
		return result;
	}

private:
	static std::uint64_t next_receipt_id() noexcept {
		static std::atomic<std::uint64_t> next{1};
		return next.fetch_add(1u, std::memory_order_relaxed);
	}

	std::shared_ptr<std::atomic<std::uint32_t>> active_;
	std::uint32_t max_active_;
};

}
