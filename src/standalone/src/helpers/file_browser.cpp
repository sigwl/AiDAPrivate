
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../preview/shell_preview_platform.hpp"
#include "../preview/shell_preview.hpp"
#else
#include <windows.h>
#include <shlobj.h>
#endif
#ifdef small
#undef small
#endif

#include "globals.h"
#include "hex_view.hpp"
#include "image_view.hpp"
#include "analysis_session.hpp"
#include "standalone_settings.hpp"
#include "../core/settings/settings_persistence_service.hpp"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "diag_log.hpp"
#endif
#include "imgui/imgui.h"
#include "components.hpp"
#include "theme.hpp"
#include "fonts.hpp"
#include "ui_anim.hpp"
#include "../core/ui/application_view_registry.hpp"
#include "../core/ui/design_system.hpp"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../core/infra/executor.hpp"
#include "../core/infra/taskflow_runtime.hpp"
#include "../core/analysis/workspace/byte_provider.hpp"
#include "../core/analysis/workspace/workspace_registry.hpp"
#include "../core/analysis/workspace/zip_container.hpp"
#include "../core/ui/ui_thread_dispatcher.hpp"
#endif

#include <nlohmann/json.hpp>

#include <filesystem>
#include <algorithm>
#include <cctype>
#include <chrono>
#include <string>
#include <string_view>
#include <vector>
#include <fstream>
#include <sstream>
#include <atomic>
#include <limits>
#include <memory>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <optional>
#include <cstring>
#include <exception>

namespace fs = std::filesystem;

extern HWND g_hwnd;

namespace {

fs::path explorer_path_from_utf8(std::string_view value)
{
#if defined(__cpp_char8_t)
	const auto* begin = reinterpret_cast<const char8_t*>(value.data());
	return fs::path(std::u8string(begin, begin + value.size()));
#else
	return fs::u8path(value.begin(), value.end());
#endif
}

std::string explorer_path_to_utf8(const fs::path& value)
{
	const auto encoded = value.generic_u8string();
#if defined(__cpp_char8_t)
	return std::string(reinterpret_cast<const char*>(encoded.data()), encoded.size());
#else
	return encoded;
#endif
}

std::string normalized_explorer_path(const std::string& input)
{
	std::string value = explorer_path_to_utf8(
		explorer_path_from_utf8(input).lexically_normal());
	while (value.size() > 1 && value.back() == '/')
		value.pop_back();
	std::transform(value.begin(), value.end(), value.begin(), [](unsigned char character) {
		return static_cast<char>(std::tolower(character));
	});
	return value;
}

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
bool native_path_has_reparse_point(const fs::path& path)
{
    const std::wstring native = path.wstring();
    if (native.empty()) return true;
    const DWORD attributes = GetFileAttributesW(native.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES &&
        (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
}

std::string final_native_path_utf8(const fs::path& path, bool directory)
{
    const std::wstring native = path.wstring();
    if (native.empty()) return {};
    const DWORD flags = directory ? FILE_FLAG_BACKUP_SEMANTICS : FILE_ATTRIBUTE_NORMAL;
    HANDLE handle = CreateFileW(native.c_str(), FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, flags, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return {};
    std::wstring final_path;
    const DWORD needed = GetFinalPathNameByHandleW(handle, nullptr, 0, FILE_NAME_NORMALIZED);
    if (needed != 0) {
        final_path.resize(needed);
        const DWORD written = GetFinalPathNameByHandleW(handle, final_path.data(), needed, FILE_NAME_NORMALIZED);
        if (written == 0 || written >= needed)
            final_path.clear();
        else
            final_path.resize(written);
    }
    CloseHandle(handle);
    if (final_path.rfind(L"\\\\?\\UNC\\", 0) == 0)
        final_path = L"\\\\" + final_path.substr(8);
    else if (final_path.rfind(L"\\\\?\\", 0) == 0)
        final_path.erase(0, 4);
    if (final_path.empty()) return {};
    return explorer_path_to_utf8(fs::path(final_path).lexically_normal());
}

bool path_is_within_root(const std::string& candidate, const std::string& root)
{
    const std::string c = normalized_explorer_path(candidate);
    const std::string r = normalized_explorer_path(root);
    return !c.empty() && !r.empty() && (c == r ||
        (c.size() > r.size() && c.compare(0, r.size(), r) == 0 && c[r.size()] == '/'));
}

bool admitted_file_open_path(const std::string& path, bool directory, std::string* error = nullptr)
{
    if (path.empty()) {
        if (error) *error = "empty path";
        return false;
    }
    const fs::path candidate = explorer_path_from_utf8(path);
    fs::path component = candidate;
    while (!component.empty()) {
        if (native_path_has_reparse_point(component)) {
            if (error) *error = "reparse point rejected";
            return false;
        }
        const fs::path parent = component.parent_path();
        if (parent == component) break;
        component = parent;
    }
    const std::string final_path = final_native_path_utf8(candidate, directory);
    if (final_path.empty()) {
        if (error) *error = "path could not be opened for verification";
        return false;
    }
    for (const auto& root : file_browser::roots) {
        if (path_is_within_root(final_path, root))
            return true;
    }
    if (error) *error = "path is outside the configured workspace roots";
    return false;
}
#endif

}

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
namespace {

constexpr std::size_t k_explorer_entry_limit = 250000;
constexpr std::size_t k_explorer_string_budget = 64ULL * 1024ULL * 1024ULL;
constexpr std::size_t k_explorer_publish_batch = 512;

struct explorer_index_control_t {
    std::shared_ptr<std::atomic<bool>> cancelled;
    std::shared_ptr<std::atomic<std::size_t>> pending_publications;
    std::uint64_t task_id = 0;
    std::uint64_t generation = 0;
};

explorer_index_control_t& explorer_index_control()
{
    static explorer_index_control_t value;
    return value;
}

std::uint64_t explorer_identity(std::string_view value, std::uint64_t seed = 14695981039346656037ULL)
{
    std::uint64_t hash = seed;
    for (const char character : value) {
        hash ^= static_cast<unsigned char>(character);
        hash *= 1099511628211ULL;
    }
    return hash == 0 ? 1 : hash;
}

bool publish_explorer_batch(std::uint64_t generation,
    std::shared_ptr<const std::vector<FileBrowserEntry>> batch,
    std::size_t directory_count, bool final, bool cancelled,
    bool truncated, std::string error, std::string selected_path,
    std::shared_ptr<std::unordered_set<std::string>> matched_selected_paths,
    int matched_primary_index, std::string matched_primary_path,
    std::string retained_anchor_path, std::uint64_t retained_selection_revision,
    std::shared_ptr<std::atomic<std::size_t>> pending_publications)
{
    bool posted = false;
    for (int attempt = 0; attempt < 100 && !posted; ++attempt) {
        posted = aida::ui_thread::post(
        [generation, batch, directory_count, final, cancelled,
         truncated, error, selected_path, matched_selected_paths,
         matched_primary_index, matched_primary_path,
         retained_anchor_path, retained_selection_revision, pending_publications]() mutable {
            struct publication_guard_t {
                std::shared_ptr<std::atomic<std::size_t>> pending;
                ~publication_guard_t() {
                    if (pending) pending->fetch_sub(1, std::memory_order_acq_rel);
                }
            } publication_guard{pending_publications};
            if (generation != file_browser::index_generation)
                return;
            if (batch) {
                file_browser::entries.insert(file_browser::entries.end(),
                    batch->begin(), batch->end());
                if (file_browser::selected_idx < 0 && !selected_path.empty()) {
                    for (std::size_t index = file_browser::entries.size() - batch->size();
                         index < file_browser::entries.size(); ++index) {
                        if (normalized_explorer_path(file_browser::entries[index].full_path) == selected_path) {
                            file_browser::selected_idx = static_cast<int>(index);
                            break;
                        }
                    }
                }
            }
            file_browser::indexed_directory_count = directory_count;
            file_browser::indexed_entry_count = file_browser::entries.size();
            file_browser::index_truncated = truncated;
            if (!error.empty())
                file_browser::index_error = std::move(error);
            if (final) {
                file_browser::index_state = cancelled
                    ? file_browser::index_state_t::cancelled
                    : (file_browser::entries.empty() && !file_browser::index_error.empty()
                        ? file_browser::index_state_t::error
                        : file_browser::index_state_t::ready);
                const bool selection_unchanged = file_browser::selection_revision ==
                    retained_selection_revision;
                if (matched_selected_paths && selection_unchanged)
                    file_browser::selected_paths.swap(*matched_selected_paths);
                if (selection_unchanged) {
                    file_browser::selected_idx = matched_primary_index >= 0 &&
                        static_cast<std::size_t>(matched_primary_index) < file_browser::entries.size()
                        ? matched_primary_index : -1;
                    file_browser::selection_anchor_path =
                        file_browser::selected_paths.find(retained_anchor_path) !=
                            file_browser::selected_paths.end()
                        ? retained_anchor_path : matched_primary_path;
                }
                if (file_browser::selected_paths.size() < 100000)
                    file_browser::selection_error.clear();
                auto& control = explorer_index_control();
                if (control.generation == generation)
                    control.task_id = 0;
            }
        }, "file_browser", "index_snapshot", final ? "worker_final" : "worker_batch");
        if (!posted)
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    if (!posted)
    {
        if (pending_publications)
            pending_publications->fetch_sub(1, std::memory_order_acq_rel);
        diag::log_tagged_fmt("file_browser",
            "index_snapshot_dispatch_failed generation=%llu final=%d entries=%zu",
            static_cast<unsigned long long>(generation), final ? 1 : 0,
            batch ? batch->size() : 0U);
    }
    return posted;
}

}
#endif

void file_browser::refresh(const std::string& dir)
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    ++index_generation;
    if (!dir.empty())
        current_dir = dir;
    if (current_dir.empty())
        current_dir = "C:/Preview/ReverseEngineering";
    roots = {current_dir};
    strncpy_s(path_buf, sizeof(path_buf), current_dir.c_str(), _TRUNCATE);
    if (entries.empty()) {
        entries = {
            { "samples", current_dir + "/samples", true, true, 0 },
            { "sample.exe", current_dir + "/samples/sample.exe", false, false, 1 },
            { "packed_sample.dll", current_dir + "/samples/packed_sample.dll", false, false, 1 },
            { "symbols", current_dir + "/symbols", true, false, 0 },
            { "notes.md", current_dir + "/notes.md", false, false, 0 }
        };
    }
    needs_refresh = false;
    index_state = index_state_t::ready;
    index_error.clear();
    indexed_entry_count = entries.size();
    if (selected_idx >= static_cast<int>(entries.size()))
        selected_idx = -1;
    const auto preview_key = [](const std::string& value) {
        std::string key = explorer_path_to_utf8(
            explorer_path_from_utf8(value).lexically_normal());
        std::transform(key.begin(), key.end(), key.begin(), [](unsigned char character) {
            return static_cast<char>(std::tolower(character));
        });
        return key;
    };
    std::unordered_set<std::string> live_paths;
    for (const auto& entry : entries) live_paths.insert(preview_key(entry.full_path));
    for (auto iterator = selected_paths.begin(); iterator != selected_paths.end();) {
        if (live_paths.find(*iterator) == live_paths.end())
            iterator = selected_paths.erase(iterator);
        else
            ++iterator;
    }
    if (selected_idx < 0 || selected_paths.find(preview_key(entries[
            static_cast<std::size_t>(selected_idx)].full_path)) == selected_paths.end()) {
        selected_idx = -1;
        for (std::size_t index = 0; index < entries.size(); ++index)
            if (selected_paths.find(preview_key(entries[index].full_path)) != selected_paths.end()) {
                selected_idx = static_cast<int>(index);
                break;
            }
    }
    if (selected_paths.find(selection_anchor_path) == selected_paths.end())
        selection_anchor_path = selected_idx >= 0
            ? preview_key(entries[static_cast<std::size_t>(selected_idx)].full_path)
            : std::string{};
    aida::preview::record(aida::preview::shell_action_t::open_folder, current_dir);
    return;
#else
    if (!aida::ui_thread::is_owner_thread()) {
        const bool routed = aida::ui_thread::post([dir]() {
            file_browser::refresh(dir);
        }, "file_browser", "refresh", "entry");
        if (!routed)
            diag::log_tagged_fmt("file_browser", "refresh denied dir=%s reason=ui_affinity_route_failed", dir.c_str());
        return;
    }
    if (!aida::ui_thread::require_owner("file_browser", "refresh", "entry"))
        return;

    std::string root = dir;
    if (root.empty() && current_dir.empty() && roots.empty()) {
        char buf[MAX_PATH] = {};
        GetCurrentDirectoryA(MAX_PATH, buf);
        root = buf;
    }
    if (!root.empty()) {
        roots = {fs::absolute(fs::path(root)).lexically_normal().string()};
        expanded_paths.clear();
        expanded_paths.insert(normalized_explorer_path(roots.front()));
    }
    else if (roots.empty() && !current_dir.empty()) {
        roots = {fs::absolute(fs::path(current_dir)).lexically_normal().string()};
        expanded_paths.insert(normalized_explorer_path(roots.front()));
    }
    if (roots.empty())
        return;
    current_dir = roots.front();
    strncpy_s(path_buf, sizeof(path_buf), current_dir.c_str(), _TRUNCATE);

    for (const auto& entry : entries)
        if (entry.is_dir && entry.expanded)
            expanded_paths.insert(normalized_explorer_path(entry.full_path));
    std::string selected_path = normalized_explorer_path(pending_reveal_path);
    pending_reveal_path.clear();
    if (selected_path.empty() && selected_idx >= 0 && static_cast<std::size_t>(selected_idx) < entries.size())
        selected_path = normalized_explorer_path(entries[static_cast<std::size_t>(selected_idx)].full_path);
    auto selected_keys = std::make_shared<const std::unordered_set<std::string>>(selected_paths);
    if (!selected_path.empty() && selected_keys->find(selected_path) == selected_keys->end()) {
        auto completed_keys = std::make_shared<std::unordered_set<std::string>>(*selected_keys);
        completed_keys->insert(selected_path);
        selected_keys = std::static_pointer_cast<const std::unordered_set<std::string>>(completed_keys);
    }
    const std::string retained_anchor_path = selection_anchor_path;
    const std::uint64_t retained_selection_revision = selection_revision;

    auto& control = explorer_index_control();
    if (control.cancelled)
        control.cancelled->store(true, std::memory_order_release);
    if (control.task_id != 0)
        aida::infra::executor::cancel(control.task_id);
    control.cancelled = std::make_shared<std::atomic<bool>>(false);
    control.pending_publications = std::make_shared<std::atomic<std::size_t>>(0);
    control.generation = ++index_generation;
    control.task_id = 0;

    entries.clear();
    selected_idx = -1;
    needs_refresh = false;
    index_state = index_state_t::loading;
    index_error.clear();
    indexed_directory_count = 0;
    indexed_entry_count = 0;
    index_truncated = false;

    auto roots_copy = roots;
    if (roots_copy.size() > 8)
        roots_copy.resize(8);
    const auto expanded_copy = expanded_paths;
    const auto cancel = control.cancelled;
    const auto pending_publications = control.pending_publications;
    const std::uint64_t generation = control.generation;
    aida::infra::executor::submission_t submission;
    submission.owner_subsystem = "file_browser";
    submission.label = "file_browser.project_index";
    submission.thread_class = "blocking_directory_io";
    submission.domain = aida::infra::executor::domain_t::feature_worker;
    submission.priority = 3;
    submission.generation = generation;
    submission.cancel_hook = [cancel]() {
        cancel->store(true, std::memory_order_release);
    };
    submission.body = [roots_copy, expanded_copy, cancel, pending_publications, generation,
                       selected_path = std::move(selected_path), selected_keys,
                       retained_anchor_path, retained_selection_revision]() mutable {
        std::size_t directory_count = 0;
        bool truncated = false;
        auto matched_selected_paths = std::make_shared<std::unordered_set<std::string>>();
        matched_selected_paths->reserve(selected_keys->size());
        int matched_primary_index = -1;
        std::string matched_primary_path;
        try {
        std::vector<FileBrowserEntry> batch;
        batch.reserve(k_explorer_publish_batch);
        std::size_t total_entries = 0;
        std::size_t total_string_bytes = 0;
        std::string errors;
        const bool multiple_roots = roots_copy.size() > 1;
        auto append_error = [&errors](const std::string& path, const std::string& detail) {
            if (errors.size() >= 4096) return;
            if (!errors.empty()) errors.append("; ");
            errors.append(path).append(": ").append(detail);
            if (errors.size() > 4096) errors.resize(4096);
        };

        auto flush = [&](bool final) {
            while (pending_publications->load(std::memory_order_acquire) >= 8 &&
                   !cancel->load(std::memory_order_acquire))
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            pending_publications->fetch_add(1, std::memory_order_acq_rel);
            auto immutable = std::make_shared<const std::vector<FileBrowserEntry>>(std::move(batch));
            const bool published = publish_explorer_batch(generation, std::move(immutable), directory_count,
                final, cancel->load(std::memory_order_acquire), truncated,
                final ? errors : std::string{}, selected_path,
                final ? matched_selected_paths : nullptr,
                final ? matched_primary_index : -1,
                final ? matched_primary_path : std::string{},
                retained_anchor_path, retained_selection_revision,
                pending_publications);
            batch.clear();
            batch.reserve(k_explorer_publish_batch);
            if (!published) {
                cancel->store(true, std::memory_order_release);
                append_error("Project index", "UI publication remained unavailable after bounded retries");
            }
            return published;
        };
        auto append = [&](FileBrowserEntry entry) {
            const std::size_t bytes = entry.name.size() + entry.full_path.size();
            if (total_entries >= k_explorer_entry_limit ||
                total_string_bytes + bytes > k_explorer_string_budget) {
                truncated = true;
                return false;
            }
            total_string_bytes += bytes;
            const std::string key = normalized_explorer_path(entry.full_path);
            if (selected_keys->find(key) != selected_keys->end()) {
                matched_selected_paths->insert(key);
                if (matched_primary_index < 0 || key == selected_path) {
                    matched_primary_index = static_cast<int>(total_entries);
                    matched_primary_path = key;
                }
            }
            ++total_entries;
            batch.push_back(std::move(entry));
            if (batch.size() >= k_explorer_publish_batch && !flush(false))
                return false;
            return true;
        };

        std::function<void(const std::string&, int, std::uint64_t, std::uint64_t)> scan;
        scan = [&](const std::string& directory, int depth,
                   std::uint64_t root_id, std::uint64_t parent_id) {
            if (cancel->load(std::memory_order_acquire) || truncated)
                return;
            if (depth > 256) {
                truncated = true;
                append_error(directory, "maximum Explorer nesting depth (256) reached");
                return;
            }
            ++directory_count;
            std::error_code ec;
            std::vector<FileBrowserEntry> directories;
            std::vector<FileBrowserEntry> files;
            std::size_t local_string_bytes = 0;
            const std::size_t remaining_entries = k_explorer_entry_limit - total_entries;
            const std::size_t remaining_string_bytes = k_explorer_string_budget - total_string_bytes;
            fs::directory_iterator iterator(fs::path(directory),
                fs::directory_options::skip_permission_denied, ec);
            if (ec) {
                append_error(directory, ec.message());
                return;
            }
            const fs::directory_iterator end;
            while (iterator != end) {
                if (cancel->load(std::memory_order_acquire) || truncated)
                    return;
                const fs::directory_entry item = *iterator;
                const std::string name = item.path().filename().string();
                if (!name.empty() && name.front() != '.') {
                    FileBrowserEntry entry;
                    entry.full_path = item.path().lexically_normal().string();
                    entry.name = name;
                    entry.depth = depth;
                    entry.root_id = root_id;
                    entry.parent_id = parent_id;
                    entry.generation = generation;
                    const std::string key = normalized_explorer_path(entry.full_path);
                    entry.entry_id = explorer_identity(key, root_id);
                    const std::size_t entry_string_bytes = entry.name.size() + entry.full_path.size();
                    if (directories.size() + files.size() >= remaining_entries ||
                        local_string_bytes + entry_string_bytes > remaining_string_bytes) {
                        truncated = true;
                        break;
                    }
                    std::error_code type_error;
                    const bool directory_entry = item.is_directory(type_error) && !type_error;
                    const bool symlink_entry = directory_entry && item.is_symlink(type_error) && !type_error;
                    if (directory_entry && !symlink_entry) {
                        local_string_bytes += entry_string_bytes;
                        entry.is_dir = true;
                        entry.expanded = expanded_copy.find(key) != expanded_copy.end();
                        directories.push_back(std::move(entry));
                    } else if (item.is_regular_file(type_error) && !type_error) {
                        local_string_bytes += entry_string_bytes;
                        files.push_back(std::move(entry));
                    }
                }
                iterator.increment(ec);
                if (ec) {
                    append_error(directory, ec.message());
                    break;
                }
            }
            const auto by_name = [](const FileBrowserEntry& left, const FileBrowserEntry& right) {
                return _stricmp(left.name.c_str(), right.name.c_str()) < 0;
            };
            std::sort(directories.begin(), directories.end(), by_name);
            std::sort(files.begin(), files.end(), by_name);
            for (auto& child : directories) {
                const bool expanded = child.expanded;
                const std::string child_path = child.full_path;
                const std::uint64_t child_id = child.entry_id;
                if (!append(std::move(child))) return;
                if (expanded)
                    scan(child_path, depth + 1, root_id, child_id);
            }
            for (auto& child : files)
                if (!append(std::move(child))) return;
        };

        for (const auto& root_path : roots_copy) {
            if (cancel->load(std::memory_order_acquire) || truncated)
                break;
            const std::string root_key = normalized_explorer_path(root_path);
            const std::uint64_t root_id = explorer_identity(root_key);
            std::error_code root_error;
            if (!fs::is_directory(fs::path(root_path), root_error) || root_error) {
                append_error(root_path, root_error ? root_error.message() : "not a directory");
                continue;
            }
            bool scan_root = true;
            if (multiple_roots) {
                FileBrowserEntry root_entry;
                root_entry.name = fs::path(root_path).filename().string();
                if (root_entry.name.empty()) root_entry.name = root_path;
                root_entry.full_path = root_path;
                root_entry.is_dir = true;
                root_entry.expanded = expanded_copy.find(root_key) != expanded_copy.end();
                scan_root = root_entry.expanded;
                root_entry.depth = 0;
                root_entry.root_id = root_id;
                root_entry.entry_id = root_id;
                root_entry.generation = generation;
                root_entry.is_root = true;
                if (!append(std::move(root_entry))) break;
            }
            if (scan_root)
                scan(root_path, multiple_roots ? 1 : 0, root_id, multiple_roots ? root_id : 0);
        }
        flush(true);
        } catch (const std::exception& exception) {
            while (pending_publications->load(std::memory_order_acquire) >= 8 &&
                   !cancel->load(std::memory_order_acquire))
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            pending_publications->fetch_add(1, std::memory_order_acq_rel);
            auto empty = std::make_shared<const std::vector<FileBrowserEntry>>();
            publish_explorer_batch(generation, std::move(empty), directory_count, true,
                cancel->load(std::memory_order_acquire), truncated,
                std::string("Project index failed: ") + exception.what(), selected_path,
                matched_selected_paths, matched_primary_index, matched_primary_path,
                retained_anchor_path, retained_selection_revision,
                pending_publications);
        } catch (...) {
            while (pending_publications->load(std::memory_order_acquire) >= 8 &&
                   !cancel->load(std::memory_order_acquire))
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            pending_publications->fetch_add(1, std::memory_order_acq_rel);
            auto empty = std::make_shared<const std::vector<FileBrowserEntry>>();
            publish_explorer_batch(generation, std::move(empty), directory_count, true,
                cancel->load(std::memory_order_acquire), truncated,
                "Project index failed with an unknown filesystem error.", selected_path,
                matched_selected_paths, matched_primary_index, matched_primary_path,
                retained_anchor_path, retained_selection_revision,
                pending_publications);
        }
    };
    const auto submitted = aida::infra::executor::submit(std::move(submission));
    if (!submitted.submitted) {
        index_state = index_state_t::error;
        index_error = "The project index worker could not be scheduled: " + submitted.reject_reason;
        control.cancelled.reset();
        diag::log_tagged_fmt("file_browser", "index_submit_failed generation=%llu reason=%s",
            static_cast<unsigned long long>(generation), submitted.reject_reason.c_str());
        return;
    }
    control.task_id = submitted.task_id;
#endif
}

bool file_browser::reveal_path(const std::string& path)
{
    if (path.empty() || roots.empty())
        return false;
    const fs::path candidate = explorer_path_from_utf8(path).lexically_normal();
    const std::string candidate_key = normalized_explorer_path(
        explorer_path_to_utf8(candidate));
    bool inside_root = false;
    for (const auto& root_value : roots) {
        const fs::path root = explorer_path_from_utf8(root_value).lexically_normal();
        const std::string root_key = normalized_explorer_path(explorer_path_to_utf8(root));
        if (candidate_key == root_key || (candidate_key.size() > root_key.size() &&
            candidate_key.compare(0, root_key.size(), root_key) == 0 &&
            (candidate_key[root_key.size()] == '/' || candidate_key[root_key.size()] == '\\'))) {
            inside_root = true;
            fs::path parent = candidate.parent_path();
            while (!parent.empty()) {
                expanded_paths.insert(normalized_explorer_path(explorer_path_to_utf8(parent)));
                if (normalized_explorer_path(explorer_path_to_utf8(parent)) == root_key)
                    break;
                const fs::path next = parent.parent_path();
                if (next == parent)
                    break;
                parent = next;
            }
            break;
        }
    }
    if (!inside_root)
        return false;
    pending_reveal_path = explorer_path_to_utf8(candidate);
    selected_paths.clear();
    selected_paths.insert(normalized_explorer_path(pending_reveal_path));
    selection_anchor_path = normalized_explorer_path(pending_reveal_path);
    selected_idx = -1;
    ++selection_revision;
    needs_refresh = true;
    return true;
}

void file_browser::set_roots(std::vector<std::string> requested_roots)
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    if (!requested_roots.empty())
        refresh(requested_roots.front());
#else
    if (!aida::ui_thread::is_owner_thread()) {
        const bool routed = aida::ui_thread::post(
            [requested_roots = std::move(requested_roots)]() mutable {
                file_browser::set_roots(std::move(requested_roots));
            }, "file_browser", "set_roots", "entry");
        if (!routed)
            diag::log_tagged("file_browser", "set_roots denied reason=ui_affinity_route_failed");
        return;
    }
    if (!aida::ui_thread::require_owner("file_browser", "set_roots", "entry"))
        return;
    std::vector<std::string> normalized;
    std::unordered_set<std::string> seen;
    normalized.reserve(requested_roots.size());
    for (auto& root : requested_roots) {
        if (normalized.size() >= 8) break;
        if (root.empty()) continue;
        root = fs::path(root).lexically_normal().string();
        if (seen.insert(normalized_explorer_path(root)).second)
            normalized.push_back(std::move(root));
    }
    roots = std::move(normalized);
    std::unordered_set<std::string> retained_expansions;
    retained_expansions.reserve((std::min)(expanded_paths.size() + roots.size(), k_explorer_entry_limit));
    for (const auto& root : roots) {
        const std::string key = normalized_explorer_path(root);
        retained_expansions.insert(key);
        const std::string prefix = key + "/";
        for (const auto& expanded : expanded_paths) {
            if (retained_expansions.size() >= k_explorer_entry_limit) break;
            if (expanded.compare(0, prefix.size(), prefix) == 0)
                retained_expansions.insert(expanded);
        }
    }
    expanded_paths = std::move(retained_expansions);
    current_dir = roots.empty() ? std::string{} : roots.front();
    needs_refresh = true;
#endif
}

bool file_browser::set_workspace_root(const std::string& path, std::string* error)
{
    try {
        if (path.empty()) {
            if (error) *error = "Select a folder before setting the workspace root";
            return false;
        }
        if (path.size() > 32768) {
            if (error) *error = "The selected workspace-root path exceeds the supported bound";
            return false;
        }
        const std::string normalized = explorer_path_to_utf8(
            explorer_path_from_utf8(path).lexically_normal());
        if (normalized.empty()) {
            if (error) *error = "The selected workspace-root path is invalid";
            return false;
        }
        const std::vector<std::string> previous_roots = roots;
        const std::string previous_setting = g_sa_settings.workspace.root_path;
        selected_paths.clear();
        selection_anchor_path.clear();
        selection_error.clear();
        selected_idx = -1;
        ++selection_revision;
        pending_reveal_path.clear();
        refresh(normalized);
        g_sa_settings.workspace.root_path = normalized;
        const auto requested = aida::settings_persistence::request_save(g_sa_settings);
        if (!aida::settings_persistence::accepted(requested)) {
            g_sa_settings.workspace.root_path = previous_setting;
            set_roots(previous_roots);
            if (error) *error = "Settings persistence rejected the workspace-root transaction; the previous roots were restored";
            return false;
        }
        if (error) error->clear();
        return true;
    } catch (const std::exception&) {
        if (error) *error = "The selected workspace-root path is not valid UTF-8 or cannot be represented natively";
        return false;
    } catch (...) {
        if (error) *error = "The selected workspace-root path could not be converted safely";
        return false;
    }
}

bool file_browser::binary_analysis_candidate(const std::string& path)
{
    if (path.empty()) return false;
    std::string extension;
    try {
        extension = explorer_path_to_utf8(explorer_path_from_utf8(path).extension());
    } catch (...) {
        return false;
    }
    std::transform(extension.begin(), extension.end(), extension.begin(), [](unsigned char value) {
        return static_cast<char>(std::tolower(value));
    });
    static constexpr const char* extensions[] = {
        ".exe", ".dll", ".sys", ".efi", ".scr", ".cpl", ".ocx", ".ax",
        ".drv", ".mui", ".tsp", ".node", ".bin", ".lib", ".obj", ".o",
        ".a", ".so", ".dylib", ".elf", ".out", ".com", ".ko", ".kext",
        ".dmp", ".pdb", ".rom", ".img", ".uefi", ".class", ".jar", ".pyc",
        ".pyo", ".rar", ".zip", ".7z", ".tar", ".gz", ".bz2", ".xz",
        ".cab", ".iso", ".apk", ".ipa"
    };
    return std::find(std::begin(extensions), std::end(extensions), extension) !=
        std::end(extensions);
}

void file_browser::cancel_refresh()
{
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
    auto& control = explorer_index_control();
    if (control.cancelled)
        control.cancelled->store(true, std::memory_order_release);
    if (control.task_id != 0)
        aida::infra::executor::cancel(control.task_id);
#endif
    needs_refresh = false;
    if (index_state == index_state_t::loading)
        index_state = index_state_t::cancelled;
}


void file_browser::toggle_dir(int idx)
{
    if (idx < 0 || static_cast<std::size_t>(idx) >= entries.size()) return;
    auto& ent = entries[static_cast<std::size_t>(idx)];
    if (!ent.is_dir) return;

    ent.expanded = !ent.expanded;
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
    const std::string key = normalized_explorer_path(ent.full_path);
    if (ent.expanded)
        expanded_paths.insert(key);
    else
        expanded_paths.erase(key);
#endif
    needs_refresh = true;
}


namespace file_browser {

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)

namespace ext_classify {

static const char* k_text_exts[] = {
    ".cpp", ".c", ".h", ".hpp", ".hxx", ".cxx", ".cc",
    ".py", ".js", ".ts", ".json", ".xml", ".yaml", ".yml",
    ".md", ".txt", ".log", ".cfg", ".ini", ".toml",
    ".java", ".cs", ".rs", ".go", ".rb", ".php",
    ".html", ".css", ".scss", ".lua", ".sh", ".bat", ".ps1",
    ".cmake", ".asm", ".s", ".inc", ".def", ".rules",
    ".vcxproj", ".vcproj", ".filters", ".props", ".targets",
    ".sln", ".csproj", ".proj", ".gradle", ".gn", ".gni",
    ".diff", ".patch", ".gitignore", ".gitattributes",
    ".srt", ".vtt", ".tsv", ".csv",
    ".env", ".rc", ".pbxproj", ".plist",
};

static const char* k_binary_exts[] = {
    ".exe", ".dll", ".sys", ".efi", ".scr", ".cpl",
    ".ocx", ".ax", ".drv", ".mui", ".tsp", ".node",
    ".bin", ".lib", ".obj", ".o", ".a", ".so", ".dylib",
    ".elf", ".out", ".com", ".ko", ".kext", ".dmp",
    ".pdb", ".rom", ".img", ".uefi",
    ".class", ".jar",
    ".pyc", ".pyo",
};

static const char* k_archive_exts[] = {
    ".rar", ".zip", ".7z", ".tar", ".gz", ".bz2", ".xz",
    ".cab", ".iso", ".apk", ".ipa", ".jar",
};

inline std::string lower_ext(const std::string& filename)
{
    std::string ext;
    auto dot = filename.rfind('.');
    if (dot != std::string::npos)
        ext = filename.substr(dot);
    for (auto& c : ext) c = (char)tolower((unsigned char)c);
    return ext;
}

inline bool matches(const std::string& ext, const char* const* table, size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        if (ext == table[i]) return true;
    }
    return false;
}

inline bool is_text(const std::string& ext)
{
    return matches(ext, k_text_exts, sizeof(k_text_exts)/sizeof(k_text_exts[0]));
}

inline bool is_binary(const std::string& ext)
{
    return matches(ext, k_binary_exts, sizeof(k_binary_exts)/sizeof(k_binary_exts[0]));
}

inline bool is_archive(const std::string& ext)
{
    return matches(ext, k_archive_exts, sizeof(k_archive_exts)/sizeof(k_archive_exts[0]));
}

}

namespace {

struct hex_preview_operation_t {
    std::mutex mutex;
    std::condition_variable completion;
    std::atomic<bool> terminal{false};
    std::atomic<bool> cancellation{false};
    std::shared_ptr<aida::analysis::cancellation_source_t> provider_cancellation;
    std::optional<aida::analysis::workspace_admission_handle_t> admission;
};

struct hex_preview_state_t {
    std::mutex mutex;
    std::uint64_t serial = 0;
    bool loading = false;
    bool cancellation_requested = false;
    bool cancelled = false;
    bool archive = false;
    std::string path;
    std::string error;
    aida::infra::taskflow_runtime::job_handle_t task;
    std::optional<aida::analysis::workspace_admission_handle_t> admission;
    std::shared_ptr<hex_preview_operation_t> operation;
};

hex_preview_state_t& hex_preview_state()
{
    static hex_preview_state_t value;
    return value;
}

bool hex_preview_is_current(std::uint64_t serial)
{
    std::lock_guard<std::mutex> lock(hex_preview_state().mutex);
    return hex_preview_state().serial == serial;
}

void complete_hex_preview_failure(std::uint64_t serial, std::string path, std::string error)
{
    auto publish = [serial, path = std::move(path), error = std::move(error)]() mutable {
        auto& preview = hex_preview_state();
        std::lock_guard<std::mutex> lock(preview.mutex);
        if (preview.serial != serial)
            return;
        preview.loading = false;
        preview.cancellation_requested = false;
        preview.cancelled = false;
        preview.path = std::move(path);
        preview.error = std::move(error);
        preview.task = {};
        preview.admission.reset();
        preview.operation.reset();
    };
    if (!aida::ui_thread::post(publish, "file_browser", "hex_fallback", "failure")) {
        publish();
        diag::log_tagged_fmt("file_browser", "hex_fallback_ui_post_failed serial=%llu",
            static_cast<unsigned long long>(serial));
    }
}

void complete_hex_preview_cancelled(std::uint64_t serial, std::string path)
{
    auto publish = [serial, path = std::move(path)]() mutable {
        auto& preview = hex_preview_state();
        std::lock_guard<std::mutex> lock(preview.mutex);
        if (preview.serial != serial)
            return;
        preview.loading = false;
        preview.cancellation_requested = false;
        preview.cancelled = true;
        preview.path = std::move(path);
        preview.error.clear();
        preview.task = {};
        preview.admission.reset();
        preview.operation.reset();
    };
    if (!aida::ui_thread::post(publish, "file_browser", "hex_fallback", "cancelled")) {
        publish();
        diag::log_tagged_fmt("file_browser", "hex_fallback_cancel_ui_post_failed serial=%llu",
            static_cast<unsigned long long>(serial));
    }
}

bool claim_hex_preview_terminal(const std::shared_ptr<hex_preview_operation_t>& operation)
{
    return operation && !operation->terminal.exchange(true, std::memory_order_acq_rel);
}

void finish_hex_preview_failure(const std::shared_ptr<hex_preview_operation_t>& operation,
    std::uint64_t serial, const std::string& path, std::string error)
{
    if (!claim_hex_preview_terminal(operation))
        return;
    complete_hex_preview_failure(serial, path, std::move(error));
    operation->completion.notify_all();
}

void cancel_hex_preview_operation(const std::shared_ptr<hex_preview_operation_t>& operation,
    std::uint64_t serial, const std::string& path)
{
    if (!claim_hex_preview_terminal(operation))
        return;
    operation->cancellation.store(true, std::memory_order_release);
    std::optional<aida::analysis::workspace_admission_handle_t> admission;
    std::shared_ptr<aida::analysis::cancellation_source_t> provider_cancellation;
    {
        std::lock_guard<std::mutex> lock(operation->mutex);
        admission = operation->admission;
        provider_cancellation = operation->provider_cancellation;
    }
    if (provider_cancellation)
        provider_cancellation->request_cancel();
    if (admission)
        aida::analysis::workspace_registry_t::cancel_admission(*admission);
    complete_hex_preview_cancelled(serial, path);
    operation->completion.notify_all();
}

void timeout_hex_preview_operation(const std::shared_ptr<hex_preview_operation_t>& operation,
    std::uint64_t serial, const std::string& path)
{
    if (!claim_hex_preview_terminal(operation))
        return;
    std::optional<aida::analysis::workspace_admission_handle_t> admission;
    std::shared_ptr<aida::analysis::cancellation_source_t> provider_cancellation;
    {
        std::lock_guard<std::mutex> lock(operation->mutex);
        admission = operation->admission;
        provider_cancellation = operation->provider_cancellation;
    }
    if (provider_cancellation)
        provider_cancellation->request_cancel();
    if (admission)
        aida::analysis::workspace_registry_t::cancel_admission(*admission);
    complete_hex_preview_failure(serial, path,
        "TIMEOUT: provider admission did not complete within 60 seconds");
    operation->completion.notify_all();
}

bool has_suffix(const std::string& value, const char* suffix)
{
    const std::size_t suffix_size = std::strlen(suffix);
    return value.size() >= suffix_size && value.compare(value.size() - suffix_size,
        suffix_size, suffix) == 0;
}

int archive_member_priority(const aida::analysis::zip_member_t& member)
{
    if (member.kind != aida::analysis::zip_member_kind_t::regular_file ||
        member.uncompressed_size == 0)
        return (std::numeric_limits<int>::max)();
    std::string path = member.normalized_path;
    std::transform(path.begin(), path.end(), path.begin(), [](unsigned char value) {
        return static_cast<char>(std::tolower(value));
    });
    if (path == "classes.dex" || has_suffix(path, "/classes.dex"))
        return 0;
    if (has_suffix(path, ".dex") || has_suffix(path, ".odex") || has_suffix(path, ".vdex"))
        return 1;
    if (has_suffix(path, ".so") || has_suffix(path, ".elf") || has_suffix(path, ".exe") ||
        has_suffix(path, ".dll") || has_suffix(path, ".sys") || has_suffix(path, ".dylib"))
        return 2;
    if (has_suffix(path, ".o") || has_suffix(path, ".obj") || has_suffix(path, ".a") ||
        has_suffix(path, ".lib") || has_suffix(path, ".class"))
        return 3;
    const auto slash = path.find_last_of('/');
    const auto dot = path.find_last_of('.');
    if (path.find(".app/") != std::string::npos &&
        (dot == std::string::npos || (slash != std::string::npos && dot < slash)))
        return 4;
    return (std::numeric_limits<int>::max)();
}

bool open_archive_member_provider(const std::shared_ptr<const aida::analysis::byte_provider_t>& root,
                                  std::shared_ptr<const aida::analysis::byte_provider_t>& member_provider,
                                  const aida::analysis::cancellation_token_t& cancel,
                                  std::string& error)
{
    auto archive = aida::analysis::zip_container_t::open(root, {}, cancel);
    if (!archive) {
        error = archive.error().stable_code() + ": " + archive.error().message;
        return false;
    }
    auto integrity = archive.value()->verify_integrity(cancel);
    if (!integrity) {
        error = integrity.error().stable_code() + ": " + integrity.error().message;
        return false;
    }
    const auto& members = archive.value()->members();
    std::size_t selected = members.size();
    int priority = (std::numeric_limits<int>::max)();
    for (std::size_t index = 0; index < members.size(); ++index) {
        const int candidate = archive_member_priority(members[index]);
        if (candidate < priority || (candidate == priority && selected < members.size() &&
            members[index].normalized_path < members[selected].normalized_path)) {
            priority = candidate;
            selected = index;
        }
    }
    if (selected == members.size() || priority == (std::numeric_limits<int>::max)()) {
        error = "UNSUPPORTED_FORMAT: archive has no supported static member for the hex workspace";
        return false;
    }
    auto opened = archive.value()->open_member_provider(selected, cancel);
    if (!opened) {
        error = opened.error().stable_code() + ": " + opened.error().message;
        return false;
    }
    member_provider = std::static_pointer_cast<const aida::analysis::byte_provider_t>(opened.take_value());
    return true;
}

void complete_hex_preview_success(
    const std::shared_ptr<hex_preview_operation_t>& operation,
    std::uint64_t serial, std::string path,
    aida::analysis::workspace_result_t<std::shared_ptr<aida::analysis::analysis_workspace_t>> result)
{
    if (!claim_hex_preview_terminal(operation))
        return;
    const std::string fallback_path = path;
    if (!aida::ui_thread::post([serial, path = std::move(path), result = std::move(result)]() mutable {
        auto& preview = hex_preview_state();
        {
            std::lock_guard<std::mutex> lock(preview.mutex);
            if (preview.serial != serial)
                return;
        }
        if (!result) {
            std::lock_guard<std::mutex> lock(preview.mutex);
            if (preview.serial != serial)
                return;
            preview.loading = false;
            preview.cancellation_requested = false;
            preview.cancelled = false;
            preview.error = result.error().stable_code() + ": " + result.error().message;
            preview.task = {};
            preview.admission.reset();
            preview.operation.reset();
            return;
        }
        auto workspace = result.take_value();
        const auto selected = aida::analysis::workspace_registry().select_for_ui(
            workspace->identity().binary_id());
        const auto context = disasm_view::capture_workspace(workspace);
        std::lock_guard<std::mutex> lock(preview.mutex);
        if (preview.serial != serial)
            return;
        preview.loading = false;
        preview.cancellation_requested = false;
        preview.cancelled = false;
        preview.task = {};
        preview.admission.reset();
        preview.operation.reset();
        if (!selected || !context) {
            preview.error = !selected ? selected.error().stable_code() + ": " + selected.error().message :
                "TARGET_NOT_FOUND: admitted workspace context is unavailable";
            return;
        }
        hex_view::activate(context);
        aida::ui::application_views::open_or_focus(
            aida::ui::stable_view_id_t("document.hex"));
        record_recent_workspace(path);
        preview.error.clear();
        diag::log_tagged_fmt("file_browser", "hex_fallback_complete path=%s target=%s",
            path.c_str(), workspace->identity().binary_id().to_hex().c_str());
    }, "file_browser", "hex_fallback", "complete")) {
        complete_hex_preview_failure(serial, fallback_path,
            "SERVICE_CONFLICT: admitted workspace completion could not reach the UI owner");
        diag::log_tagged_fmt("file_browser", "hex_fallback_ui_post_failed serial=%llu",
            static_cast<unsigned long long>(serial));
    }
    operation->completion.notify_all();
}

void async_hex_fallback(const std::string& path, bool archive)
{
    std::optional<aida::analysis::workspace_admission_handle_t> previous;
    aida::infra::taskflow_runtime::job_handle_t previous_task;
    std::shared_ptr<hex_preview_operation_t> previous_operation;
    const auto operation = std::make_shared<hex_preview_operation_t>();
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(60);
    operation->provider_cancellation =
        std::make_shared<aida::analysis::cancellation_source_t>(deadline);
    std::uint64_t serial = 0;
    {
        auto& preview = hex_preview_state();
        std::lock_guard<std::mutex> lock(preview.mutex);
        previous = std::move(preview.admission);
        previous_task = preview.task;
        previous_operation = std::move(preview.operation);
        serial = ++preview.serial;
        preview.loading = true;
        preview.cancellation_requested = false;
        preview.cancelled = false;
        preview.archive = archive;
        preview.path = path;
        preview.error.clear();
        preview.task = {};
        preview.operation = operation;
    }
    if (previous_task.valid())
        static_cast<void>(aida::infra::taskflow_runtime::cancel(previous_task));
    if (previous)
        aida::analysis::workspace_registry_t::cancel_admission(*previous);
    if (previous_operation)
        cancel_hex_preview_operation(previous_operation, serial - 1, path);
    aida::infra::taskflow_runtime::task_descriptor_t task;
    task.domain = aida::infra::taskflow_runtime::executor_domain_t::feature_worker;
    task.owner_subsystem = "file_browser";
    task.label = "file_browser.hex_provider_admission";
    task.thread_class = "bounded_provider_open";
    task.ui_access_policy = "none";
    task.failure_policy = "structured_completion";
    task.shutdown_policy = "cancel_and_drain";
    task.deadline_ms = 65000;
    task.cancel_hook = [operation, serial, path] {
        cancel_hex_preview_operation(operation, serial, path);
    };
    task.cancellable_body = [path, archive, serial, operation, deadline](
        const aida::infra::taskflow_runtime::cancellation_token_t& cancel) {
        if (cancel.requested.load(std::memory_order_acquire) || !hex_preview_is_current(serial)) {
            cancel_hex_preview_operation(operation, serial, path);
            return;
        }
        auto mapped = aida::analysis::mapped_file_provider_t::open(path);
        if (!mapped) {
            finish_hex_preview_failure(operation, serial, path,
                mapped.error().stable_code() + ": " + mapped.error().message);
            return;
        }
        std::shared_ptr<const aida::analysis::byte_provider_t> provider =
            std::static_pointer_cast<const aida::analysis::byte_provider_t>(mapped.take_value());
        if (archive) {
            std::string member_error;
            std::shared_ptr<const aida::analysis::byte_provider_t> member;
            if (!open_archive_member_provider(provider, member,
                    operation->provider_cancellation->token(), member_error)) {
                finish_hex_preview_failure(operation, serial, path, std::move(member_error));
                return;
            }
            provider = std::move(member);
        }
        if (cancel.requested.load(std::memory_order_acquire) || !hex_preview_is_current(serial)) {
            cancel_hex_preview_operation(operation, serial, path);
            return;
        }
        aida::analysis::baseline_analysis_settings_t settings;
        const std::string profile = "aida-pe-workspace-engine-1|" + settings.canonical_json();
        aida::analysis::open_provider_workspace_request_t request;
        request.provider = provider;
        request.bin_name = fs::path(path).filename().string();
        if (const auto& member = provider->member_metadata())
            request.member_metadata = *member;
        request.load_profile.assign(profile.begin(), profile.end());
        request.analysis_settings = settings;
        auto admitted = aida::analysis::workspace_registry().admit_verified_provider_async(
            std::move(request), [operation, serial, path](auto result) mutable {
                complete_hex_preview_success(operation, serial, path, std::move(result));
            }, deadline);
        if (!admitted) {
            finish_hex_preview_failure(operation, serial, path,
                admitted.error().stable_code() + ": " + admitted.error().message);
            return;
        }
        auto handle = admitted.take_value();
        {
            std::lock_guard<std::mutex> lock(operation->mutex);
            operation->admission = handle;
        }
        {
            auto& preview = hex_preview_state();
            std::lock_guard<std::mutex> lock(preview.mutex);
            if (preview.serial == serial && !operation->terminal.load(std::memory_order_acquire))
                preview.admission = handle;
        }
        if (operation->terminal.load(std::memory_order_acquire)) {
            if (operation->cancellation.load(std::memory_order_acquire))
                aida::analysis::workspace_registry_t::cancel_admission(handle);
            return;
        }
        std::unique_lock<std::mutex> lock(operation->mutex);
        while (!operation->terminal.load(std::memory_order_acquire)) {
            if (cancel.requested.load(std::memory_order_acquire) ||
                !hex_preview_is_current(serial)) {
                lock.unlock();
                cancel_hex_preview_operation(operation, serial, path);
                return;
            }
            if (std::chrono::steady_clock::now() >= deadline) {
                lock.unlock();
                timeout_hex_preview_operation(operation, serial, path);
                return;
            }
            operation->completion.wait_for(lock, std::chrono::milliseconds(50));
        }
    };
    const auto submitted = aida::infra::taskflow_runtime::submit(std::move(task));
    if (!submitted.submitted) {
        auto& preview = hex_preview_state();
        std::lock_guard<std::mutex> lock(preview.mutex);
        if (preview.serial == serial) {
            preview.loading = false;
            preview.cancellation_requested = false;
            preview.cancelled = false;
            preview.error = "SERVICE_CONFLICT: provider admission task was rejected: " +
                submitted.reject_reason;
            preview.operation.reset();
        }
        operation->terminal.store(true, std::memory_order_release);
        operation->completion.notify_all();
    } else {
        auto& preview = hex_preview_state();
        std::lock_guard<std::mutex> lock(preview.mutex);
        if (preview.serial == serial && preview.loading)
            preview.task = submitted.handle;
        else
            static_cast<void>(aida::infra::taskflow_runtime::cancel(submitted.handle));
    }
}

}

#endif

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
namespace {

struct hex_preview_state_t {
    std::mutex mutex;
    std::uint64_t serial = 0;
    bool loading = false;
    bool cancellation_requested = false;
    bool cancelled = false;
    bool archive = false;
    std::string path;
    std::string error;
};

hex_preview_state_t& hex_preview_state()
{
    static hex_preview_state_t value;
    return value;
}

}
#endif

void open_path(const std::string& path)
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    if (path.empty()) return;
    const auto entry = std::find_if(entries.begin(), entries.end(), [&](const FileBrowserEntry& value) {
        return value.full_path == path;
    });
    if (entry != entries.end() && entry->is_dir) {
        current_dir = path;
        strncpy_s(path_buf, sizeof(path_buf), current_dir.c_str(), _TRUNCATE);
        aida::ui::application_views::open_or_focus(
            aida::ui::stable_view_id_t("view.project_explorer"));
        needs_refresh = false;
        aida::preview::record(aida::preview::shell_action_t::open_folder, path);
        return;
    }

    const std::size_t slash = path.find_last_of("/\\");
    const std::string filename = slash == std::string::npos ? path : path.substr(slash + 1);
    const std::size_t dot = filename.find_last_of('.');
    std::string extension = dot == std::string::npos ? std::string{} : filename.substr(dot);
    std::transform(extension.begin(), extension.end(), extension.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });

    if (image_view::is_image_extension(extension)) {
        aida::ui::application_views::open_or_focus(
            aida::ui::stable_view_id_t("document.image"));
    } else if (extension == ".cpp" || extension == ".c" || extension == ".h"
        || extension == ".hpp" || extension == ".asm" || extension == ".md"
        || extension == ".txt" || extension == ".json") {
        const std::string content = extension == ".md"
            ? "# Reverse Engineering Notes\n\n- Entrypoint mapped\n- Import resolver identified\n"
            : "int analyze_target(const char* path) {\n    return path != nullptr ? 0 : -1;\n}\n";
        file_tabs::open_or_focus(path, filename, content);
        aida::ui::application_views::open_or_focus(
            aida::ui::stable_view_id_t("document.code"));
    } else {
        std::size_t existing_index = static_cast<std::size_t>(-1);
        if (analysis_session::find_session_by_path(path, &existing_index))
            analysis_session::switch_session(existing_index);
        aida::ui::application_views::open_or_focus(
            aida::ui::stable_view_id_t("document.disassembly"));
    }
    record_recent_workspace(path);
    aida::preview::record(aida::preview::shell_action_t::open_file, path);
    return;
#else
    if (path.empty()) return;
    if (!aida::ui_thread::is_owner_thread()) {
        const bool routed = aida::ui_thread::post([path]() {
            file_browser::open_path(path);
        }, "file_browser", "open_path", "entry");
        if (!routed)
            diag::log_tagged_fmt("file_browser", "open_path denied path=%s reason=ui_affinity_route_failed", path.c_str());
        return;
    }
    if (!aida::ui_thread::require_owner("file_browser", "open_path", "entry"))
        return;

    std::string admission_error;
    std::error_code admission_ec;
    const bool is_directory = fs::is_directory(path, admission_ec) && !admission_ec;
    if (!admitted_file_open_path(path, is_directory, &admission_error)) {
        diag::log_tagged_fmt("file_open", "open_path rejected path=%s reason=%s", path.c_str(), admission_error.c_str());
        return;
    }

    std::error_code ec;
    if (fs::is_directory(path, ec) && !ec) {
        diag::log_tagged_fmt("file_browser", "open_path directory=%s", path.c_str());
        refresh(path);
        aida::ui::application_views::open_or_focus(
            aida::ui::stable_view_id_t("view.project_explorer"));
        return;
    }

    std::string fname;
    {
        size_t sl = path.find_last_of("/\\");
        fname = (sl != std::string::npos) ? path.substr(sl + 1) : path;
    }
    std::string ext = ext_classify::lower_ext(fname);

    diag::log_tagged_fmt("file_browser",
        "open_path begin path=%s ext=%s", path.c_str(), ext.c_str());

    if (image_view::is_image_extension(ext)) {
        image_view::load_from_file(path);
        aida::ui::application_views::open_or_focus(
            aida::ui::stable_view_id_t("document.image"));
        diag::log_tagged_fmt("file_browser", "open_path -> image_view path=%s", path.c_str());
        return;
    }

    if (ext_classify::is_text(ext)) {
        if (file_tabs::request_document_open(path, fname)) {
            aida::ui::application_views::open_or_focus(
                aida::ui::stable_view_id_t("document.code"));
            diag::log_tagged_fmt("file_browser", "open_path -> code_editor path=%s", path.c_str());
            return;
        }
        diag::log_tagged_fmt("file_browser",
            "open_path text open_failed path=%s", path.c_str());
    }

	if (ext_classify::is_archive(ext)) {
		async_hex_fallback(path, true);
        diag::log_tagged_fmt("file_browser", "open_path -> hex_view archive path=%s", path.c_str());
        return;
    }

    uint64_t file_size_bytes = 0;
    {
        std::error_code fec;
        auto sz = fs::file_size(path, fec);
        if (!fec) file_size_bytes = static_cast<uint64_t>(sz);
    }
    diag::log_tagged_fmt("file_browser",
        "open_path binary_branch path=%s ext=%s size=%llu",
        path.c_str(),
        ext.c_str(),
        static_cast<unsigned long long>(file_size_bytes));

    size_t existing_idx = static_cast<size_t>(-1);
    bool found = analysis_session::find_session_by_path(path, &existing_idx);
    if (found) {
        if (analysis_session::switch_session(existing_idx)) {
            aida::ui::application_views::open_or_focus(
                aida::ui::stable_view_id_t("document.disassembly"));
            record_recent_workspace(path);
            diag::log_tagged_fmt("file_browser",
                "open_path -> existing_session idx=%llu",
                static_cast<unsigned long long>(existing_idx));
            return;
        }
        diag::log_tagged_fmt("file_browser",
            "open_path switch_existing_failed idx=%llu err=%s",
            static_cast<unsigned long long>(existing_idx),
            analysis_session::last_error() ? analysis_session::last_error() : "(null)");
    }

    if (analysis_session::session_count() >= analysis_session::kMaxSessions)
        analysis_session::prune_lru(analysis_session::kMaxSessions - 1);

    bool started = analysis_session::open_session(path);
    if (started) {
        aida::ui::application_views::open_or_focus(
            aida::ui::stable_view_id_t("document.disassembly"));
        record_recent_workspace(path);
        diag::log_tagged_fmt("file_browser",
            "open_path -> new_session path=%s ext=%s", path.c_str(), ext.c_str());
        return;
    }

    const char* err = analysis_session::last_error();
    bool err_says_not_pe = err && (
        std::strstr(err, "not a PE") != nullptr ||
        std::strstr(err, "not_pe")   != nullptr ||
        std::strstr(err, "PE header") != nullptr ||
        std::strstr(err, "magic") != nullptr);

	if (ext_classify::is_binary(ext) || err_says_not_pe) {
		async_hex_fallback(path, false);
        diag::log_tagged_fmt("file_browser",
            "open_path -> hex_view fallback path=%s err=%s",
            path.c_str(), err ? err : "(null)");
        return;
    }

    diag::log_tagged_fmt("file_browser",
        "open_path failed path=%s err=%s", path.c_str(),
        err ? err : "(null)");
#endif
}

}

void file_browser::open_file(int idx)
{
    if (idx < 0 || static_cast<std::size_t>(idx) >= entries.size()) return;
    auto& ent = entries[static_cast<std::size_t>(idx)];
    if (ent.is_dir) return;
    file_browser::request_open_confirmation(ent.full_path);
}

namespace file_browser {

namespace {

inline std::string truncate_middle(const std::string& s, size_t max_len) {
    if (s.size() <= max_len) return s;
    if (max_len <= 5) return s.substr(0, max_len);
    size_t keep_head = (max_len - 3) / 2;
    size_t keep_tail = max_len - 3 - keep_head;
    std::string out;
    out.reserve(max_len);
    out.append(s, 0, keep_head);
    out.append("...");
    out.append(s, s.size() - keep_tail, keep_tail);
    return out;
}

}

void render_hex_loading_indicator()
{
    bool loading = false;
    bool cancellation_requested = false;
    bool cancelled = false;
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
    bool archive = false;
#endif
    std::string preview_path;
    std::string preview_error;
    {
        auto& preview = hex_preview_state();
        std::lock_guard<std::mutex> lock(preview.mutex);
        loading = preview.loading;
        cancellation_requested = preview.cancellation_requested;
        cancelled = preview.cancelled;
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
        archive = preview.archive;
#endif
        preview_path = preview.path;
        preview_error = preview.error;
    }
    if (!loading && !cancelled && preview_error.empty()) return;

    const char* popup = "Open as Hex###aida_hex_fallback_operation";
    ImGui::OpenPopup(popup);
    if (!aida::ui::design::begin_dialog_exact(popup, ImVec2(500.f, 300.f),
            ImVec2(340.f, 230.f)))
        return;

    const bool terminal = !loading;
    const char* primary_label = terminal ? "Retry" : "Cancel Operation";
    const char* secondary_label = terminal ? "Dismiss" : nullptr;
    const float footer_height = aida::ui::design::dialog_footer_reserve_height(
        primary_label, secondary_label);
    aida::ui::design::begin_dialog_body("file.hex_fallback.body", footer_height);

    aida::ui::design::state_presentation_t state;
    state.stable_id = loading ? "file.hex_fallback.loading" :
        (cancelled ? "file.hex_fallback.cancelled" : "file.hex_fallback.error");
    state.state = loading ? aida::ui::design::view_state_t::loading :
        (cancelled ? aida::ui::design::view_state_t::empty :
            aida::ui::design::view_state_t::error);
    state.title = loading ? (cancellation_requested ? "Cancelling file open" :
        "Opening file as Hex") : (cancelled ? "File open cancelled" :
            "Hex fallback unavailable");
    state.message = loading ?
        (cancellation_requested ?
            "Cancellation was requested. The current provider admission is being stopped." :
            "AiDA is validating and admitting a bounded read-only provider for this file.") :
        (cancelled ? "No workspace state was changed." : preview_error.c_str());
    state.target = preview_path.empty() ? "Selected file" : preview_path.c_str();
    state.hint = terminal ?
        "Retry the exact file or dismiss this result and continue using the IDE." :
        "The operation is owned by Task Center and can be cancelled safely.";
    static_cast<void>(aida::ui::design::render_state(state, ImVec2(0.f, 0.f)));
    if (!preview_path.empty()) {
        const auto slash = preview_path.find_last_of("\\/");
        const std::string filename = slash != std::string::npos
            ? preview_path.substr(slash + 1) : preview_path;
        ImGui::TextDisabled("%s", filename.c_str());
    }
    aida::ui::design::end_dialog_body();

    const auto footer = aida::ui::design::dialog_footer(
        "file.hex_fallback.actions", primary_label,
        terminal || !cancellation_requested, false, secondary_label,
        terminal || !cancellation_requested, terminal);
    const bool cancel_requested = loading && (footer.confirmed || footer.cancelled);
    const bool retry_requested = terminal && footer.confirmed;
    const bool dismiss_requested = terminal && footer.cancelled;
    ImGui::EndPopup();

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    if (cancel_requested) {
        auto& preview = hex_preview_state();
        std::lock_guard<std::mutex> lock(preview.mutex);
        preview.loading = false;
        preview.cancellation_requested = false;
        preview.cancelled = true;
        preview.error.clear();
    } else if (retry_requested) {
        open_path(preview_path);
    } else if (dismiss_requested) {
        auto& preview = hex_preview_state();
        std::lock_guard<std::mutex> lock(preview.mutex);
        ++preview.serial;
        preview.loading = false;
        preview.cancellation_requested = false;
        preview.cancelled = false;
        preview.path.clear();
        preview.error.clear();
    }
#else
    if (cancel_requested) {
        aida::infra::taskflow_runtime::job_handle_t task;
        std::shared_ptr<hex_preview_operation_t> operation;
        std::optional<aida::analysis::workspace_admission_handle_t> admission;
        std::uint64_t serial = 0;
        {
            auto& preview = hex_preview_state();
            std::lock_guard<std::mutex> lock(preview.mutex);
            if (preview.loading && !preview.cancellation_requested) {
                preview.cancellation_requested = true;
                serial = preview.serial;
                task = preview.task;
                operation = preview.operation;
                admission = preview.admission;
            }
        }
        if (task.valid())
            static_cast<void>(aida::infra::taskflow_runtime::cancel(task));
        if (admission)
            aida::analysis::workspace_registry_t::cancel_admission(*admission);
        if (operation)
            cancel_hex_preview_operation(operation, serial, preview_path);
    } else if (retry_requested) {
        async_hex_fallback(preview_path, archive);
    } else if (dismiss_requested) {
        aida::infra::taskflow_runtime::job_handle_t task;
        std::optional<aida::analysis::workspace_admission_handle_t> admission;
        {
            auto& preview = hex_preview_state();
            std::lock_guard<std::mutex> lock(preview.mutex);
            ++preview.serial;
            task = preview.task;
            admission = preview.admission;
            preview.loading = false;
            preview.cancellation_requested = false;
            preview.cancelled = false;
            preview.archive = false;
            preview.path.clear();
            preview.error.clear();
            preview.task = {};
            preview.admission.reset();
            preview.operation.reset();
        }
        if (task.valid())
            static_cast<void>(aida::infra::taskflow_runtime::cancel(task));
        if (admission)
            aida::analysis::workspace_registry_t::cancel_admission(*admission);
    }
#endif
}

void request_open_confirmation(const std::string& path)
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    if (path.empty()) return;
    const auto entry = std::find_if(entries.begin(), entries.end(), [&](const FileBrowserEntry& value) {
        return value.full_path == path;
    });
    if (entry != entries.end() && entry->is_dir) {
        open_path(path);
        return;
    }
    pending_open_path = path;
    const std::size_t slash = path.find_last_of("/\\");
    pending_open_filename = slash == std::string::npos ? path : path.substr(slash + 1);
    pending_open_should_open = true;
    pending_open_modal_visible = true;
    aida::preview::record(aida::preview::shell_action_t::open_file, "confirm:" + path);
    return;
#else
    if (path.empty()) return;
    if (!aida::ui_thread::is_owner_thread()) {
        const bool routed = aida::ui_thread::post([path]() {
            file_browser::request_open_confirmation(path);
        }, "file_browser", "request_open_confirmation", "entry");
        if (!routed)
            diag::log_tagged_fmt("file_open", "explorer_confirm_denied path=%s reason=ui_affinity_route_failed", path.c_str());
        return;
    }
    if (!aida::ui_thread::require_owner("file_browser", "request_open_confirmation", "entry"))
        return;

    std::string admission_error;
    std::error_code admission_ec;
    const bool is_directory = fs::is_directory(path, admission_ec) && !admission_ec;
    if (!admitted_file_open_path(path, is_directory, &admission_error)) {
        diag::log_tagged_fmt("file_open", "explorer_confirm_rejected path=%s reason=%s", path.c_str(), admission_error.c_str());
        return;
    }

    std::error_code ec;
    if (fs::is_directory(path, ec) && !ec) {
        open_path(path);
        return;
    }

    pending_open_path = path;
    size_t sl = path.find_last_of("/\\");
    pending_open_filename = (sl != std::string::npos) ? path.substr(sl + 1) : path;
    pending_open_should_open = true;
    pending_open_modal_visible = true;
    diag::log_tagged_fmt("file_open", "explorer_confirm_requested path=%s", path.c_str());
#endif
}

void record_recent_workspace(const std::string& path)
{
    if (path.empty()) return;

    std::vector<std::string> list;
    if (!g_sa_settings.recent_workspaces_json.empty()) {
        auto j = nlohmann::json::parse(g_sa_settings.recent_workspaces_json,
                                       nullptr, false);
        if (!j.is_discarded() && j.is_array()) {
            for (auto& el : j) {
                if (el.is_string()) {
                    list.push_back(el.get<std::string>());
                }
            }
        }
    }

    auto same_path = [&](const std::string& a, const std::string& b) -> bool {
        if (a.size() != b.size()) return false;
        for (size_t i = 0; i < a.size(); ++i) {
            char ca = a[i];
            char cb = b[i];
            if (ca == '/') ca = '\\';
            if (cb == '/') cb = '\\';
            if (ca >= 'A' && ca <= 'Z') ca = static_cast<char>(ca - 'A' + 'a');
            if (cb >= 'A' && cb <= 'Z') cb = static_cast<char>(cb - 'A' + 'a');
            if (ca != cb) return false;
        }
        return true;
    };

    list.erase(std::remove_if(list.begin(), list.end(),
                              [&](const std::string& s) { return same_path(s, path); }),
               list.end());
    list.insert(list.begin(), path);
    if (list.size() > 20) list.resize(20);

    nlohmann::json out = nlohmann::json::array();
    for (auto& s : list) out.push_back(s);
    g_sa_settings.recent_workspaces_json = out.dump();
}

void render_pending_confirm_modal()
{
    render_hex_loading_indicator();

    if (file_browser::pending_open_should_open) {
        ImGui::OpenPopup("##aida_open_binary_confirm");
        file_browser::pending_open_should_open = false;
        file_browser::pending_open_modal_visible = true;
    }

    if (!file_browser::pending_open_modal_visible) return;

    const auto& tk = aida::ui::resolved();

    ImGui::SetNextWindowBgAlpha(1.0f);

    bool open_flag_local = true;
    bool open_now    = false;
    bool switch_now  = false;
    bool cancel_now  = false;
    size_t existing_idx = static_cast<size_t>(-1);
    bool already_open = analysis_session::find_session_by_path(
        file_browser::pending_open_path, &existing_idx);

    if (aida::ui::design::begin_dialog_exact(
            "Load file?###aida_open_binary_confirm", ImVec2(460.f, 300.f),
            ImVec2(360.f, 240.f), &open_flag_local)) {
        const char* confirm_label = already_open ? "Switch" : "Load";
        const float footer_height = aida::ui::design::dialog_footer_reserve_height(
            confirm_label);
        aida::ui::design::begin_dialog_body(
            "aida_open_binary_confirm_body", footer_height);

        std::string fname = file_browser::pending_open_filename;
        if (fname.empty()) {
            size_t sl = file_browser::pending_open_path.find_last_of("/\\");
            fname = (sl != std::string::npos)
                ? file_browser::pending_open_path.substr(sl + 1)
                : file_browser::pending_open_path;
        }

        ImFont* base_font = ImGui::GetFont();
        if (base_font) {
            ImGui::PushFont(base_font);
            ImGui::SetWindowFontScale(1.18f);
            ImGui::TextUnformatted(fname.c_str());
            ImGui::SetWindowFontScale(1.0f);
            ImGui::PopFont();
        } else {
            ImGui::TextUnformatted(fname.c_str());
        }

        std::string path_display = file_browser::pending_open_path;
        std::string path_clip = truncate_middle(path_display, 70);
        ImGui::TextWrapped("%s", path_clip.c_str());

        ImGui::Spacing();
        ImGui::TextWrapped("do you want to load this file?");
        ImGui::Spacing();

        if (already_open) {
            ImGui::TextWrapped("Already open in a tab -- click 'Switch' to focus it.");
        } else if (analysis_session::session_count() >= analysis_session::kMaxSessions) {
            ImGui::TextWrapped("Already at %zu open binaries. The oldest will be closed to make room.",
                               analysis_session::kMaxSessions);
        }

        aida::ui::design::end_dialog_body();
        const auto footer = aida::ui::design::dialog_footer(
            "aida_open_binary_confirm_footer", confirm_label, true, false);
        cancel_now = footer.cancelled || !open_flag_local;
        if (footer.confirmed) {
            if (already_open) switch_now = true;
            else open_now = true;
        }

        if (open_now && !already_open) {
            std::string path_copy = file_browser::pending_open_path;
            diag::log_tagged_fmt("file_open", "explorer_confirm_load path=%s",
                path_copy.c_str());
            file_browser::open_path(path_copy);
            ImGui::CloseCurrentPopup();
            file_browser::pending_open_modal_visible = false;
            file_browser::pending_open_path.clear();
            file_browser::pending_open_filename.clear();
        } else if (switch_now && already_open) {
            if (analysis_session::switch_session(existing_idx)) {
                aida::ui::application_views::open_or_focus(
                    aida::ui::stable_view_id_t("document.disassembly"));
                diag::log_tagged_fmt("file_open", "explorer_click_switch idx=%llu",
                    static_cast<unsigned long long>(existing_idx));
            }
            ImGui::CloseCurrentPopup();
            file_browser::pending_open_modal_visible = false;
            file_browser::pending_open_path.clear();
            file_browser::pending_open_filename.clear();
        } else if (cancel_now) {
            ImGui::CloseCurrentPopup();
            file_browser::pending_open_modal_visible = false;
            file_browser::pending_open_path.clear();
            file_browser::pending_open_filename.clear();
        }

        ImGui::EndPopup();
    } else {
        file_browser::pending_open_modal_visible = false;
    }
}

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)

namespace watcher_detail {

struct watcher_t {
    std::atomic<bool>       running{false};
    std::atomic<bool>       stop{false};
    std::atomic<bool>       has_change{false};
    std::atomic<bool>       worker_done{true};
    std::atomic<uint64_t>   retry_after_ms{0};
    std::string             watched_dir;
    HANDLE                  wake_event = nullptr;
    std::mutex              mtx;
};

struct watcher_manager_t {
    std::unordered_map<std::string, std::shared_ptr<watcher_t>> active;
    std::vector<std::shared_ptr<watcher_t>> retiring;
};

inline watcher_manager_t& g_watchers()
{
    static watcher_manager_t value;
    return value;
}

inline uint64_t now_ms()
{
    return ::GetTickCount64();
}

inline bool utf8_to_wide(const std::string& in, std::wstring& out)
{
    out.clear();
    int n = ::MultiByteToWideChar(CP_UTF8, 0, in.c_str(), -1, nullptr, 0);
    if (n <= 0) return false;
    out.resize(static_cast<size_t>(n));
    if (::MultiByteToWideChar(CP_UTF8, 0, in.c_str(), -1, out.data(), n) <= 0) {
        out.clear();
        return false;
    }
    if (!out.empty() && out.back() == L'\0') out.pop_back();
    return true;
}

inline void close_completed_wake_event_locked(watcher_t& w)
{
    if (w.wake_event && w.worker_done.load(std::memory_order_acquire)) {
        ::CloseHandle(w.wake_event);
        w.wake_event = nullptr;
    }
}

inline void request_stop(watcher_t& w)
{
    if (!w.running.load(std::memory_order_acquire)) return;
    w.stop.store(true, std::memory_order_release);
    if (w.wake_event) ::SetEvent(w.wake_event);
}

inline bool is_noise_basename(const std::wstring& bn)
{
    if (bn.empty()) return true;
    if (bn.size() >= 14) {
        const wchar_t* tail = bn.c_str() + bn.size() - 14;
        if (_wcsicmp(tail, L"aida_debug.log") == 0) return true;
    }
    if (bn.size() >= 4) {
        const wchar_t* ext = bn.c_str() + bn.size() - 4;
        if (_wcsicmp(ext, L".log") == 0) return true;
        if (_wcsicmp(ext, L".tmp") == 0) return true;
    }
    if (bn.size() >= 1 && bn[0] == L'.') return true;
    return false;
}

inline void watcher_thread(std::shared_ptr<watcher_t> watcher, std::string dir, HANDLE wake_event)
{
    watcher_t& w = *watcher;

    std::wstring wdir;
    if (!utf8_to_wide(dir, wdir) || wdir.empty()) {
        diag::log_tagged("file_browser_watcher", "thread_exit empty_dir");
        w.retry_after_ms.store(now_ms() + 5000ull, std::memory_order_release);
        w.worker_done.store(true, std::memory_order_release);
        w.running.store(false, std::memory_order_release);
        return;
    }

    HANDLE h = ::CreateFileW(wdir.c_str(),
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
        nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD err = ::GetLastError();
        w.retry_after_ms.store(now_ms() + 5000ull, std::memory_order_release);
        diag::log_tagged_fmt("file_browser_watcher",
            "thread_exit CreateFileW failed err=%lu dir=%s",
            static_cast<unsigned long>(err), dir.c_str());
        w.worker_done.store(true, std::memory_order_release);
        w.running.store(false, std::memory_order_release);
        return;
    }

    diag::log_tagged_fmt("file_browser_watcher",
        "thread_started dir=%s", dir.c_str());

    constexpr DWORD kBufSize = 32768;
    std::vector<uint8_t> buf(kBufSize);

    uint64_t last_signal_ms = 0;

    while (!w.stop.load(std::memory_order_acquire)) {
        OVERLAPPED ov{};
        ov.hEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!ov.hEvent) break;

        DWORD bytes_returned = 0;
        BOOL ok = ::ReadDirectoryChangesW(
            h,
            buf.data(),
            kBufSize,
            TRUE,
            FILE_NOTIFY_CHANGE_FILE_NAME |
            FILE_NOTIFY_CHANGE_DIR_NAME |
            FILE_NOTIFY_CHANGE_SIZE,
            &bytes_returned,
            &ov,
            nullptr);
        if (!ok) {
            DWORD err = ::GetLastError();
            w.retry_after_ms.store(now_ms() + 5000ull, std::memory_order_release);
            diag::log_tagged_fmt("file_browser_watcher",
                "ReadDirectoryChangesW failed err=%lu",
                static_cast<unsigned long>(err));
            ::CloseHandle(ov.hEvent);
            break;
        }

        HANDLE waits[2] = { ov.hEvent, wake_event };
        DWORD wait_count = wake_event ? 2u : 1u;
        DWORD waited = ::WaitForMultipleObjects(wait_count, waits, FALSE, INFINITE);

        if (waited == WAIT_OBJECT_0) {
            DWORD transferred = 0;
            if (::GetOverlappedResult(h, &ov, &transferred, FALSE) && transferred > 0) {
                bool has_meaningful = false;
                DWORD off = 0;
                const uint8_t* p = buf.data();
                while (off + sizeof(FILE_NOTIFY_INFORMATION) <= transferred) {
                    const FILE_NOTIFY_INFORMATION* fni =
                        reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(p + off);
                    USHORT name_chars = static_cast<USHORT>(fni->FileNameLength / sizeof(WCHAR));
                    std::wstring bn(fni->FileName, name_chars);
                    if (!is_noise_basename(bn)) {
                        has_meaningful = true;
                        break;
                    }
                    if (fni->NextEntryOffset == 0) break;
                    off += fni->NextEntryOffset;
                }

                if (has_meaningful) {
                    uint64_t stamp_ms = now_ms();
                    if (stamp_ms - last_signal_ms >= 500ull) {
                        last_signal_ms = stamp_ms;
                        w.has_change.store(true, std::memory_order_release);
                    }
                }
            }
        } else {
            ::CancelIoEx(h, &ov);
            DWORD tmp = 0;
            ::GetOverlappedResult(h, &ov, &tmp, TRUE);
        }
        ::CloseHandle(ov.hEvent);
    }

    ::CloseHandle(h);
    diag::log_tagged_fmt("file_browser_watcher",
        "thread_exit dir=%s", dir.c_str());
    w.worker_done.store(true, std::memory_order_release);
    w.running.store(false, std::memory_order_release);
}

inline void start_watcher(const std::shared_ptr<watcher_t>& watcher)
{
    watcher_t& w = *watcher;
    std::lock_guard<std::mutex> lk(w.mtx);
    const uint64_t stamp_ms = now_ms();
    if (w.running.load(std::memory_order_acquire)) return;
    const uint64_t retry_after_ms = w.retry_after_ms.load(std::memory_order_acquire);
    if (retry_after_ms != 0 && stamp_ms < retry_after_ms) return;
    close_completed_wake_event_locked(w);
    w.wake_event = ::CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (!w.wake_event) return;
    w.stop.store(false, std::memory_order_release);
    w.has_change.store(false, std::memory_order_release);
    HANDLE we = w.wake_event;
    const std::string cap = w.watched_dir;
    w.worker_done.store(false, std::memory_order_release);
    w.running.store(true, std::memory_order_release);
    aida::infra::executor::submission_t sub;
    sub.owner_subsystem = "file_browser_watcher";
    sub.label = "file_browser_watcher.watch";
    sub.thread_class = "long_lived_service";
    sub.domain = aida::infra::executor::domain_t::service;
    sub.priority = 3;
    sub.cancel_hook = [watcher]() {
        request_stop(*watcher);
    };
    sub.body = [watcher, cap, we]() { watcher_thread(watcher, cap, we); };
    if (aida::infra::executor::submit(std::move(sub)).submitted) {
        w.retry_after_ms.store(0, std::memory_order_release);
        diag::log_tagged_fmt("file_browser_watcher", "ensure_running_for dir=%s", cap.c_str());
    }
    else {
        if (w.wake_event) {
            ::CloseHandle(w.wake_event);
            w.wake_event = nullptr;
        }
        w.stop.store(false, std::memory_order_release);
        w.running.store(false, std::memory_order_release);
        w.worker_done.store(true, std::memory_order_release);
        w.retry_after_ms.store(stamp_ms + 5000ull, std::memory_order_release);
        diag::log_tagged_fmt("file_browser_watcher", "executor_submit_failed dir=%s",
            cap.c_str());
    }
}

inline void ensure_running_for(const std::vector<std::string>& roots)
{
    auto& manager = g_watchers();
    std::unordered_set<std::string> requested;
    for (const auto& root : roots) {
        if (requested.size() >= 8) break;
        if (!root.empty()) requested.insert(normalized_explorer_path(root));
    }

    for (auto iterator = manager.active.begin(); iterator != manager.active.end();) {
        if (requested.find(iterator->first) != requested.end()) {
            ++iterator;
            continue;
        }
        request_stop(*iterator->second);
        manager.retiring.push_back(iterator->second);
        iterator = manager.active.erase(iterator);
    }
    for (const auto& root : roots) {
        if (root.empty()) continue;
        const std::string key = normalized_explorer_path(root);
        if (requested.find(key) == requested.end()) continue;
        auto found = manager.active.find(key);
        if (found == manager.active.end()) {
            auto watcher = std::make_shared<watcher_t>();
            watcher->watched_dir = root;
            found = manager.active.emplace(key, std::move(watcher)).first;
        }
        start_watcher(found->second);
    }
    for (auto iterator = manager.retiring.begin(); iterator != manager.retiring.end();) {
        auto& watcher = **iterator;
        if (!watcher.worker_done.load(std::memory_order_acquire)) {
            ++iterator;
            continue;
        }
        std::lock_guard<std::mutex> lock(watcher.mtx);
        close_completed_wake_event_locked(watcher);
        iterator = manager.retiring.erase(iterator);
    }
}

inline bool consume_change()
{
    auto& manager = g_watchers();
    bool changed = false;
    for (const auto& item : manager.active)
        changed = item.second->has_change.exchange(false, std::memory_order_acq_rel) || changed;
    return changed;
}

}

#endif

void tick_watcher()
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    needs_refresh = false;
#else
    watcher_detail::ensure_running_for(roots.empty()
        ? std::vector<std::string>{current_dir} : roots);
    if (watcher_detail::consume_change()) {
        needs_refresh = true;
    }
#endif
}

}
