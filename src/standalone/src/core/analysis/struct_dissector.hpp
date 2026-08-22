#pragma once

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../preview/shell_preview_platform.hpp"
#include "../../preview/re_hubs_preview_adapter.hpp"
#else
#include "standalone_driver.hpp"
#include "../infra/executor.hpp"
#include "../scanner/scanner_async_io.hpp"
#include "../ui/task_center.hpp"
#include "../../helpers/diag_log.hpp"
#endif

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <exception>
#include <filesystem>
#include <limits>
#include <mutex>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>
#include <nlohmann/json.hpp>

namespace struct_dissector {

enum class field_type_t : int {
	int8 = 0,
	uint8,
	int16,
	uint16,
	int32,
	uint32,
	int64,
	uint64,
	float32,
	float64,
	pointer,
	ascii_string,
	utf16_string,
	byte_array,
	padding,
	nested_struct,
	COUNT
};

enum class structure_kind_t : std::uint8_t {
	structure = 0,
	union_type = 1
};

struct enum_value_t {
	std::string name;
	std::int64_t value = 0;
};

struct enum_def_t {
	std::uint64_t stable_id = 0;
	std::string name;
	field_type_t underlying_type = field_type_t::int32;
	std::vector<enum_value_t> values;
};

struct field_def_t {
	std::string   name;
	field_type_t  type = field_type_t::int32;
	uint32_t      offset = 0;
	uint32_t      size = 0;
	uint32_t      array_count = 1;
	int           parent_idx = -1;
	std::vector<int> children;
	bool          is_pointer = false;
	int           pointer_target_struct = -1;
	std::string   description;
	std::uint64_t stable_id = 0;
	std::uint64_t target_structure_id = 0;
	std::uint64_t enum_id = 0;
	std::string   referenced_type_name;
	std::uint16_t bit_offset = 0;
	std::uint16_t bit_width = 0;
	std::uint16_t explicit_alignment = 0;
};

struct struct_def_t {
	std::string              name;
	std::vector<field_def_t> fields;
	uint32_t                 total_size = 0;
	std::uint64_t            stable_id = 0;
	std::uint64_t            layout_revision = 1;
	structure_kind_t         kind = structure_kind_t::structure;
	std::uint16_t            packing = 0;
	std::uint16_t            explicit_alignment = 0;
};

enum class layout_issue_severity_t : std::uint8_t {
	error,
	warning
};

struct layout_issue_t {
	layout_issue_severity_t severity = layout_issue_severity_t::error;
	int field_index = -1;
	std::string code;
	std::string detail;
};

struct layout_validation_t {
	std::vector<layout_issue_t> issues;
	std::uint32_t computed_size = 0;
	std::uint32_t effective_alignment = 1;

	bool valid() const {
		return std::none_of(issues.begin(), issues.end(), [](const layout_issue_t& issue) {
			return issue.severity == layout_issue_severity_t::error;
		});
	}
};

struct live_value_t {
	std::vector<uint8_t> raw_bytes;
	std::string          display_text;
	bool                 changed = false;
};

struct state_t {
	std::vector<struct_def_t> structs;
	std::vector<enum_def_t>   enums;
	int                       active_struct = -1;
	uint64_t                  base_address = 0;
	std::vector<live_value_t> cached_values;
	std::mutex                mtx;
	bool                      auto_refresh = false;
	float                     refresh_interval = 0.5f;
	float                     refresh_timer = 0.f;
	std::atomic<bool>         refresh_in_flight{false};
	std::atomic<uint64_t>     refresh_seq{0};
	std::atomic<uint64_t>     last_completed_seq{0};
	std::uint64_t             schema_revision = 1;
	std::uint64_t             next_stable_id = 1;
	std::atomic<bool>         persistence_in_flight{false};
	std::atomic<bool>         persistence_initial_load_requested{false};
	std::shared_ptr<std::atomic<bool>> persistence_cancellation;
	std::string               persistence_status;
	bool                      persistence_error = false;
};

inline state_t g_state;

struct catalog_transaction_snapshot_t {
	std::vector<struct_def_t> structs;
	std::vector<enum_def_t> enums;
	std::vector<live_value_t> cached_values;
	int active_struct = -1;
	std::uint64_t schema_revision = 0;
	std::uint64_t next_stable_id = 0;
};

inline catalog_transaction_snapshot_t capture_catalog_transaction() {
	std::lock_guard<std::mutex> lock(g_state.mtx);
	return {g_state.structs, g_state.enums, g_state.cached_values,
		g_state.active_struct, g_state.schema_revision, g_state.next_stable_id};
}

inline bool catalog_mutation_available() {
	return !g_state.persistence_in_flight.load(std::memory_order_acquire);
}

inline bool rollback_catalog_transaction(catalog_transaction_snapshot_t snapshot,
	std::uint64_t expected_schema_revision,
	bool allow_persistence_in_flight = false) {
	std::lock_guard<std::mutex> lock(g_state.mtx);
	if ((!allow_persistence_in_flight &&
		g_state.persistence_in_flight.load(std::memory_order_acquire)) ||
		g_state.schema_revision != expected_schema_revision)
		return false;
	g_state.structs = std::move(snapshot.structs);
	g_state.enums = std::move(snapshot.enums);
	g_state.cached_values = std::move(snapshot.cached_values);
	g_state.active_struct = snapshot.active_struct;
	g_state.schema_revision = snapshot.schema_revision;
	g_state.next_stable_id = snapshot.next_stable_id;
	return true;
}

inline std::uint64_t catalog_schema_revision() {
	std::lock_guard<std::mutex> lock(g_state.mtx);
	return g_state.schema_revision;
}

inline std::size_t field_type_size(field_type_t t);

inline bool valid_index(int index, std::size_t count) {
	return index >= 0 && static_cast<std::size_t>(index) < count;
}

inline bool index_fits_int(std::size_t index) {
	return index <= static_cast<std::size_t>((std::numeric_limits<int>::max)());
}

inline bool valid_power_of_two(std::uint32_t value) {
	return value != 0 && (value & (value - 1)) == 0;
}

inline bool checked_add_u32(std::uint32_t left, std::uint32_t right,
	std::uint32_t& result) {
	if (right > (std::numeric_limits<std::uint32_t>::max)() - left)
		return false;
	result = left + right;
	return true;
}

inline bool checked_multiply_u32(std::uint32_t left, std::uint32_t right,
	std::uint32_t& result) {
	if (left != 0 && right > (std::numeric_limits<std::uint32_t>::max)() / left)
		return false;
	result = left * right;
	return true;
}

inline std::uint32_t align_up_u32(std::uint32_t value, std::uint32_t alignment) {
	if (alignment <= 1)
		return value;
	const std::uint32_t mask = alignment - 1;
	if (value > (std::numeric_limits<std::uint32_t>::max)() - mask)
		return (std::numeric_limits<std::uint32_t>::max)();
	return (value + mask) & ~mask;
}

inline std::uint64_t allocate_stable_id_locked() {
	if (g_state.next_stable_id == 0)
		g_state.next_stable_id = 1;
	return g_state.next_stable_id++;
}

inline int structure_index_by_id_locked(std::uint64_t stable_id) {
	if (stable_id == 0)
		return -1;
	for (std::size_t index = 0; index < g_state.structs.size(); ++index)
		if (g_state.structs[index].stable_id == stable_id)
			return index_fits_int(index) ? static_cast<int>(index) : -1;
	return -1;
}

inline int structure_index_by_name(const std::string& name) {
	std::lock_guard<std::mutex> lock(g_state.mtx);
	for (std::size_t index = 0; index < g_state.structs.size(); ++index)
		if (g_state.structs[index].name == name)
			return index_fits_int(index) ? static_cast<int>(index) : -1;
	return -1;
}

inline int enum_index_by_id_locked(std::uint64_t stable_id) {
	for (std::size_t index = 0; index < g_state.enums.size(); ++index)
		if (g_state.enums[index].stable_id == stable_id)
			return index_fits_int(index) ? static_cast<int>(index) : -1;
	return -1;
}

inline bool structure_reaches_locked(std::uint64_t current_id, std::uint64_t target_id,
	std::set<std::uint64_t>& visited) {
	if (current_id == target_id)
		return true;
	if (!visited.insert(current_id).second)
		return false;
	const int current = structure_index_by_id_locked(current_id);
	if (!valid_index(current, g_state.structs.size()))
		return false;
	for (const auto& field : g_state.structs[static_cast<std::size_t>(current)].fields)
		if (field.type == field_type_t::nested_struct && field.target_structure_id != 0 &&
			structure_reaches_locked(field.target_structure_id, target_id, visited))
			return true;
	return false;
}

inline std::size_t field_scalar_size_locked(const field_def_t& field) {
	if (field.type == field_type_t::nested_struct && field.target_structure_id != 0) {
		const int target = structure_index_by_id_locked(field.target_structure_id);
		if (valid_index(target, g_state.structs.size()))
			return g_state.structs[static_cast<std::size_t>(target)].total_size;
	}
	if (field.size != 0)
		return field.size;
	const std::size_t natural = field_type_size(field.type);
	return natural == 0 ? 1 : natural;
}

inline std::uint32_t field_natural_alignment_locked(const field_def_t& field) {
	if (field.explicit_alignment != 0)
		return field.explicit_alignment;
	const std::size_t size = field_scalar_size_locked(field);
	std::uint32_t alignment = 1;
	while (alignment < size && alignment < 16)
		alignment <<= 1;
	return alignment;
}

inline layout_validation_t validate_structure_locked(const struct_def_t& definition) {
	layout_validation_t result;
	if (definition.name.empty() || definition.name.size() > 256)
		result.issues.push_back({layout_issue_severity_t::error, -1,
			"structure.name", "Structure names must contain 1-256 bytes"});
	if (definition.packing != 0 &&
		(!valid_power_of_two(definition.packing) || definition.packing > 4096))
		result.issues.push_back({layout_issue_severity_t::error, -1,
			"structure.packing", "Packing must be 0 or a power of two no greater than 4096"});
	if (definition.explicit_alignment != 0 &&
		(!valid_power_of_two(definition.explicit_alignment) ||
			definition.explicit_alignment > 4096))
		result.issues.push_back({layout_issue_severity_t::error, -1,
			"structure.alignment", "Structure alignment must be 0 or a power of two no greater than 4096"});
	std::uint32_t max_end = 0;
	std::uint32_t structure_alignment = definition.explicit_alignment == 0
		? 1 : definition.explicit_alignment;
	std::set<std::string> names;
	struct span_t { std::uint32_t begin; std::uint32_t end; int index; };
	std::vector<span_t> spans;
	spans.reserve(definition.fields.size());
	for (std::size_t index = 0; index < definition.fields.size(); ++index) {
		const auto& field = definition.fields[index];
		const int field_index = index_fits_int(index) ? static_cast<int>(index) : -1;
		if (field.name.empty() || field.name.size() > 256)
			result.issues.push_back({layout_issue_severity_t::error, field_index,
				"field.name", "Field names must contain 1-256 bytes"});
		else if (!names.insert(field.name).second)
			result.issues.push_back({layout_issue_severity_t::error, field_index,
				"field.duplicate_name", "Field names must be unique within a structure"});
		if (field.parent_idx != -1 && !valid_index(field.parent_idx, definition.fields.size()))
			result.issues.push_back({layout_issue_severity_t::error, field_index,
				"field.parent", "Field parent index is outside the structure"});
		std::set<int> child_indices;
		for (const int child : field.children)
			if (!valid_index(child, definition.fields.size()) ||
				!child_indices.insert(child).second ||
				definition.fields[static_cast<std::size_t>(child)].parent_idx != field_index)
				result.issues.push_back({layout_issue_severity_t::error, field_index,
					"field.children", "Field child links must be unique, in range, and reciprocal"});
		if (field.array_count == 0 || field.array_count > 1048576)
			result.issues.push_back({layout_issue_severity_t::error, field_index,
				"field.array_count", "Array count must be between 1 and 1,048,576"});
		if (field.explicit_alignment != 0 &&
			(!valid_power_of_two(field.explicit_alignment) || field.explicit_alignment > 4096))
			result.issues.push_back({layout_issue_severity_t::error, field_index,
				"field.alignment", "Field alignment must be 0 or a power of two no greater than 4096"});
		if (field.type == field_type_t::nested_struct) {
			const int target = structure_index_by_id_locked(field.target_structure_id);
			if (!valid_index(target, g_state.structs.size()))
				result.issues.push_back({layout_issue_severity_t::error, field_index,
					"field.nested_target", "Nested fields require a current target structure"});
			else if (g_state.structs[static_cast<std::size_t>(target)].stable_id == definition.stable_id)
				result.issues.push_back({layout_issue_severity_t::error, field_index,
					"field.recursive_value", "A structure cannot contain itself by value"});
			else {
				std::set<std::uint64_t> visited;
				if (structure_reaches_locked(field.target_structure_id, definition.stable_id, visited))
					result.issues.push_back({layout_issue_severity_t::error, field_index,
						"field.recursive_cycle", "Nested value fields cannot form a recursive structure cycle"});
			}
		}
		if (field.enum_id != 0 && !valid_index(enum_index_by_id_locked(field.enum_id), g_state.enums.size()))
			result.issues.push_back({layout_issue_severity_t::error, field_index,
				"field.enum", "Enum fields require a current enum definition"});
		if (field.bit_width != 0) {
			const std::size_t scalar = field_scalar_size_locked(field);
			if (field.array_count != 1 || scalar == 0 || scalar > 8 ||
				field.bit_width > scalar * 8 || field.bit_offset >= scalar * 8 ||
				field.bit_offset + field.bit_width > scalar * 8)
				result.issues.push_back({layout_issue_severity_t::error, field_index,
					"field.bitfield", "Bitfield offset and width must fit one 1-8 byte scalar and cannot be arrays"});
		}
		std::uint32_t scalar = 0;
		const std::size_t scalar_size = field_scalar_size_locked(field);
		if (scalar_size > 16777216 || scalar_size > (std::numeric_limits<std::uint32_t>::max)())
			result.issues.push_back({layout_issue_severity_t::error, field_index,
				"field.size", "Field scalar size exceeds the 16 MiB structure limit"});
		else
			scalar = static_cast<std::uint32_t>(scalar_size);
		std::uint32_t span = 0;
		std::uint32_t end = 0;
		if (!checked_multiply_u32(scalar, field.array_count, span) ||
			!checked_add_u32(field.offset, span, end) || end > 16777216)
			result.issues.push_back({layout_issue_severity_t::error, field_index,
				"field.range", "Field range overflows or exceeds the 16 MiB structure limit"});
		else {
			max_end = (std::max)(max_end, end);
			if (field.parent_idx < 0 && span != 0)
				spans.push_back({field.offset, end, field_index});
		}
		std::uint32_t alignment = field_natural_alignment_locked(field);
		if (definition.packing != 0)
			alignment = (std::min)(alignment, static_cast<std::uint32_t>(definition.packing));
		structure_alignment = (std::max)(structure_alignment, alignment);
		if (definition.kind == structure_kind_t::structure && alignment > 1 &&
			field.offset % alignment != 0)
			result.issues.push_back({layout_issue_severity_t::warning, field_index,
				"field.misaligned", "Field offset does not satisfy its effective alignment"});
		if (definition.kind == structure_kind_t::union_type && field.parent_idx < 0 && field.offset != 0)
			result.issues.push_back({layout_issue_severity_t::error, field_index,
				"union.offset", "Top-level union fields must start at offset zero"});
	}
	if (definition.kind == structure_kind_t::structure) {
		std::sort(spans.begin(), spans.end(), [](const span_t& left, const span_t& right) {
			return left.begin < right.begin || (left.begin == right.begin && left.end < right.end);
		});
		for (std::size_t index = 1; index < spans.size(); ++index)
			if (spans[index].begin < spans[index - 1].end) {
				const auto& current = definition.fields[static_cast<std::size_t>(spans[index].index)];
				const auto& previous = definition.fields[static_cast<std::size_t>(spans[index - 1].index)];
				const bool compatible_bits = current.bit_width != 0 && previous.bit_width != 0 &&
					current.offset == previous.offset &&
					field_scalar_size_locked(current) == field_scalar_size_locked(previous) &&
					(current.bit_offset + current.bit_width <= previous.bit_offset ||
					 previous.bit_offset + previous.bit_width <= current.bit_offset);
				if (!compatible_bits)
					result.issues.push_back({layout_issue_severity_t::error, spans[index].index,
						"field.overlap", "Field overlaps another top-level field"});
			}
	}
	result.effective_alignment = (std::max)(std::uint32_t{1}, structure_alignment);
	result.computed_size = align_up_u32(max_end, result.effective_alignment);
	if (result.computed_size > 16777216)
		result.issues.push_back({layout_issue_severity_t::error, -1,
			"structure.size", "Aligned structure size exceeds 16 MiB"});
	return result;
}

inline layout_validation_t validate_structure(int structure_index) {
	std::lock_guard<std::mutex> lock(g_state.mtx);
	if (!valid_index(structure_index, g_state.structs.size())) {
		layout_validation_t result;
		result.issues.push_back({layout_issue_severity_t::error, -1,
			"structure.index", "The structure no longer exists"});
		return result;
	}
	return validate_structure_locked(g_state.structs[static_cast<std::size_t>(structure_index)]);
}

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
inline void ensure_preview_fixture() {
	std::lock_guard<std::mutex> lock(g_state.mtx);
	if (!g_state.structs.empty())
		return;
	struct_def_t context;
	context.name = "IMAGE_RUNTIME_CONTEXT";
	context.fields = {
		{"image_base", field_type_t::pointer, 0x00, 8, 1, -1,
			std::vector<int>{}, true, -1, "Mapped image base", 0, 0, 0,
			std::string{}, 0, 0, 0},
		{"entry_point", field_type_t::pointer, 0x08, 8, 1, -1,
			std::vector<int>{}, true, -1, "Resolved entry point", 0, 0, 0,
			std::string{}, 0, 0, 0},
		{"image_size", field_type_t::uint32, 0x10, 4, 1, -1,
			std::vector<int>{}, false, -1, "Size of image", 0, 0, 0,
			std::string{}, 0, 0, 0},
		{"machine", field_type_t::uint16, 0x14, 2, 1, -1,
			std::vector<int>{}, false, -1, "PE machine type", 0, 0, 0,
			std::string{}, 0, 0, 0},
		{"section_count", field_type_t::uint16, 0x16, 2, 1, -1,
			std::vector<int>{}, false, -1, "Number of sections", 0, 0, 0,
			std::string{}, 0, 0, 0},
		{"flags", field_type_t::uint32, 0x18, 4, 1, -1,
			std::vector<int>{}, false, -1, "Analysis flags", 0, 0, 0,
			std::string{}, 0, 0, 0},
		{"module_name", field_type_t::ascii_string, 0x20, 16, 1, -1,
			std::vector<int>{}, false, -1, "Target module", 0, 0, 0,
			std::string{}, 0, 0, 0}
	};
	context.total_size = 0x30;
	struct_def_t node;
	node.name = "CONTROL_FLOW_NODE";
	node.fields = {
		{"address", field_type_t::pointer, 0x00, 8, 1, -1,
			std::vector<int>{}, true, -1, "Block start", 0, 0, 0,
			std::string{}, 0, 0, 0},
		{"successors", field_type_t::pointer, 0x08, 8, 1, -1,
			std::vector<int>{}, true, -1, "Successor array", 0, 0, 0,
			std::string{}, 0, 0, 0},
		{"successor_count", field_type_t::uint32, 0x10, 4, 1, -1,
			std::vector<int>{}, false, -1, "Outgoing edge count", 0, 0, 0,
			std::string{}, 0, 0, 0},
		{"instruction_count", field_type_t::uint32, 0x14, 4, 1, -1,
			std::vector<int>{}, false, -1, "Instruction count", 0, 0, 0,
			std::string{}, 0, 0, 0},
		{"flags", field_type_t::uint64, 0x18, 8, 1, -1,
			std::vector<int>{}, false, -1, "Node flags", 0, 0, 0,
			std::string{}, 0, 0, 0},
		{"confidence", field_type_t::float32, 0x20, 4, 1, -1,
			std::vector<int>{}, false, -1, "Recovery confidence", 0, 0, 0,
			std::string{}, 0, 0, 0}
	};
	node.total_size = 0x24;
	context.stable_id = allocate_stable_id_locked();
	for (auto& field : context.fields)
		field.stable_id = allocate_stable_id_locked();
	node.stable_id = allocate_stable_id_locked();
	for (auto& field : node.fields)
		field.stable_id = allocate_stable_id_locked();
	g_state.structs = {std::move(context), std::move(node)};
	g_state.active_struct = 0;
	g_state.base_address = 0x0000000140005000ULL;
}
#endif

inline const char* field_type_name(field_type_t t) {
	static const char* names[] = {
		"Int8", "UInt8", "Int16", "UInt16", "Int32", "UInt32",
		"Int64", "UInt64", "Float", "Double", "Pointer",
		"ASCII String", "UTF-16 String", "Byte Array", "Padding", "Struct"
	};
	int idx = static_cast<int>(t);
	if (valid_index(idx, static_cast<std::size_t>(field_type_t::COUNT)))
		return names[static_cast<std::size_t>(idx)];
	return "Unknown";
}

inline std::size_t field_type_size(field_type_t t) {
	switch (t) {
	case field_type_t::int8:          return 1;
	case field_type_t::uint8:         return 1;
	case field_type_t::int16:         return 2;
	case field_type_t::uint16:        return 2;
	case field_type_t::int32:         return 4;
	case field_type_t::uint32:        return 4;
	case field_type_t::int64:         return 8;
	case field_type_t::uint64:        return 8;
	case field_type_t::float32:       return 4;
	case field_type_t::float64:       return 8;
	case field_type_t::pointer:       return 8;
	case field_type_t::ascii_string:  return 0;
	case field_type_t::utf16_string:  return 0;
	case field_type_t::byte_array:    return 0;
	case field_type_t::padding:       return 0;
	case field_type_t::nested_struct: return 0;
	default:                          return 4;
	}
}

inline std::string format_field_value(const std::vector<uint8_t>& bytes, field_type_t type) {
	if (bytes.empty()) return "<no data>";
	char buf[128];
	switch (type) {
	case field_type_t::int8: {
		int8_t v = 0;
		std::memcpy(&v, bytes.data(), (std::min)(bytes.size(), std::size_t{1}));
		std::snprintf(buf, sizeof(buf), "%d", v);
		return buf;
	}
	case field_type_t::uint8: {
		uint8_t v = bytes[0];
		std::snprintf(buf, sizeof(buf), "%u (0x%02X)",
			static_cast<unsigned int>(v), static_cast<unsigned int>(v));
		return buf;
	}
	case field_type_t::int16: {
		int16_t v = 0;
		if (bytes.size() >= 2) std::memcpy(&v, bytes.data(), 2);
		std::snprintf(buf, sizeof(buf), "%d", v);
		return buf;
	}
	case field_type_t::uint16: {
		uint16_t v = 0;
		if (bytes.size() >= 2) std::memcpy(&v, bytes.data(), 2);
		std::snprintf(buf, sizeof(buf), "%u (0x%04X)",
			static_cast<unsigned int>(v), static_cast<unsigned int>(v));
		return buf;
	}
	case field_type_t::int32: {
		int32_t v = 0;
		if (bytes.size() >= 4) std::memcpy(&v, bytes.data(), 4);
		std::snprintf(buf, sizeof(buf), "%d (0x%08X)", v, static_cast<uint32_t>(v));
		return buf;
	}
	case field_type_t::uint32: {
		uint32_t v = 0;
		if (bytes.size() >= 4) std::memcpy(&v, bytes.data(), 4);
		std::snprintf(buf, sizeof(buf), "%u (0x%08X)", v, v);
		return buf;
	}
	case field_type_t::int64: {
		int64_t v = 0;
		if (bytes.size() >= 8) std::memcpy(&v, bytes.data(), 8);
		std::snprintf(buf, sizeof(buf), "%lld", static_cast<long long>(v));
		return buf;
	}
	case field_type_t::uint64: {
		uint64_t v = 0;
		if (bytes.size() >= 8) std::memcpy(&v, bytes.data(), 8);
		std::snprintf(buf, sizeof(buf), "%llu (0x%016llX)", static_cast<unsigned long long>(v), static_cast<unsigned long long>(v));
		return buf;
	}
	case field_type_t::float32: {
		float v = 0.f;
		if (bytes.size() >= 4) std::memcpy(&v, bytes.data(), 4);
		std::snprintf(buf, sizeof(buf), "%.6g", v);
		return buf;
	}
	case field_type_t::float64: {
		double v = 0.0;
		if (bytes.size() >= 8) std::memcpy(&v, bytes.data(), 8);
		std::snprintf(buf, sizeof(buf), "%.10g", v);
		return buf;
	}
	case field_type_t::pointer: {
		uint64_t v = 0;
		if (bytes.size() >= 8) std::memcpy(&v, bytes.data(), 8);
		std::snprintf(buf, sizeof(buf), "0x%016llX", static_cast<unsigned long long>(v));
		return buf;
	}
	case field_type_t::ascii_string: {
		std::string s;
		s.reserve(bytes.size());
		for (auto b : bytes) {
			if (b == 0) break;
			s += (b >= 0x20 && b <= 0x7E) ? static_cast<char>(b) : '.';
		}
		return "\"" + s + "\"";
	}
	case field_type_t::utf16_string: {
		std::string s;
		for (std::size_t i = 0; i + 1 < bytes.size(); i += 2) {
			uint16_t ch = 0;
			std::memcpy(&ch, bytes.data() + i, 2);
			if (ch == 0) break;
			if (ch >= 0x20 && ch < 0x7F)
				s += static_cast<char>(ch);
			else
				s += '.';
		}
		return "L\"" + s + "\"";
	}
	case field_type_t::byte_array:
	case field_type_t::padding: {
		std::string hex;
		std::size_t limit = (std::min)(bytes.size(), std::size_t{32});
		for (std::size_t i = 0; i < limit; ++i) {
			if (!hex.empty()) hex += ' ';
			char h[4];
			std::snprintf(h, sizeof(h), "%02X", static_cast<unsigned int>(bytes[i]));
			hex += h;
		}
		if (bytes.size() > limit) hex += " ...";
		return hex;
	}
	case field_type_t::nested_struct:
		return "{...}";
	default:
		return "<unknown>";
	}
}

inline std::string format_field_value_locked(const std::vector<uint8_t>& bytes,
	const field_def_t& field) {
	if (bytes.empty())
		return "<no data>";
	if (field.bit_width != 0) {
		std::uint64_t storage = 0;
		std::memcpy(&storage, bytes.data(), (std::min)(bytes.size(), sizeof(storage)));
		const std::uint64_t mask = field.bit_width == 64
			? (std::numeric_limits<std::uint64_t>::max)()
			: ((std::uint64_t{1} << field.bit_width) - 1);
		const std::uint64_t value = (storage >> field.bit_offset) & mask;
		char output[96];
		std::snprintf(output, sizeof(output), "%llu (0x%llX, bits %u:%u)",
			static_cast<unsigned long long>(value), static_cast<unsigned long long>(value),
			static_cast<unsigned int>(field.bit_offset), static_cast<unsigned int>(field.bit_width));
		return output;
	}
	if (field.enum_id != 0) {
		const int enum_index = enum_index_by_id_locked(field.enum_id);
		if (valid_index(enum_index, g_state.enums.size())) {
			const auto enumeration = g_state.enums.begin() + enum_index;
			std::uint64_t raw = 0;
			std::memcpy(&raw, bytes.data(), (std::min)(bytes.size(), sizeof(raw)));
			const auto value = std::find_if(enumeration->values.begin(), enumeration->values.end(),
				[&](const enum_value_t& item) { return static_cast<std::uint64_t>(item.value) == raw; });
			if (value != enumeration->values.end())
				return enumeration->name + "::" + value->name + " (" + std::to_string(value->value) + ")";
			return enumeration->name + "(" + std::to_string(raw) + ")";
		}
	}
	if (field.type == field_type_t::nested_struct) {
		const int target = structure_index_by_id_locked(field.target_structure_id);
		const std::string name = valid_index(target, g_state.structs.size())
			? g_state.structs[static_cast<std::size_t>(target)].name : field.referenced_type_name;
		return (name.empty() ? std::string("structure") : name) + " {" +
			std::to_string(bytes.size()) + " bytes}";
	}
	if (field.array_count > 1) {
		const std::size_t scalar = field_scalar_size_locked(field);
		std::string output = field_type_name(field.type);
		output += "[" + std::to_string(field.array_count) + "] ";
		const std::size_t shown = (std::min)(static_cast<std::size_t>(field.array_count), std::size_t{4});
		for (std::size_t index = 0; index < shown; ++index) {
			if (index != 0)
				output += ", ";
			const std::size_t begin = index * scalar;
			if (begin >= bytes.size()) {
				output += "<out of range>";
				continue;
			}
			const std::size_t end = (std::min)(bytes.size(), begin + scalar);
			output += format_field_value(std::vector<std::uint8_t>(bytes.begin() +
				static_cast<std::ptrdiff_t>(begin), bytes.begin() + static_cast<std::ptrdiff_t>(end)), field.type);
		}
		if (shown < field.array_count)
			output += ", ...";
		return output;
	}
	std::string output = format_field_value(bytes, field.type);
	if (field.type == field_type_t::pointer && !field.referenced_type_name.empty())
		output += " -> " + field.referenced_type_name;
	return output;
}

inline void recalc_total_size(struct_def_t& sd) {
	const auto validation = validate_structure_locked(sd);
	sd.total_size = validation.computed_size;
}

inline int create_struct(const std::string& name) {
	int idx = -1;
	std::size_t total = 0;
	{
		std::lock_guard<std::mutex> lk(g_state.mtx);
		if (name.empty() || name.size() > 256 || g_state.structs.size() >= 1024 ||
			std::any_of(g_state.structs.begin(), g_state.structs.end(), [&](const struct_def_t& item) {
				return item.name == name;
			}))
			return -1;
		if (!index_fits_int(g_state.structs.size())) {
			diag::log_tagged_fmt("dissector",
				"create_struct rejected reason='index_overflow' total=%zu", g_state.structs.size());
			return -1;
		}
		struct_def_t sd;
		sd.name = name;
		sd.total_size = 0;
		sd.stable_id = allocate_stable_id_locked();
		idx = static_cast<int>(g_state.structs.size());
		g_state.structs.push_back(std::move(sd));
		++g_state.schema_revision;
		total = g_state.structs.size();
	}
	diag::log_tagged_fmt("dissector",
		"create_struct name='%s' idx=%d total=%zu",
		name.c_str(), idx, total);
	return idx;
}

inline int add_field(int struct_idx, const field_def_t& field) {
	int idx = -1;
	uint32_t total_after = 0;
	std::string sd_name;
	{
		std::lock_guard<std::mutex> lk(g_state.mtx);
		if (!valid_index(struct_idx, g_state.structs.size())) {
			diag::log_tagged_fmt("dissector",
				"add_field rejected reason='bad_struct_idx' idx=%d", struct_idx);
			return -1;
		}
		auto& sd = g_state.structs[static_cast<std::size_t>(struct_idx)];
		struct_def_t candidate = sd;
		field_def_t f = field;
		if (f.stable_id == 0)
			f.stable_id = allocate_stable_id_locked();
		else if (std::any_of(g_state.structs.begin(), g_state.structs.end(), [&](const struct_def_t& definition) {
			return definition.stable_id == f.stable_id ||
				std::any_of(definition.fields.begin(), definition.fields.end(), [&](const field_def_t& item) {
					return item.stable_id == f.stable_id;
				});
		}) || std::any_of(g_state.enums.begin(), g_state.enums.end(), [&](const enum_def_t& item) {
			return item.stable_id == f.stable_id;
		}))
			return -1;
		if (f.array_count == 0)
			f.array_count = 1;
		if (f.size == 0) {
			std::size_t ts = field_type_size(f.type);
			f.size = static_cast<uint32_t>(ts > 0 ? ts : 1);
		}
		if (!index_fits_int(candidate.fields.size()) || candidate.fields.size() >= 65536) {
			diag::log_tagged_fmt("dissector",
				"add_field rejected reason='index_overflow' struct='%s' field_count=%zu",
				sd.name.c_str(), sd.fields.size());
			return -1;
		}
		idx = static_cast<int>(candidate.fields.size());
		if (valid_index(f.parent_idx, candidate.fields.size()))
			candidate.fields[static_cast<std::size_t>(f.parent_idx)].children.push_back(idx);
		candidate.fields.push_back(std::move(f));
		const auto validation = validate_structure_locked(candidate);
		if (!validation.valid())
			return -1;
		candidate.total_size = validation.computed_size;
		candidate.layout_revision = sd.layout_revision + 1;
		sd = std::move(candidate);
		++g_state.schema_revision;
		total_after = sd.total_size;
		sd_name = sd.name;
	}
	diag::log_tagged_fmt("dissector",
		"add_field struct='%s' field='%s' offset=0x%X size=%u type=%s field_idx=%d total=%u",
		sd_name.c_str(),
		field.name.c_str(),
		field.offset,
		field.size,
		field_type_name(field.type),
		idx,
		total_after);
	return idx;
}

inline bool remove_field(int struct_idx, int field_idx) {
	std::string removed_name;
	std::string sd_name;
	uint32_t total_after = 0;
	{
		std::lock_guard<std::mutex> lk(g_state.mtx);
		if (!valid_index(struct_idx, g_state.structs.size())) {
			diag::log_tagged_fmt("dissector",
				"remove_field rejected reason='bad_struct_idx' idx=%d", struct_idx);
			return false;
		}
		auto& sd = g_state.structs[static_cast<std::size_t>(struct_idx)];
		if (!valid_index(field_idx, sd.fields.size())) {
			diag::log_tagged_fmt("dissector",
				"remove_field rejected reason='bad_field_idx' struct='%s' field_idx=%d field_count=%zu",
				sd.name.c_str(), field_idx, sd.fields.size());
			return false;
		}
		const auto field_index = static_cast<std::size_t>(field_idx);
		removed_name = sd.fields[field_index].name;
		sd_name = sd.name;
		int parent = sd.fields[field_index].parent_idx;
		if (valid_index(parent, sd.fields.size())) {
			auto& pc = sd.fields[static_cast<std::size_t>(parent)].children;
			pc.erase(std::remove(pc.begin(), pc.end(), field_idx), pc.end());
		}
		sd.fields.erase(sd.fields.begin() + static_cast<std::ptrdiff_t>(field_index));
		for (auto& f : sd.fields) {
			if (f.parent_idx > field_idx) --f.parent_idx;
			else if (f.parent_idx == field_idx) f.parent_idx = -1;
			for (auto& ci : f.children) {
				if (ci > field_idx) --ci;
			}
			f.children.erase(
				std::remove_if(f.children.begin(), f.children.end(),
					[&](int c) { return !valid_index(c, sd.fields.size()); }),
				f.children.end());
		}
		recalc_total_size(sd);
		++sd.layout_revision;
		++g_state.schema_revision;
		total_after = sd.total_size;
	}
	diag::log_tagged_fmt("dissector",
		"remove_field struct='%s' field='%s' idx=%d total=%u",
		sd_name.c_str(), removed_name.c_str(), field_idx, total_after);
	return true;
}

inline bool rename_struct(int struct_idx, const std::string& new_name) {
	std::string old_name;
	{
		std::lock_guard<std::mutex> lk(g_state.mtx);
		if (!valid_index(struct_idx, g_state.structs.size())) {
			diag::log_tagged_fmt("dissector",
				"rename_struct rejected reason='bad_idx' idx=%d", struct_idx);
			return false;
		}
		if (new_name.empty() || new_name.size() > 256 ||
			std::any_of(g_state.structs.begin(), g_state.structs.end(), [&](const struct_def_t& item) {
				return item.name == new_name && item.stable_id != g_state.structs[static_cast<std::size_t>(struct_idx)].stable_id;
			})) {
			diag::log_tagged_fmt("dissector",
				"rename_struct rejected reason='empty_name' idx=%d", struct_idx);
			return false;
		}
		auto& sd = g_state.structs[static_cast<std::size_t>(struct_idx)];
		old_name = sd.name;
		sd.name = new_name;
		++sd.layout_revision;
		for (auto& definition : g_state.structs) {
			bool changed = false;
			for (auto& field : definition.fields)
				if (field.target_structure_id == sd.stable_id) {
					field.referenced_type_name = new_name;
					changed = true;
				}
			if (changed && definition.stable_id != sd.stable_id)
				++definition.layout_revision;
		}
		++g_state.schema_revision;
	}
	diag::log_tagged_fmt("dissector",
		"rename_struct idx=%d old='%s' new='%s'",
		struct_idx, old_name.c_str(), new_name.c_str());
	return true;
}

inline bool rename_field(int struct_idx, int field_idx, const std::string& new_name) {
	std::string sd_name, old_name;
	{
		std::lock_guard<std::mutex> lk(g_state.mtx);
		if (!valid_index(struct_idx, g_state.structs.size())) {
			diag::log_tagged_fmt("dissector",
				"rename_field rejected reason='bad_struct_idx' idx=%d", struct_idx);
			return false;
		}
		auto& sd = g_state.structs[static_cast<std::size_t>(struct_idx)];
		if (!valid_index(field_idx, sd.fields.size())) {
			diag::log_tagged_fmt("dissector",
				"rename_field rejected reason='bad_field_idx' struct='%s' field_idx=%d",
				sd.name.c_str(), field_idx);
			return false;
		}
		const auto field_index = static_cast<std::size_t>(field_idx);
		sd_name = sd.name;
		old_name = sd.fields[field_index].name;
		if (new_name.empty() || new_name.size() > 256 ||
			std::any_of(sd.fields.begin(), sd.fields.end(), [&](const field_def_t& item) {
				return item.name == new_name && item.stable_id != sd.fields[field_index].stable_id;
			}))
			return false;
		sd.fields[field_index].name = new_name;
		++sd.layout_revision;
		++g_state.schema_revision;
	}
	diag::log_tagged_fmt("dissector",
		"rename_field struct='%s' field_idx=%d old='%s' new='%s'",
		sd_name.c_str(), field_idx, old_name.c_str(), new_name.c_str());
	return true;
}

inline bool retype_field(int struct_idx, int field_idx, field_type_t new_type) {
	std::string sd_name, fname;
	field_type_t old_type = field_type_t::int32;
	uint32_t total_after = 0;
	{
		std::lock_guard<std::mutex> lk(g_state.mtx);
		if (!valid_index(struct_idx, g_state.structs.size())) {
			diag::log_tagged_fmt("dissector",
				"retype_field rejected reason='bad_struct_idx' idx=%d", struct_idx);
			return false;
		}
		auto& sd = g_state.structs[static_cast<std::size_t>(struct_idx)];
		if (!valid_index(field_idx, sd.fields.size())) {
			diag::log_tagged_fmt("dissector",
				"retype_field rejected reason='bad_field_idx' struct='%s' field_idx=%d",
				sd.name.c_str(), field_idx);
			return false;
		}
		struct_def_t candidate = sd;
		auto& f = candidate.fields[static_cast<std::size_t>(field_idx)];
		old_type = f.type;
		f.type = new_type;
		std::size_t ts = field_type_size(new_type);
		if (ts > 0) {
			f.size = static_cast<uint32_t>(ts);
		} else if (f.size == 0) {
			f.size = 1;
		}
		f.target_structure_id = new_type == field_type_t::nested_struct ? f.target_structure_id : 0;
		f.enum_id = 0;
		f.bit_offset = 0;
		f.bit_width = 0;
		const auto validation = validate_structure_locked(candidate);
		if (!validation.valid())
			return false;
		fname = f.name;
		candidate.total_size = validation.computed_size;
		candidate.layout_revision = sd.layout_revision + 1;
		sd = std::move(candidate);
		++g_state.schema_revision;
		sd_name = sd.name;
		total_after = sd.total_size;
	}
	diag::log_tagged_fmt("dissector",
		"retype_field struct='%s' field='%s' old=%s new=%s total=%u",
		sd_name.c_str(), fname.c_str(),
		field_type_name(old_type), field_type_name(new_type), total_after);
	return true;
}

inline bool set_field_size(int struct_idx, int field_idx, uint32_t new_size) {
	std::string sd_name, fname;
	uint32_t old_size = 0;
	uint32_t total_after = 0;
	{
		std::lock_guard<std::mutex> lk(g_state.mtx);
		if (!valid_index(struct_idx, g_state.structs.size())) {
			diag::log_tagged_fmt("dissector",
				"set_field_size rejected reason='bad_struct_idx' idx=%d", struct_idx);
			return false;
		}
		auto& sd = g_state.structs[static_cast<std::size_t>(struct_idx)];
		if (!valid_index(field_idx, sd.fields.size())) {
			diag::log_tagged_fmt("dissector",
				"set_field_size rejected reason='bad_field_idx' struct='%s' field_idx=%d",
				sd.name.c_str(), field_idx);
			return false;
		}
		if (new_size == 0 || new_size > 65536u) {
			diag::log_tagged_fmt("dissector",
				"set_field_size rejected reason='bad_size' new=%u", new_size);
			return false;
		}
		struct_def_t candidate = sd;
		auto& f = candidate.fields[static_cast<std::size_t>(field_idx)];
		old_size = f.size;
		f.size = new_size;
		const auto validation = validate_structure_locked(candidate);
		if (!validation.valid())
			return false;
		fname = f.name;
		candidate.total_size = validation.computed_size;
		candidate.layout_revision = sd.layout_revision + 1;
		sd = std::move(candidate);
		++g_state.schema_revision;
		sd_name = sd.name;
		total_after = sd.total_size;
	}
	diag::log_tagged_fmt("dissector",
		"set_field_size struct='%s' field='%s' old=%u new=%u total=%u",
		sd_name.c_str(), fname.c_str(), old_size, new_size, total_after);
	return true;
}

inline bool set_field_comment(int struct_idx, int field_idx, const std::string& comment) {
	std::string sd_name, fname;
	{
		std::lock_guard<std::mutex> lk(g_state.mtx);
		if (!valid_index(struct_idx, g_state.structs.size())) {
			diag::log_tagged_fmt("dissector",
				"set_field_comment rejected reason='bad_struct_idx' idx=%d", struct_idx);
			return false;
		}
		auto& sd = g_state.structs[static_cast<std::size_t>(struct_idx)];
		if (!valid_index(field_idx, sd.fields.size())) {
			diag::log_tagged_fmt("dissector",
				"set_field_comment rejected reason='bad_field_idx' struct='%s' field_idx=%d",
				sd.name.c_str(), field_idx);
			return false;
		}
		const auto field_index = static_cast<std::size_t>(field_idx);
		sd.fields[field_index].description = comment;
		++sd.layout_revision;
		++g_state.schema_revision;
		sd_name = sd.name;
		fname = sd.fields[field_index].name;
	}
	diag::log_tagged_fmt("dissector",
		"set_field_comment struct='%s' field='%s' bytes=%zu",
		sd_name.c_str(), fname.c_str(), comment.size());
	return true;
}

inline bool remove_field(int struct_idx, int field_idx);

inline bool move_field(int struct_idx, int field_idx, int destination_idx) {
	std::lock_guard<std::mutex> lock(g_state.mtx);
	if (!valid_index(struct_idx, g_state.structs.size()))
		return false;
	auto& definition = g_state.structs[static_cast<std::size_t>(struct_idx)];
	if (!valid_index(field_idx, definition.fields.size()) ||
		!valid_index(destination_idx, definition.fields.size()))
		return false;
	if (field_idx == destination_idx)
		return true;
	struct_def_t candidate = definition;
	const auto remap = [field_idx, destination_idx](int index) {
		if (index < 0)
			return index;
		if (index == field_idx)
			return destination_idx;
		if (field_idx < destination_idx && index > field_idx && index <= destination_idx)
			return index - 1;
		if (destination_idx < field_idx && index >= destination_idx && index < field_idx)
			return index + 1;
		return index;
	};
	auto moving = std::move(candidate.fields[static_cast<std::size_t>(field_idx)]);
	candidate.fields.erase(candidate.fields.begin() + field_idx);
	candidate.fields.insert(candidate.fields.begin() + destination_idx, std::move(moving));
	for (auto& field : candidate.fields) {
		field.parent_idx = remap(field.parent_idx);
		for (auto& child : field.children)
			child = remap(child);
	}
	const auto validation = validate_structure_locked(candidate);
	if (!validation.valid())
		return false;
	candidate.total_size = validation.computed_size;
	candidate.layout_revision = definition.layout_revision + 1;
	definition = std::move(candidate);
	++g_state.schema_revision;
	return true;
}

inline int insert_field(int struct_idx, int destination_idx, const field_def_t& field) {
	const int appended = add_field(struct_idx, field);
	if (appended < 0)
		return -1;
	if (destination_idx < 0)
		destination_idx = 0;
	if (destination_idx >= appended)
		return appended;
	if (move_field(struct_idx, appended, destination_idx))
		return destination_idx;
	static_cast<void>(remove_field(struct_idx, appended));
	return -1;
}

inline bool remove_structure(int struct_idx, std::string& error) {
	std::lock_guard<std::mutex> lock(g_state.mtx);
	if (!valid_index(struct_idx, g_state.structs.size())) {
		error = "The structure no longer exists";
		return false;
	}
	const auto target_id = g_state.structs[static_cast<std::size_t>(struct_idx)].stable_id;
	for (const auto& definition : g_state.structs)
		for (const auto& field : definition.fields)
			if (field.target_structure_id == target_id) {
				error = "Remove or retarget fields that reference this structure first";
				return false;
			}
	g_state.structs.erase(g_state.structs.begin() + static_cast<std::ptrdiff_t>(struct_idx));
	for (auto& definition : g_state.structs)
		for (auto& field : definition.fields) {
			if (field.pointer_target_struct > struct_idx)
				--field.pointer_target_struct;
		}
	if (g_state.active_struct == struct_idx)
		g_state.active_struct = g_state.structs.empty() ? -1 :
			(static_cast<std::size_t>(struct_idx) < g_state.structs.size() ? struct_idx :
			static_cast<int>(g_state.structs.size() - 1));
	else if (g_state.active_struct > struct_idx)
		--g_state.active_struct;
	g_state.cached_values.clear();
	++g_state.schema_revision;
	error.clear();
	return true;
}

template <typename Mutator>
inline bool mutate_structure(int struct_idx, Mutator&& mutator) {
	std::lock_guard<std::mutex> lock(g_state.mtx);
	if (!valid_index(struct_idx, g_state.structs.size()))
		return false;
	auto& current = g_state.structs[static_cast<std::size_t>(struct_idx)];
	struct_def_t candidate = current;
	if (!mutator(candidate))
		return false;
	const auto validation = validate_structure_locked(candidate);
	if (!validation.valid())
		return false;
	candidate.total_size = validation.computed_size;
	candidate.layout_revision = current.layout_revision + 1;
	current = std::move(candidate);
	++g_state.schema_revision;
	return true;
}

inline bool set_field_array_count(int struct_idx, int field_idx, std::uint32_t count) {
	if (count == 0 || count > 1048576)
		return false;
	return mutate_structure(struct_idx, [&](struct_def_t& definition) {
		if (!valid_index(field_idx, definition.fields.size()))
			return false;
		auto& field = definition.fields[static_cast<std::size_t>(field_idx)];
		if (field.bit_width != 0 && count != 1)
			return false;
		field.array_count = count;
		return true;
	});
}

inline bool set_field_nested_target(int struct_idx, int field_idx, int target_idx,
	bool pointer_target) {
	std::uint64_t target_id = 0;
	std::string target_name;
	{
		std::lock_guard<std::mutex> lock(g_state.mtx);
		if (!valid_index(target_idx, g_state.structs.size()))
			return false;
		target_id = g_state.structs[static_cast<std::size_t>(target_idx)].stable_id;
		target_name = g_state.structs[static_cast<std::size_t>(target_idx)].name;
	}
	return mutate_structure(struct_idx, [&](struct_def_t& definition) {
		if (!valid_index(field_idx, definition.fields.size()))
			return false;
		auto& field = definition.fields[static_cast<std::size_t>(field_idx)];
		field.type = pointer_target ? field_type_t::pointer : field_type_t::nested_struct;
		field.is_pointer = pointer_target;
		field.target_structure_id = target_id;
		field.enum_id = 0;
		field.pointer_target_struct = target_idx;
		field.referenced_type_name = target_name;
		field.size = pointer_target ? 8u : field.size;
		field.bit_offset = 0;
		field.bit_width = 0;
		return true;
	});
}

inline bool set_field_nested_target_by_name(int struct_idx, int field_idx,
	const std::string& target_name, bool pointer_target) {
	int target = -1;
	{
		std::lock_guard<std::mutex> lock(g_state.mtx);
		for (std::size_t index = 0; index < g_state.structs.size(); ++index)
			if (g_state.structs[index].name == target_name) {
				target = index_fits_int(index) ? static_cast<int>(index) : -1;
				break;
			}
	}
	return set_field_nested_target(struct_idx, field_idx, target, pointer_target);
}

inline bool set_field_bitfield(int struct_idx, int field_idx, std::uint16_t bit_offset,
	std::uint16_t bit_width) {
	return mutate_structure(struct_idx, [&](struct_def_t& definition) {
		if (!valid_index(field_idx, definition.fields.size()))
			return false;
		auto& field = definition.fields[static_cast<std::size_t>(field_idx)];
		field.bit_offset = bit_width == 0 ? 0 : bit_offset;
		field.bit_width = bit_width;
		return true;
	});
}

inline bool set_field_alignment(int struct_idx, int field_idx, std::uint16_t alignment) {
	if (alignment != 0 && (!valid_power_of_two(alignment) || alignment > 4096))
		return false;
	return mutate_structure(struct_idx, [&](struct_def_t& definition) {
		if (!valid_index(field_idx, definition.fields.size()))
			return false;
		definition.fields[static_cast<std::size_t>(field_idx)].explicit_alignment = alignment;
		return true;
	});
}

inline bool set_structure_packing(int struct_idx, std::uint16_t packing) {
	if (packing != 0 && (!valid_power_of_two(packing) || packing > 4096))
		return false;
	return mutate_structure(struct_idx, [&](struct_def_t& definition) {
		definition.packing = packing;
		return true;
	});
}

inline bool set_structure_alignment(int struct_idx, std::uint16_t alignment) {
	if (alignment != 0 && (!valid_power_of_two(alignment) || alignment > 4096))
		return false;
	return mutate_structure(struct_idx, [&](struct_def_t& definition) {
		definition.explicit_alignment = alignment;
		return true;
	});
}

inline bool set_structure_kind(int struct_idx, structure_kind_t kind) {
	return mutate_structure(struct_idx, [&](struct_def_t& definition) {
		definition.kind = kind;
		if (kind == structure_kind_t::union_type)
			for (auto& field : definition.fields)
				if (field.parent_idx < 0)
					field.offset = 0;
		if (kind == structure_kind_t::structure) {
			std::uint32_t cursor = 0;
			for (auto& field : definition.fields) {
				if (field.parent_idx >= 0)
					continue;
				std::uint32_t alignment = field_natural_alignment_locked(field);
				if (definition.packing != 0)
					alignment = (std::min)(alignment, static_cast<std::uint32_t>(definition.packing));
				field.offset = align_up_u32(cursor, alignment);
				std::uint32_t span = 0;
				if (!checked_multiply_u32(static_cast<std::uint32_t>(field_scalar_size_locked(field)),
					field.array_count, span) || !checked_add_u32(field.offset, span, cursor))
					return false;
			}
		}
		return true;
	});
}

inline bool upsert_enum_checked(const enum_def_t& source,
	const std::optional<std::uint64_t>& expected_schema_revision) {
	if (source.name.empty() || source.name.size() > 256 || source.values.size() > 65536 ||
		static_cast<int>(source.underlying_type) < static_cast<int>(field_type_t::int8) ||
		static_cast<int>(source.underlying_type) > static_cast<int>(field_type_t::uint64))
		return false;
	std::set<std::string> names;
	for (const auto& value : source.values)
		if (value.name.empty() || value.name.size() > 256 || !names.insert(value.name).second)
			return false;
	std::lock_guard<std::mutex> lock(g_state.mtx);
	if (expected_schema_revision && g_state.schema_revision != *expected_schema_revision)
		return false;
	auto found = source.stable_id == 0
		? std::find_if(g_state.enums.begin(), g_state.enums.end(), [&](const enum_def_t& item) {
			return item.name == source.name;
		})
		: std::find_if(g_state.enums.begin(), g_state.enums.end(), [&](const enum_def_t& item) {
			return item.stable_id == source.stable_id;
		});
	if (std::any_of(g_state.enums.begin(), g_state.enums.end(), [&](const enum_def_t& item) {
		return item.name == source.name && item.stable_id != source.stable_id &&
			(found == g_state.enums.end() || item.stable_id != found->stable_id);
	}))
		return false;
	if (found != g_state.enums.end() && found->underlying_type != source.underlying_type &&
		std::any_of(g_state.structs.begin(), g_state.structs.end(), [&](const struct_def_t& definition) {
			return std::any_of(definition.fields.begin(), definition.fields.end(), [&](const field_def_t& field) {
				return field.enum_id == found->stable_id;
			});
		}))
		return false;
	enum_def_t candidate = source;
	if (candidate.stable_id == 0)
		candidate.stable_id = found == g_state.enums.end() ? allocate_stable_id_locked() : found->stable_id;
	else if ((found == g_state.enums.end() || found->stable_id != candidate.stable_id) &&
		(std::any_of(g_state.enums.begin(), g_state.enums.end(), [&](const enum_def_t& item) {
			return item.stable_id == candidate.stable_id;
		}) || std::any_of(g_state.structs.begin(), g_state.structs.end(), [&](const struct_def_t& definition) {
			return definition.stable_id == candidate.stable_id ||
				std::any_of(definition.fields.begin(), definition.fields.end(), [&](const field_def_t& field) {
					return field.stable_id == candidate.stable_id;
				});
		})))
		return false;
	if (found == g_state.enums.end() && g_state.enums.size() >= 4096)
		return false;
	const std::uint64_t published_id = candidate.stable_id;
	const std::string published_name = candidate.name;
	auto updated_enums = g_state.enums;
	if (found == g_state.enums.end())
		updated_enums.push_back(std::move(candidate));
	else
		updated_enums[static_cast<std::size_t>(std::distance(g_state.enums.begin(), found))] =
			std::move(candidate);
	auto updated_structs = g_state.structs;
	for (auto& definition : updated_structs) {
		bool changed = false;
		for (auto& field : definition.fields) {
			if (field.enum_id != published_id)
				continue;
			field.referenced_type_name = published_name;
			changed = true;
		}
		if (changed)
			++definition.layout_revision;
	}
	g_state.enums.swap(updated_enums);
	g_state.structs.swap(updated_structs);
	++g_state.schema_revision;
	return true;
}

inline bool upsert_enum(const enum_def_t& source) {
	return upsert_enum_checked(source, std::nullopt);
}

inline bool upsert_enum_exact(const enum_def_t& source,
	std::uint64_t expected_schema_revision) {
	return upsert_enum_checked(source, expected_schema_revision);
}

inline bool delete_enum_exact(std::uint64_t stable_id, const std::string& expected_name,
	std::uint64_t expected_schema_revision) {
	if (stable_id == 0 || expected_name.empty())
		return false;
	std::lock_guard<std::mutex> lock(g_state.mtx);
	if (g_state.schema_revision != expected_schema_revision)
		return false;
	const auto found = std::find_if(g_state.enums.begin(), g_state.enums.end(),
		[&](const enum_def_t& item) {
			return item.stable_id == stable_id && item.name == expected_name;
		});
	if (found == g_state.enums.end())
		return false;
	if (std::any_of(g_state.structs.begin(), g_state.structs.end(),
		[stable_id](const struct_def_t& definition) {
			return std::any_of(definition.fields.begin(), definition.fields.end(),
				[stable_id](const field_def_t& field) { return field.enum_id == stable_id; });
		}))
		return false;
	g_state.enums.erase(found);
	++g_state.schema_revision;
	return true;
}

inline bool rename_enum(std::uint64_t stable_id, const std::string& name) {
	if (stable_id == 0 || name.empty() || name.size() > 256)
		return false;
	std::lock_guard<std::mutex> lock(g_state.mtx);
	if (std::any_of(g_state.enums.begin(), g_state.enums.end(),
		[&](const enum_def_t& item) { return item.name == name && item.stable_id != stable_id; }))
		return false;
	auto found = std::find_if(g_state.enums.begin(), g_state.enums.end(),
		[stable_id](const enum_def_t& item) { return item.stable_id == stable_id; });
	if (found == g_state.enums.end())
		return false;
	found->name = name;
	for (auto& definition : g_state.structs) {
		bool changed = false;
		for (auto& field : definition.fields) {
			if (field.enum_id != stable_id)
				continue;
			field.referenced_type_name = name;
			changed = true;
		}
		if (changed)
			++definition.layout_revision;
	}
	++g_state.schema_revision;
	return true;
}

inline bool set_field_enum_reference(int struct_idx, int field_idx, const std::string& enum_name) {
	field_type_t underlying = field_type_t::int32;
	std::uint64_t enum_id = 0;
	{
		std::lock_guard<std::mutex> lock(g_state.mtx);
		auto found = std::find_if(g_state.enums.begin(), g_state.enums.end(), [&](const enum_def_t& item) {
			return item.name == enum_name;
		});
		if (found == g_state.enums.end())
			return false;
		underlying = found->underlying_type;
		enum_id = found->stable_id;
	}
	return mutate_structure(struct_idx, [&](struct_def_t& definition) {
		if (!valid_index(field_idx, definition.fields.size()))
			return false;
		auto& field = definition.fields[static_cast<std::size_t>(field_idx)];
		field.type = underlying;
		field.size = static_cast<std::uint32_t>((std::max)(std::size_t{1}, field_type_size(underlying)));
		field.referenced_type_name = enum_name;
		field.enum_id = enum_id;
		return true;
	});
}

inline bool request_save_schema();
inline bool request_save_schema_transactional(catalog_transaction_snapshot_t snapshot,
	std::uint64_t expected_schema_revision);

struct user_catalog_edit_t {
	catalog_transaction_snapshot_t before;
	catalog_transaction_snapshot_t after;
	std::string label;
	std::uint64_t before_identity = 0;
	std::uint64_t after_identity = 0;
	std::uint64_t fence_revision = 0;
	std::size_t retained_bytes = 0;
};

struct user_catalog_history_t {
	std::deque<user_catalog_edit_t> undo;
	std::deque<user_catalog_edit_t> redo;
	std::size_t retained_bytes = 0;
	std::mutex mutex;
};

inline user_catalog_history_t g_user_catalog_history;

inline constexpr std::size_t user_catalog_max_snapshot_bytes = 8U * 1024U * 1024U;
inline constexpr std::size_t user_catalog_max_history_bytes = 64U * 1024U * 1024U;
inline constexpr std::size_t user_catalog_max_history_entries = 64;

inline std::size_t catalog_definitions_retained_bytes(
	const std::vector<struct_def_t>& structures,
	const std::vector<enum_def_t>& enums) {
	std::size_t total = sizeof(catalog_transaction_snapshot_t);
	const auto add = [&total](std::size_t value) {
		if (value > (std::numeric_limits<std::size_t>::max)() - total)
			total = (std::numeric_limits<std::size_t>::max)();
		else
			total += value;
	};
	for (const auto& definition : structures) {
		add(sizeof(definition) + definition.name.size());
		for (const auto& field : definition.fields) {
			add(sizeof(field) + field.name.size() + field.description.size() +
				field.referenced_type_name.size() + field.children.size() * sizeof(int));
		}
	}
	for (const auto& definition : enums) {
		add(sizeof(definition) + definition.name.size());
		for (const auto& value : definition.values)
			add(sizeof(value) + value.name.size());
	}
	return total;
}

inline std::size_t catalog_snapshot_retained_bytes(const catalog_transaction_snapshot_t& snapshot) {
	return catalog_definitions_retained_bytes(snapshot.structs, snapshot.enums);
}

inline std::uint64_t catalog_snapshot_identity(const catalog_transaction_snapshot_t& snapshot) {
	std::uint64_t hash = 1469598103934665603ULL;
	const auto mix = [&hash](std::uint64_t value) {
		hash ^= value;
		hash *= 1099511628211ULL;
	};
	const auto mix_text = [&mix](const std::string& value) {
		mix(value.size());
		for (const char character : value)
			mix(static_cast<unsigned char>(character));
	};
	mix(snapshot.structs.size());
	for (const auto& definition : snapshot.structs) {
		mix(definition.stable_id);
		mix_text(definition.name);
		mix(static_cast<std::uint64_t>(definition.kind));
		mix(definition.packing);
		mix(definition.explicit_alignment);
		mix(definition.total_size);
		mix(definition.fields.size());
		for (const auto& field : definition.fields) {
			mix(field.stable_id);
			mix_text(field.name);
			mix(static_cast<std::uint64_t>(field.type));
			mix(field.offset);
			mix(field.size);
			mix(field.array_count);
			mix(static_cast<std::uint64_t>(field.parent_idx + 1));
			mix(field.children.size());
			for (const int child : field.children)
				mix(static_cast<std::uint64_t>(child + 1));
			mix(field.is_pointer ? 1 : 0);
			mix(static_cast<std::uint64_t>(field.pointer_target_struct + 1));
			mix(field.target_structure_id);
			mix(field.enum_id);
			mix_text(field.referenced_type_name);
			mix_text(field.description);
			mix(field.bit_offset);
			mix(field.bit_width);
			mix(field.explicit_alignment);
		}
	}
	mix(snapshot.enums.size());
	for (const auto& definition : snapshot.enums) {
		mix(definition.stable_id);
		mix_text(definition.name);
		mix(static_cast<std::uint64_t>(definition.underlying_type));
		mix(definition.values.size());
		for (const auto& value : definition.values) {
			mix_text(value.name);
			mix(static_cast<std::uint64_t>(value.value));
		}
	}
	return hash;
}

inline bool catalog_snapshot_is_bounded(const catalog_transaction_snapshot_t& snapshot) {
	if (snapshot.structs.size() > 1024 || snapshot.enums.size() > 4096 ||
		(!valid_index(snapshot.active_struct, snapshot.structs.size()) && snapshot.active_struct != -1))
		return false;
	std::set<std::uint64_t> identities;
	std::set<std::string> structure_names;
	std::set<std::string> enum_names;
	for (const auto& definition : snapshot.structs) {
		if (definition.stable_id == 0 || definition.name.empty() || definition.name.size() > 256 ||
			definition.fields.size() > 65536 || !identities.insert(definition.stable_id).second ||
			!structure_names.insert(definition.name).second)
			return false;
		for (const auto& field : definition.fields)
			if (field.stable_id == 0 || !identities.insert(field.stable_id).second)
				return false;
	}
	for (const auto& definition : snapshot.enums) {
		if (definition.stable_id == 0 || definition.name.empty() || definition.name.size() > 256 ||
			definition.values.size() > 65536 || !identities.insert(definition.stable_id).second ||
			!enum_names.insert(definition.name).second)
			return false;
		std::set<std::string> value_names;
		for (const auto& value : definition.values)
			if (value.name.empty() || value.name.size() > 256 || !value_names.insert(value.name).second)
				return false;
	}
	return catalog_snapshot_retained_bytes(snapshot) <= user_catalog_max_snapshot_bytes;
}

inline bool begin_user_catalog_edit(catalog_transaction_snapshot_t& before, std::string& error) {
	if (!catalog_mutation_available()) {
		error = "Wait for the current catalog persistence operation to finish";
		return false;
	}
	try {
		std::lock_guard<std::mutex> lock(g_state.mtx);
		if (catalog_definitions_retained_bytes(g_state.structs, g_state.enums) >
			user_catalog_max_snapshot_bytes) {
			error = "The catalog exceeds the bounded 8 MiB edit-history contract";
			return false;
		}
		before = {g_state.structs, g_state.enums, {},
			g_state.active_struct, g_state.schema_revision, g_state.next_stable_id};
		if (!catalog_snapshot_is_bounded(before)) {
			error = "The catalog is outside the validated edit-history contract";
			return false;
		}
	} catch (const std::bad_alloc&) {
		error = "Memory allocation for the bounded catalog edit transaction failed";
		return false;
	}
	error.clear();
	return true;
}

inline bool commit_user_catalog_edit(catalog_transaction_snapshot_t before,
	std::string label, std::string& error) {
	catalog_transaction_snapshot_t after;
	try {
		std::lock_guard<std::mutex> lock(g_state.mtx);
		after = {g_state.structs, g_state.enums, {}, g_state.active_struct,
			g_state.schema_revision, g_state.next_stable_id};
	} catch (const std::bad_alloc&) {
		const auto current_revision = catalog_schema_revision();
		const bool rolled_back = rollback_catalog_transaction(before, current_revision);
		error = rolled_back
			? "Memory allocation for edit history failed; the catalog edit was rolled back"
			: "Memory allocation for edit history failed and exact rollback was blocked";
		return false;
	}
	if (after.schema_revision == before.schema_revision ||
		catalog_snapshot_identity(after) == catalog_snapshot_identity(before)) {
		error = "The catalog edit did not publish a new state";
		return false;
	}
	bool after_bounded = false;
	try {
		after_bounded = catalog_snapshot_is_bounded(after);
	} catch (const std::bad_alloc&) {
		static_cast<void>(rollback_catalog_transaction(std::move(before), after.schema_revision));
		error = "Catalog validation allocation failed; the edit was rolled back";
		return false;
	}
	if (!after_bounded) {
		static_cast<void>(rollback_catalog_transaction(std::move(before), after.schema_revision));
		error = "The edit exceeded the bounded 8 MiB catalog history contract and was rolled back";
		return false;
	}
	before.cached_values.clear();
	after.cached_values.clear();
	user_catalog_edit_t entry;
	entry.before_identity = catalog_snapshot_identity(before);
	entry.after_identity = catalog_snapshot_identity(after);
	entry.fence_revision = after.schema_revision;
	entry.retained_bytes = catalog_snapshot_retained_bytes(before) +
		catalog_snapshot_retained_bytes(after) + label.size();
	entry.before = std::move(before);
	entry.after = std::move(after);
	entry.label = std::move(label);
	try {
		std::lock_guard<std::mutex> lock(g_user_catalog_history.mutex);
		const bool divergent_undo = !g_user_catalog_history.undo.empty() &&
			(g_user_catalog_history.undo.back().fence_revision != entry.before.schema_revision ||
			 g_user_catalog_history.undo.back().after_identity != entry.before_identity);
		const bool divergent_redo = g_user_catalog_history.undo.empty() &&
			!g_user_catalog_history.redo.empty() &&
			(g_user_catalog_history.redo.back().fence_revision != entry.before.schema_revision ||
			 g_user_catalog_history.redo.back().before_identity != entry.before_identity);
		if (divergent_undo || divergent_redo) {
			g_user_catalog_history.undo.clear();
			g_user_catalog_history.redo.clear();
			g_user_catalog_history.retained_bytes = 0;
		}
		for (const auto& redo : g_user_catalog_history.redo)
			g_user_catalog_history.retained_bytes -= (std::min)(
				g_user_catalog_history.retained_bytes, redo.retained_bytes);
		g_user_catalog_history.redo.clear();
		g_user_catalog_history.retained_bytes += entry.retained_bytes;
		g_user_catalog_history.undo.push_back(std::move(entry));
		while (g_user_catalog_history.undo.size() > user_catalog_max_history_entries ||
			g_user_catalog_history.retained_bytes > user_catalog_max_history_bytes) {
			g_user_catalog_history.retained_bytes -= (std::min)(
				g_user_catalog_history.retained_bytes,
				g_user_catalog_history.undo.front().retained_bytes);
			g_user_catalog_history.undo.pop_front();
		}
	} catch (const std::bad_alloc&) {
		{
			std::lock_guard<std::mutex> lock(g_user_catalog_history.mutex);
			g_user_catalog_history.retained_bytes -= (std::min)(
				g_user_catalog_history.retained_bytes, entry.retained_bytes);
		}
		const auto revision = catalog_schema_revision();
		const bool rolled_back = rollback_catalog_transaction(
			std::move(entry.before), revision);
		error = rolled_back
			? "Edit-history allocation failed; the catalog edit was rolled back"
			: "Edit-history allocation failed and exact catalog rollback was blocked";
		return false;
	}
	error.clear();
	return true;
}

template <typename Mutation, typename Success>
inline bool perform_user_catalog_edit(const std::string& label, Mutation&& mutation,
	Success&& success, std::string& error) {
	catalog_transaction_snapshot_t before;
	if (!begin_user_catalog_edit(before, error))
		return false;
	catalog_transaction_snapshot_t persistence_rollback;
	try {
		persistence_rollback = before;
	} catch (const std::bad_alloc&) {
		error = "Memory allocation for the durable catalog transaction failed";
		return false;
	}
	using result_t = std::decay_t<decltype(mutation())>;
	std::optional<result_t> result;
	try {
		result.emplace(mutation());
	} catch (const std::exception& exception) {
		const auto current_revision = catalog_schema_revision();
		const bool rolled_back = current_revision == before.schema_revision ||
			rollback_catalog_transaction(std::move(before), current_revision);
		error = rolled_back
			? std::string("Catalog mutation failed and was rolled back: ") + exception.what()
			: "Catalog mutation threw an exception and exact rollback was blocked";
		return false;
	} catch (...) {
		const auto current_revision = catalog_schema_revision();
		const bool rolled_back = current_revision == before.schema_revision ||
			rollback_catalog_transaction(std::move(before), current_revision);
		error = rolled_back
			? "Catalog mutation failed and was rolled back"
			: "Catalog mutation threw an exception and exact rollback was blocked";
		return false;
	}
	if (!success(*result)) {
		const auto current_revision = catalog_schema_revision();
		if (current_revision != before.schema_revision &&
			!rollback_catalog_transaction(std::move(before), current_revision)) {
			error = "The catalog mutation failed and exact transaction rollback was blocked";
			return false;
		}
		error = "The catalog mutation was rejected";
		return false;
	}
	if (!commit_user_catalog_edit(std::move(before), label, error))
		return false;
	const auto published_revision = catalog_schema_revision();
	if (!request_save_schema_transactional(std::move(persistence_rollback),
		published_revision)) {
		std::lock_guard<std::mutex> lock(g_user_catalog_history.mutex);
		g_user_catalog_history.undo.clear();
		g_user_catalog_history.redo.clear();
		g_user_catalog_history.retained_bytes = 0;
		error = "The durable catalog save was rejected and the edit transaction was rolled back";
		return false;
	}
	return true;
}

template <typename Mutation>
inline bool perform_user_catalog_edit(const std::string& label, Mutation&& mutation,
	std::string& error) {
	return perform_user_catalog_edit(label, std::forward<Mutation>(mutation),
		[](const auto& result) { return static_cast<bool>(result); }, error);
}

inline bool user_catalog_can_undo(std::string* label = nullptr) {
	if (!catalog_mutation_available())
		return false;
	catalog_transaction_snapshot_t current;
	try {
		std::lock_guard<std::mutex> state_lock(g_state.mtx);
		current = {g_state.structs, g_state.enums, {}, g_state.active_struct,
			g_state.schema_revision, g_state.next_stable_id};
	} catch (const std::bad_alloc&) {
		return false;
	}
	std::lock_guard<std::mutex> lock(g_user_catalog_history.mutex);
	if (g_user_catalog_history.undo.empty())
		return false;
	const auto& entry = g_user_catalog_history.undo.back();
	if (entry.fence_revision != current.schema_revision ||
		entry.after_identity != catalog_snapshot_identity(current)) {
		g_user_catalog_history.undo.clear();
		g_user_catalog_history.redo.clear();
		g_user_catalog_history.retained_bytes = 0;
		return false;
	}
	if (label)
		*label = entry.label;
	return true;
}

inline bool user_catalog_can_redo(std::string* label = nullptr) {
	if (!catalog_mutation_available())
		return false;
	catalog_transaction_snapshot_t current;
	try {
		std::lock_guard<std::mutex> state_lock(g_state.mtx);
		current = {g_state.structs, g_state.enums, {}, g_state.active_struct,
			g_state.schema_revision, g_state.next_stable_id};
	} catch (const std::bad_alloc&) {
		return false;
	}
	std::lock_guard<std::mutex> lock(g_user_catalog_history.mutex);
	if (g_user_catalog_history.redo.empty())
		return false;
	const auto& entry = g_user_catalog_history.redo.back();
	if (entry.fence_revision != current.schema_revision ||
		entry.before_identity != catalog_snapshot_identity(current)) {
		g_user_catalog_history.undo.clear();
		g_user_catalog_history.redo.clear();
		g_user_catalog_history.retained_bytes = 0;
		return false;
	}
	if (label)
		*label = entry.label;
	return true;
}

inline bool apply_user_catalog_snapshot(const catalog_transaction_snapshot_t& target,
	std::uint64_t expected_revision, std::uint64_t expected_identity,
	std::uint64_t& published_revision, std::string& error) {
	if (!catalog_mutation_available()) {
		error = "Wait for the current catalog persistence operation to finish";
		return false;
	}
	bool target_bounded = false;
	try {
		target_bounded = catalog_snapshot_is_bounded(target);
	} catch (const std::bad_alloc&) {
		error = "Memory allocation for retained catalog validation failed";
		return false;
	}
	if (!target_bounded) {
		error = "The retained catalog state is invalid or exceeds its bounds";
		return false;
	}
	std::lock_guard<std::mutex> lock(g_state.mtx);
	catalog_transaction_snapshot_t current;
	catalog_transaction_snapshot_t restored;
	try {
		current = {g_state.structs, g_state.enums, {}, g_state.active_struct,
			g_state.schema_revision, g_state.next_stable_id};
		restored = target;
	} catch (const std::bad_alloc&) {
		error = "Memory allocation for the retained catalog state failed";
		return false;
	}
	if (current.schema_revision != expected_revision ||
		catalog_snapshot_identity(current) != expected_identity) {
		error = "The catalog changed after this edit; stale history was rejected";
		return false;
	}
	const std::uint64_t next_revision = current.schema_revision + 1;
	for (auto& definition : restored.structs) {
		const auto found = std::find_if(current.structs.begin(), current.structs.end(),
			[&](const struct_def_t& item) { return item.stable_id == definition.stable_id; });
		const std::uint64_t current_layout = found == current.structs.end()
			? 0 : found->layout_revision;
		definition.layout_revision = (std::max)(definition.layout_revision, current_layout) + 1;
	}
	g_state.structs = std::move(restored.structs);
	g_state.enums = std::move(restored.enums);
	g_state.active_struct = restored.active_struct;
	g_state.cached_values.clear();
	g_state.next_stable_id = (std::max)(current.next_stable_id, restored.next_stable_id);
	g_state.schema_revision = next_revision;
	for (const auto& definition : g_state.structs)
		if (!validate_structure_locked(definition).valid()) {
			g_state.structs = std::move(current.structs);
			g_state.enums = std::move(current.enums);
			g_state.cached_values = std::move(current.cached_values);
			g_state.active_struct = current.active_struct;
			g_state.schema_revision = current.schema_revision;
			g_state.next_stable_id = current.next_stable_id;
			error = "The retained edit no longer passes catalog layout validation";
			return false;
		}
	published_revision = next_revision;
	error.clear();
	return true;
}

inline bool user_catalog_undo(std::string& label, std::string& error) {
	user_catalog_edit_t entry;
	try {
		std::lock_guard<std::mutex> lock(g_user_catalog_history.mutex);
		if (g_user_catalog_history.undo.empty()) {
			error = "No catalog edit is available to undo";
			return false;
		}
		try {
			entry = g_user_catalog_history.undo.back();
		} catch (const std::bad_alloc&) {
			error = "Memory allocation for the retained undo state failed";
			return false;
		}
	} catch (const std::bad_alloc&) {
		error = "Memory allocation while selecting the retained undo state failed";
		return false;
	}
	label = entry.label;
	catalog_transaction_snapshot_t persistence_rollback;
	try {
		std::lock_guard<std::mutex> lock(g_state.mtx);
		persistence_rollback = {g_state.structs, g_state.enums, {}, g_state.active_struct,
			g_state.schema_revision, g_state.next_stable_id};
	} catch (const std::bad_alloc&) {
		error = "Memory allocation for the durable undo transaction failed";
		return false;
	}
	std::uint64_t published_revision = 0;
	if (!apply_user_catalog_snapshot(entry.before, entry.fence_revision,
		entry.after_identity, published_revision, error))
		return false;
	if (!request_save_schema_transactional(std::move(persistence_rollback),
		published_revision)) {
		error = "The durable undo save was rejected and the catalog transaction was rolled back";
		return false;
	}
	try {
		std::lock_guard<std::mutex> lock(g_user_catalog_history.mutex);
		if (g_user_catalog_history.undo.empty() ||
			g_user_catalog_history.undo.back().fence_revision != entry.fence_revision) {
			g_user_catalog_history.undo.clear();
			g_user_catalog_history.redo.clear();
			g_user_catalog_history.retained_bytes = 0;
			error = "History changed while the undo was applied";
			return false;
		}
		g_user_catalog_history.undo.pop_back();
		entry.fence_revision = published_revision;
		g_user_catalog_history.redo.push_back(std::move(entry));
		if (!g_user_catalog_history.undo.empty())
			g_user_catalog_history.undo.back().fence_revision = published_revision;
	} catch (const std::bad_alloc&) {
		std::lock_guard<std::mutex> lock(g_user_catalog_history.mutex);
		g_user_catalog_history.undo.clear();
		g_user_catalog_history.redo.clear();
		g_user_catalog_history.retained_bytes = 0;
	}
	error.clear();
	return true;
}

inline bool user_catalog_redo(std::string& label, std::string& error) {
	user_catalog_edit_t entry;
	try {
		std::lock_guard<std::mutex> lock(g_user_catalog_history.mutex);
		if (g_user_catalog_history.redo.empty()) {
			error = "No catalog edit is available to redo";
			return false;
		}
		try {
			entry = g_user_catalog_history.redo.back();
		} catch (const std::bad_alloc&) {
			error = "Memory allocation for the retained redo state failed";
			return false;
		}
	} catch (const std::bad_alloc&) {
		error = "Memory allocation while selecting the retained redo state failed";
		return false;
	}
	label = entry.label;
	catalog_transaction_snapshot_t persistence_rollback;
	try {
		std::lock_guard<std::mutex> lock(g_state.mtx);
		persistence_rollback = {g_state.structs, g_state.enums, {}, g_state.active_struct,
			g_state.schema_revision, g_state.next_stable_id};
	} catch (const std::bad_alloc&) {
		error = "Memory allocation for the durable redo transaction failed";
		return false;
	}
	std::uint64_t published_revision = 0;
	if (!apply_user_catalog_snapshot(entry.after, entry.fence_revision,
		entry.before_identity, published_revision, error))
		return false;
	if (!request_save_schema_transactional(std::move(persistence_rollback),
		published_revision)) {
		error = "The durable redo save was rejected and the catalog transaction was rolled back";
		return false;
	}
	try {
		std::lock_guard<std::mutex> lock(g_user_catalog_history.mutex);
		if (g_user_catalog_history.redo.empty() ||
			g_user_catalog_history.redo.back().fence_revision != entry.fence_revision) {
			g_user_catalog_history.undo.clear();
			g_user_catalog_history.redo.clear();
			g_user_catalog_history.retained_bytes = 0;
			error = "History changed while the redo was applied";
			return false;
		}
		g_user_catalog_history.redo.pop_back();
		entry.fence_revision = published_revision;
		g_user_catalog_history.undo.push_back(std::move(entry));
		if (!g_user_catalog_history.redo.empty())
			g_user_catalog_history.redo.back().fence_revision = published_revision;
	} catch (const std::bad_alloc&) {
		std::lock_guard<std::mutex> lock(g_user_catalog_history.mutex);
		g_user_catalog_history.undo.clear();
		g_user_catalog_history.redo.clear();
		g_user_catalog_history.retained_bytes = 0;
	}
	error.clear();
	return true;
}

inline void refresh_values() {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	ensure_preview_fixture();
	std::lock_guard<std::mutex> lock(g_state.mtx);
	if (!valid_index(g_state.active_struct, g_state.structs.size()))
		return;
	const auto& definition = g_state.structs[static_cast<std::size_t>(g_state.active_struct)];
	g_state.cached_values.resize(definition.fields.size());
	const std::uint64_t sequence = g_state.refresh_seq.fetch_add(1) + 1;
	for (std::size_t index = 0; index < definition.fields.size(); ++index) {
		const auto& field = definition.fields[index];
		const std::size_t length = (std::max)(std::size_t{1},
			field_scalar_size_locked(field) * field.array_count);
		std::vector<std::uint8_t> bytes(length);
		for (std::size_t offset = 0; offset < length; ++offset)
			bytes[offset] = static_cast<std::uint8_t>(
				(g_state.base_address + field.offset + offset + sequence * 3) & 0xFFu);
		if (field.type == field_type_t::ascii_string) {
			static constexpr char module[] = "AiDA_Target.exe";
			std::fill(bytes.begin(), bytes.end(), 0);
			std::copy_n(module, (std::min)(sizeof(module) - 1, bytes.size()), bytes.begin());
		}
		auto& value = g_state.cached_values[index];
		value.changed = !value.raw_bytes.empty() && value.raw_bytes != bytes;
		value.raw_bytes = std::move(bytes);
		value.display_text = format_field_value_locked(value.raw_bytes, field);
	}
	g_state.last_completed_seq.store(sequence, std::memory_order_release);
	g_state.refresh_in_flight.store(false, std::memory_order_release);
	aida::preview::re_hubs::action(aida::preview::re_hubs::domain_t::types, 6,
		"refresh_values", definition.name);
	return;
#else
	if (!driver_bridge::is_loaded()) {
		diag::log_tagged_fmt("dissector",
			"refresh_values skipped reason='driver_not_loaded'");
		return;
	}

	bool expected = false;
	if (!g_state.refresh_in_flight.compare_exchange_strong(expected, true)) {
		diag::log_tagged_fmt("dissector",
			"refresh_values skipped reason='in_flight'");
		return;
	}

	uint64_t base = 0;
	uint32_t total_size = 0;
	uint32_t target_pid = 0;
	int active = -1;
	std::size_t field_count = 0;
	{
		std::lock_guard<std::mutex> lk(g_state.mtx);
		active = g_state.active_struct;
		if (!valid_index(active, g_state.structs.size())) {
			g_state.refresh_in_flight.store(false);
			diag::log_tagged_fmt("dissector",
				"refresh_values skipped reason='no_active_struct'");
			return;
		}
		if (g_state.base_address == 0) {
			g_state.refresh_in_flight.store(false);
			diag::log_tagged_fmt("dissector",
				"refresh_values skipped reason='base_addr_zero' active=%d", active);
			return;
		}
		const auto& sd = g_state.structs[static_cast<std::size_t>(active)];
		if (sd.total_size == 0) {
			g_state.refresh_in_flight.store(false);
			diag::log_tagged_fmt("dissector",
				"refresh_values skipped reason='total_size_zero' name='%s'",
				sd.name.c_str());
			return;
		}
		base = g_state.base_address;
		total_size = sd.total_size;
		target_pid = driver_bridge::attached_pid();
		field_count = sd.fields.size();
	}

	uint64_t seq = g_state.refresh_seq.fetch_add(1) + 1;

	aida::infra::executor::submission_t sub;
	sub.owner_subsystem = "analysis";
	sub.label = "analysis.struct_dissector.refresh_values";
	sub.thread_class = "bounded_task";
	sub.domain = aida::infra::executor::domain_t::diagnostics;
	sub.priority = 4;
	sub.target_pid = target_pid;
	sub.body = [base, total_size, target_pid, active, seq, field_count]() {
		std::vector<uint8_t> block;
		bool ok = driver_bridge::read_memory_for(target_pid, base, total_size, block);
		if (!ok || block.size() != total_size) {
			g_state.refresh_in_flight.store(false);
			diag::log_tagged_fmt("dissector",
				"refresh_values_read_failed pid=%u base=0x%llX requested=%u returned=%zu",
				 target_pid,
				static_cast<unsigned long long>(base), total_size, block.size());
			return;
		}

		std::size_t changed_count = 0;
		std::size_t oor_count = 0;
		{
			std::lock_guard<std::mutex> lk(g_state.mtx);
			if (driver_bridge::attached_pid() != target_pid) {
				g_state.refresh_in_flight.store(false);
				diag::log_tagged_fmt("dissector",
					"refresh_values_discarded pid=%u active_pid=%u seq=%llu",
					target_pid, driver_bridge::attached_pid(),
					static_cast<unsigned long long>(seq));
				return;
			}
			if (!valid_index(active, g_state.structs.size())) {
				g_state.refresh_in_flight.store(false);
				return;
			}
			if (g_state.last_completed_seq.load() > seq) {
				g_state.refresh_in_flight.store(false);
				return;
			}
			const auto& sd = g_state.structs[static_cast<std::size_t>(active)];
			g_state.cached_values.resize(sd.fields.size());
			for (std::size_t i = 0; i < sd.fields.size(); ++i) {
				const auto& f = sd.fields[i];
				const std::size_t field_offset = static_cast<std::size_t>(f.offset);
				const std::size_t field_size = field_scalar_size_locked(f) * f.array_count;
				if (field_offset > block.size() || field_size > block.size() - field_offset) {
					g_state.cached_values[i].display_text = "<out of range>";
					g_state.cached_values[i].changed = false;
					++oor_count;
					continue;
				}
				const auto first = block.begin() + static_cast<std::ptrdiff_t>(field_offset);
				const auto last = first + static_cast<std::ptrdiff_t>(field_size);
				std::vector<uint8_t> raw(first, last);
				bool changed = (raw != g_state.cached_values[i].raw_bytes);
				g_state.cached_values[i].raw_bytes = std::move(raw);
				g_state.cached_values[i].display_text =
					format_field_value_locked(g_state.cached_values[i].raw_bytes, f);
				g_state.cached_values[i].changed = changed;
				if (changed) ++changed_count;
			}
			g_state.last_completed_seq.store(seq);
		}

		g_state.refresh_in_flight.store(false);
		diag::log_tagged_fmt("dissector",
			"refresh_values_done base=0x%llX size=%u fields=%zu changed=%zu oor=%zu seq=%llu",
			static_cast<unsigned long long>(base), total_size,
			field_count, changed_count, oor_count,
			static_cast<unsigned long long>(seq));
	};
	if (!aida::infra::executor::submit(std::move(sub)).submitted) {
		g_state.refresh_in_flight.store(false);
		diag::log_tagged_fmt("dissector",
			"refresh_values_post_failed base=0x%llX size=%u fields=%zu seq=%llu",
			static_cast<unsigned long long>(base), total_size, field_count,
			static_cast<unsigned long long>(seq));
	}
#endif
}

inline std::string auto_detect_type(uint64_t address, std::size_t size) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	if (size >= 16)
		return "byte_array";
	if ((address & 7u) == 0)
		return "pointer";
	if ((address & 3u) == 0)
		return "uint32";
	return "uint8";
#else
	if (!driver_bridge::is_loaded()) return "unknown";
	if (size == 0) size = 8;
	std::vector<uint8_t> bytes;
	if (!driver_bridge::read_memory(address, size, bytes) || bytes.empty())
		return "unknown";

	if (bytes.size() >= 8) {
		uint64_t v = 0;
		std::memcpy(&v, bytes.data(), 8);
		if (v >= 0x10000ULL && v < 0x00007FFFFFFFFFFFULL && (v & 0xFFF) == 0)
			return "pointer (aligned)";
		if (v >= 0x10000ULL && v < 0x00007FFFFFFFFFFFULL)
			return "pointer";
	}
	if (bytes.size() >= 4) {
		float fv = 0.f;
		std::memcpy(&fv, bytes.data(), 4);
		if (std::isfinite(fv) && std::fabs(fv) > 1e-30f && std::fabs(fv) < 1e30f)
			return "float32";
	}
	if (bytes.size() >= 4) {
		int32_t iv = 0;
		std::memcpy(&iv, bytes.data(), 4);
		if (iv >= -1000000 && iv <= 1000000)
			return "int32";
	}
	bool all_printable = true;
	for (std::size_t i = 0; i < bytes.size(); ++i) {
		if (bytes[i] == 0) break;
		if (bytes[i] < 0x20 || bytes[i] > 0x7E) { all_printable = false; break; }
	}
	if (all_printable && bytes.size() >= 4 && bytes[0] >= 0x20)
		return "ascii_string";

	return "byte_array";
#endif
}

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
inline bool write_preview_value(int field_index, const std::string& text) {
	std::lock_guard<std::mutex> lock(g_state.mtx);
	if (!valid_index(g_state.active_struct, g_state.structs.size()))
		return false;
	const auto& definition = g_state.structs[static_cast<std::size_t>(g_state.active_struct)];
	if (!valid_index(field_index, definition.fields.size()))
		return false;
	g_state.cached_values.resize(definition.fields.size());
	auto& value = g_state.cached_values[static_cast<std::size_t>(field_index)];
	value.display_text = text;
	value.raw_bytes.assign(text.begin(), text.end());
	value.changed = true;
	aida::preview::re_hubs::action(aida::preview::re_hubs::domain_t::types, 6,
		"write_field", definition.fields[static_cast<std::size_t>(field_index)].name);
	return true;
}
#endif

inline nlohmann::json schema_json_locked() {
	nlohmann::json root = {
		{"schema_version", 3},
		{"schema_revision", g_state.schema_revision},
		{"structures", nlohmann::json::array()},
		{"enums", nlohmann::json::array()}
	};
	for (const auto& definition : g_state.structs) {
		nlohmann::json item = {
			{"id", definition.stable_id}, {"revision", definition.layout_revision},
			{"name", definition.name},
			{"kind", definition.kind == structure_kind_t::union_type ? "union" : "struct"},
			{"packing", definition.packing}, {"alignment", definition.explicit_alignment},
			{"size", definition.total_size}, {"fields", nlohmann::json::array()}
		};
		for (const auto& field : definition.fields)
			item["fields"].push_back({
				{"id", field.stable_id}, {"name", field.name},
				{"type", static_cast<int>(field.type)}, {"offset", field.offset},
				{"size", field.size}, {"array_count", field.array_count},
				{"parent", field.parent_idx}, {"children", field.children},
				{"is_pointer", field.is_pointer}, {"pointer_target", field.pointer_target_struct},
				{"target_structure_id", field.target_structure_id}, {"enum_id", field.enum_id},
				{"referenced_type", field.referenced_type_name},
				{"bit_offset", field.bit_offset}, {"bit_width", field.bit_width},
				{"alignment", field.explicit_alignment}, {"description", field.description}
			});
		root["structures"].push_back(std::move(item));
	}
	for (const auto& enumeration : g_state.enums) {
		nlohmann::json item = {
			{"id", enumeration.stable_id}, {"name", enumeration.name},
			{"underlying_type", static_cast<int>(enumeration.underlying_type)},
			{"values", nlohmann::json::array()}
		};
		for (const auto& value : enumeration.values)
			item["values"].push_back({{"name", value.name}, {"value", value.value}});
		root["enums"].push_back(std::move(item));
	}
	return root;
}

inline std::string serialize_schema() {
	std::lock_guard<std::mutex> lock(g_state.mtx);
	return schema_json_locked().dump(2);
}

inline bool deserialize_schema(const std::string& encoded, std::string& error,
	std::uint64_t expected_schema_revision = 0) {
	if (encoded.empty() || encoded.size() > 16777216) {
		error = "Schema payload must contain 1 byte to 16 MiB";
		return false;
	}
	if (expected_schema_revision == 0) {
		std::lock_guard<std::mutex> lock(g_state.mtx);
		expected_schema_revision = g_state.schema_revision;
	}
	try {
		const auto root = nlohmann::json::parse(encoded,
			[](int depth, nlohmann::json::parse_event_t, nlohmann::json&) {
				return depth <= 64;
			});
		const int version = root.value("schema_version", 1);
		if (version < 1 || version > 3 || !root.contains("structures") || !root["structures"].is_array()) {
			error = "Unsupported or malformed structure schema";
			return false;
		}
		if (root["structures"].size() > 1024) {
			error = "Schema exceeds the 1,024 structure limit";
			return false;
		}
		std::vector<struct_def_t> structures;
		std::vector<enum_def_t> enums;
		std::set<std::uint64_t> identities;
		std::set<std::string> structure_names;
		std::set<std::string> enum_names;
		std::uint64_t max_identity = 0;
		std::size_t total_fields = 0;
		for (const auto& item : root["structures"]) {
			struct_def_t definition;
			definition.stable_id = item.value("id", std::uint64_t{0});
			definition.layout_revision = (std::max)(std::uint64_t{1}, item.value("revision", std::uint64_t{1}));
			definition.name = item.value("name", std::string{});
			definition.kind = item.value("kind", std::string{"struct"}) == "union"
				? structure_kind_t::union_type : structure_kind_t::structure;
			definition.packing = item.value("packing", std::uint16_t{0});
			definition.explicit_alignment = item.value("alignment", std::uint16_t{0});
			if (!item.contains("fields") || !item["fields"].is_array() ||
				item["fields"].size() > 65536 || total_fields + item["fields"].size() > 65536 ||
				definition.name.empty() || !structure_names.insert(definition.name).second) {
				error = "Schema contains invalid structure names or field counts";
				return false;
			}
			total_fields += item["fields"].size();
			for (const auto& entry : item["fields"]) {
				field_def_t field;
				field.stable_id = entry.value("id", std::uint64_t{0});
				field.name = entry.value("name", std::string{});
				const int type = entry.value("type", static_cast<int>(field_type_t::byte_array));
				if (!valid_index(type, static_cast<std::size_t>(field_type_t::COUNT))) {
					error = "Schema contains an unknown field type";
					return false;
				}
				field.type = static_cast<field_type_t>(type);
				field.offset = entry.value("offset", std::uint32_t{0});
				field.size = entry.value("size", static_cast<std::uint32_t>((std::max)(std::size_t{1}, field_type_size(field.type))));
				field.array_count = entry.value("array_count", std::uint32_t{1});
				field.parent_idx = entry.value("parent", -1);
				field.children = entry.value("children", std::vector<int>{});
				field.is_pointer = entry.value("is_pointer", field.type == field_type_t::pointer);
				field.pointer_target_struct = entry.value("pointer_target", -1);
				field.target_structure_id = entry.value("target_structure_id", std::uint64_t{0});
				field.enum_id = entry.value("enum_id", std::uint64_t{0});
				field.referenced_type_name = entry.value("referenced_type", std::string{});
				field.bit_offset = entry.value("bit_offset", std::uint16_t{0});
				field.bit_width = entry.value("bit_width", std::uint16_t{0});
				field.explicit_alignment = entry.value("alignment", std::uint16_t{0});
				field.description = entry.value("description", std::string{});
				definition.fields.push_back(std::move(field));
			}
			structures.push_back(std::move(definition));
		}
		if (root.contains("enums")) {
			if (!root["enums"].is_array() || root["enums"].size() > 4096) {
				error = "Schema enum catalog exceeds limits";
				return false;
			}
			for (const auto& item : root["enums"]) {
				enum_def_t enumeration;
				enumeration.stable_id = item.value("id", std::uint64_t{0});
				enumeration.name = item.value("name", std::string{});
				const int type = item.value("underlying_type", static_cast<int>(field_type_t::int32));
				if (enumeration.name.empty() || enumeration.name.size() > 256 ||
					!enum_names.insert(enumeration.name).second || type < static_cast<int>(field_type_t::int8) ||
					type > static_cast<int>(field_type_t::uint64) ||
					!item.contains("values") || !item["values"].is_array() || item["values"].size() > 65536) {
					error = "Schema contains an invalid enum";
					return false;
				}
				enumeration.underlying_type = static_cast<field_type_t>(type);
				std::set<std::string> value_names;
				for (const auto& value : item["values"]) {
					const std::string name = value.value("name", std::string{});
					if (name.empty() || name.size() > 256 || !value_names.insert(name).second) {
						error = "Schema contains invalid enum values";
						return false;
					}
					enumeration.values.push_back({name, value.value("value", std::int64_t{0})});
				}
				enums.push_back(std::move(enumeration));
			}
		}
		for (auto& definition : structures) {
			if (definition.stable_id == 0)
				definition.stable_id = ++max_identity;
			if (!identities.insert(definition.stable_id).second) {
				error = "Schema stable identities are not unique";
				return false;
			}
			max_identity = (std::max)(max_identity, definition.stable_id);
			for (auto& field : definition.fields) {
				if (field.stable_id == 0)
					field.stable_id = ++max_identity;
				if (!identities.insert(field.stable_id).second) {
					error = "Schema stable identities are not unique";
					return false;
				}
				max_identity = (std::max)(max_identity, field.stable_id);
			}
		}
		for (auto& definition : structures)
			for (auto& field : definition.fields)
				if (field.target_structure_id == 0 &&
					valid_index(field.pointer_target_struct, structures.size())) {
					const auto& target = structures[static_cast<std::size_t>(field.pointer_target_struct)];
					field.target_structure_id = target.stable_id;
					if (field.referenced_type_name.empty())
						field.referenced_type_name = target.name;
				}
		for (auto& enumeration : enums) {
			if (enumeration.stable_id == 0)
				enumeration.stable_id = ++max_identity;
			if (!identities.insert(enumeration.stable_id).second) {
				error = "Schema stable identities are not unique";
				return false;
			}
			max_identity = (std::max)(max_identity, enumeration.stable_id);
		}
		for (auto& definition : structures)
			for (auto& field : definition.fields)
				if (field.enum_id == 0 && field.type != field_type_t::pointer &&
					field.type != field_type_t::nested_struct && !field.referenced_type_name.empty()) {
					const auto enumeration = std::find_if(enums.begin(), enums.end(), [&](const enum_def_t& item) {
						return item.name == field.referenced_type_name;
					});
					if (enumeration != enums.end())
						field.enum_id = enumeration->stable_id;
				}
		std::lock_guard<std::mutex> lock(g_state.mtx);
		if (expected_schema_revision != 0 && g_state.schema_revision != expected_schema_revision) {
			error = "The structure catalog changed while the saved schema was loading";
			return false;
		}
		auto previous = std::move(g_state.structs);
		auto previous_enums = std::move(g_state.enums);
		g_state.structs = std::move(structures);
		g_state.enums = std::move(enums);
		bool valid = true;
		for (auto& definition : g_state.structs) {
			const auto validation = validate_structure_locked(definition);
			if (!validation.valid()) {
				valid = false;
				break;
			}
			definition.total_size = validation.computed_size;
		}
		if (!valid) {
			g_state.structs = std::move(previous);
			g_state.enums = std::move(previous_enums);
			error = "Schema layout validation failed";
			return false;
		}
		g_state.schema_revision = (std::max)(g_state.schema_revision + 1,
			root.value("schema_revision", std::uint64_t{1}) + 1);
		g_state.next_stable_id = max_identity == (std::numeric_limits<std::uint64_t>::max)()
			? 1 : max_identity + 1;
		g_state.active_struct = g_state.structs.empty() ? -1 : 0;
		g_state.cached_values.clear();
		error.clear();
		return true;
	} catch (const std::exception& exception) {
		error = exception.what();
		return false;
	}
}

inline std::string durable_schema_path() {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	return {};
#else
	const char* appdata = std::getenv("APPDATA");
	if (!appdata || !*appdata)
		return {};
	return (std::filesystem::path(appdata) / "AiDA" / "Standalone" / "types" /
		"dissector_schema_v3.json").string();
#endif
}

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
inline std::string g_preview_durable_schema;
#endif

inline bool request_persistence(bool save,
	std::shared_ptr<catalog_transaction_snapshot_t> transactional_rollback = {},
	std::uint64_t transactional_revision = 0) {
	bool expected = false;
	if (!g_state.persistence_in_flight.compare_exchange_strong(expected, true,
		std::memory_order_acq_rel, std::memory_order_acquire)) {
		if (save && transactional_rollback)
			static_cast<void>(rollback_catalog_transaction(
				std::move(*transactional_rollback), transactional_revision, true));
		return false;
	}
	auto cancellation = std::make_shared<std::atomic<bool>>(false);
	{
		std::lock_guard<std::mutex> lock(g_state.mtx);
		g_state.persistence_cancellation = cancellation;
		g_state.persistence_error = false;
		g_state.persistence_status = save ? "Saving structure schema..." : "Loading structure schema...";
	}
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	std::string error;
	if (save)
		g_preview_durable_schema = serialize_schema();
	const bool success = save || (!g_preview_durable_schema.empty() &&
		deserialize_schema(g_preview_durable_schema, error));
	{
		std::lock_guard<std::mutex> lock(g_state.mtx);
		g_state.persistence_error = !success;
		g_state.persistence_status = success ? (save ? "Structure schema saved" : "Structure schema loaded") :
			(error.empty() ? "No saved structure schema exists" : error);
		g_state.persistence_cancellation.reset();
	}
	g_state.persistence_in_flight.store(false, std::memory_order_release);
	return success;
#else
	const std::string path = durable_schema_path();
	if (path.empty()) {
		const bool rolled_back = !save || !transactional_rollback ||
			rollback_catalog_transaction(std::move(*transactional_rollback),
				transactional_revision, true);
		std::lock_guard<std::mutex> lock(g_state.mtx);
		g_state.persistence_error = true;
		g_state.persistence_status = rolled_back
			? "APPDATA is unavailable for structure schema persistence"
			: "APPDATA is unavailable and the exact catalog transaction could not be rolled back";
		g_state.persistence_cancellation.reset();
		g_state.persistence_in_flight.store(false, std::memory_order_release);
		return false;
	}
	std::string payload;
	std::uint64_t captured_revision = 0;
	{
		std::lock_guard<std::mutex> lock(g_state.mtx);
		captured_revision = g_state.schema_revision;
		if (save)
			payload = schema_json_locked().dump(2);
	}
	aida::infra::executor::submission_t submission;
	submission.owner_subsystem = "analysis";
	submission.label = save ? "analysis.struct_dissector.save_schema" :
		"analysis.struct_dissector.load_schema";
	submission.thread_class = "bounded_task";
	submission.domain = aida::infra::executor::domain_t::diagnostics;
	submission.priority = 3;
	submission.body = [save, path, payload = std::move(payload), captured_revision,
		cancellation, transactional_rollback, transactional_revision] {
		bool success = false;
		bool missing_catalog = false;
		std::string error;
		if (save) {
			const auto result = scanner_async_io::atomic_replace(path, payload, true, cancellation,
				[captured_revision] {
					std::lock_guard<std::mutex> lock(g_state.mtx);
					return g_state.schema_revision == captured_revision;
				});
			success = result.success;
			error = result.error;
		} else {
			std::error_code exists_error;
			missing_catalog = !std::filesystem::exists(path, exists_error) && !exists_error;
			if (missing_catalog)
				success = true;
			else {
				std::string encoded;
				const auto result = scanner_async_io::read_bounded(path, 16777216, cancellation, encoded);
				if (result.success && !cancellation->load(std::memory_order_acquire))
					success = deserialize_schema(encoded, error, captured_revision);
				else
					error = result.error.empty() ? "Structure schema load cancelled" : result.error;
			}
		}
		if (!success && save && transactional_rollback &&
			!rollback_catalog_transaction(std::move(*transactional_rollback),
				transactional_revision, true))
			error = error.empty()
				? "Structure schema persistence failed and exact transaction rollback was blocked"
				: error + "; exact transaction rollback was blocked";
		{
			std::lock_guard<std::mutex> lock(g_state.mtx);
			g_state.persistence_error = !success;
			g_state.persistence_status = success ? (save ? "Structure schema saved" :
				(missing_catalog ? "No saved structure schema; using an empty catalog" : "Structure schema loaded")) :
				(error.empty() ? "Structure schema persistence failed" : error);
			g_state.persistence_cancellation.reset();
		}
		g_state.persistence_in_flight.store(false, std::memory_order_release);
		if (!success)
			throw std::runtime_error(error.empty() ? "Structure schema persistence failed" : error);
	};
	const auto submitted = aida::infra::executor::submit(std::move(submission));
	if (!submitted.submitted) {
		const bool rolled_back = !save || !transactional_rollback ||
			rollback_catalog_transaction(std::move(*transactional_rollback),
				transactional_revision, true);
		std::lock_guard<std::mutex> lock(g_state.mtx);
		g_state.persistence_error = true;
		g_state.persistence_status = rolled_back ? submitted.reject_reason
			: submitted.reject_reason + "; exact catalog transaction rollback was blocked";
		g_state.persistence_cancellation.reset();
		g_state.persistence_in_flight.store(false, std::memory_order_release);
		return false;
	}
	aida::ui::task_center::task_registration_t registration;
	registration.owner = "analysis";
	registration.owner_view = "view.types.dissector";
	registration.owner_action = save ? "types.dissector.schema.save" :
		"types.dissector.schema.load";
	registration.label = save ? "Save structure schema" : "Load structure schema";
	registration.stage = "Queued";
	registration.progress = -1.f;
	registration.cancellation_is_safe = true;
	registration.callbacks.cancel = [cancellation] {
		cancellation->store(true, std::memory_order_release);
		return true;
	};
	static_cast<void>(aida::ui::task_center::register_executor_job(submitted.task_id,
		std::move(registration)));
	return true;
#endif
}

inline bool request_save_schema() {
	return request_persistence(true);
}

inline bool request_save_schema_transactional(catalog_transaction_snapshot_t snapshot,
	std::uint64_t expected_schema_revision) {
	std::shared_ptr<catalog_transaction_snapshot_t> rollback;
	try {
		rollback = std::make_shared<catalog_transaction_snapshot_t>(std::move(snapshot));
	} catch (const std::bad_alloc&) {
		static_cast<void>(rollback_catalog_transaction(std::move(snapshot),
			expected_schema_revision));
		return false;
	}
	try {
		return request_persistence(true, rollback, expected_schema_revision);
	} catch (const std::exception& exception) {
		const bool rolled_back = rollback_catalog_transaction(std::move(*rollback),
			expected_schema_revision, true);
		{
			std::lock_guard<std::mutex> lock(g_state.mtx);
			g_state.persistence_error = true;
			g_state.persistence_status = rolled_back
				? std::string("Structure schema persistence failed: ") + exception.what()
				: "Structure schema persistence failed and exact transaction rollback was blocked";
			g_state.persistence_cancellation.reset();
		}
		g_state.persistence_in_flight.store(false, std::memory_order_release);
		return false;
	} catch (...) {
		const bool rolled_back = rollback_catalog_transaction(std::move(*rollback),
			expected_schema_revision, true);
		{
			std::lock_guard<std::mutex> lock(g_state.mtx);
			g_state.persistence_error = true;
			g_state.persistence_status = rolled_back
				? "Structure schema persistence failed"
				: "Structure schema persistence failed and exact transaction rollback was blocked";
			g_state.persistence_cancellation.reset();
		}
		g_state.persistence_in_flight.store(false, std::memory_order_release);
		return false;
	}
}

inline bool request_load_schema() {
	return request_persistence(false);
}

inline void ensure_persistence_loaded() {
	bool expected = false;
	if (g_state.persistence_initial_load_requested.compare_exchange_strong(expected, true,
		std::memory_order_acq_rel, std::memory_order_acquire))
		request_load_schema();
}

inline bool cancel_persistence() {
	std::shared_ptr<std::atomic<bool>> cancellation;
	{
		std::lock_guard<std::mutex> lock(g_state.mtx);
		cancellation = g_state.persistence_cancellation;
	}
	if (!cancellation)
		return false;
	cancellation->store(true, std::memory_order_release);
	return true;
}

inline std::string c_identifier(std::string value, const std::string& fallback) {
	for (auto& character : value)
		if (!(character == '_' || (character >= '0' && character <= '9') ||
			(character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z')))
			character = '_';
	if (value.empty())
		value = fallback;
	if (value.front() >= '0' && value.front() <= '9')
		value.insert(value.begin(), '_');
	return value;
}

inline std::string c_field_type_locked(const field_def_t& field) {
	if (field.type == field_type_t::nested_struct) {
		const int target = structure_index_by_id_locked(field.target_structure_id);
		const std::string name = valid_index(target, g_state.structs.size())
			? g_state.structs[static_cast<std::size_t>(target)].name : field.referenced_type_name;
		return c_identifier(name, "anonymous_structure") + "_t";
	}
	if (field.enum_id != 0) {
		const int enumeration = enum_index_by_id_locked(field.enum_id);
		if (valid_index(enumeration, g_state.enums.size()))
			return c_identifier(g_state.enums[static_cast<std::size_t>(enumeration)].name,
				"anonymous_enum") + "_t";
	}
	if (field.type == field_type_t::pointer && !field.referenced_type_name.empty())
		return c_identifier(field.referenced_type_name, "void") + "_t*";
	switch (field.type) {
	case field_type_t::int8: return "int8_t";
	case field_type_t::uint8: return "uint8_t";
	case field_type_t::int16: return "int16_t";
	case field_type_t::uint16: return "uint16_t";
	case field_type_t::int32: return "int32_t";
	case field_type_t::uint32: return "uint32_t";
	case field_type_t::int64: return "int64_t";
	case field_type_t::uint64: return "uint64_t";
	case field_type_t::float32: return "float";
	case field_type_t::float64: return "double";
	case field_type_t::pointer: return "void*";
	case field_type_t::ascii_string: return "char";
	case field_type_t::utf16_string: return "char16_t";
	default: return "uint8_t";
	}
}

inline std::string export_to_c(int struct_idx) {
	constexpr std::size_t maximum_output = 64U * 1024U;
	std::lock_guard<std::mutex> lk(g_state.mtx);
	if (!valid_index(struct_idx, g_state.structs.size())) {
		diag::log_tagged_fmt("dissector",
			"export_to_c rejected reason='bad_idx' idx=%d", struct_idx);
		return {};
	}
	const auto& sd = g_state.structs[static_cast<std::size_t>(struct_idx)];
	const std::string type_name = c_identifier(sd.name, "anonymous_structure") + "_t";
	std::string out = "#include <cstddef>\n#include <cstdint>\n\n";
	if (sd.packing != 0)
		out += "#pragma pack(push, " + std::to_string(sd.packing) + ")\n";
	out += "typedef ";
	if (sd.explicit_alignment != 0)
		out += "alignas(" + std::to_string(sd.explicit_alignment) + ") ";
	out += sd.kind == structure_kind_t::union_type ? "union {\n" : "struct {\n";
	std::vector<const field_def_t*> fields;
	for (const auto& field : sd.fields)
		if (field.parent_idx < 0)
			fields.push_back(&field);
	std::stable_sort(fields.begin(), fields.end(), [](const field_def_t* left, const field_def_t* right) {
		return left->offset < right->offset;
	});
	std::uint32_t cursor = 0;
	std::size_t padding_index = 0;
	std::uint32_t bit_storage_offset = (std::numeric_limits<std::uint32_t>::max)();
	std::uint32_t bit_cursor = 0;
	for (const auto* field : fields) {
		if (sd.kind == structure_kind_t::structure && field->offset > cursor) {
			out += "    uint8_t __padding_" + std::to_string(padding_index++) + "[" +
				std::to_string(field->offset - cursor) + "];\n";
		}
		out += "    ";
		if (field->explicit_alignment != 0)
			out += "alignas(" + std::to_string(field->explicit_alignment) + ") ";
		const std::string declared_type = c_field_type_locked(*field);
		if (field->bit_width != 0) {
			if (bit_storage_offset != field->offset) {
				bit_storage_offset = field->offset;
				bit_cursor = 0;
			}
			if (field->bit_offset > bit_cursor)
				out += declared_type + " : " + std::to_string(field->bit_offset - bit_cursor) + ";\n    ";
			out += declared_type + " " +
				c_identifier(field->name, "field_" + std::to_string(field->offset)) +
				" : " + std::to_string(field->bit_width);
			bit_cursor = field->bit_offset + field->bit_width;
		} else {
			bit_storage_offset = (std::numeric_limits<std::uint32_t>::max)();
			bit_cursor = 0;
			out += declared_type + " " +
				c_identifier(field->name, "field_" + std::to_string(field->offset));
		}
		if (field->bit_width == 0 && field->array_count > 1)
			out += "[" + std::to_string(field->array_count) + "]";
		else if (field->bit_width == 0 && (field->type == field_type_t::ascii_string || field->type == field_type_t::utf16_string ||
			field->type == field_type_t::byte_array || field->type == field_type_t::padding))
			out += "[" + std::to_string(field->size) + "]";
		out += ";\n";
		if (out.size() > maximum_output)
			return {};
		std::uint32_t span = 0;
		checked_multiply_u32(static_cast<std::uint32_t>(field_scalar_size_locked(*field)), field->array_count, span);
		cursor = (std::max)(cursor, field->offset + span);
	}
	if (sd.kind == structure_kind_t::structure && sd.total_size > cursor)
		out += "    uint8_t __padding_" + std::to_string(padding_index) + "[" +
			std::to_string(sd.total_size - cursor) + "];\n";
	out += "} " + type_name + ";\n";
	if (sd.packing != 0)
		out += "#pragma pack(pop)\n";
	for (const auto* field : fields)
		if (field->bit_width == 0) {
			out += "static_assert(offsetof(" + type_name + ", " +
				c_identifier(field->name, "field_" + std::to_string(field->offset)) + ") == " +
				std::to_string(field->offset) + ");\n";
			if (out.size() > maximum_output)
				return {};
		}
	out += "static_assert(sizeof(" + type_name + ") == " + std::to_string(sd.total_size) + ");\n";
	diag::log_tagged_fmt("dissector",
		"export_to_c name='%s' fields=%zu bytes=%zu",
		sd.name.c_str(), sd.fields.size(), out.size());
	return out.size() <= maximum_output ? out : std::string{};
}

}
