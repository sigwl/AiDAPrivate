#pragma once
#include "imgui/imgui.h"
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include <string>

class CKeybind
{
public:
	enum c_keybind_type : int { TOGGLE, HOLD, ALWAYS };
	int key = 0;
	c_keybind_type type = TOGGLE;
	const char* name = "none";
	bool enabled = false;
	bool waiting_for_input = false;

	explicit CKeybind(const char* value) : name(value ? value : "none") {}

	void update()
	{
		if (type == ALWAYS) enabled = true;
		else if (type == HOLD && key != 0) enabled = ImGui::IsKeyDown(static_cast<ImGuiKey>(key));
		else if (type == TOGGLE && key != 0 && ImGui::IsKeyPressed(static_cast<ImGuiKey>(key), false)) enabled = !enabled;
	}

	std::string get_key_name() const
	{
		if (key == 0) return "none";
		const char* value = ImGui::GetKeyName(static_cast<ImGuiKey>(key));
		return value && value[0] ? value : "none";
	}

	std::string get_name() const { return name ? name : "none"; }

	std::string get_type() const
	{
		if (type == TOGGLE) return "toggle";
		if (type == HOLD) return "hold";
		if (type == ALWAYS) return "always";
		return "none";
	}

	bool set_key()
	{
		if (ImGui::IsKeyPressed(ImGuiKey_Escape, false)) {
			key = 0;
			return true;
		}
		for (int candidate = ImGuiKey_NamedKey_BEGIN; candidate < ImGuiKey_NamedKey_END; ++candidate) {
			if (ImGui::IsKeyPressed(static_cast<ImGuiKey>(candidate), false)) {
				key = candidate;
				return true;
			}
		}
		return false;
	}
};
#else
#include "keybind.h"
#endif
#include "../core/ui/theme.hpp"
#include "../core/ui/motion.hpp"
#include "../core/ui/clock.hpp"
#include "../core/ui/transition.hpp"
#include "../core/ui/components.hpp"
#include "../core/ui/blur_layer.hpp"
#include "../core/ui/avatar.hpp"
#include "../core/ui/brand.hpp"
#include "../core/ui/empty_state.hpp"
#include "../core/ui/fonts.hpp"
#include "../core/ui/skeleton.hpp"
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include <cstdint>
struct ID3D11Device;
struct ID3D11ShaderResourceView;
using HWND = void*;
#else
#include <d3d11.h>
#endif
#include <atomic>

extern ID3D11Device* g_pd3dDevice;

struct helpers
{
	static int  active_tab;
	static int  active_subsection;
	static bool init;

	static ID3D11ShaderResourceView* icon_aim;
	static ID3D11ShaderResourceView* icon_see;
	static ID3D11ShaderResourceView* icon_misc;
	static ID3D11ShaderResourceView* icon_player;
	static ID3D11ShaderResourceView* icon_settings;
	static ID3D11ShaderResourceView* icon_solitude;


	static ID3D11ShaderResourceView* theme_rias;
	static ID3D11ShaderResourceView* theme_nagi;
	static ID3D11ShaderResourceView* theme_mio;
	static ID3D11ShaderResourceView* theme_kaneki;
	static bool themes_loaded;

	static int icon_w, icon_h;
	static bool icons_loaded;

	static bool tab(const char* label, int index, ImVec2 pos, ImVec2 size);
	static void begin_child(const char* str_id, ImVec2 pos, ImVec2 size, float alpha = 1.f, ImGuiWindowFlags flags = 0);
	static void end_child();
	static int  subsection(const char** labels, int count, ImVec2 pos);
	static int  subsection(const char** labels, int count, ImVec2 pos, int& state);
	static void add_key(const char* label, CKeybind* keybind);
	static void render_title();
};

namespace icon_loader
{
	bool load(const unsigned char* data, int size, ID3D11ShaderResourceView** out_srv, int* out_w, int* out_h, bool force_white = true);
	bool load_file(const char* path, ID3D11ShaderResourceView** out_srv, int* out_w, int* out_h, bool force_white = false);
}

extern HWND g_hwnd;

bool claim_chrome_shutdown_admission(const char* source);

struct render_section_state_t
{
	render_section_state_t() noexcept : value("idle") {}
	render_section_state_t(const render_section_state_t&) = delete;
	render_section_state_t& operator=(const render_section_state_t&) = delete;
	render_section_state_t& operator=(const char* section) noexcept
	{
		value.store(section ? section : "<null>", std::memory_order_release);
		return *this;
	}
	const char* c_str() const noexcept
	{
		const char* section = value.load(std::memory_order_acquire);
		return section ? section : "<null>";
	}
	operator const char*() const noexcept
	{
		return c_str();
	}
private:
	std::atomic<const char*> value;
};

extern render_section_state_t g_render_section;

namespace ui_input_gate
{
	bool any_fake_modal_open();
	bool popup_blocks_background_input();
	bool true_modal_open();
	bool chrome_input_blocked();
	bool splitter_input_blocked();

	inline bool mouse_clicked_left()
	{
		if (popup_blocks_background_input()) return false;
		return ImGui::IsMouseClicked(ImGuiMouseButton_Left);
	}

	inline bool mouse_clicked_right()
	{
		if (popup_blocks_background_input()) return false;
		return ImGui::IsMouseClicked(ImGuiMouseButton_Right);
	}

	inline bool mouse_clicked_middle()
	{
		if (popup_blocks_background_input()) return false;
		return ImGui::IsMouseClicked(ImGuiMouseButton_Middle);
	}
}
