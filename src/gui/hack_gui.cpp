#include "../gui/hack_gui.h"
#include "../hack/hack.h"
#include "../hack/constants.h"
#include "../gui/status_ui.h"
#include "../utils/key_utils.h"
#include "../utils/hotkey_definitions.h"
#include "../libs/imgui/imgui.h"
#include "../libs/imgui/imgui_internal.h"

#include <windows.h>
#include <shellapi.h>
#include <string>
#include <vector>
#include <mutex>


/**
 * Constructor for HackGUI.
 * @m_hack: Reference to the Hack instance for performing actions.
 * @m_rebinding_hotkey_id: ID of the hotkey currently being rebound, or NONE.
 * 
 * description - This class manages the graphical user interface for the KX Next hack,
 * allowing users to configure hotkeys, toggle features, and view logs.
 * It interacts with the Hack class to perform actions in the game.
 */
HackGUI::HackGUI(Hack& hack) : m_hack(hack), m_rebinding_hotkey_id(HotkeyID::NONE)
{
    // Define all available hotkeys and their default properties
    m_hotkeys = {
        {HotkeyID::SAVE_POS,             "Save Position",   Constants::Hotkeys::KEY_SAVEPOS,         HotkeyTriggerType::ON_PRESS, [](Hack& h, bool) { h.savePosition(); }},
        {HotkeyID::LOAD_POS,             "Load Position",   Constants::Hotkeys::KEY_LOADPOS,         HotkeyTriggerType::ON_PRESS, [](Hack& h, bool) { h.loadPosition(); }},
        {HotkeyID::TOGGLE_INVISIBILITY,  "Invisibility",    Constants::Hotkeys::KEY_INVISIBILITY,    HotkeyTriggerType::ON_PRESS, [](Hack& h, bool) { h.toggleInvisibility(!h.IsInvisibilityEnabled()); }},
        {HotkeyID::TOGGLE_WALLCLIMB,     "Wall Climb",      Constants::Hotkeys::KEY_WALLCLIMB,       HotkeyTriggerType::ON_PRESS, [](Hack& h, bool) { h.toggleWallClimb(!h.IsWallClimbEnabled()); }},
        {HotkeyID::TOGGLE_CLIPPING,      "Clipping",        Constants::Hotkeys::KEY_CLIPPING,        HotkeyTriggerType::ON_PRESS, [](Hack& h, bool) { h.toggleClipping(!h.IsClippingEnabled()); }},
        {HotkeyID::TOGGLE_OBJECT_CLIPPING,"Object Clipping", Constants::Hotkeys::KEY_OBJECT_CLIPPING, HotkeyTriggerType::ON_PRESS, [](Hack& h, bool) { h.toggleObjectClipping(!h.IsObjectClippingEnabled()); }},
        {HotkeyID::TOGGLE_FULL_STRAFE,   "Full Strafe",     Constants::Hotkeys::KEY_FULL_STRAFE,     HotkeyTriggerType::ON_PRESS, [](Hack& h, bool) { h.toggleFullStrafe(!h.IsFullStrafeEnabled()); }},
        {HotkeyID::TOGGLE_NO_FOG,        "No Fog",          Constants::Hotkeys::KEY_NO_FOG,          HotkeyTriggerType::ON_PRESS, [](Hack& h, bool) { h.toggleFog(!h.IsFogEnabled()); }},
        {HotkeyID::HOLD_SUPER_SPRINT,    "Super Sprint",    Constants::Hotkeys::KEY_SUPER_SPRINT,    HotkeyTriggerType::ON_HOLD,  [](Hack& h, bool held) { h.handleSuperSprint(held); }},
        {HotkeyID::TOGGLE_SPRINT_PREF,   "Sprint",          Constants::Hotkeys::KEY_SPRINT,          HotkeyTriggerType::ON_PRESS, [this](Hack& /*h*/, bool) { this->m_sprintEnabled = !this->m_sprintEnabled; }}, // Toggles the GUI preference flag
        {HotkeyID::HOLD_FLY,             "Fly",             Constants::Hotkeys::KEY_FLY,             HotkeyTriggerType::ON_HOLD,  [](Hack& h, bool held) { h.handleFly(held); }}
    };

    // TODO: Load saved currentKeyCode values from a config file here, overwriting the defaults set in HotkeyInfo constructor
}

/**
 * RenderHotkeyControl - Renders the UI controls for a single hotkey.
 * @hotkey: Reference to the HotkeyInfo struct representing the hotkey to render.
 */
void HackGUI::RenderHotkeyControl(HotkeyInfo& hotkey)
{
    ImGui::Text("%s:", hotkey.name);
    ImGui::SameLine(150.0f); // Alignment

    if (m_rebinding_hotkey_id == hotkey.id)
        ImGui::TextDisabled("<Press any key>");
    else
    {
        // Display key name, adding '*' for hold actions
        const char* baseKeyName = GetKeyName(hotkey.currentKeyCode);
        if (hotkey.triggerType == HotkeyTriggerType::ON_HOLD)
        {
            std::string keyNameWithIndicator = std::string(baseKeyName) + "*";
            ImGui::Text("%s", keyNameWithIndicator.c_str());
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("Hold");
        } 
        else
            ImGui::Text("%s", baseKeyName);
        ImGui::SameLine(280.0f); // Alignment

        // Create a unique ID for the button using the hotkey name
        std::string button_label = "Change##" + std::string(hotkey.name);
        if (ImGui::Button(button_label.c_str()))
            m_rebinding_hotkey_id = hotkey.id; // Set the ID of the hotkey being rebound
    }
}

/**
 * RenderAlwaysOnTop - Renders the "Always on Top" checkbox and manages window z-order.
 */
void HackGUI::RenderAlwaysOnTop()
{
    static bool always_on_top_checkbox = false;
    static bool current_window_is_topmost = false;
    HWND current_window_hwnd = nullptr;

    ImGuiWindow* current_imgui_win = ImGui::GetCurrentWindowRead();
    if (current_imgui_win && current_imgui_win->Viewport)
        current_window_hwnd = (HWND)current_imgui_win->Viewport->PlatformHandleRaw;

    ImGui::Checkbox("Always on Top", &always_on_top_checkbox);

    if (current_window_hwnd)
    {
        HWND insert_after = always_on_top_checkbox ? HWND_TOPMOST : HWND_NOTOPMOST;
        bool should_be_topmost = always_on_top_checkbox;

        if (should_be_topmost != current_window_is_topmost)
        {
            ::SetWindowPos(current_window_hwnd, insert_after, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
            current_window_is_topmost = should_be_topmost;
        }
    }
    ImGui::Separator();
    ImGui::Spacing();
}

/**
 * HandleHotkeys - Processes registered hotkeys and triggers their actions.
 */
void HackGUI::HandleHotkeys()
{
    // Don't process hotkeys if currently rebinding one
    if (m_rebinding_hotkey_id != HotkeyID::NONE)
        return;

    for (const auto& hotkey : m_hotkeys)
    {
        if (hotkey.currentKeyCode == 0 || !hotkey.action) // Skip unbound or unassigned actions
            continue;

        SHORT keyState = GetAsyncKeyState(hotkey.currentKeyCode);

        switch (hotkey.triggerType)
        {
            case HotkeyTriggerType::ON_PRESS:
                // Check the least significant bit (1 means pressed *since the last call*)
                if (keyState & 1)
                    hotkey.action(m_hack, true); // Pass true for pressed state
                break;

            case HotkeyTriggerType::ON_HOLD:
                // Check the most significant bit (1 means currently held down)
                bool isHeld = (keyState & 0x8000) != 0;
                hotkey.action(m_hack, isHeld); // Pass the current hold state
                break;
        }
    }
}

/**
 * HandleHotkeyRebinding - Captures key input for rebinding hotkeys.
 */
void HackGUI::HandleHotkeyRebinding()
{
    if (m_rebinding_hotkey_id == HotkeyID::NONE)
        return;

    int captured_vk = -1; // -1 means no key captured yet

    // Check special keys first
    if (GetAsyncKeyState(VK_ESCAPE) & 1)
        captured_vk = VK_ESCAPE; // Special value to indicate cancellation
    else if ((GetAsyncKeyState(VK_DELETE) & 1) || (GetAsyncKeyState(VK_BACK) & 1))
        captured_vk = 0; // 0 means unbind
    else
    {
        // Iterate through common key codes to find the first pressed key
        for (int vk = VK_MBUTTON; vk < VK_OEM_CLEAR; ++vk) {
            // Skip keys that interfere, are unsuitable, or handled above
            if (vk == VK_ESCAPE || vk == VK_DELETE || vk == VK_BACK ||
                vk == VK_LBUTTON || vk == VK_RBUTTON || // Avoid UI clicks binding easily
                vk == VK_SHIFT || vk == VK_CONTROL || vk == VK_MENU || // Prefer specific L/R versions if needed, though GetKeyName handles these
                vk == VK_CAPITAL || vk == VK_NUMLOCK || vk == VK_SCROLL) // State keys are poor choices
                continue;
            // Check if key was pressed *since the last call*
            if (GetAsyncKeyState(vk) & 1)
            {
                captured_vk = vk;
                break; // Found the first pressed key
            }
        }
    }

    // If a key was captured or an action key (Esc/Del/Back) was pressed
    if (captured_vk != -1)
    {
        if (captured_vk != VK_ESCAPE)
        { // If not cancelling
            // Find the hotkey being rebound in the vector
            for (auto& hotkey : m_hotkeys)
            {
                if (hotkey.id == m_rebinding_hotkey_id)
                {
                    hotkey.currentKeyCode = captured_vk; // Assign the captured key (or 0 for unbind)
                    // TODO: Save updated hotkeys to config file here
                    break; // Found and updated
                }
            }
        }
        // Reset rebinding state regardless of whether we assigned or cancelled
        m_rebinding_hotkey_id = HotkeyID::NONE;
    }
}

/**
 * RenderTogglesSection - Renders the toggles section of the GUI.
 */
void HackGUI::RenderTogglesSection()
{
    if (ImGui::CollapsingHeader("Toggles", ImGuiTreeNodeFlags_DefaultOpen))
    {
        bool tempState = false; // Temporary variable for ImGui interaction

        tempState = m_hack.IsFogEnabled();
        if (ImGui::Checkbox("No Fog", &tempState))
            m_hack.toggleFog(tempState);

        tempState = m_hack.IsObjectClippingEnabled();
        if (ImGui::Checkbox("Object Clipping", &tempState))
            m_hack.toggleObjectClipping(tempState);

        tempState = m_hack.IsFullStrafeEnabled();
        if (ImGui::Checkbox("Full Strafe", &tempState))
            m_hack.toggleFullStrafe(tempState);

        // Sprint checkbox controls the user preference flag
        ImGui::Checkbox("Sprint", &m_sprintEnabled);

        tempState = m_hack.IsInvisibilityEnabled();
        if (ImGui::Checkbox("Invisibility (Mobs)", &tempState))
            m_hack.toggleInvisibility(tempState);

        tempState = m_hack.IsWallClimbEnabled();
        if (ImGui::Checkbox("Wall Climb", &tempState))
            m_hack.toggleWallClimb(tempState);

        tempState = m_hack.IsClippingEnabled();
        if (ImGui::Checkbox("Clipping", &tempState))
            m_hack.toggleClipping(tempState);

        ImGui::Spacing();
    }
}

/**
 * RenderActionsSection - Renders the actions section of the GUI.
 */
void HackGUI::RenderActionsSection()
{
    if (ImGui::CollapsingHeader("Actions", ImGuiTreeNodeFlags_DefaultOpen))
    {
        float button_width = ImGui::GetContentRegionAvail().x * 0.48f; // Approx half width
        if (ImGui::Button("Save Position", ImVec2(button_width, 0)))
            m_hack.savePosition();
        ImGui::SameLine();
        if (ImGui::Button("Load Position", ImVec2(-1.0f, 0)))
            m_hack.loadPosition(); // Fill remaining
        ImGui::Spacing();
    }
}

/**
 * RenderHotkeysSection - Renders the hotkeys configuration section of the GUI.
 */
void HackGUI::RenderHotkeysSection()
{
    if (ImGui::CollapsingHeader("Hotkeys"))
    {
        // Display rebinding prompt if active
        if (m_rebinding_hotkey_id != HotkeyID::NONE)
        {
            const char* rebinding_name = "Unknown"; // Fallback
            for (const auto& hk : m_hotkeys)
            {
                if (hk.id == m_rebinding_hotkey_id)
                {
                    rebinding_name = hk.name;
                    break;
                }
            }
            ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), "Rebinding '%s'. Press a key (ESC to cancel, DEL/BKSP to clear)...", rebinding_name);
            ImGui::Separator();
        }

        // Dim controls while rebinding
        bool disable_controls = (m_rebinding_hotkey_id != HotkeyID::NONE);
        if (disable_controls)
        {
            ImGui::PushItemFlag(ImGuiItemFlags_Disabled, true);
            ImGui::PushStyleVar(ImGuiStyleVar_Alpha, ImGui::GetStyle().Alpha * 0.5f);
        }

        // Iterate through hotkeys and render controls
        for (auto& hotkey : m_hotkeys)
            RenderHotkeyControl(hotkey);


        if (disable_controls) 
        {
            ImGui::PopItemFlag();
            ImGui::PopStyleVar();
        }
        ImGui::Separator();
        ImGui::Spacing();

        // Buttons for defaults and unbinding
        if (ImGui::Button("Apply Recommended Defaults"))
        {
            for (auto& hotkey : m_hotkeys)
                hotkey.currentKeyCode = hotkey.defaultKeyCode;
            // TODO: Save updated hotkeys to config file
        }
        ImGui::SameLine();
        if (ImGui::Button("Unbind All"))
        {
            for (auto& hotkey : m_hotkeys)
                hotkey.currentKeyCode = 0; // 0 represents unbound
            // TODO: Save updated hotkeys to config file
        }
        ImGui::Spacing();
    }
}

/**
 * RenderLogSection - Renders the log section of the GUI.
 */
void HackGUI::RenderLogSection()
{
    // Assumes StatusUI is still used for logging until Step 1 is done.
    // If Step 1 (ILogger) was done, this would pull from the logger instance.
    if (ImGui::CollapsingHeader("Log", ImGuiTreeNodeFlags_None))
    { // Start collapsed
        ImGui::BeginChild("LogScrollingRegion", ImVec2(0, 100), true, ImGuiWindowFlags_HorizontalScrollbar);
        {
            std::vector<std::string> current_messages = StatusUI::GetMessages(); // <-- Keep using StatusUI for now

            for (const auto& msg : current_messages)
            {
                ImVec4 color = ImGui::GetStyleColorVec4(ImGuiCol_Text); // Default
                if (msg.rfind("ERROR:", 0) == 0)
                    color = ImVec4(1.0f, 0.4f, 0.4f, 1.0f); // Red
                else if (msg.rfind("WARN:", 0) == 0)
                    color = ImVec4(1.0f, 1.0f, 0.4f, 1.0f); // Yellow
                else if (msg.rfind("INFO:", 0) == 0)
                    color = ImVec4(0.5f, 1.0f, 0.5f, 1.0f); // Green
                ImGui::TextColored(color, "%s", msg.c_str());
            }
            // Auto-scroll
            if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - ImGui::GetTextLineHeight() * 2)
                ImGui::SetScrollHereY(1.0f);
        }
        ImGui::EndChild();

        if (ImGui::Button("Clear Log"))
            StatusUI::ClearMessages(); // <-- Keep using StatusUI for now
        ImGui::Spacing();
    }
}

/**
 * RenderInfoSection - Renders the info section of the GUI with links.
 */
void HackGUI::RenderInfoSection()
{
    if (ImGui::CollapsingHeader("Info"))
    {
        ImGui::Text("KX Next by Matsadura, Originally by Krixx");
        ImGui::Text("Consider the paid version at kxtools.xyz!");
        ImGui::Separator();

        // GitHub Link
        ImGui::Text("GitHub:");
        ImGui::SameLine();
        if (ImGui::Button("Repository"))
            ShellExecuteA(NULL, "open", "https://github.com/Matsadura/KX-Next", NULL, NULL, SW_SHOWNORMAL);

        // kxtools.xyz Link
        ImGui::Text("Website:");
        ImGui::SameLine();
        if (ImGui::Button("kxtools.xyz"))
             ShellExecuteA(NULL, "open", "https://kxtools.xyz", NULL, NULL, SW_SHOWNORMAL);

        // Discord Link
        ImGui::Text("Discord:");
        ImGui::SameLine();
        if (ImGui::Button("Join Server"))
             ShellExecuteA(NULL, "open", "https://discord.gg/z92rnB4kHm", NULL, NULL, SW_SHOWNORMAL);
    }
}

/**
 * renderUI - Main rendering function for the GUI.
 * Returns true if the user requested to exit (closed the window).
 */
bool HackGUI::renderUI()
{
    static bool main_window_open = true;
    bool exit_requested = false;

    const float min_window_width = 400.0f;
    ImGui::SetNextWindowSizeConstraints(ImVec2(min_window_width, 0.0f), ImVec2(FLT_MAX, FLT_MAX));

    ImGuiWindowFlags window_flags = 0;
    ImGui::Begin("KX Next", &main_window_open, window_flags);

    if (!main_window_open)
        exit_requested = true; // Request exit if user closes window

    RenderAlwaysOnTop();

    m_hack.refreshAddresses(); // Ensure pointers are valid before reading/writing
    HandleHotkeys();           // Process registered hotkeys
    HandleHotkeyRebinding();   // Handle input if rebinding

    // Apply continuous states based on user preference toggles
    m_hack.handleSprint(m_sprintEnabled);

    // Render UI sections
    RenderTogglesSection();
    RenderActionsSection();
    RenderHotkeysSection();
    RenderLogSection();
    RenderInfoSection();

    ImGui::End();

    return (exit_requested);
}