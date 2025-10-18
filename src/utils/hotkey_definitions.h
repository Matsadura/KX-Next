#pragma once

#include <functional>
#include <utility>

class Hack; // Forward declaration needed for the action function signature

/**
 * HotkeyID - Enum representing unique identifiers for each hotkey.
 */
enum class HotkeyID
{
    NONE = -1, // Represents no hotkey being rebound
    SAVE_POS,
    LOAD_POS,
    TOGGLE_INVISIBILITY,
    TOGGLE_WALLCLIMB,
    TOGGLE_CLIPPING,
    TOGGLE_OBJECT_CLIPPING,
    TOGGLE_FULL_STRAFE,
    TOGGLE_NO_FOG,
    HOLD_SUPER_SPRINT,
    TOGGLE_SPRINT_PREF, // Hotkey to toggle the m_sprintEnabled preference flag
    HOLD_FLY
};

/**
 * HotkeyTriggerType - Enum representing how a hotkey is triggered.
 */
enum class HotkeyTriggerType
{
    ON_PRESS, // Trigger once when key goes down
    ON_HOLD   // Trigger continuously while key is held
};

/**
 * HotkeyInfo - Struct representing a hotkey's properties and action.
 */
struct HotkeyInfo
{
    using HotkeyAction = std::function<void(Hack&, bool)>;

    HotkeyID id = HotkeyID::NONE;
    const char* name = "";
    int defaultKeyCode = 0;
    int currentKeyCode = 0; // 0 = unbound
    HotkeyTriggerType triggerType = HotkeyTriggerType::ON_PRESS;
    HotkeyAction action{}; // empty by default

    HotkeyInfo() = default;

    HotkeyInfo(HotkeyID id_, const char* name_, int defaultKey, HotkeyTriggerType type_, HotkeyAction action_)
        : id(id_),
          name(name_),
          defaultKeyCode(defaultKey),
          currentKeyCode(0),
          triggerType(type_),
          action(std::move(action_))
    {}
};
