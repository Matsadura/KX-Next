#include "hack.h"
#include "constants.h"
#include "../managers/process_memory_manager.h"
#include <thread>
#include <chrono>
#include <string>
#include <sstream>
#include <iomanip>
#include <atomic>

using namespace Constants::Process;
using namespace Constants::Offsets;
using namespace Constants::Scan;
using namespace Constants::Patterns;
using namespace Constants::Settings;

/**
 * to_hex_string - Converts an address to a hexadecimal string representation.
 * @address: The address to convert.
 * Returns a string containing the hexadecimal representation of the address.
 */
std::string to_hex_string(uintptr_t address)
{
    std::ostringstream oss;
    oss << "0x" << std::hex << std::uppercase << address;
    return (oss.str());
}

/**
 * Hack Constructor
 * Initializes the Hack class and sets up the status callback.
 */
Hack::Hack(std::function<void(const std::string&)> statusCallback)
    : m_statusCallback(std::move(statusCallback))
{
    // Initialize only members that don't require process interaction yet.
    initializeOffsets();
    // Actual process attachment and scanning happens in Initialize()
}

/**
 * Hack Destructor
 * Cleans up resources and detaches from the process if necessary.
 */
Hack::~Hack()
{
    reportStatus("INFO: Shutting down KX Next.");
    // Ensure detachment if Initialize() failed partially or wasn't called
    if (m_memoryManager.IsAttached())
        m_memoryManager.Detach();
}

/**
 * initializeOffsets - Sets up the pointer chain offsets for various game data.
 */
void Hack::initializeOffsets()
{
    m_xOffsets = { BYTE1, BYTE2, BYTE3, BYTE4, 0x120 };
    m_yOffsets = { BYTE1, BYTE2, BYTE3, BYTE4, 0x128 };
    m_zOffsets = { BYTE1, BYTE2, BYTE3, BYTE4, 0x124 };
    m_zHeight1Offsets = { BYTE1, BYTE2, BYTE3, BYTE4, 0x118 };
    m_zHeight2Offsets = { BYTE1, BYTE2, BYTE3, BYTE4, 0x114 };
    m_gravityOffsets = { BYTE1, BYTE2, BYTE3, 0x1FC };
    m_speedOffsets = { BYTE1, BYTE2, BYTE3, 0x220 };
    m_wallClimbOffsets = { BYTE1, BYTE2, BYTE3, 0x204 };
}

/**
 * Initialize - Performs process attachment and initial memory scans.
 *
 * Returns true if initialization was successful, false otherwise.
 */
bool Hack::Initialize()
{
    reportStatus("INFO: Starting KX Next initialization...");
    try {
        findProcess();
        performBaseScan();
        scanForPatterns();

        // Initialize cached bytes by reading initial game state
        // These reads are less critical, failure here doesn't stop initialization
        // but might affect initial state reporting in the UI.
        if (m_fogAddress)
        {
            if (!m_memoryManager.Read<byte>(m_fogAddress, m_fogByte))
                reportStatus("WARN: Failed to read initial fog state.");
        }
        if (m_objectClippingAddress)
        {
            if (!m_memoryManager.Read<byte>(m_objectClippingAddress, m_objectClippingByte))
                reportStatus("WARN: Failed to read initial object clipping state.");
        }
        if (m_fullStrafeAddress)
        {
            if (!m_memoryManager.Read<byte>(m_fullStrafeAddress, m_fullStrafeByte))
                reportStatus("WARN: Failed to read initial full strafe state.");
        }

        reportStatus("INFO: Initialization successful.");
        return (true);
    }
    catch (const HackInitializationError& e) {
        // Error already reported by the function that threw it.
        // Ensure detachment before returning failure.
        if (m_memoryManager.IsAttached())
            m_memoryManager.Detach();
        return (false);
    }
    catch (const std::exception& e) {
        reportStatus("ERROR: An unexpected standard error occurred during initialization - " + std::string(e.what()));
        if (m_memoryManager.IsAttached())
            m_memoryManager.Detach();
        return (false);
    }
    catch (...) {
        reportStatus("ERROR: An unknown error occurred during initialization.");
        if (m_memoryManager.IsAttached())
            m_memoryManager.Detach();
        return (false);
    }
}

/**
 * findProcess - Attaches to the Guild Wars 2 process.
 * Throws HackInitializationError if attachment fails.
 */
void Hack::findProcess()
{
    reportStatus("INFO: Searching for process: " + std::string(GW2_PROCESS_NAME_A));
    if (!m_memoryManager.Attach(GW2_PROCESS_NAME_W))
        throw HackInitializationError("Failed to attach to process '" + std::string(GW2_PROCESS_NAME_A) + "'.");

    reportStatus("INFO: Process handle obtained successfully.");
}

/**
 * performBaseScan - Scans for the base address location using pattern scanning.
 * Throws HackInitializationError if the scan fails after maximum attempts.
 */
void Hack::performBaseScan()
{
    reportStatus("INFO: Starting base address scan...");
    int scans = 0;
    bool locationFound = false;
    m_baseAddressLocation = 0; // Ensure reset before scan

    while (scans < MAX_BASE_SCAN_ATTEMPTS && !locationFound)
    {
        scans++;
        reportStatus("INFO: Scanning for base address location... (Attempt " + std::to_string(scans) + "/" + std::to_string(MAX_BASE_SCAN_ATTEMPTS) + ")");

        uintptr_t patternMatchAddress = m_memoryManager.ScanPatternModule(GW2_PROCESS_NAME_W, BASE_SCAN_PATTERN, BASE_SCAN_MASK);

        if (patternMatchAddress != 0)
        {
            // Calculate the address where the base pointer value is expected to be stored.
            uintptr_t potentialPtrLocation = patternMatchAddress - POINTER_LOCATION_OFFSET;

            uintptr_t pointerValue = 0;
            // Attempt to read the 8-byte pointer value from the calculated location.
            if (m_memoryManager.Read<uintptr_t>(potentialPtrLocation, pointerValue))
            {
                // Sanity check: Ensure the read pointer value is above the minimum threshold.
                if (pointerValue > BASE_ADDRESS_MIN_VALUE)
                {
                    m_baseAddressLocation = potentialPtrLocation; // Store the valid location
                    reportStatus("INFO: Base address location validated: " + to_hex_string(m_baseAddressLocation) + " (Value: " + to_hex_string(pointerValue) + ")");
                    locationFound = true; // Exit loop after successful validation
                }
                else
                    // Value read is 0 or too low, likely invalid or not yet initialized by the game.
                    reportStatus("WARN: Pointer location found (" + to_hex_string(potentialPtrLocation) + "), but value (" + to_hex_string(pointerValue) + ") is below minimum threshold. Retrying scan...");
            }
            else
                // Failed to read memory at the location derived from the pattern.
                reportStatus("WARN: Found potential pointer location (" + to_hex_string(potentialPtrLocation) + "), but failed to read the 8-byte value. Retrying scan...");
        }
        else
            reportStatus("INFO: Pattern not found in attempt " + std::to_string(scans));

        if (!locationFound)
            std::this_thread::sleep_for(std::chrono::milliseconds(BASE_SCAN_RETRY_DELAY_MS));
    } // End while loop

    if (!locationFound)
    {
        std::string errorMsg = "Failed to find or validate base address location after maximum attempts.";
        reportStatus("ERROR: " + errorMsg);
        m_baseAddressLocation = 0; // Ensure state reflects failure
        throw HackInitializationError(errorMsg);
    }
}

/**
 * scanForPatterns - Scans for feature-related patterns in the game's memory.
 * Throws HackInitializationError if any pattern scan fails.
 */
void Hack::scanForPatterns()
{
    reportStatus("INFO: Scanning for feature patterns...");
    std::string errorMsg;

    m_fogAddress = m_memoryManager.ScanPatternModule(GW2_PROCESS_NAME_W, FOG_PATTERN, FOG_MASK);
    if (m_fogAddress == 0)
    {
        errorMsg = "Failed to find Fog pattern."; reportStatus("ERROR: " + errorMsg);
        throw HackInitializationError(errorMsg);
    }
    m_fogAddress += 0x3; // Apply specific offset for the patch byte relative to pattern start

    m_objectClippingAddress = m_memoryManager.ScanPatternModule(GW2_PROCESS_NAME_W, OBJECT_CLIPPING_PATTERN, OBJECT_CLIPPING_MASK);
    if (m_objectClippingAddress == 0)
    {
        errorMsg = "Failed to find Object Clipping pattern."; reportStatus("ERROR: " + errorMsg);
        throw HackInitializationError(errorMsg);
    }
    // No offset needed for object clipping based on constants.h

    m_fullStrafeAddress = m_memoryManager.ScanPatternModule(GW2_PROCESS_NAME_W, FULL_STRAFE_PATTERN, FULL_STRAFE_MASK);
    if (m_fullStrafeAddress == 0)
    {
        errorMsg = "Failed to find Full Strafe pattern."; reportStatus("ERROR: " + errorMsg);
        throw HackInitializationError(errorMsg);
    }
    m_fullStrafeAddress += 0x2; // Apply specific offset for the patch byte relative to pattern start

    reportStatus("INFO: Feature patterns found successfully.");
}

/**
 * refreshAddresses - Refreshes all dynamic addresses based on the base address location.
 */
void Hack::refreshAddresses()
{
    if (!m_memoryManager.IsAttached() || m_baseAddressLocation == 0)
        return;

    m_xAddr = refreshAddr(m_xOffsets);
    m_yAddr = refreshAddr(m_yOffsets);
    m_zAddr = refreshAddr(m_zOffsets);
    m_zHeight1Addr = refreshAddr(m_zHeight1Offsets);
    m_zHeight2Addr = refreshAddr(m_zHeight2Offsets);
    m_gravityAddr = refreshAddr(m_gravityOffsets);
    m_speedAddr = refreshAddr(m_speedOffsets);
    m_wallClimbAddr = refreshAddr(m_wallClimbOffsets);
}

/**
 * readXYZ - Reads the current X, Y, Z position values from memory.
 */
void Hack::readXYZ()
{
    if (!m_memoryManager.IsAttached())
        return;
    if (m_xAddr != 0)
        m_memoryManager.Read<float>(m_xAddr, m_xValue);
    if (m_yAddr != 0)
        m_memoryManager.Read<float>(m_yAddr, m_yValue);
    if (m_zAddr != 0)
        m_memoryManager.Read<float>(m_zAddr, m_zValue);
}

/**
 * writeXYZ - Writes the specified X, Y, Z position values to memory.
 * @xValue: The X coordinate to write.
 * @yValue: The Y coordinate to write.
 * @zValue: The Z coordinate to write.
 */
void Hack::writeXYZ(float xValue, float yValue, float zValue)
{
    if (!m_memoryManager.IsAttached())
        return;
    if (m_xAddr != 0)
        m_memoryManager.Write<float>(m_xAddr, xValue);
    if (m_yAddr != 0)
        m_memoryManager.Write<float>(m_yAddr, yValue);
    if (m_zAddr != 0)
        m_memoryManager.Write<float>(m_zAddr, zValue);
}

/**
 * refreshAddr - Resolves a dynamic address using the base address location and provided offsets.
 * @offsets: The vector of offsets to traverse the pointer chain.
 * Returns: The resolved address, or 0 if resolution fails.
 */
uintptr_t Hack::refreshAddr(const std::vector<unsigned int>& offsets)
{
    return (m_memoryManager.ResolvePointerChain(m_baseAddressLocation, offsets));
}

/**
 * reportStatus - Reports a status message via the callback function.
 * @message: The status message to report.
 */
void Hack::reportStatus(const std::string& message)
{
    if (m_statusCallback)
        m_statusCallback(message);
}

// --- Feature Toggles / Handlers ---

/**
 * toggleFog - Enables or disables fog based on user preference.
 * @enable: True to enable fog, false to disable.
 */
void Hack::toggleFog(bool enable)
{
    if (!m_memoryManager.IsAttached() || m_fogAddress == 0)
        return;
    m_fogByte = enable ? NO_FOG_ON : NO_FOG_OFF;
    m_memoryManager.Write<byte>(m_fogAddress, m_fogByte);
}

/**
 * toggleObjectClipping - Enables or disables object clipping based on user preference.
 * @enable: True to enable object clipping, false to disable.
 */
void Hack::toggleObjectClipping(bool enable)
{
    if (!m_memoryManager.IsAttached() || m_objectClippingAddress == 0)
        return;
    m_objectClippingByte = enable ? OBJECT_CLIPPING_ON : OBJECT_CLIPPING_OFF;
    m_memoryManager.Write<byte>(m_objectClippingAddress, m_objectClippingByte);
}

/**
 * toggleFullStrafe - Enables or disables full strafe based on user preference.
 * @enable: True to enable full strafe, false to disable.
 */
void Hack::toggleFullStrafe(bool enable)
{
    if (!m_memoryManager.IsAttached() || m_fullStrafeAddress == 0)
        return;
    m_fullStrafeByte = enable ? FULL_STRAFE_ON : FULL_STRAFE_OFF;
    m_memoryManager.Write<byte>(m_fullStrafeAddress, m_fullStrafeByte);
}

/**
 * handleSprint - Enables or disables sprint based on user preference.
 * @userPrefersSprint: True if the user wants to sprint, false otherwise.
 */
void Hack::handleSprint(bool userPrefersSprint)
{
    if (!m_memoryManager.IsAttached() || m_speedAddr == 0)
        return;

    if (userPrefersSprint)
    {
        if (m_memoryManager.Read<float>(m_speedAddr, m_speed))
        {
            // Apply sprint only if not super sprinting and currently near normal speed
            if (m_speed >= (NORMAL_SPEED - 0.1f) && m_speed < (SPRINT_SPEED - 0.1f) && !m_wasSuperSprinting)
            {
                m_speed = SPRINT_SPEED;
                m_memoryManager.Write<float>(m_speedAddr, m_speed);
            }
        }
        m_wasSprinting = true;
    }
    else
    {
        // Revert from sprint only if we were sprinting and not super sprinting
        if (m_wasSprinting && !m_wasSuperSprinting)
        {
            if (m_memoryManager.Read<float>(m_speedAddr, m_speed))
            {
                // Revert only if current speed is actually sprint speed
                if (abs(m_speed - SPRINT_SPEED) < 0.1f)
                {
                    m_speed = NORMAL_SPEED;
                    m_memoryManager.Write<float>(m_speedAddr, m_speed);
                }
            }
        }
        m_wasSprinting = false;
    }
}

/**
 * handleSuperSprint - Enables or disables super sprint based on key state.
 * @enable: True if the super sprint key is held down, false otherwise.
 */
void Hack::handleSuperSprint(bool enable)
{
    if (!m_memoryManager.IsAttached() || m_speedAddr == 0)
        return;

    if (enable)
    {
        if (!m_wasSuperSprinting)
        { // Key just pressed
            if (m_memoryManager.Read<float>(m_speedAddr, m_speed))
            {
                // Save speed only if it's not already super sprint
                if (abs(m_speed - SUPER_SPRINT_SPEED) > 0.1f)
                    m_savedSpeed = m_speed;
                m_speed = SUPER_SPRINT_SPEED;
                m_memoryManager.Write<float>(m_speedAddr, m_speed);
                m_wasSuperSprinting = true;
            }
            else
            {
                reportStatus("WARN: Failed read speed before activating Super Sprint.");
                m_speed = SUPER_SPRINT_SPEED; // Try activating anyway
                m_memoryManager.Write<float>(m_speedAddr, m_speed);
                m_wasSuperSprinting = true;
            }
        }
        else
        { // Key held
            // Re-apply speed just in case it was changed externally
            m_speed = SUPER_SPRINT_SPEED;
            m_memoryManager.Write<float>(m_speedAddr, m_speed);
        }
    }
    else
    { // Key not pressed
        if (m_wasSuperSprinting)
        { // Key just released
            if (m_memoryManager.Read<float>(m_speedAddr, m_speed))
            {
                // Only restore if current speed is super sprint speed
                if (abs(m_speed - SUPER_SPRINT_SPEED) < 0.1f)
                {
                    // Restore to a valid speed
                    m_speed = (m_savedSpeed >= NORMAL_SPEED - 0.1f) ? m_savedSpeed : NORMAL_SPEED;
                    m_memoryManager.Write<float>(m_speedAddr, m_speed);
                }
            }
            else
            {
                reportStatus("WARN: Failed read speed before deactivating Super Sprint, setting to normal.");
                m_speed = NORMAL_SPEED; // Fallback
                m_memoryManager.Write<float>(m_speedAddr, m_speed);
            }
            m_wasSuperSprinting = false;
        }
        // else: Key wasn't pressed, do nothing
    }
}

/**
 * savePosition - Saves the current position from memory.
 */
void Hack::savePosition()
{
    readXYZ();
    m_xSave = m_xValue;
    m_ySave = m_yValue;
    m_zSave = m_zValue;
    if (m_xAddr != 0 && m_yAddr != 0 && m_zAddr != 0)
        reportStatus("INFO: Position saved.");
    else
        reportStatus("WARN: Position saved, but coordinate addresses might be invalid.");
}

/**
 * loadPosition - Loads the saved position into memory.
 */
void Hack::loadPosition()
{
    if (m_xAddr == 0 || m_yAddr == 0 || m_zAddr == 0)
    {
        reportStatus("ERROR: Cannot load position, coordinate addresses not resolved.");
        return;
    }
    // Basic check if position has ever been saved to non-zero coords
    if (m_xSave != 0.0f || m_ySave != 0.0f || m_zSave != 0.0f)
    {
        writeXYZ(m_xSave, m_ySave, m_zSave);
        reportStatus("INFO: Position loaded.");
    }
    else
        reportStatus("WARN: No position saved to load.");
}

/**
 * toggleInvisibility - Enables or disables the invisibility feature by modifying Z height.
 * @enable: True to enable invisibility, false to disable.
 */
void Hack::toggleInvisibility(bool enable)
{
    if (!m_memoryManager.IsAttached() || m_zHeight1Addr == 0)
        return;

    m_isInvisibilityActive = enable; // Update state flag first
    if (enable)
        m_invisibilityValue = INVISIBILITY_ON;
    else
    {
        // Nudge Y position slightly on disable - potentially helps refresh visibility
        if (m_yAddr != 0 && m_memoryManager.Read<float>(m_yAddr, m_yValue))
        {
            m_yValue += 3.f;
            m_memoryManager.Write<float>(m_yAddr, m_yValue);
        }
        m_invisibilityValue = INVISIBILITY_OFF;
    }
    m_memoryManager.Write<float>(m_zHeight1Addr, m_invisibilityValue);
}

/**
 * toggleWallClimb - Enables or disables the wall climbing feature by modifying wall climb speed.
 * @enable: True to enable wall climbing, false to disable.
 */
void Hack::toggleWallClimb(bool enable)
{
    if (!m_memoryManager.IsAttached() || m_wallClimbAddr == 0)
        return;
    m_isWallClimbActive = enable;
    m_wallClimbValue = enable ? WALLCLIMB_SPEED : WALLCLIMB_NORMAL_SPEED;
    m_memoryManager.Write<float>(m_wallClimbAddr, m_wallClimbValue);
}

/**
 * toggleClipping - Enables or disables the clipping feature by modifying Z height.
 * @enable: True to enable clipping, false to disable.
 */
void Hack::toggleClipping(bool enable)
{
    if (!m_memoryManager.IsAttached() || m_zHeight2Addr == 0)
        return;
    m_isClippingActive = enable;
    m_clippingValue = enable ? CLIPPING_ON : CLIPPING_OFF;
    m_memoryManager.Write<float>(m_zHeight2Addr, m_clippingValue);
}

/**
 * handleFly - Enables or disables the flying feature by modifying gravity.
 * @enable: True to enable flying, false to disable.
 */
void Hack::handleFly(bool enable)
{
    if (!m_memoryManager.IsAttached() || m_gravityAddr == 0)
        return;

    m_isFlyingActive = enable; // Update state flag first
    if (enable)
    {
        if (m_memoryManager.Read<float>(m_gravityAddr, m_flyValue))
        {
            // Apply only if not already flying
            if (m_flyValue < (FLY_SPEED - 0.1f))
            {
                m_flyValue = FLY_SPEED;
                m_memoryManager.Write<float>(m_gravityAddr, m_flyValue);
            }
        }
        else
        {
            reportStatus("WARN: Failed read gravity before enabling Fly.");
            m_flyValue = FLY_SPEED; // Attempt write anyway
            m_memoryManager.Write<float>(m_gravityAddr, m_flyValue);
        }
    }
    else
    { // Key released or not pressed
        // Check wasFlyingActive? Not strictly needed if we read first
        if (m_memoryManager.Read<float>(m_gravityAddr, m_flyValue))
        {
            // Only revert if currently at fly speed
            if (abs(m_flyValue - FLY_SPEED) < 0.1f)
            {
                m_flyValue = FLY_NORMAL_SPEED;
                m_memoryManager.Write<float>(m_gravityAddr, m_flyValue);
            }
        }
        else
        {
            reportStatus("WARN: Failed read gravity before disabling Fly.");
            m_flyValue = FLY_NORMAL_SPEED; // Attempt write anyway
            m_memoryManager.Write<float>(m_gravityAddr, m_flyValue);
        }
    }
}

/**
 * toggleAntiAfk - Enables or disables the anti-AFK feature.
 * @enable: True to enable anti-AFK, false to disable.
 */
void Hack::toggleAntiAfk(bool enable)
{
    m_isAntiAfkActive = enable;
}

/**
 * updateAntiAfk - Performs periodic input simulation to prevent AFK detection.
 * Should be called regularly in the main update loop.
 */
void Hack::updateAntiAfk()
{
    if (!m_isAntiAfkActive)
        return;

    const auto now = std::chrono::steady_clock::now();
    if (m_lastAntiAfkTick.time_since_epoch().count() == 0)
        m_lastAntiAfkTick = now;

    auto elapsed = std::chrono::duration_cast<std::chrono::minutes>(now - m_lastAntiAfkTick);
    if (elapsed.count() >= 4)
    {
        // Send 'Q' then 'D' to simulate small movement inputs
        m_memoryManager.PostVirtualKey('Q');
        m_memoryManager.PostVirtualKey('D');
        m_lastAntiAfkTick = now;
    }
}

// --- State Getters Implementation ---

/**
 * IsFogEnabled - Checks if the fog feature is currently active.
 *
 * Returns true if fog is active, false otherwise.
 */
bool Hack::IsFogEnabled() const
{
    return (m_fogByte == Constants::Settings::NO_FOG_ON);
}

/**
 * IsObjectClippingEnabled - Checks if the object clipping feature is currently active.
 *
 * Returns true if object clipping is active, false otherwise.
 */
bool Hack::IsObjectClippingEnabled() const
{
    return (m_objectClippingByte == Constants::Settings::OBJECT_CLIPPING_ON);
}

/**
 * IsFullStrafeEnabled - Checks if the full strafe feature is currently active.
 *
 * Returns true if full strafe is active, false otherwise.
 */
bool Hack::IsFullStrafeEnabled() const
{
    return (m_fullStrafeByte == Constants::Settings::FULL_STRAFE_ON);
}

/**
 * IsSuperSprinting - Checks if the super sprint feature is currently active.
 *
 * Returns true if super sprint is active, false otherwise.
 */
bool Hack::IsSuperSprinting() const
{
    return (m_wasSuperSprinting);
}

/**
 * IsInvisibilityEnabled - Checks if the invisibility feature is currently active.
 *
 * Returns true if invisibility is active, false otherwise.
 */
bool Hack::IsInvisibilityEnabled() const
{
    return (m_isInvisibilityActive);
}

/**
 * IsWallClimbEnabled - Checks if the wall climb feature is currently active.
 *
 * Returns true if wall climb is active, false otherwise.
 */
bool Hack::IsWallClimbEnabled() const
{
    return (m_isWallClimbActive);
}

/**
 * IsClippingEnabled - Checks if the clipping feature is currently active.
 *
 * Returns true if clipping is active, false otherwise.
 */
bool Hack::IsClippingEnabled() const
{
    return (m_isClippingActive);
}

/**
 * IsFlying - Checks if the flying feature is currently active.
 *
 * Returns true if flying is active, false otherwise.
 */
bool Hack::IsFlying() const
{
    return (m_isFlyingActive);
}

/**
 * IsAntiAfkEnabled - Checks if the anti-AFK feature is currently active.
 *
 * Returns true if anti-AFK is active, false otherwise.
 */
bool Hack::IsAntiAfkEnabled() const
{
    return (m_isAntiAfkActive);
}