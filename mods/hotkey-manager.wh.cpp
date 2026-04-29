// ==WindhawkMod==
// @id              scalpel-hotkey-manager
// @name            Scalpel Hotkey Manager
// @description     Zero-latency interception and remapping of protected Windows OS hotkeys (Win+Shift+S).
// @version         1.0.1
// @author          vfxturjo
// @github          https://github.com/zunaidFarouque
// @include         explorer.exe
// @include         windhawk.exe
// @compilerOptions -lcomctl32 -loleaut32 -lole32 -lversion
// ==/WindhawkMod==

// ==WindhawkModReadme==
/*
# Scalpel Hotkey Manager
A zero-daemon, zero-latency interceptor for protected Windows hotkeys.
Operates purely via API hooking (`RegisterHotKey`) and Taskbar subclassing.

## The 4 Test Pillars included in Settings:
1. **Normal Layer:** `Ctrl+Alt+I` -> Opens Notepad.
2. **Upper Layer:** `Win+W` -> Opens Calculator (tests `Win` key masking).
3. **Blocking Test:** `Win+Shift+S` set to `ACTION_NOTHING` (Silently kills the
Snipping Tool).
4. **Remapping Test:** `Win+Shift+S` set to `ACTION_START_PROCESS` (Overrides
Snipping tool and launches Paint. Edit the path to launch
Flameshot/ZeroSnip.bat).

Need more built-in predefined shortcuts (such as media/display/system actions)?
Open a request at: https://github.com/zunaidFarouque/windhawk-mods
*/
// ==/WindhawkModReadme==

// ==WindhawkModSettings==
/*
- HotkeyActions:
  - - Hotkey: "Ctrl+Alt+I"
      $name: Hotkey
      $description: "Hotkey (e.g., Win+Shift+S)"
    - Action: "ACTION_START_PROCESS"
      $name: Action to Perform
      $options:
      - ACTION_NOTHING: Block / Do Nothing
      - ACTION_START_PROCESS: Run Custom App / File / URL
      - ACTION_VOL_UP: Volume Up
      - ACTION_VOL_DOWN: Volume Down
      - ACTION_VOL_MUTE: Toggle Mute
      - ACTION_MEDIA_PLAY: Media Play / Pause
      - ACTION_MEDIA_NEXT: Next Track
      - ACTION_MEDIA_PREV: Previous Track
      - ACTION_BRIGHTNESS_UP: Brightness Up
      - ACTION_BRIGHTNESS_DOWN: Brightness Down
      - ACTION_SLEEP_DISPLAY: Sleep Display
      - ACTION_LOCK_PC: Lock PC
      - ACTION_SHOW_DESKTOP: Show Desktop
      - ACTION_TASK_MANAGER: Open Task Manager
      - ACTION_VD_NEXT: Next Virtual Desktop
      - ACTION_VD_PREV: Previous Virtual Desktop
    - Args: "notepad.exe"
      $name: Target Path / Arguments
      $description: "Only used if Action is 'Run Custom App'. Enter your .exe, .bat, or URL here."
  - - Hotkey: "Win+Shift+S"
      $name: Hotkey
      $description: "Hotkey (e.g., Win+Shift+S)"
    - Action: "ACTION_START_PROCESS"
      $name: Action to Perform
      $options:
      - ACTION_NOTHING: Block / Do Nothing
      - ACTION_START_PROCESS: Run Custom App / File / URL
      - ACTION_VOL_UP: Volume Up
      - ACTION_VOL_DOWN: Volume Down
      - ACTION_VOL_MUTE: Toggle Mute
      - ACTION_MEDIA_PLAY: Media Play / Pause
      - ACTION_MEDIA_NEXT: Next Track
      - ACTION_MEDIA_PREV: Previous Track
      - ACTION_BRIGHTNESS_UP: Brightness Up
      - ACTION_BRIGHTNESS_DOWN: Brightness Down
      - ACTION_SLEEP_DISPLAY: Sleep Display
      - ACTION_LOCK_PC: Lock PC
      - ACTION_SHOW_DESKTOP: Show Desktop
      - ACTION_TASK_MANAGER: Open Task Manager
      - ACTION_VD_NEXT: Next Virtual Desktop
      - ACTION_VD_PREV: Previous Virtual Desktop
    - Args: "mspaint.exe"
      $name: Target Path / Arguments
      $description: "Only used if Action is 'Run Custom App'. Enter your .exe, .bat, or URL here."
  $name: "Hotkey Configurations"
  $description: "Add, remove, or modify your custom hotkey overrides."
*/
// ==/WindhawkModSettings==

#include <commctrl.h>  // Ensure this is included at the top of your file
#pragma comment(lib, "comctl32.lib")

#include <commctrl.h>
#include <shellapi.h>
#include <windhawk_api.h>
#include <windhawk_utils.h>
#include <windows.h>
#include <algorithm>
#include <cwctype>
#include <filesystem>
#include <functional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

// Older SDKs used by some Windhawk toolchains don't expose these.
#ifndef APPCOMMAND_BRIGHTNESS_UP
#define APPCOMMAND_BRIGHTNESS_UP 53
#endif

#ifndef APPCOMMAND_BRIGHTNESS_DOWN
#define APPCOMMAND_BRIGHTNESS_DOWN 54
#endif


// =====================================================================
// Globals & Types
// =====================================================================

enum class HotkeyActionType {
    Nothing,
    StartProcess,
    VolUp,
    VolDown,
    VolMute,
    MediaPlay,
    MediaNext,
    MediaPrev,
    BrightnessUp,
    BrightnessDown,
    SleepDisplay,
    LockPc,
    ShowDesktop,
    TaskManager,
    VdNext,
    VdPrev,
};

struct HotkeyAction {
    std::wstring hotkeyString;
    HotkeyActionType actionType;
    std::wstring additionalArgs;
    std::function<void()> actionExecutor;
    UINT modifiers;
    UINT vk;
    int hotkeyId;
    bool registered;
};

static struct {
    std::vector<HotkeyAction> hotkeyActions;
} g_settings;

static HWND g_hTaskbarWnd = nullptr;
static const int kHotkeyIdBase = 0x4000;  // Safe base ID for our hotkeys
static const DWORD kHotkeyOwnerThreadJoinTimeoutMs = 2000;
static HANDLE g_hotkeyOwnerThread = nullptr;
static DWORD g_hotkeyOwnerThreadId = 0;
static HANDLE g_hotkeyOwnerReadyEvent = nullptr;
static bool g_hotkeyOwnerReady = false;
static bool g_isToolModProcessLauncher = false;
static bool g_isCurrentToolModProcess = false;
static HANDLE g_toolModProcessMutex = nullptr;

// Cross-thread IPC Messages (Anti-Deadlock)
static UINT g_msgRegister = RegisterWindowMessage(L"Scalpel_Register");
static UINT g_msgUnregister = RegisterWindowMessage(L"Scalpel_Unregister");

// Timer constants for deferring physical modifier conflicts
static const int kMaxKeypressRetryCount = 50;
static const UINT kKeypressRetryIntervalMs = 10;
static std::vector<int> g_pendingKeypressKeys;
static int g_pendingKeypressRetryCount = 0;
static UINT_PTR g_keypressTimerId = 0;

static bool DispatchHotkeyById(int hotkeyId);
static bool RegisterOwnedHotkeysForThread();
static void UnregisterOwnedHotkeysForThread();
static DWORD WINAPI HotkeyOwnerThreadProc(LPVOID);
static bool StartHotkeyOwnerThread();
static void StopHotkeyOwnerThread();
static BOOL InitExplorerLane();
static void ExplorerLaneAfterInit();
static void ExplorerLaneSettingsChanged();
static void ExplorerLaneUninit();
static bool IsCurrentProcessWindhawk();
static bool DetermineToolProcessRole();
static BOOL StartToolModProcessIfLauncher();
static BOOL WhTool_ModInit();
static void WhTool_ModSettingsChanged();
static void WhTool_ModUninit();
static void LoadSettings();
static void WINAPI EntryPoint_Hook();

// =====================================================================
// String & Hotkey Parsing (Lifted from m417z)
// =====================================================================

namespace stringtools {
std::wstring trim(const std::wstring& s) {
    auto wsfront = std::find_if_not(s.begin(), s.end(),
                                    [](int c) { return std::iswspace(c); });
    auto wsback = std::find_if_not(s.rbegin(), s.rend(), [](int c) {
                      return std::iswspace(c);
                  }).base();
    return (wsback <= wsfront ? std::wstring() : std::wstring(wsfront, wsback));
}
std::wstring toLower(const std::wstring& s) {
    std::wstring result = s;
    std::transform(result.begin(), result.end(), result.begin(), ::towlower);
    return result;
}
bool startsWith(const std::wstring& s, const std::wstring& prefix) {
    if (s.length() < prefix.length())
        return false;
    return std::equal(prefix.begin(), prefix.end(), s.begin());
}
}  // namespace stringtools

std::vector<std::wstring> SplitArgs(const std::wstring& args,
                                    const wchar_t delimiter = L';') {
    std::vector<std::wstring> result;
    std::wstring args_ = stringtools::trim(args);
    if (args_.empty())
        return result;
    size_t start = 0, end = args_.find(delimiter);
    while (end != std::wstring::npos) {
        auto sub = stringtools::trim(args_.substr(start, end - start));
        if (!sub.empty())
            result.push_back(sub);
        start = end + 1;
        end = args_.find(delimiter, start);
    }
    auto sub = stringtools::trim(args_.substr(start));
    if (!sub.empty())
        result.push_back(sub);
    return result;
}

bool FromStringHotKey(std::wstring_view hotkeyString,
                      UINT* modifiersOut,
                      UINT* vkOut) {
    static const std::unordered_map<std::wstring_view, UINT> modifiersMap = {
        {L"ALT", MOD_ALT},
        {L"CTRL", MOD_CONTROL},
        {L"SHIFT", MOD_SHIFT},
        {L"WIN", MOD_WIN},
    };
    static const std::unordered_map<std::wstring_view, UINT> vkMap = {
        // Alphabet keys
        {L"A", 0x41},
        {L"B", 0x42},
        {L"C", 0x43},
        {L"D", 0x44},
        {L"E", 0x45},
        {L"F", 0x46},
        {L"G", 0x47},
        {L"H", 0x48},
        {L"I", 0x49},
        {L"J", 0x4A},
        {L"K", 0x4B},
        {L"L", 0x4C},
        {L"M", 0x4D},
        {L"N", 0x4E},
        {L"O", 0x4F},
        {L"P", 0x50},
        {L"Q", 0x51},
        {L"R", 0x52},
        {L"S", 0x53},
        {L"T", 0x54},
        {L"U", 0x55},
        {L"V", 0x56},
        {L"W", 0x57},
        {L"X", 0x58},
        {L"Y", 0x59},
        {L"Z", 0x5A},

        // Function keys
        {L"F1", VK_F1},
        {L"F2", VK_F2},
        {L"F3", VK_F3},
        {L"F4", VK_F4},
        {L"F5", VK_F5},
        {L"F6", VK_F6},
        {L"F7", VK_F7},
        {L"F8", VK_F8},
        {L"F9", VK_F9},
        {L"F10", VK_F10},
        {L"F11", VK_F11},
        {L"F12", VK_F12},
        {L"F13", VK_F13},
        {L"F14", VK_F14},
        {L"F15", VK_F15},
        {L"F16", VK_F16},
        {L"F17", VK_F17},
        {L"F18", VK_F18},
        {L"F19", VK_F19},
        {L"F20", VK_F20},
        {L"F21", VK_F21},
        {L"F22", VK_F22},
        {L"F23", VK_F23},
        {L"F24", VK_F24},

        // Navigation/edit keys
        {L"INSERT", VK_INSERT},
        {L"INS", VK_INSERT},
        {L"DELETE", VK_DELETE},
        {L"DEL", VK_DELETE},
        {L"HOME", VK_HOME},
        {L"END", VK_END},
        {L"PAGEUP", VK_PRIOR},
        {L"PGUP", VK_PRIOR},
        {L"PAGEDOWN", VK_NEXT},
        {L"PGDOWN", VK_NEXT},
        {L"PGDN", VK_NEXT},

        // Arrow keys
        {L"LEFT", VK_LEFT},
        {L"RIGHT", VK_RIGHT},
        {L"UP", VK_UP},
        {L"DOWN", VK_DOWN},

        // Lock/system keys
        {L"CAPSLOCK", VK_CAPITAL},
        {L"NUMLOCK", VK_NUMLOCK},
        {L"SCROLLLOCK", VK_SCROLL},
        {L"PRINTSCREEN", VK_SNAPSHOT},
        {L"PRTSC", VK_SNAPSHOT},
        {L"PRTSCN", VK_SNAPSHOT},
        {L"PAUSE", VK_PAUSE},

        // Numpad keys
        {L"NUMPAD0", VK_NUMPAD0},
        {L"NUMPAD1", VK_NUMPAD1},
        {L"NUMPAD2", VK_NUMPAD2},
        {L"NUMPAD3", VK_NUMPAD3},
        {L"NUMPAD4", VK_NUMPAD4},
        {L"NUMPAD5", VK_NUMPAD5},
        {L"NUMPAD6", VK_NUMPAD6},
        {L"NUMPAD7", VK_NUMPAD7},
        {L"NUMPAD8", VK_NUMPAD8},
        {L"NUMPAD9", VK_NUMPAD9},
        {L"NUMPAD_ADD", VK_ADD},
        {L"NUMPAD_SUBTRACT", VK_SUBTRACT},
        {L"NUMPAD_MULTIPLY", VK_MULTIPLY},
        {L"NUMPAD_DIVIDE", VK_DIVIDE},
        {L"NUMPAD_DECIMAL", VK_DECIMAL},
        // RegisterHotKey doesn't differentiate main vs numpad Enter.
        {L"NUMPAD_ENTER", VK_RETURN},

        // Misc control keys
        {L"BACKSPACE", VK_BACK},
        {L"BS", VK_BACK},
        {L"TAB", 0x09},
        {L"ENTER", 0x0D},
        {L"RETURN", 0x0D},
        {L"ESCAPE", 0x1B},
        {L"ESC", 0x1B},
        {L"SPACE", 0x20},

        // OEM symbol keys and aliases
        {L"`", VK_OEM_3},
        {L"~", VK_OEM_3},
        {L"OEM_3", VK_OEM_3},
        {L"[", VK_OEM_4},
        {L"OEM_4", VK_OEM_4},
        {L"]", VK_OEM_6},
        {L"OEM_6", VK_OEM_6},
        {L";", VK_OEM_1},
        {L"OEM_1", VK_OEM_1},
        {L"'", VK_OEM_7},
        {L"OEM_7", VK_OEM_7},
        {L"\\", VK_OEM_5},
        {L"OEM_5", VK_OEM_5},
        {L",", VK_OEM_COMMA},
        {L"OEM_COMMA", VK_OEM_COMMA},
        {L".", VK_OEM_PERIOD},
        {L"OEM_PERIOD", VK_OEM_PERIOD},
        {L"/", VK_OEM_2},
        {L"OEM_2", VK_OEM_2},
        {L"-", VK_OEM_MINUS},
        {L"OEM_MINUS", VK_OEM_MINUS},
        {L"=", VK_OEM_PLUS},
        {L"OEM_PLUS", VK_OEM_PLUS},
    };

    auto splitStringView = [](std::wstring_view s, WCHAR delimiter) {
        size_t pos_start = 0, pos_end;
        std::vector<std::wstring_view> res;
        while ((pos_end = s.find(delimiter, pos_start)) !=
               std::wstring_view::npos) {
            res.push_back(s.substr(pos_start, pos_end - pos_start));
            pos_start = pos_end + 1;
        }
        res.push_back(s.substr(pos_start));
        return res;
    };

    UINT modifiers = 0;
    UINT vk = 0;

    for (auto part : splitStringView(hotkeyString, '+')) {
        part.remove_prefix(
            std::min(part.find_first_not_of(L" \t"), part.size()));
        part.remove_suffix(std::min(
            part.size() - part.find_last_not_of(L" \t") - 1, part.size()));

        std::wstring partUpper{part};
        std::transform(partUpper.begin(), partUpper.end(), partUpper.begin(),
                       ::toupper);

        if (auto it = modifiersMap.find(partUpper); it != modifiersMap.end()) {
            modifiers |= it->second;
            continue;
        }

        if (vk)
            return false;  // Only one VK allowed
        if (auto it = vkMap.find(partUpper); it != vkMap.end()) {
            vk = it->second;
            continue;
        }
    }
    if (!vk)
        return false;

    *modifiersOut = modifiers;
    *vkOut = vk;
    return true;
}

// =====================================================================
// Execution Wrappers
// =====================================================================

bool AreModifierKeysPressed() {
    return (GetAsyncKeyState(VK_CONTROL) & 0x8000) ||
           (GetAsyncKeyState(VK_MENU) & 0x8000) ||
           (GetAsyncKeyState(VK_SHIFT) & 0x8000) ||
           (GetAsyncKeyState(VK_LWIN) & 0x8000) ||
           (GetAsyncKeyState(VK_RWIN) & 0x8000);
}

void SendKeypressInternal(const std::vector<int>& keys) {
    if (keys.empty())
        return;
    const int NUM_KEYS = static_cast<int>(keys.size());
    std::unique_ptr<INPUT[]> input(new INPUT[NUM_KEYS * 2]);

    for (int i = 0; i < NUM_KEYS; i++) {
        input[i].type = INPUT_KEYBOARD;
        input[i].ki.wVk = static_cast<WORD>(keys[i]);
        input[i].ki.dwFlags = 0;
    }
    for (int i = 0; i < NUM_KEYS; i++) {
        input[NUM_KEYS + i].type = INPUT_KEYBOARD;
        input[NUM_KEYS + i].ki.wVk = static_cast<WORD>(keys[i]);
        input[NUM_KEYS + i].ki.dwFlags = KEYEVENTF_KEYUP;
    }
    SendInput(NUM_KEYS * 2, input.get(), sizeof(input[0]));
}

void StartProcess(std::wstring command) {
    if (command.empty())
        return;

    std::wstring executable = command;
    std::wstring parameters;

    // Simple command parser (unwraps basic args for tests)
    size_t spacePos = command.find(L' ');
    if (spacePos != std::wstring::npos &&
        !stringtools::startsWith(command, L"\"")) {
        executable = command.substr(0, spacePos);
        parameters = command.substr(spacePos + 1);
    }

    // Capture current cursor for DPI/Multi-monitor awareness
    POINT cursorPos;
    GetCursorPos(&cursorPos);
    HMONITOR hMonitor = MonitorFromPoint(cursorPos, MONITOR_DEFAULTTONEAREST);

    SHELLEXECUTEINFO sei = {sizeof(sei)};
    sei.fMask = SEE_MASK_HMONITOR | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI;
    sei.lpVerb = L"open";
    sei.lpFile = executable.c_str();
    sei.lpParameters = parameters.empty() ? NULL : parameters.c_str();
    sei.nShow = SW_SHOWNORMAL;
    sei.hMonitor = (HANDLE)hMonitor;

    ShellExecuteEx(&sei);
}

HotkeyActionType ParseActionType(const std::wstring& actionName) {
    if (actionName == L"ACTION_NOTHING")
        return HotkeyActionType::Nothing;
    if (actionName == L"ACTION_START_PROCESS")
        return HotkeyActionType::StartProcess;
    if (actionName == L"ACTION_VOL_UP")
        return HotkeyActionType::VolUp;
    if (actionName == L"ACTION_VOL_DOWN")
        return HotkeyActionType::VolDown;
    if (actionName == L"ACTION_VOL_MUTE")
        return HotkeyActionType::VolMute;
    if (actionName == L"ACTION_MEDIA_PLAY")
        return HotkeyActionType::MediaPlay;
    if (actionName == L"ACTION_MEDIA_NEXT")
        return HotkeyActionType::MediaNext;
    if (actionName == L"ACTION_MEDIA_PREV")
        return HotkeyActionType::MediaPrev;
    if (actionName == L"ACTION_BRIGHTNESS_UP")
        return HotkeyActionType::BrightnessUp;
    if (actionName == L"ACTION_BRIGHTNESS_DOWN")
        return HotkeyActionType::BrightnessDown;
    if (actionName == L"ACTION_SLEEP_DISPLAY")
        return HotkeyActionType::SleepDisplay;
    if (actionName == L"ACTION_LOCK_PC")
        return HotkeyActionType::LockPc;
    if (actionName == L"ACTION_SHOW_DESKTOP")
        return HotkeyActionType::ShowDesktop;
    if (actionName == L"ACTION_TASK_MANAGER")
        return HotkeyActionType::TaskManager;
    if (actionName == L"ACTION_VD_NEXT")
        return HotkeyActionType::VdNext;
    if (actionName == L"ACTION_VD_PREV")
        return HotkeyActionType::VdPrev;
    return HotkeyActionType::Nothing;
}

std::function<void()> ParseActionSetting(HotkeyActionType actionType,
                                         const std::wstring& args) {
    switch (actionType) {
        case HotkeyActionType::Nothing:
            return []() {};
        case HotkeyActionType::StartProcess: {
            std::wstring cmd = stringtools::trim(args);
            return [cmd]() { StartProcess(cmd); };
        }
        case HotkeyActionType::VolUp:
            return []() { SendKeypressInternal({VK_VOLUME_UP}); };
        case HotkeyActionType::VolDown:
            return []() { SendKeypressInternal({VK_VOLUME_DOWN}); };
        case HotkeyActionType::VolMute:
            return []() { SendKeypressInternal({VK_VOLUME_MUTE}); };
        case HotkeyActionType::MediaPlay:
            return []() { SendKeypressInternal({VK_MEDIA_PLAY_PAUSE}); };
        case HotkeyActionType::MediaNext:
            return []() { SendKeypressInternal({VK_MEDIA_NEXT_TRACK}); };
        case HotkeyActionType::MediaPrev:
            return []() { SendKeypressInternal({VK_MEDIA_PREV_TRACK}); };
        case HotkeyActionType::BrightnessUp:
            return []() {
                SendMessageW(HWND_BROADCAST, WM_APPCOMMAND, 0,
                             MAKELPARAM(0, APPCOMMAND_BRIGHTNESS_UP));
            };
        case HotkeyActionType::BrightnessDown:
            return []() {
                SendMessageW(HWND_BROADCAST, WM_APPCOMMAND, 0,
                             MAKELPARAM(0, APPCOMMAND_BRIGHTNESS_DOWN));
            };
        case HotkeyActionType::SleepDisplay:
            return []() {
                SendMessageW(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, 2);
            };
        case HotkeyActionType::LockPc:
            return []() { LockWorkStation(); };
        case HotkeyActionType::ShowDesktop:
            return []() { SendKeypressInternal({VK_LWIN, 0x44}); };
        case HotkeyActionType::TaskManager:
            return []() { StartProcess(L"taskmgr.exe"); };
        case HotkeyActionType::VdNext:
            return []() {
                SendKeypressInternal({VK_LWIN, VK_LCONTROL, VK_RIGHT});
            };
        case HotkeyActionType::VdPrev:
            return []() {
                SendKeypressInternal({VK_LWIN, VK_LCONTROL, VK_LEFT});
            };
    }

    return []() {};
}

// =====================================================================
// Phase A: The Preemptive Intercept Hooks
// =====================================================================

typedef BOOL(WINAPI* RegisterHotKey_t)(HWND hWnd,
                                       int id,
                                       UINT fsModifiers,
                                       UINT vk);
RegisterHotKey_t RegisterHotKey_Original;

BOOL WINAPI RegisterHotKey_Hook(HWND hWnd, int id, UINT fsModifiers, UINT vk) {
    // Strip MOD_NOREPEAT flag that Windows often appends implicitly
    UINT cleanMods = fsModifiers & ~MOD_NOREPEAT;

    // Check O(1) array for overrides
    for (const auto& action : g_settings.hotkeyActions) {
        if (action.modifiers == cleanMods && action.vk == vk) {
            // SCALPEL BLOCK: Deny OS Registration
            SetLastError(ERROR_HOTKEY_ALREADY_REGISTERED);
            Wh_Log(L"SCALPEL: Preemptively blocked OS from registering %s",
                   action.hotkeyString.c_str());
            return FALSE;
        }
    }

    // Not our hotkey, let it pass natively
    return RegisterHotKey_Original(hWnd, id, fsModifiers, vk);
}

// =====================================================================
// Phase B: Taskbar Subclass & Re-Registration
// =====================================================================

bool DispatchHotkeyById(int hotkeyId) {
    for (const auto& action : g_settings.hotkeyActions) {
        if (!action.registered || action.hotkeyId != hotkeyId)
            continue;

        if (action.actionType != HotkeyActionType::Nothing &&
            action.actionExecutor) {
            action.actionExecutor();
        }

        // Keep Win-key masking mitigation to suppress Start menu flicker.
        if (action.modifiers & MOD_WIN) {
            SendKeypressInternal({0xFF});
        }
        return true;
    }

    return false;
}

bool RegisterOwnedHotkeysForThread() {
    auto registerHotKeyFn =
        RegisterHotKey_Original ? RegisterHotKey_Original : RegisterHotKey;

    bool anyRegistered = false;
    int registeredCount = 0;
    for (auto& action : g_settings.hotkeyActions) {
        if (action.hotkeyString.empty())
            continue;

        // Thread-owned global hotkey (hWnd = nullptr) dispatches WM_HOTKEY to
        // the owner's message queue.
        if (registerHotKeyFn(nullptr, action.hotkeyId, action.modifiers,
                             action.vk)) {
            action.registered = true;
            anyRegistered = true;
            registeredCount++;
            Wh_Log(L"SCALPEL: Owner thread registered %s (id=%d).",
                   action.hotkeyString.c_str(), action.hotkeyId);
        } else {
            action.registered = false;
            Wh_Log(L"SCALPEL: Owner thread failed to register %s (id=%d), err=%u",
                   action.hotkeyString.c_str(), action.hotkeyId, GetLastError());
        }
    }

    if (!anyRegistered && !g_settings.hotkeyActions.empty()) {
        Wh_Log(L"SCALPEL: Warning - no hotkeys registered by owner thread.");
    } else {
        Wh_Log(L"SCALPEL: Owner thread registered count=%d.", registeredCount);
    }

    return anyRegistered;
}

void UnregisterOwnedHotkeysForThread() {
    for (auto& action : g_settings.hotkeyActions) {
        if (action.registered) {
            UnregisterHotKey(nullptr, action.hotkeyId);
            action.registered = false;
        }
    }
}

DWORD WINAPI HotkeyOwnerThreadProc(LPVOID) {
    MSG msg;
    PeekMessage(&msg, nullptr, 0, 0, PM_NOREMOVE);

    if (!RegisterOwnedHotkeysForThread()) {
        Wh_Log(L"SCALPEL: Owner thread started with zero registered hotkeys.");
    }

    g_hotkeyOwnerReady = true;
    if (g_hotkeyOwnerReadyEvent) {
        SetEvent(g_hotkeyOwnerReadyEvent);
    }

    while (GetMessage(&msg, nullptr, 0, 0) > 0) {
        if (msg.message == WM_HOTKEY) {
            DispatchHotkeyById(static_cast<int>(msg.wParam));
            continue;
        }
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    UnregisterOwnedHotkeysForThread();
    return 0;
}

bool StartHotkeyOwnerThread() {
    StopHotkeyOwnerThread();

    g_hotkeyOwnerReady = false;
    g_hotkeyOwnerReadyEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    if (!g_hotkeyOwnerReadyEvent) {
        Wh_Log(L"SCALPEL: Failed to create owner-ready event.");
        return false;
    }

    g_hotkeyOwnerThread =
        CreateThread(nullptr, 0, HotkeyOwnerThreadProc, nullptr, 0,
                     &g_hotkeyOwnerThreadId);
    if (!g_hotkeyOwnerThread) {
        CloseHandle(g_hotkeyOwnerReadyEvent);
        g_hotkeyOwnerReadyEvent = nullptr;
        g_hotkeyOwnerThreadId = 0;
        Wh_Log(L"SCALPEL: Failed to create owner thread.");
        return false;
    }

    DWORD waitResult = WaitForSingleObject(g_hotkeyOwnerReadyEvent, 2000);
    CloseHandle(g_hotkeyOwnerReadyEvent);
    g_hotkeyOwnerReadyEvent = nullptr;

    if (waitResult != WAIT_OBJECT_0 || !g_hotkeyOwnerReady) {
        Wh_Log(L"SCALPEL: Owner thread startup timed out.");
        StopHotkeyOwnerThread();
        return false;
    }

    Wh_Log(L"SCALPEL: Owner thread started (tid=%u).", g_hotkeyOwnerThreadId);
    return true;
}

void StopHotkeyOwnerThread() {
    if (!g_hotkeyOwnerThread)
        return;

    if (g_hotkeyOwnerThreadId != 0) {
        PostThreadMessage(g_hotkeyOwnerThreadId, WM_QUIT, 0, 0);
    }

    DWORD waitResult =
        WaitForSingleObject(g_hotkeyOwnerThread, kHotkeyOwnerThreadJoinTimeoutMs);
    if (waitResult != WAIT_OBJECT_0) {
        Wh_Log(L"SCALPEL: Owner thread join timed out.");
    }

    CloseHandle(g_hotkeyOwnerThread);
    g_hotkeyOwnerThread = nullptr;
    g_hotkeyOwnerThreadId = 0;
    g_hotkeyOwnerReady = false;
    Wh_Log(L"SCALPEL: Owner thread stopped.");
}

LRESULT CALLBACK TaskbarWindowSubclassProc(HWND hWnd,
                                           UINT uMsg,
                                           WPARAM wParam,
                                           LPARAM lParam,
                                           DWORD_PTR dwRefData) {
    // Compatibility path: shared dispatcher in case fallback ownership is used.
    if (uMsg == WM_HOTKEY) {
        if (DispatchHotkeyById(static_cast<int>(wParam))) {
            return 0;
        }
    }

    // Keep IPC messages accepted for compatibility; ownership moved to tool
    // thread so these become no-ops.
    if (uMsg == g_msgRegister) {
        return 0;
    }
    if (uMsg == g_msgUnregister) {
        return 0;
    }

    return DefSubclassProc(hWnd, uMsg, wParam, lParam);
}

void HandleIdentifiedTaskbarWindow(HWND hWnd) {
    g_hTaskbarWnd = hWnd;
    if (WindhawkUtils::SetWindowSubclassFromAnyThread(
            hWnd, TaskbarWindowSubclassProc, 0)) {
        Wh_Log(L"SCALPEL: Target Shell_TrayWnd subclassed successfully.");
    }
}

// =====================================================================
// Target Validation (Window Creation Hook)
// =====================================================================

using CreateWindowExW_t = decltype(&CreateWindowExW);
CreateWindowExW_t CreateWindowExW_Original;

HWND WINAPI CreateWindowExW_Hook(DWORD dwExStyle,
                                 LPCWSTR lpClassName,
                                 LPCWSTR lpWindowName,
                                 DWORD dwStyle,
                                 int X,
                                 int Y,
                                 int nWidth,
                                 int nHeight,
                                 HWND hWndParent,
                                 HMENU hMenu,
                                 HINSTANCE hInstance,
                                 LPVOID lpParam) {
    HWND hWnd = CreateWindowExW_Original(dwExStyle, lpClassName, lpWindowName,
                                         dwStyle, X, Y, nWidth, nHeight,
                                         hWndParent, hMenu, hInstance, lpParam);
    if (!hWnd)
        return hWnd;

    BOOL bTextualClassName = ((ULONG_PTR)lpClassName & ~(ULONG_PTR)0xffff) != 0;

    // Only capture the PRIMARY Tray. Ignore Shell_SecondaryTrayWnd
    // (Multi-monitors) to prevent duplicates.
    if (bTextualClassName && _wcsicmp(lpClassName, L"Shell_TrayWnd") == 0) {
        HandleIdentifiedTaskbarWindow(hWnd);
    }

    return hWnd;
}

HWND FindCurrentProcessTaskbarWindow() {
    HWND hWnd = nullptr;
    EnumWindows(
        [](HWND hWnd, LPARAM lParam) WINAPI -> BOOL {
            DWORD dwProcessId = 0;
            if (!GetWindowThreadProcessId(hWnd, &dwProcessId) ||
                dwProcessId != GetCurrentProcessId())
                return TRUE;

            WCHAR szClassName[32];
            if (GetClassName(hWnd, szClassName, ARRAYSIZE(szClassName)) == 0)
                return TRUE;

            if (_wcsicmp(szClassName, L"Shell_TrayWnd") == 0) {
                *(HWND*)lParam = hWnd;
                return FALSE;
            }
            return TRUE;
        },
        (LPARAM)&hWnd);
    return hWnd;
}

// =====================================================================
// Option A: The Brutal Silent Restart (Not Recommended)
// =====================================================================
// This function instantly kills and reboots Explorer.
// DANGER: It will abruptly close all open file browser windows and flash the
// screen.
void RestartExplorerSilently() {
    WCHAR commandLine[] =
        L"cmd.exe /c \"taskkill /F /IM explorer.exe & start explorer.exe\"";
    STARTUPINFO si = {sizeof(si)};
    PROCESS_INFORMATION pi = {0};

    // Run the command completely hidden
    if (CreateProcessW(nullptr, commandLine, nullptr, nullptr, FALSE,
                       CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
}

// =====================================================================
// Option B: The Polite UX Prompt (Highly Recommended)
// =====================================================================
// This uses native Windows UI to ask the user if they want to restart Explorer.
// You can steal this directly from Lone's mod.


void PromptForExplorerRestart() {
    TASKDIALOGCONFIG taskDialogConfig = {0};
    taskDialogConfig.cbSize = sizeof(taskDialogConfig);
    taskDialogConfig.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION;
    taskDialogConfig.dwCommonButtons = TDCBF_YES_BUTTON | TDCBF_NO_BUTTON;
    taskDialogConfig.pszWindowTitle = L"Scalpel Hotkey Manager";
    taskDialogConfig.pszMainIcon = TD_INFORMATION_ICON;
    taskDialogConfig.pszContent =
        L"Explorer needs to be restarted to steal the protected hotkeys from "
        L"the OS.\n\nRestart now? (This will close open folder windows).";

    int button = 0;
    if (SUCCEEDED(
            TaskDialogIndirect(&taskDialogConfig, &button, nullptr, nullptr))) {
        if (button == IDYES) {
            RestartExplorerSilently();
        }
    }
}

// =====================================================================
// Windhawk Lifecycle & Export Methods
// =====================================================================

bool IsCurrentProcessWindhawk() {
    WCHAR currentProcessPath[MAX_PATH];
    if (!GetModuleFileName(nullptr, currentProcessPath,
                           ARRAYSIZE(currentProcessPath))) {
        return false;
    }

    PCWSTR baseName = wcsrchr(currentProcessPath, L'\\');
    baseName = baseName ? baseName + 1 : currentProcessPath;
    return _wcsicmp(baseName, L"windhawk.exe") == 0;
}

void WINAPI EntryPoint_Hook() {
    // Tool-mod process should only run this mod logic, then idle in its own
    // hotkey thread/message loop. Prevent normal windhawk.exe flow in this
    // spawned process instance.
    ExitThread(0);
}

bool DetermineToolProcessRole() {
    g_isToolModProcessLauncher = false;
    g_isCurrentToolModProcess = false;

    if (!IsCurrentProcessWindhawk()) {
        return false;
    }

    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLine(), &argc);
    if (!argv) {
        return false;
    }

    bool isExcluded = false;
    for (int i = 1; i < argc; i++) {
        if (wcscmp(argv[i], L"-service") == 0 ||
            wcscmp(argv[i], L"-service-start") == 0 ||
            wcscmp(argv[i], L"-service-stop") == 0) {
            isExcluded = true;
            break;
        }
    }

    bool isToolModProcess = false;
    for (int i = 1; !isExcluded && i < argc - 1; i++) {
        if (wcscmp(argv[i], L"-tool-mod") == 0) {
            isToolModProcess = true;
            if (wcscmp(argv[i + 1], WH_MOD_ID) == 0) {
                g_isCurrentToolModProcess = true;
            }
            break;
        }
    }

    LocalFree(argv);

    if (isExcluded) {
        return false;
    }

    if (!isToolModProcess) {
        g_isToolModProcessLauncher = true;
    }

    return true;
}

BOOL StartToolModProcessIfLauncher() {
    if (!g_isToolModProcessLauncher) {
        return TRUE;
    }

    WCHAR currentProcessPath[MAX_PATH];
    switch (GetModuleFileName(nullptr, currentProcessPath,
                              ARRAYSIZE(currentProcessPath))) {
        case 0:
        case ARRAYSIZE(currentProcessPath):
            Wh_Log(L"SCALPEL: GetModuleFileName failed for tool launcher.");
            return FALSE;
    }

    WCHAR commandLine[MAX_PATH + 2 +
                      (sizeof(L" -tool-mod \"" WH_MOD_ID "\"") /
                       sizeof(WCHAR)) -
                      1];
    swprintf_s(commandLine, L"\"%s\" -tool-mod \"%s\"", currentProcessPath,
               WH_MOD_ID);

    HMODULE kernelModule = GetModuleHandle(L"kernelbase.dll");
    if (!kernelModule) {
        kernelModule = GetModuleHandle(L"kernel32.dll");
        if (!kernelModule) {
            Wh_Log(L"SCALPEL: Missing kernelbase/kernel32.");
            return FALSE;
        }
    }

    using CreateProcessInternalW_t = BOOL(WINAPI*)(
        HANDLE hUserToken, LPCWSTR lpApplicationName, LPWSTR lpCommandLine,
        LPSECURITY_ATTRIBUTES lpProcessAttributes,
        LPSECURITY_ATTRIBUTES lpThreadAttributes, WINBOOL bInheritHandles,
        DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory,
        LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation,
        PHANDLE hRestrictedUserToken);
    CreateProcessInternalW_t pCreateProcessInternalW =
        (CreateProcessInternalW_t)GetProcAddress(kernelModule,
                                                 "CreateProcessInternalW");
    if (!pCreateProcessInternalW) {
        Wh_Log(L"SCALPEL: CreateProcessInternalW unavailable.");
        return FALSE;
    }

    STARTUPINFO si{
        .cb = sizeof(STARTUPINFO),
        .dwFlags = STARTF_FORCEOFFFEEDBACK,
    };
    PROCESS_INFORMATION pi = {};
    if (!pCreateProcessInternalW(nullptr, currentProcessPath, commandLine,
                                 nullptr, nullptr, FALSE, NORMAL_PRIORITY_CLASS,
                                 nullptr, nullptr, &si, &pi, nullptr)) {
        Wh_Log(L"SCALPEL: Failed to spawn tool-mod process.");
        return FALSE;
    }

    Wh_Log(L"SCALPEL: Spawned tool-mod process pid=%u.", pi.dwProcessId);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return TRUE;
}

BOOL WhTool_ModInit() {
    g_toolModProcessMutex =
        CreateMutex(nullptr, TRUE, L"windhawk-tool-mod_" WH_MOD_ID);
    if (!g_toolModProcessMutex) {
        Wh_Log(L"SCALPEL: CreateMutex failed in tool-mod process.");
        return FALSE;
    }

    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        Wh_Log(L"SCALPEL: Tool-mod process already running.");
        return FALSE;
    }

    LoadSettings();
    return StartHotkeyOwnerThread() ? TRUE : FALSE;
}

void WhTool_ModSettingsChanged() {
    StopHotkeyOwnerThread();
    LoadSettings();
    StartHotkeyOwnerThread();
}

void WhTool_ModUninit() {
    StopHotkeyOwnerThread();
    if (g_toolModProcessMutex) {
        CloseHandle(g_toolModProcessMutex);
        g_toolModProcessMutex = nullptr;
    }
}

std::wstring GetStringSettingSafe(PCWSTR name) {
    PCWSTR val = Wh_GetStringSetting(name);
    if (!val)
        return L"";
    std::wstring res(val);
    Wh_FreeStringSetting(val);
    return res;
}

void LoadSettings() {
    g_settings.hotkeyActions.clear();

    for (int i = 0; i < 50; i++) {
        std::wstring baseKey = L"HotkeyActions[" + std::to_wstring(i) + L"]";
        std::wstring hotkeyKey = baseKey + L".Hotkey";
        std::wstring actionKey = baseKey + L".Action";
        std::wstring argsKey = baseKey + L".Args";

        std::wstring hotkeyStr = GetStringSettingSafe(hotkeyKey.c_str());
        std::wstring actionStr = GetStringSettingSafe(actionKey.c_str());
        std::wstring argsStr = GetStringSettingSafe(argsKey.c_str());

        if (hotkeyStr.empty())
            break;

        HotkeyActionType actionType = ParseActionType(actionStr);
        HotkeyAction action;
        action.hotkeyString = hotkeyStr;
        action.actionType = actionType;
        action.additionalArgs = argsStr;
        action.actionExecutor = ParseActionSetting(actionType, argsStr);
        action.hotkeyId = kHotkeyIdBase + static_cast<int>(i);
        action.registered = false;

        if (FromStringHotKey(hotkeyStr, &action.modifiers, &action.vk)) {
            g_settings.hotkeyActions.push_back(std::move(action));
        }
    }
}

BOOL InitExplorerLane() {
    LoadSettings();

    // Setup Phase A Intercept Hook
    HMODULE hUser32 = GetModuleHandleW(L"user32.dll");
    if (hUser32) {
        void* pRegisterHotKey =
            (void*)GetProcAddress(hUser32, "RegisterHotKey");
        if (pRegisterHotKey) {
            Wh_SetFunctionHook(pRegisterHotKey, (void*)RegisterHotKey_Hook,
                               (void**)&RegisterHotKey_Original);
        }
    }

    // Setup Target Trap Hook
    Wh_SetFunctionHook((void*)CreateWindowExW, (void*)CreateWindowExW_Hook,
                       (void**)&CreateWindowExW_Original);

    return TRUE;
}

void ExplorerLaneAfterInit() {
    HWND hWnd = FindCurrentProcessTaskbarWindow();
    if (hWnd) {
        HandleIdentifiedTaskbarWindow(hWnd);
    }
}

void ExplorerLaneUninit() {
    if (g_hTaskbarWnd) {
        // Clean up IPC Thread safely
        WindhawkUtils::RemoveWindowSubclassFromAnyThread(
            g_hTaskbarWnd, TaskbarWindowSubclassProc);
    }

    PromptForExplorerRestart();

}

void ExplorerLaneSettingsChanged() {
    LoadSettings();

    // Optional: Only prompt if specific protected keys (like Win+Shift+S) were
    // modified. For now, prompt the user so they are aware a restart is needed.
    PromptForExplorerRestart();
}

BOOL Wh_ModInit() {
    bool isWindhawkRole = DetermineToolProcessRole();
    if (isWindhawkRole) {
        if (g_isCurrentToolModProcess) {
            Wh_Log(L"SCALPEL: Role=current tool-mod process.");
            if (!WhTool_ModInit()) {
                ExitProcess(1);
            }

            IMAGE_DOS_HEADER* dosHeader =
                (IMAGE_DOS_HEADER*)GetModuleHandle(nullptr);
            IMAGE_NT_HEADERS* ntHeaders =
                (IMAGE_NT_HEADERS*)((BYTE*)dosHeader + dosHeader->e_lfanew);
            DWORD entryPointRVA = ntHeaders->OptionalHeader.AddressOfEntryPoint;
            void* entryPoint = (BYTE*)dosHeader + entryPointRVA;

            Wh_SetFunctionHook(entryPoint, (void*)EntryPoint_Hook, nullptr);
            return TRUE;
        }

        if (g_isToolModProcessLauncher) {
            Wh_Log(L"SCALPEL: Role=tool-mod launcher process.");
            return TRUE;
        }

        // This is a tool-mod process for a different mod ID. Skip.
        Wh_Log(L"SCALPEL: Role=non-current tool-mod process, skipping.");
        return FALSE;
    }

    Wh_Log(L"SCALPEL: Role=explorer lane.");
    return InitExplorerLane();
}

void Wh_ModAfterInit() {
    if (g_isCurrentToolModProcess) {
        Wh_Log(L"SCALPEL: Wh_ModAfterInit skipped in current tool-mod process.");
        return;
    }

    if (g_isToolModProcessLauncher) {
        Wh_Log(L"SCALPEL: Wh_ModAfterInit launching tool-mod process.");
        StartToolModProcessIfLauncher();
        return;
    }

    ExplorerLaneAfterInit();
}

void Wh_ModSettingsChanged() {
    if (g_isCurrentToolModProcess) {
        Wh_Log(L"SCALPEL: Settings changed in tool-mod process.");
        WhTool_ModSettingsChanged();
        return;
    }

    if (g_isToolModProcessLauncher) {
        Wh_Log(L"SCALPEL: Settings changed in launcher process (no-op).");
        return;
    }

    ExplorerLaneSettingsChanged();
}

void Wh_ModUninit() {
    if (g_isCurrentToolModProcess) {
        Wh_Log(L"SCALPEL: Uninit current tool-mod process.");
        WhTool_ModUninit();
        ExitProcess(0);
    }

    if (g_isToolModProcessLauncher) {
        Wh_Log(L"SCALPEL: Uninit launcher process (no-op).");
        return;
    }

    ExplorerLaneUninit();
}