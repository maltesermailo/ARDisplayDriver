#pragma once

#include <iostream>

#if defined(_WIN32) || defined(_WIN64)
#ifdef ARDISPLAYLIB_EXPORTS
#define ARDISPLAYLIB_API __declspec(dllexport)
#else
#define ARDISPLAYLIB_API __declspec(dllimport)
#endif
#else
#define ARDISPLAYLIB_API
#endif

enum EventType {
	CONNECT = 0,
	DISCONNECT,
	DISPLAY_ADDED,
	DISPLAY_REMOVED,
};

typedef void* EventData;

typedef struct Event {
	EventType type;
	int size;

	EventData eventData;
} event_t;

typedef struct EventConnect {
	char* ip;
} event_connect_t;

typedef struct EventDisconnect {
	char* ip;
} event_disconnect_t;

typedef struct EventDisplayAdded {
	int index;
} event_display_added_t;

typedef struct EventDisplayRemoved {
	int index;
} event_display_removed_t;

enum Setting {
	SETTING_NUM_DISPLAYS = 0,
	SETTING_ULTRAWIDE,
};

ARDISPLAYLIB_API bool Init();
ARDISPLAYLIB_API bool Shutdown();

ARDISPLAYLIB_API void RegisterEventHandler(void(*handler)(event_t* event));
ARDISPLAYLIB_API void UnregisterEventHandler(void(*handler)(event_t* event));

ARDISPLAYLIB_API char* GetPSK();

ARDISPLAYLIB_API void SetSettingBool(enum Setting, bool value);
ARDISPLAYLIB_API void SetSettingInt(enum Setting, int value);