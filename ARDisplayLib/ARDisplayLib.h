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

enum DebugData {
	DEBUG_DATA_RTSP_URL = 0,
	DEBUG_DATA_CONNECTION_STATE,
};

/*
Initialies the Library, creating internal structures and setting up the driver.
*/
ARDISPLAYLIB_API bool Init();

//Disconnects from the current client and shuts down the library.
ARDISPLAYLIB_API bool Shutdown();

//Starts the discovery UDP thread to announce to clients that display is reachable.
ARDISPLAYLIB_API void RunDiscovery();

//Runs a display thread for the given display index. This will start the frame capture from the driver.
ARDISPLAYLIB_API void RunDisplayThread(int displayIndex);

//Runs the RTSP server thread. Has to be started before running the discovery or any display threads.
ARDISPLAYLIB_API void RunServerThread();

//Stops the discovery. Call this once a client connection has been established.
ARDISPLAYLIB_API void StopDiscovery();

ARDISPLAYLIB_API void RegisterEventHandler(void(*handler)(event_t* event));
ARDISPLAYLIB_API void UnregisterEventHandler(void(*handler)(event_t* event));

//Gets the current random generated 6-digit PSK
ARDISPLAYLIB_API char* GetPSK();

//Sets a server setting to a given value.
ARDISPLAYLIB_API void SetSettingBool(enum Setting setting, bool value);
ARDISPLAYLIB_API void SetSettingInt(enum Setting setting, int value);

//Get debug value from the library.
ARDISPLAYLIB_API char* GetDebugData(enum DebugData data);