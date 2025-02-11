#pragma once

#include <iostream>
#include <format>

#if defined(_WIN32) || defined(_WIN64)
#ifdef ARDISPLAYLIB_EXPORTS
#define ARDISPLAYLIB_API __declspec(dllexport)
#else
#define ARDISPLAYLIB_API __declspec(dllimport)
#endif
#else
#define ARDISPLAYLIB_API
#endif

#define SETTING_DISPLAY_RESOLUTION(n) std::format("displays.{}.resolution", n)
#define SETTING_DISPLAY_ULTRAWIDE(n) std::format("displays.{}.ultrawide", n)
#define SETTING_DISPLAY_POS_X(n) std::format("displays.{}.pos.x", n)
#define SETTING_DISPLAY_POS_Y(n) std::format("displays.{}.pos.y", n)
#define SETTING_DISPLAY_NUMBER "displays.count"
#define SETTING_PSK "psk"

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

enum CallbackType {
	GET_SETTING = 0,
};

enum ExpectedType {
	STRING = 0,
	INTEGER = 1,
};

typedef char* (*callback)(enum CallbackType callbackType, enum ExpectedType returnType, char* data);

/*
Initialies the Library, creating internal structures and setting up the driver. Should be called after setting up callbacks and event handlers.
*/
ARDISPLAYLIB_API bool Startup();

//Disconnects from the current client and shuts down the library.
ARDISPLAYLIB_API bool Shutdown();

//Starts the discovery UDP thread to announce to clients that display is reachable.
ARDISPLAYLIB_API void RunDiscovery();

//Stops the discovery. Call this once a client connection has been established.
ARDISPLAYLIB_API void StopDiscovery();

//Runs a display thread for the given display index. This will start the frame capture from the driver.
ARDISPLAYLIB_API void RunDisplayThread(int displayIndex);

//Runs the RTSP server thread. Has to be started before running the discovery or any display threads.
ARDISPLAYLIB_API void RunServerThread();

ARDISPLAYLIB_API void RegisterEventHandler(void(*handler)(event_t* event));
ARDISPLAYLIB_API void UnregisterEventHandler(void(*handler)(event_t* event));

ARDISPLAYLIB_API void SetCallback(callback cb);

//Gets the current random generated 6-digit PSK
ARDISPLAYLIB_API char* GetPSK();

//Get debug value from the library.
ARDISPLAYLIB_API char* GetDebugData(enum DebugData data);