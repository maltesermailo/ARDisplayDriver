#include "../Internals.h"
#include "../ARDisplayLib.h"

Display::~Display() {

}

FrameHandler::~FrameHandler() {
	running = false;
	if (processingThread.joinable()) {
		processingThread.join();
	}
}