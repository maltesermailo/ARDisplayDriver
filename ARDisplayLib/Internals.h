#ifndef INTERNALS_H_
#define INTERNALS_H_
#include <atomic>
#include <memory>
#include <thread>
#include <vector>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <gst/gst.h>
#include <gst/rtsp-server/rtsp-server.h>
#include <gst/app/gstappsrc.h>
#include <gst/rtp/rtp.h>
#include <string>


class RTSPStreamer {
private:
    GstRTSPServer* server;
    GstRTSPMediaFactory* factory;
    GstRTSPAuth* auth;
    GTlsCertificate* certificate;
    int srcId;
    std::string psk;
    GMainLoop* loop;
    std::atomic<bool> running{ true };

    bool authenticateClient(GstRTSPContext* ctx);
    void setupSelfSignedCert();

public:
    RTSPStreamer(int port, const std::string& pre_shared_key);
    ~RTSPStreamer();

    void mainLoop();
    void pushFrame(int displayIndex, int sequenceNumber, const std::vector<uint8_t>& frameData);
};

class FrameHandler {
private:
    std::unique_ptr<RTSPStreamer> streamer;
    std::atomic<bool> running{ true };
    std::thread processingThread;

    void processLoop();

public:
    FrameHandler(int width, int height, int fps, int bitrate, int rtspPort);
    ~FrameHandler();
};

class Display {
public:
	Display(int index);
	~Display();

    int index;

	std::unique_ptr<FrameHandler> frameHandler;
};

extern std::unique_ptr<RTSPStreamer> streamer;
extern std::vector<std::unique_ptr<Display>> displays;

#endif // !INTERNALS_H_
