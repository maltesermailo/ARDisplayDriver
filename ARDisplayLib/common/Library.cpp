#include "../ARDisplayLib.h"
#include "../Internals.h"

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <iostream>
#include <sstream>
#include <winsock.h>

std::unique_ptr<RTSPStreamer> streamer;
std::vector<std::unique_ptr<Display>> displays;
std::atomic<bool> runningDiscovery{false};

ARDISPLAYLIB_API bool Init() {
	try {
		streamer = std::make_unique<RTSPStreamer>(8554, "123456");
	}
	catch (...) {
		return false;
	}

	return true;
}

ARDISPLAYLIB_API bool Shutdown() {
	streamer.reset();
}

ARDISPLAYLIB_API void RunServerThread() {
	if (!streamer) {
		return;
	}

	streamer->mainLoop();
}


void initializeSockets() {
#ifdef _WIN32
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		std::cerr << "WSAStartup failed.\n";
		exit(EXIT_FAILURE);
	}
#endif
}

void cleanupSockets() {
#ifdef _WIN32
	WSACleanup();
#endif
}

ARDISPLAYLIB_API void RunDiscovery() {
	runningDiscovery = true;

	initializeSockets();

	int sock = socket(AF_INET, SOCK_DGRAM, 0);

	if (sock == INVALID_SOCKET) {
		perror("socket");
#ifdef _WIN32
		closesocket(sock);
#else
		close(sock);
#endif
		throw "we fucked up sockets";
	}

	int broadcast = 1;

	if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (char*)&broadcast, sizeof(broadcast)) == -1) {
		perror("setsockopt");
#ifdef _WIN32
		closesocket(sock);
#else
		close(sock);
#endif
		cleanupSockets();
		throw "we fucked up sockopt";
	}

	sockaddr_in broadcastAddr;
	memset(&broadcastAddr, 0, sizeof(broadcastAddr));
	broadcastAddr.sin_family = AF_INET;
	broadcastAddr.sin_port = htons(8000); // Broadcast port
	broadcastAddr.sin_addr.s_addr = inet_addr("255.255.255.255"); // Broadcast address

	while (runningDiscovery) {
		const char* message = "ARDisplayDiscovery";
		if (sendto(sock, message, strlen(message), 0, (struct sockaddr*)&broadcastAddr, sizeof(broadcastAddr)) < 0) {
			perror("sendto");
#ifdef _WIN32
			closesocket(sock);
#else
			close(sock);
#endif
			cleanupSockets();

			throw "we fucked up sending";
		}
	}
}

//#########################################################################################
//Helper functions
//#########################################################################################

static void push_buffer_with_metadata(GstElement* payloader, GstBuffer* buffer, int displayIndex, int sequenceNumber) {
	GstRTPBuffer rtp = GST_RTP_BUFFER_INIT;

	if (gst_rtp_buffer_map(buffer, GST_MAP_WRITE, &rtp)) {
		guint8 metadata[2];
		guint16 appbits = 0;

		// Pack your metadata
		metadata[0] = displayIndex;
		metadata[1] = sequenceNumber;

		gst_rtp_buffer_add_extension_onebyte_header(&rtp,
			1,
			metadata,
			2);

		gst_rtp_buffer_unmap(&rtp);
	}
}

//#########################################################################################
//RTSPStreamer class
//#########################################################################################

RTSPStreamer::RTSPStreamer(int port, const std::string& pre_shared_key) : psk(pre_shared_key) {
	GError* error = nullptr;
	GstRTSPToken* token;
	gchar* basic;
	gchar port_str[6];

	gst_init(NULL, NULL);

	this->server = gst_rtsp_server_new();
	gst_rtsp_server_set_service(this->server, itoa(port, port_str, 10));

	this->setupSelfSignedCert();

	auth = gst_rtsp_auth_new();

	//GTlsDatabase* database = g_tls_file_database_new("./ca_cert.pem", &error);
	//gst_rtsp_auth_set_tls_database(auth, database);

	gst_rtsp_auth_set_tls_authentication_mode(auth, G_TLS_AUTHENTICATION_NONE);
	gst_rtsp_auth_set_tls_certificate(auth, certificate);

	token =
		gst_rtsp_token_new(GST_RTSP_TOKEN_MEDIA_FACTORY_ROLE, G_TYPE_STRING,
			"aruser", NULL);

	basic = gst_rtsp_auth_make_basic("aruser", this->psk.c_str());

	gst_rtsp_auth_add_basic(auth, basic, token);
	g_free(basic);
	gst_rtsp_token_unref(token);

	gst_rtsp_server_set_auth(this->server, auth);

	//We accept every certificate
	g_signal_connect(auth, "accept-certificate", G_CALLBACK(+[](GstRTSPAuth* auth, GTlsConnection* conn, GTlsCertificate* cert, const gchar* host, GError** error) -> gboolean {
		return TRUE;
		}), NULL);


	factory = gst_rtsp_media_factory_new();

	gst_rtsp_media_factory_add_role(factory,
		"aruser", 
		GST_RTSP_PERM_MEDIA_FACTORY_ACCESS, G_TYPE_BOOLEAN, TRUE,
		GST_RTSP_PERM_MEDIA_FACTORY_CONSTRUCT, G_TYPE_BOOLEAN, TRUE,
		NULL);

	gst_rtsp_media_factory_set_launch(factory,
		"( appsrc name=source format=time is-live=true "
        "caps=video/x-raw,format=BGRA,width=1920,height=1080,framerate=60/1 "
		"! videoconvert ! x265enc ! rtph265pay name = pay0 pt = 96 "
		"! application/x-rtp,media=video,encoding-name=H265,payload=96 )");

	gst_rtsp_media_factory_set_profiles(factory, GstRTSPProfile::GST_RTSP_PROFILE_SAVPF);

	gst_rtsp_mount_points_add_factory(
		gst_rtsp_server_get_mount_points(server),
		"/stream", factory);
}

RTSPStreamer::~RTSPStreamer() {
	running = false;

	g_main_loop_quit(loop);

	if (srcId != 0) {
		g_source_remove(srcId);
	}

	g_free(factory);
	g_free(auth);
	g_free(server);
}

void RTSPStreamer::setupSelfSignedCert() {
    GError* error = nullptr;

	std::string private_key_str;

	EVP_PKEY* pkey = EVP_PKEY_new();
	RSA* rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
	EVP_PKEY_assign_RSA(pkey, rsa);

	X509* x509 = X509_new();
	X509_set_version(x509, 2);
	ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

	X509_gmtime_adj(X509_get_notBefore(x509), 0);
	X509_gmtime_adj(X509_get_notAfter(x509), 30*24*3600);

	X509_set_pubkey(x509, pkey);

	X509_NAME* name = X509_get_subject_name(x509);

	X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)"DE", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, (unsigned char*)"Hessen", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC, (unsigned char*)"Frankfurt am Main", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)"VirtualDisplay", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"nighti.dev", -1, -1, 0);

	X509_set_issuer_name(x509, name);

	X509_sign(x509, pkey, EVP_sha256());

	BIO* pkey_bio = BIO_new(BIO_s_mem());
	PEM_write_bio_PrivateKey(pkey_bio, pkey, nullptr, nullptr, 0, nullptr, nullptr);

	BUF_MEM* pkey_buf;
	BIO_get_mem_ptr(pkey_bio, &pkey_buf);
	private_key_str.assign(pkey_buf->data, pkey_buf->length);

	BIO_free(pkey_bio);

	// Convert certificate to string
	BIO* cert_bio = BIO_new(BIO_s_mem());
	PEM_write_bio_X509(cert_bio, x509);

	BUF_MEM* cert_buf;
	BIO_get_mem_ptr(cert_bio, &cert_buf);
	private_key_str.append("\n");
	private_key_str.append(cert_buf->data, cert_buf->length);

	BIO_free(cert_bio);

	// Clean up
	X509_free(x509);
	EVP_PKEY_free(pkey);

	const gchar* cert = private_key_str.c_str();

    certificate = g_tls_certificate_new_from_pem(cert, 0, &error);
    if (error != nullptr) {
        g_error_free(error);
        throw std::runtime_error("Failed to generate self-signed certificate");
    }
}

void RTSPStreamer::mainLoop() {
	loop = g_main_loop_new(nullptr, FALSE);
	gst_rtsp_server_attach(server, nullptr);

	g_main_loop_run(loop);
	g_main_loop_unref(loop);
}

void RTSPStreamer::pushFrame(int displayIndex, int sequenceNumber, const std::vector<uint8_t>& frameData) {
	if (GstElement* source = gst_bin_get_by_name(GST_BIN(factory), "source")) {
		GstElement* payloader = gst_bin_get_by_name(GST_BIN(factory), "pay0");
		GstBuffer* buffer = gst_buffer_new_allocate(nullptr, frameData.size(), nullptr);
		gst_buffer_fill(buffer, 0, frameData.data(), frameData.size());
		push_buffer_with_metadata(payloader, buffer, displayIndex, sequenceNumber);
		gst_app_src_push_buffer(GST_APP_SRC(source), buffer);
		gst_object_unref(source);
		gst_object_unref(payloader);
	}
}
