
#include "../ARDisplayLib.h"
#include "../Internals.h"

#include <iostream>
#include <sstream>
#include <winsock.h>

std::atomic<bool> runningDiscovery{ false };

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