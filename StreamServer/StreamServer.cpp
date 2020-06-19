#include "Mongo.h"
#include "Server.h"
#include "Logging.h"
#include "Config.h"

#include "SubsystemStreaming.h"
#include "SubsystemSymbols.h"

#include <udis86.h>
#include <Windows.h>
#include <winnt.h>
#include <iostream>
#include <fstream>
#include <map>

//
// Handles an initialized packet.
//
static VOID OnInitializedPacket(PVOID Ctx, Server *Server, ServerClient *Client, Packet *P) {
	if (Client->Allocated) {
		Client->Disconnect();
		return;
	}

	auto Body = (PacketC2SInitialized*)P->Body;
	SubsystemStreamingInitialized(Client, Body);
}

//
// Called when a new connection happens.
//
static VOID OnNewConnection(ServerClient *Client) {
	LOG("New connection");
	SubsystemStreamingOnNewConnection(Client);
}

//
// Called when a user has sent a bad packet.
//
static VOID OnBadPacket(ServerClient *Client, Packet *Packet) {
	Client->Disconnect();
}

//
// Called when the user has sent malformed data to the server.
//
static VOID OnMalformedData(ServerClient *Client) {
	Client->Disconnect();
}

//
// Starts the server.
//
static BOOLEAN StartServer(VOID) {
	Server Server;
	Server.Port = BIND_PORT;
	Server.OnNewConnection = OnNewConnection;
	Server.OnBadPacket = OnBadPacket;
	Server.OnMalformedData = OnMalformedData;
	Server.RegisterHandler(OP_C2S_INITIALIZED, OnInitializedPacket, NULL, sizeof(PacketC2SInitialized));

	SubsystemStreamingInitNet(&Server);
	SubsystemSymbolsInitNet(&Server);

	LOG("Initializing");
	if (!Server.Init()) {
		LOG("Failed to init!");
		return FALSE;
	}

	LOG("Binding");
	if (!Server.Bind()) {
		LOG("Failed to bind!");
		return FALSE;
	}

	LOG("Accepting new connections");
	Server.Accept();

	return TRUE;
}

//
// Logs the booted message.
//
static VOID LogBootedMsg(VOID) {
	LogData Log;
	Log.Msg = "Server booted!";
	MongoNew("Logs", &Log);
	MongoSave("Logs", &Log);
}

//
// Boots mongo.
//
static BOOLEAN BootMongo() {
	MongoInit(MONGO_URI, MONGO_DB);
	LogBootedMsg();
	return TRUE;
}

int main(int Argc, LPCSTR Argv[]) {
	if (Argc <= 1) {
		LOG("Correct format: StreamServer BinaryName.exe");
		return 1;
	}

	LOG("Initializing mongo");
	if (!BootMongo()) {
		return 1;
	}
	

	LOG("Initializing streaming subsystem");
	if (!SubsystemStreamingInit(Argv[1])) {
		return 1;
	}

	LOG("Initializing symbols subsystem");
	if (!SubsystemSymbolsInit()) {
		return 1;
	}

	LOG("Starting server");
	if (!StartServer()) {
		return 1;
	}

	LOG("Finished running!");
	std::cin.get();
	return 0;
}
