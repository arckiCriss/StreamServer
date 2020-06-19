#include "Mongo.h"
#include "Server.h"
#include "Logging.h"
#include "Config.h"

#include "SubsystemStreaming.h"
#include "SubsystemSymbols.h"

#include "Rsa.h"
#include "Aes.h"

#include <udis86.h>
#include <Windows.h>
#include <winnt.h>
#include <iostream>
#include <fstream>
#include <map>

#include <cryptopp/sha3.h>
#include <cryptopp/strciphr.h>
#include <cryptopp/filters.h>

//
// Handles a login packet.
//
static VOID OnLoginPacket(PVOID Ctx, Server *Server, ServerClient *Client, Packet *P) {
	LOG("Logging in..");
	auto Body = (PacketC2SLogin*)P->Body;

	PVOID Decrypted = NULL;
	SIZE_T DecryptedLength = 0;

	CryptoPP::Integer N(RSA_N);
	CryptoPP::Integer E(RSA_E);
	CryptoPP::Integer D(RSA_D);

	RsaDecrypt(N, E, D, Body->RsaBlock, Body->RsaBlockSize, &Decrypted, &DecryptedLength);
	memcpy(&Client->KeyBlock, (RsaBlock*)Decrypted, DecryptedLength);
	
	LOG("Decrypted " << DecryptedLength << " " << Client->KeyBlock.Username);

	CryptoPP::SHA3_256 Sha3;
	std::string Hashed = "";
	CryptoPP::StringSource("", true, new CryptoPP::HashFilter(Sha3, new CryptoPP::HexEncoder(new CryptoPP::StringSink(Hashed))));

	bsoncxx::builder::stream::document Filter;
	Filter << "Username" << std::string(Client->KeyBlock.Username);
	Filter << "Password" << Hashed;

	AccountData Account;
	if (!MongoLoadByFilter("Accounts", Filter.view(), &Account)) {
		LOG("Invalid username or password ({User= " << Client->KeyBlock.Username << ", Pass= " << Hashed << "})");
		Client->Disconnect();
		return;
	}

	LOG("Authenticated successfully");
	Client->Authenticated = TRUE;

	SubsystemStreamingOnNewConnection(Client);
	RsaFree(Decrypted);
}

//
// Handles an initialized packet.
//
static VOID OnInitializedPacket(PVOID Ctx, Server *Server, ServerClient *Client, Packet *P) {
	if (!Client->Authenticated) {
		Client->Disconnect();
		return;
	}

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
	Server.RegisterHandler(OP_C2S_LOGIN, OnLoginPacket, NULL, sizeof(PacketC2SLogin));
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

//
// Tests RSA.
//
static VOID TestRsa() {
	PVOID Encrypted = NULL;
	SIZE_T EncryptedLength = 0;

	PVOID Decrypted = NULL;
	SIZE_T DecryptedLength = 0;

	CryptoPP::Integer N(RSA_N);
	CryptoPP::Integer E(RSA_E);
	CryptoPP::Integer D(RSA_D);

	auto Input = "TEST!";
	RsaEncrypt(N, E, (PVOID)Input, strlen(Input) + 1, &Encrypted, &EncryptedLength);
	RsaDecrypt(N, E, D, Encrypted, EncryptedLength, &Decrypted, &DecryptedLength);

	if (strcmp(Input, (PCHAR)Decrypted) != 0) {
		LOG("Test failed");
	}

	RsaFree(Encrypted);
	RsaFree(Decrypted);
}

//
// Tests AES.
//
static VOID TestAes() {
	auto Key = AesRandomKey();
	auto Iv = AesRandomIv();

	PVOID Encrypted = NULL;
	SIZE_T EncryptedLength = 0;

	PVOID Decrypted = NULL;
	SIZE_T DecryptedLength = 0;

	auto Input = "TEST!";
	AesEncrypt(Key, Iv, (PVOID)Input, strlen(Input) + 1, &Encrypted, &EncryptedLength);
	AesDecrypt(Key, Iv, Encrypted, EncryptedLength, &Decrypted, &DecryptedLength);

	if (strcmp(Input, (PCHAR)Decrypted) != 0) {
		LOG("Test failed");
	}

	AesFree(Key);
	AesFree(Iv);
	AesFree(Encrypted);
	AesFree(Decrypted);
}

int main(int Argc, LPCSTR Argv[]) {
	if (Argc <= 1) {
		LOG("Correct format: StreamServer BinaryName.exe");
		return 1;
	}

	LOG("Testing RSA");
	TestRsa();

	LOG("Testing AES");
	TestAes();

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
