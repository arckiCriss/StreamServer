#pragma once

#include <vector>
#include <winsock2.h>
#include <WS2tcpip.h>
#include <windows.h>
#include <cstdint>
#include <map>

#pragma comment (lib, "Ws2_32.lib")

#define PACKET_LEN 0x200

#define OP_C2S_LOGIN 1
#define OP_C2S_INITIALIZED 2
#define OP_C2S_REQUEST_INSTRUCTION 3

#define OP_S2C_INIT 1
#define OP_S2C_WRITE 2

class ServerClient;
class Server;

//
// A packet.
//
struct Packet {
	//
	// The opcode of the packet.
	//
	uint8_t Opcode = 0;
	//
	// The body of the packet.
	//
	void *Body = NULL;
	//
	// The length of the body.
	//
	uint32_t BodyLength = 0;

	//
	// Nulls the packet body.
	//
	inline void Null() {
		Body = NULL;
		BodyLength = 0;
	}
};

#pragma pack(push, 1)
//
// A packet fragment.
//
struct PacketFragment {
	//
	// The total size of the packet.
	//
	uint32_t TotalSize;
	//
	// The total number of parts in the packet.
	//
	uint32_t TotalParts;
	//
	// The size of this part.
	//
	uint16_t part_size;
	//
	// The index of this part.
	//
	uint32_t Part;
	//
	// The opcode of the packet.
	//
	uint8_t Opcode;
	//
	// The id of the packet.
	//
	uint16_t Id;
	//
	// The body of this fragment.
	//
	uint8_t Body[PACKET_LEN];
};
#pragma pack(pop)

//
// A packet trace.
//
struct PacketTrace {
	//
	// All tracked fragments for this trace.
	//
	std::vector<PacketFragment> Fragments;
	//
	// The root fragment.
	//
	PacketFragment Root;
	//
	// The total number of parts assembled.
	//
	uint32_t PartsAssembled = 0;

	//
	// Assemblies a piece of the packet being traced.
	//
	inline void Assemble(PacketFragment Fragment) {
		if (Fragment.TotalParts >= Fragments.size()) {
			Fragments.resize(Fragment.TotalParts);
		}

		if (Fragment.Part == 0) {
			Root = Fragment;
		}

		Fragments[Fragment.Part] = Fragment;
		PartsAssembled += 1;
	}

	//
	// Retrieves the id of this trace.
	//
	// @return The id of this packet.
	//
	inline uint16_t GetId() {
		return Root.Id;
	}

	//
	// Retrieves the opcode of this trace.
	//
	// @return The opcode of this packet.
	//
	inline uint8_t GetOpcode() {
		return Root.Opcode;
	}

	//
	// Determines if this trace is completed.
	//
	// @return If this packet is complete.
	//
	inline bool IsComplete() {
		if (Fragments.size() < Root.TotalParts) {
			return false;
		}

		auto Valid = 0u;
		auto SigCounter = 0;
		for (auto i = 0u; i < Root.TotalParts; i++) {
			auto Fragment = &Fragments[i];
			if (Fragment->Part == SigCounter) {
				Valid += 1;
			}
			SigCounter += 1;
		}

		return Valid >= Root.TotalParts;

	}

	//
	// Combines this trace into a packet.
	//
	// This function can fail due to being incomplete, please ensure validity
	// and not to expect a valid packet.
	//
	// The returned packet body must be freed using the 'free' API.
	//
	inline bool Combine(Packet *Packet) {
		if (!IsComplete()) {
			return false;
		}

		auto Buf = (char *)malloc(Root.TotalSize);
		auto Offset = 0;
		for (auto i = 0u; i < Root.TotalParts; i++) {
			auto fragment = &Fragments[i];
			memcpy(Buf + Offset, fragment->Body, fragment->part_size);
			Offset += fragment->part_size;
		}

		Packet->Opcode = GetOpcode();
		Packet->Body = (void*)Buf;
		Packet->BodyLength = Root.TotalSize;
		return true;
	}
};


//
// A packet handler function.
//
typedef void(*FnHandleServerPacket)(void *Ctx, Server *Server, ServerClient *Client, Packet *Packet);

//
// A packet handler.
//
struct ServerPacketHandler {
	//
	// The handler function.
	//
	FnHandleServerPacket Func;
	//
	// The context to pass to the function.
	//
	void *Ctx = NULL;
};

//
// A client connected to the server.
//
class ServerClient {
public:
	//
	// The server parent of this client.
	//
	Server *Server = NULL;
	//
	// The socket.
	//
	SOCKET Socket;

	//
	// If they're connected.
	//
	BOOLEAN Connected = TRUE;

	//
	// The server-sided image.
	//
	void *Image = NULL;

	//
	// The currently decoding part.
	//
	PacketFragment CurrentPart;
	//
	// The receive fragment offset.
	//
	uint64_t FragmentOff = 0;
	//
	// A map of packet traces.
	//
	std::vector<PacketTrace> Traces = std::vector<PacketTrace>(0xffff);
	//
	// Sent pieces of code.
	//
	std::map<void*, bool> Sent;

	//
	// The packet send id.
	//
	uint16_t SendId = 0;
	//
	// The packet recv id.
	//
	uint16_t RecvId = 0;

	//
	// The allocated address.
	//
	void *Allocated = NULL;

public:
	//
	// Handles a network manager tick.
	//
	void Tick();

public:
	//
	// Attempts to receive from this client.
	//
	bool AttemptRecv();

public:
	//
	// Sends a packet fragment to the host.
	//
	void SendFragment(Packet *packet, uint32_t SendId, uint32_t parts, uint32_t part_idx);
	//
	// Sends a packet to the host.
	//
	void Send(Packet *Packet);
};

typedef void(*FnOnNewConnection)(ServerClient *Client);

//
// A server.
//
class Server {
private:
	//
	// WSA init data.
	//
	WSADATA WsaData;
	//
	// The socket connection for the binding.
	//
	SOCKET ServerSocket = INVALID_SOCKET;
	
	//
	// A map of packet handlers.
	//
	ServerPacketHandler PacketHandlers[0xFF] = { };
	
public:
	//
	// If we're binded.
	//
	bool Binded = false;

public:
	//
	// New connection event handler.
	//
	FnOnNewConnection OnNewConnection = NULL;

public:
	//
	// Handles an incoming packet.
	//
	void HandlePacket(Packet *incoming, ServerClient *Client);

public:
	//
	// Initializes the server.
	//
	bool Init();
	//
	// Binds to the server port.
	//
	bool Bind();
	//
	// Accepts new connections.
	//
	void Accept();

	//
	// Stops the server.
	//
	void Stop();
	//
	// Registers a packet handler to this server.
	//
	void RegisterHandler(uint8_t Opcode, FnHandleServerPacket handler, void *Ctx);
};
#pragma pack(push, 1)

//
// A login packet.
//
struct PacketC2SLogin {
	//
	// The version of the loader.
	//
	uint32_t Version = 0;
};

//
// An initialized packet.
//
struct PacketC2SInitialized {
	//
	// The base of the allocated memory.
	//
	void *Allocated = NULL;
};

//
// A request instruction packet.
//
struct PacketC2SRequestInstruction {
	//
	// The address of the requested instruction.
	//
	void *Address = NULL;
	//
	// CPU state.
	//
	DWORD64 Rax;
	DWORD64 Rcx;
	DWORD64 Rdx;
	DWORD64 Rbx;
	DWORD64 Rsp;
	DWORD64 Rbp;
	DWORD64 Rsi;
	DWORD64 Rdi;
	DWORD64 R8;
	DWORD64 R9;
	DWORD64 R10;
	DWORD64 R11;
	DWORD64 R12;
	DWORD64 R13;
	DWORD64 R14;
	DWORD64 R15;
	DWORD64 Rip;
	DWORD EFlags;
};

//
// An init packet.
//
struct PacketS2CInit {
	//
	// The length of the image.
	//
	uint64_t Length;
	//
	// The entry point offset.
	//
	uint64_t Off;
};

//
// A write packet.
//
struct PacketS2CWrite {
	//
	// The address to write at.
	//
	void *Address = NULL;
	//
	// The length of the data.
	//
	uint64_t Length = 0;
	//
	// The data.
	//
	char Data[0x100] = { 0 };
};

#pragma pack(pop)