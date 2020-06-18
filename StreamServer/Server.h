#pragma once
#include <vector>
#include <winsock2.h>
#include <WS2tcpip.h>
#include <windows.h>
#include <cstdint>
#include <map>

#include "Net.h"

class ServerClient;
class Server;

#pragma pack(push, 1)
//
// A packet.
//
struct Packet {
	//
	// The opcode of the packet.
	//
	UINT8 Opcode = 0;
	//
	// The body of the packet.
	//
	PVOID Body = NULL;
	//
	// The length of the body.
	//
	UINT32 BodyLength = 0;

	//
	// Nulls the packet body.
	//
	inline VOID Null(VOID) {
		Body = NULL;
		BodyLength = 0;
	}
};

//
// A packet fragment.
//
struct PacketFragment {
	//
	// The total size of the packet.
	//
	UINT32 TotalSize;
	//
	// The total number of parts in the packet.
	//
	UINT32 TotalParts;
	//
	// The size of this part.
	//
	UINT16 PartSize;
	//
	// The index of this part.
	//
	UINT32 Part;
	//
	// The opcode of the packet.
	//
	UINT8 Opcode;
	//
	// The id of the packet.
	//
	UINT16 Id;
	//
	// The body of this fragment.
	//
	UINT8 Body[PACKET_LEN];
};

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
	UINT32 PartsAssembled = 0;

	//
	// Assemblies a piece of the packet being traced.
	//
	inline VOID Assemble(PacketFragment Fragment) {
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
	inline UINT16 GetId(VOID) {
		return Root.Id;
	}

	//
	// Retrieves the opcode of this trace.
	//
	// @return The opcode of this packet.
	//
	inline UINT8 GetOpcode(VOID) {
		return Root.Opcode;
	}

	//
	// Verifies the parts of this packet.
	//
	inline BOOLEAN Verify(VOID) {
		for (auto i = 0u; i < Root.TotalParts; i++) {
			if (Fragments[i].PartSize > Root.TotalSize) {
				return FALSE;
			}

			for (auto j = 0u; j < Root.TotalParts; j++) {
				if (Fragments[i].TotalSize != Fragments[j].TotalSize) {
					return FALSE;
				}

				if (Fragments[i].TotalParts != Fragments[j].TotalParts) {
					return FALSE;
				}
			}
		}

		return TRUE;
	}

	//
	// Determines if this trace is completed.
	//
	// @return If this packet is complete.
	//
	inline BOOLEAN IsComplete(VOID) {
		if (Fragments.size() < Root.TotalParts) {
			return FALSE;
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
	inline BOOLEAN Combine(Packet *Packet) {
		if (!IsComplete()) {
			return FALSE;
		}

		auto Buf = (PCHAR)malloc(Root.TotalSize);
		auto Offset = 0;
		for (auto i = 0u; i < Root.TotalParts; i++) {
			auto fragment = &Fragments[i];
			memcpy(Buf + Offset, fragment->Body, fragment->PartSize);
			Offset += fragment->PartSize;
		}

		Packet->Opcode = GetOpcode();
		Packet->Body = (PVOID)Buf;
		Packet->BodyLength = Root.TotalSize;
		return TRUE;
	}
};


//
// A packet handler function.
//
typedef VOID(*FnHandleServerPacket)(PVOID Ctx, Server *Server, ServerClient *Client, Packet *Packet);

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
	PVOID Ctx = NULL;
	//
	// The minimum length of packets coming into this handler.
	//
	UINT64 MinimumLength;
};

//
// A symbol request.
//
struct SymbolRequest {
	//
	// The address to fill in.
	//
	PVOID FillAddress;
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
	PVOID Image = NULL;
	//
	// All symbol requests.
	//
	SymbolRequest SymbolRequests[1000];
	//
	// The current symbol request id.
	//
	UINT64 SymbolRequestId = 0;

	//
	// The currently decoding part.
	//
	PacketFragment CurrentPart;
	//
	// The receive fragment offset.
	//
	UINT64 FragmentOff = 0;
	//
	// A map of packet traces.
	//
	std::vector<PacketTrace> Traces = std::vector<PacketTrace>(0xffff);
	//
	// Sent pieces of code.
	//
	std::map<VOID*, bool> Sent;

	//
	// The packet send id.
	//
	UINT16 SendId = 0;
	//
	// The packet recv id.
	//
	UINT16 RecvId = 0;

	//
	// The allocated address.
	//
	PVOID Allocated = NULL;

public:
	//
	// Handles a client tick.
	//
	VOID Tick(VOID);

public:
	//
	// Attempts to receive from this client.
	//
	BOOLEAN AttemptRecv(VOID);

public:
	//
	// Sends a packet fragment to the host.
	//
	VOID SendFragment(Packet *packet, UINT32 SendId, UINT32 parts, UINT32 part_idx);
	//
	// Sends a packet to the host.
	//
	VOID Send(Packet *Packet);

public:
	//
	// Disconnects this client from the server.
	//
	VOID Disconnect(VOID);
};

typedef VOID(*FnOnNewConnection)(ServerClient *Client);
typedef VOID(*FnOnBadPacket)(ServerClient *Client, Packet *Packet);
typedef VOID(*FnOnMalformedData)(ServerClient *Client);

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

public:
	//
	// The port to bind to.
	//
	PCSTR Port = "8263";
	//
	// If we're binded.
	//
	BOOLEAN Binded = FALSE;

public:
	//
	// A map of packet handlers.
	//
	ServerPacketHandler PacketHandlers[0xFF] = { };
	//
	// The maximum size of a packet.
	//
	UINT64 MaxPacketSize = 0x10000;
	//
	// New connection event handler.
	//
	FnOnNewConnection OnNewConnection = NULL;
	//
	// Bad packet event handler.
	//
	FnOnBadPacket OnBadPacket = NULL;
	//
	// Malformed data event handler.
	//
	FnOnMalformedData OnMalformedData = NULL;

public:
	//
	// Registers a packet handler to this server.
	//
	VOID RegisterHandler(UINT8 Opcode, FnHandleServerPacket handler, PVOID Ctx, UINT64 MinimumLength);
	//
	// Handles an incoming packet.
	//
	VOID HandlePacket(Packet *incoming, ServerClient *Client);

public:
	//
	// Initializes the server.
	//
	BOOLEAN Init(VOID);
	//
	// Binds to the server port.
	//
	BOOLEAN Bind(VOID);
	//
	// Accepts new connections.
	//
	VOID Accept(VOID);
	//
	// Stops the server.
	//
	VOID Stop(VOID);
};
#pragma pack(pop)
