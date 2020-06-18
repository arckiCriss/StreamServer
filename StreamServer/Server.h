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
	uint16_t PartSize;
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
	// Verifies the parts of this packet.
	//
	inline bool Verify() {
		for (auto i = 0u; i < Root.TotalParts; i++) {
			if (Fragments[i].PartSize > Root.TotalSize) {
				return false;
			}

			for (auto j = 0u; j < Root.TotalParts; j++) {
				if (Fragments[i].TotalSize != Fragments[j].TotalSize) {
					return false;
				}

				if (Fragments[i].TotalParts != Fragments[j].TotalParts) {
					return false;
				}
			}
		}

		return true;
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
			memcpy(Buf + Offset, fragment->Body, fragment->PartSize);
			Offset += fragment->PartSize;
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
	//
	// The minimum length of packets coming into this handler.
	//
	uint64_t MinimumLength;
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

	//
	// Disconnects this client from the server.
	//
	void Disconnect();
};

typedef void(*FnOnNewConnection)(ServerClient *Client);
typedef void(*FnOnBadPacket)(ServerClient *Client, Packet *Packet);
typedef void(*FnOnMalformedData)(ServerClient *Client);

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
	bool Binded = false;

public:
	//
	// A map of packet handlers.
	//
	ServerPacketHandler PacketHandlers[0xFF] = { };
	//
	// The maximum size of a packet.
	//
	uint64_t MaxPacketSize = 0x10000;
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
	void RegisterHandler(uint8_t Opcode, FnHandleServerPacket handler, void *Ctx, uint64_t MinimumLength);
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
};
#pragma pack(pop)
