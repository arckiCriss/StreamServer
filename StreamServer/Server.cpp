#include "Server.h"
#include "Logging.h"
#include "Config.h"

#include <future>
#include <thread>
#include <chrono>

NOINLINE void Server::HandlePacket(Packet *Incoming, ServerClient *Client) {
	auto Handler = PacketHandlers[Incoming->Opcode];
	if (auto Func = Handler.Func) {
		if (Incoming->BodyLength < Handler.MinimumLength) {
			if (OnBadPacket) {
				OnBadPacket(Client, Incoming);
				return;
			}
		}

		Func(Handler.Ctx, this, Client, Incoming);
	}
}

//
// The context for a new thread.
//
struct NEW_THREAD_CONTEXT {
	Server *Server;
	ServerClient *Client;
};

//
// Handles a new connection
//
static void HandleConnection(NEW_THREAD_CONTEXT *Context) {
	auto Server = Context->Server;
	auto Client = Context->Client;
	while (Client->Connected) {
		for (auto i = 0; i < 10000 && Client->AttemptRecv(); i++);
		Sleep(1);
	}
}

NOINLINE bool Server::Init() {
	LOG("WSAStartup");
	WSAStartup(MAKEWORD(2, 2), &WsaData);
	return true;
}

NOINLINE bool Server::Bind() {
	struct addrinfo *Result = NULL;
	struct addrinfo Hints;

	ZeroMemory(&Hints, sizeof(Hints));
	Hints.ai_family = AF_INET;
	Hints.ai_socktype = SOCK_STREAM;
	Hints.ai_protocol = IPPROTO_TCP;
	Hints.ai_flags = AI_PASSIVE;

	auto AddrInfoResult = getaddrinfo(NULL, Port, &Hints, &Result);
	if (AddrInfoResult != 0) {
		LOG("getaddrinfo failed with error: %d", AddrInfoResult);
		return false;
	}


	LOG("Opening socket");
	ServerSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (ServerSocket == INVALID_SOCKET) {
		LOG("Failed to open socket");
		return false;
	}

	LOG("Binding");
	auto BindResult = bind(ServerSocket, Result->ai_addr, (int)Result->ai_addrlen);
	if (BindResult == SOCKET_ERROR) {
		LOG("Bind failed with error: %d", WSAGetLastError());
		freeaddrinfo(Result);
		closesocket(ServerSocket);
		return false;
	}

	LOG("Freeing result");
	freeaddrinfo(Result);

	LOG("Listening");
	if (listen(ServerSocket, SOMAXCONN) == SOCKET_ERROR) {
		printf("Listen failed with error: %ld\n", WSAGetLastError());
		closesocket(ServerSocket);
		return false;
	}

	Binded = true;
	return true;
}

NOINLINE void Server::Accept() {
	while (Binded) {
		auto Future = std::async(std::launch::async, [&]() -> SOCKET {
			return accept(ServerSocket, (sockaddr*)NULL, (int*)NULL);
		});

		auto Status = std::future_status::deferred;
		while (Status != std::future_status::ready) {
			Status = Future.wait_for(std::chrono::milliseconds(100));
		}

		if (Status == std::future_status::ready) {
			auto ClientSocket = Future.get();
			if (ClientSocket != INVALID_SOCKET) {
				u_long Ul = 1;
				ioctlsocket(ClientSocket, FIONBIO, &Ul);

				auto Client = new ServerClient();
				Client->Server = this;
				Client->Socket = ClientSocket;

				if (OnNewConnection) {
					OnNewConnection(Client);
				}
				NEW_THREAD_CONTEXT Context;
				Context.Server = this;
				Context.Client = Client;
				CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)HandleConnection, &Context, 0, NULL);
			}
		}
	}
}

NOINLINE bool ServerClient::AttemptRecv() {
	auto Decoded = false;
	if (Connected) {
		auto RecvAmt = 0;
		auto HeaderSize = sizeof(PacketFragment) - 0x200;
		if (HeaderSize > FragmentOff) {
			RecvAmt = (int)(HeaderSize - FragmentOff);
		} else {
			auto Rel = FragmentOff - HeaderSize;
			RecvAmt = (int)(CurrentPart.PartSize - Rel);
		}

		if (RecvAmt) {
			auto Received = recv(Socket, (char*)&CurrentPart + FragmentOff, RecvAmt, 0);
			if (WSAGetLastError() != WSAEWOULDBLOCK && (Received == 0 || Received == -1)) {
				Connected = false;
				return false;
			}

			if (Received > 0) {
				FragmentOff += Received;
				RecvAmt -= Received;
				Decoded = true;
			}
		} else {
			//
			// Verify the packet is not too big
			//
			if (CurrentPart.TotalSize > Server->MaxPacketSize) {
				if (auto E = Server->OnMalformedData) {
					E(this);
				}

				FragmentOff = 0;
				Decoded = true;
				return true;
			}

			auto &Trace = Traces[CurrentPart.Id];
			Trace.Assemble(CurrentPart);

			if (Trace.IsComplete()) {
				//
				// Verify the packet is consistent..
				//
				if (!Trace.Verify()) {
					if (auto E = Server->OnMalformedData) {
						E(this);
					}

					FragmentOff = 0;
					Decoded = true;
					return true;
				}
			}

			auto Pkt = Packet();
			if (Trace.Combine(&Pkt)) {
				Server->HandlePacket(&Pkt, this);
			}
			Traces[CurrentPart.Id] = PacketTrace();

			FragmentOff = 0;
			Decoded = true;
		}
	}

	return Decoded;
}

NOINLINE void ServerClient::Tick() {
	if (Connected) {
		for (auto i = 0; i < 10000 && AttemptRecv(); i++);
	}
}

NOINLINE void ServerClient::SendFragment(Packet *Packet, uint32_t SendId, uint32_t Parts, uint32_t PartIdx) {
	auto BufBegin = PartIdx * PACKET_LEN;
	auto BufLen = min((uint32_t)PACKET_LEN, Packet->BodyLength - BufBegin);

	auto Fragment = PacketFragment();
	Fragment.TotalSize = Packet->BodyLength;
	Fragment.TotalParts = Parts;
	Fragment.PartSize = BufLen;
	Fragment.Id = SendId;
	Fragment.Part = PartIdx;
	Fragment.Opcode = Packet->Opcode;
	memcpy(Fragment.Body, (char*)Packet->Body + BufBegin, BufLen);

	auto SizeNBody = sizeof(Fragment) - PACKET_LEN;
	auto Size = (int)(SizeNBody + BufLen);
	auto Ptr = (char*)&Fragment;
	auto End = Ptr + Size;
	while (Ptr < End) {
		auto Sent = ::send(Socket, Ptr, End - Ptr, 0);
		if (Sent <= 0) {
			if (WSAGetLastError() != WSAEWOULDBLOCK) {
				Connected = false;
				return;
			}

			continue;
		}

		Ptr += Sent;
	}
}

NOINLINE void ServerClient::Send(Packet *packet) {
	auto count = packet->BodyLength / PACKET_LEN;
	if (packet->BodyLength % PACKET_LEN) {
		count += 1;
	}

	auto PktId = SendId++;
	for (auto i = 0u; i < count; i++) {
		SendFragment(packet, PktId, count, i);
	}
}

NOINLINE void Server::Stop() {
	closesocket(ServerSocket);
}

NOINLINE void Server::RegisterHandler(uint8_t Opcode, FnHandleServerPacket Func, void *Ctx, uint64_t MinimumLength) {
	ServerPacketHandler Handler;
	Handler.Ctx = Ctx;
	Handler.Func = Func;
	Handler.MinimumLength = MinimumLength;

	PacketHandlers[Opcode] = Handler;
}