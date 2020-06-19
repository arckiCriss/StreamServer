#include "SubsystemSymbols.h"

//
// Called when a symbol address request has been fulfilled by a client.
//
static VOID OnFulfillRequestSymbolAddressPacket(PVOID Ctx, Server *Server, ServerClient *Client, Packet *P) {
	auto Body = (PacketC2SFulfillRequestSymbolAddress*)P->Body;
	auto &Request = Client->SymbolRequests[Body->RequestId];

	PacketS2CWrite NB;
	NB.Address = Request.FillAddress;
	memcpy(NB.Data, &Body->Address, sizeof(Body->Address));
	NB.Length = sizeof(Body->Address);
	Client->SendWrapped(OP_S2C_WRITE, NB);
}

BOOLEAN SubsystemSymbolsInit() {
	return TRUE;
}

VOID SubsystemSymbolsInitNet(Server *Server) {
	Server->RegisterHandler(OP_C2S_FULFILL_REQUEST_SYMBOL_ADDR, OnFulfillRequestSymbolAddressPacket, NULL, sizeof(PacketC2SFulfillRequestSymbolAddress));
}