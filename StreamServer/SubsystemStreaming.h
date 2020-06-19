#pragma once
#include "Server.h"
#include <Windows.h>

//
// Called when a client initializes.
//
VOID SubsystemStreamingInitialized(ServerClient *Client, PacketC2SInitialized *Packet);

//
// Called when a new connection is opened.
//
VOID SubsystemStreamingOnNewConnection(ServerClient *Client);

//
// Initializes the streaming subsystem.
//
BOOLEAN SubsystemStreamingInit(LPCSTR ImageName);

//
// Initializes the streaming subsystem networking.
//
VOID SubsystemStreamingInitNet(Server *Server);