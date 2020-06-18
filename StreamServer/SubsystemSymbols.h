#pragma once
#include "Server.h"

//
// Initializes the symbol subsystem.
//
BOOLEAN SubsystemSymbolsInit();

//
// Initializes the symbol subsystem networking.
//
VOID SubsystemSymbolsInitNet(Server *Server);