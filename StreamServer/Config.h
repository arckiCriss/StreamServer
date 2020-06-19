#pragma once
#include "Net.h"

//
// Various opcodes.
//
#define OP_JMP_IMM32 0xe9
#define OP_NOP 0x90

//
// Optional. Good for usage with packers.
//
#define NOINLINE __declspec(noinline)

//
// The port to bind to for accepting connections.
//
#define BIND_PORT "8263"

//
// The URI to use for mongo.
//
#define MONGO_URI "mongodb://localhost:27017"

//
// The database to use.
//
#define MONGO_DB "Stream"

//
// If defined, all conditional branches will be replaced with direct ones.
//
//#define UNROLL_CONTROL_FLOW