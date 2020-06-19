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
// Public RSA.
//
#define RSA_N "83f65c821aa422f7c9e1ed8a9ace08c5ddd2bfa9b12a6e4331841c22dd40330bd8e728dbfbb88e31a61c205b11d21e2a245cd9bef3901f62c50b29677f68a75f27e5c73fa3675c1374f0f844e617b3fe233fae05be3bd298c167a63cceca96d50534a3ea73eb7b053acd08ddc1ffd1c2c4772be30b46e465ae891e309232837fh"
#define RSA_E "10001h"

//
// Private RSA (do not share with anyone.)
//
#define RSA_D "5cb85d878cf0872153d84aef78960bd3fb687902e258cde0a88a0abaf47a87636ba40031914cbb9c66fa9c4160e4220dba3f03400822dbeaaa488d6f0b369d6255fb026b45f65f28e973287075e45f801f4832d55ed92ea36b837b036b6e5ebd3080929f42bba62dc23d61c80bcbf8a46e5b03b28b1cc82db30f31cf5103071h"

//
// If defined, all conditional branches will be replaced with direct ones.
//
//#define UNROLL_CONTROL_FLOW