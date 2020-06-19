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
#define RSA_N "e18af8bfa0c3a098f6238290c5d86ba35f83a6ca4fa0edee6cb928eba8487fe140ce09a653ea4a7bfe2ee34b625614b88faf7f1405049f1a3a6a110823dcd9260860ff845e452e312b9bfe240dbf6b69fa69c0c51f7d41f61b338415667effae1d510b8971fe29ab0ffe70676f40f62973f730387cf4c3301885b2f348c420a75c4db7a466c2f8b84d751f046b3f289ab3bd7502cd059f48c2155eef6576d1ec632af498f58267dc862c550c6596daef0c0f64a52b06a2bbcf1dc3cd0c555b2c46c22759c5619d10692c7f941197f0015cf010c1c5871ad37c7962af45babc731dda0a812bc47e0299e4df1d23973e2ff1ce6f668db4bb3d04dfa2255a6c2213h"
#define RSA_E "10001h"

//
// Private RSA (do not share with anyone.)
//
#define RSA_D "ce6421e519f46ace0ecfc7f73b55248ac828ed444d41f2f92fbcf0d95591a2943a7d510f47d32a7df4c86b6edc79f154430851bdbc29d27e69de0ddfe9117c14f5adeda4efaf56e9e0024bba2a6a749cf26e3bdd2747b448c5f38a771ae83488dc83018fb124e874859a4cba1a70d3d273304c8c24acc6c1086fb0a6387c61738d198cb1cce63cc1c5d2745a6ce8e30876222866b2f7116f5196093e6122dbba6c393c46bc63895e9395e544c7391846ab4e9a4755ea8d4381ddb1af60ac1d2e7fe7d26da95122420908c7636fa620a0538f0ef979f97e9b30a401214bb59a423daf94bbcaf423356b73e8745820d968821cd0a246aa7eff40bc3d0789409081h"

//
// If defined, all conditional branches will be replaced with direct ones.
//
//#define UNROLL_CONTROL_FLOW

//
// If defined, passwords will be hashed on the client.
//
// This may prevent attackers from gathering passwords if they compromise the server.
//
#define CLIENT_SIDED_HASHING