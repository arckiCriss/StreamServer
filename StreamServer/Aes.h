#pragma once

#include <cryptopp/cryptlib.h>
#include <cryptopp/integer.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>

#include <Windows.h>

//
// Encrypts some data using AES.
//
VOID AesEncrypt(PVOID Key, PVOID Iv, PVOID Msg, SIZE_T MsgLength, PVOID *Out, PSIZE_T OutLen);

//
// Decrypts some data using AES.
//
VOID AesDecrypt(PVOID Key, PVOID Iv, PVOID Msg, SIZE_T MsgLength, PVOID *Out, PSIZE_T OutLen);

//
// Creates a random key of maximum length.
//
PVOID AesRandomKey();

//
// Creates a random IV of maximum length.
//
PVOID AesRandomIv();

//
// Frees some memory allocated by this API.
//
VOID AesFree(PVOID Memory);