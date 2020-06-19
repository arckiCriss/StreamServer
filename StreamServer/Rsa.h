#pragma once

#include <cryptopp/cryptlib.h>
#include <cryptopp/integer.h>
#include <cryptopp/rsa.h>
#include <cryptopp/rng.h>
#include <cryptopp/osrng.h>

#include <Windows.h>

//
// Encrypts some data using RSA.
//
VOID RsaEncrypt(CryptoPP::Integer &n, CryptoPP::Integer &e, PVOID Msg, SIZE_T MsgLength, PVOID *Out, PSIZE_T OutLen);

//
// Decrypts some data using RSA.
//
VOID RsaDecrypt(CryptoPP::Integer &n, CryptoPP::Integer &e, CryptoPP::Integer &d, PVOID Msg, SIZE_T MsgLength, PVOID *Out, PSIZE_T OutLen);

//
// Frees some memory allocated by this API.
//
VOID RsaFree(PVOID Memory);