#include "Rsa.h"
#include "Logging.h"

VOID RsaEncrypt(CryptoPP::Integer &n, CryptoPP::Integer &e, PVOID Msg, SIZE_T MsgLength, PVOID *Out, PSIZE_T OutLen) {
	LOG("Initializing key");
	CryptoPP::RSA::PublicKey Key;
	Key.Initialize(n, e);

	LOG("Getting raw");
	auto Raw = CryptoPP::Integer((PBYTE)Msg, MsgLength);

	LOG("Applying key");
	auto Encrypted = Key.ApplyFunction(Raw);

	LOG("Allocating");
	auto Allocated = malloc(Encrypted.MinEncodedSize());

	LOG("Encoding");
	Encrypted.Encode((PBYTE)Allocated, Encrypted.MinEncodedSize());

	LOG("Writing output");
	*Out = Allocated;
	*OutLen = Encrypted.MinEncodedSize();
}

VOID RsaDecrypt(CryptoPP::Integer &n, CryptoPP::Integer &e, CryptoPP::Integer &d, PVOID Msg, SIZE_T MsgLength, PVOID *Out, PSIZE_T OutLen) {
	LOG("Initializing key");
	CryptoPP::RSA::PrivateKey Key;
	Key.Initialize(n, e, d);

	LOG("Getting raw");
	auto Raw = CryptoPP::Integer((PBYTE)Msg, MsgLength);
	CryptoPP::AutoSeededRandomPool Rng;

	LOG("Calculating inverse");
	auto Inverse = Key.CalculateInverse(Rng, Raw);

	LOG("Allocating");
	auto Allocated = malloc(Inverse.MinEncodedSize());

	LOG("Encoding");
	Inverse.Encode((PBYTE)Allocated, Inverse.MinEncodedSize());
	
	LOG("Writing output");
	*Out = Allocated;
	*OutLen = Inverse.MinEncodedSize();
}

VOID RsaFree(PVOID Memory) {
	free(Memory);
}