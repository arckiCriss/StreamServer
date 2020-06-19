#include "Rsa.h"
#include "Logging.h"

VOID RsaEncrypt(CryptoPP::Integer &n, CryptoPP::Integer &e, PVOID Msg, SIZE_T MsgLength, PVOID *Out, PSIZE_T OutLen) {
	CryptoPP::RSA::PublicKey Key;
	Key.Initialize(n, e);

	auto Raw = CryptoPP::Integer((PBYTE)Msg, MsgLength);
	auto Encrypted = Key.ApplyFunction(Raw);

	auto Allocated = malloc(Encrypted.MinEncodedSize());
	Encrypted.Encode((PBYTE)Allocated, Encrypted.MinEncodedSize());

	*Out = Allocated;
	*OutLen = Encrypted.MinEncodedSize();
}

VOID RsaDecrypt(CryptoPP::Integer &n, CryptoPP::Integer &e, CryptoPP::Integer &d, PVOID Msg, SIZE_T MsgLength, PVOID *Out, PSIZE_T OutLen) {
	CryptoPP::RSA::PrivateKey Key;
	Key.Initialize(n, e, d);

	auto Raw = CryptoPP::Integer((PBYTE)Msg, MsgLength);
	CryptoPP::AutoSeededRandomPool Rng;

	auto Inverse = Key.CalculateInverse(Rng, Raw);

	auto Allocated = malloc(Inverse.MinEncodedSize());
	Inverse.Encode((PBYTE)Allocated, Inverse.MinEncodedSize());
	
	*Out = Allocated;
	*OutLen = Inverse.MinEncodedSize();
}

VOID RsaFree(PVOID Memory) {
	free(Memory);
}