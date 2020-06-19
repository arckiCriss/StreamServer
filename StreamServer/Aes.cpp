#include "Aes.h"
#include "Logging.h"

VOID AesEncrypt(PVOID Key, PVOID Iv, PVOID Msg, SIZE_T MsgLength, PVOID *Out, PSIZE_T OutLen) {
	CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption Enc;
	Enc.SetKeyWithIV((CryptoPP::byte*)Key, 0x10, (CryptoPP::byte*)Iv, 0x10);

	auto Allocated = malloc(MsgLength + CryptoPP::AES::BLOCKSIZE);
	CryptoPP::ArraySink Cs((CryptoPP::byte*)Allocated, MsgLength + CryptoPP::AES::BLOCKSIZE);
	CryptoPP::ArraySource((CryptoPP::byte*)Msg, MsgLength, true,
		new CryptoPP::StreamTransformationFilter(Enc, new CryptoPP::Redirector(Cs)));

	auto RealAllocated = malloc(Cs.TotalPutLength());
	memcpy(RealAllocated, Allocated, Cs.TotalPutLength());

	//
	// We had to allocate 2 buffers, only the real one is used as the output.
	//
	free(Allocated);

	*Out = RealAllocated;
	*OutLen = Cs.TotalPutLength();
}

VOID AesDecrypt(PVOID Key, PVOID Iv, PVOID Msg, SIZE_T MsgLength, PVOID *Out, PSIZE_T OutLen) {
	CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption Dec;
	Dec.SetKeyWithIV((CryptoPP::byte*)Key, 0x10, (CryptoPP::byte*)Iv, 0x10);

	auto Allocated = malloc(MsgLength);
	CryptoPP::ArraySink Cs((CryptoPP::byte*)Allocated, MsgLength + CryptoPP::AES::BLOCKSIZE);
	CryptoPP::ArraySource((CryptoPP::byte*)Msg, MsgLength, true,
		new CryptoPP::StreamTransformationFilter(Dec, new CryptoPP::Redirector(Cs)));

	auto RealAllocated = malloc(Cs.TotalPutLength());
	memcpy(RealAllocated, Allocated, Cs.TotalPutLength());

	//
	// We had to allocate 2 buffers, only the real one is used as the output.
	//
	free(Allocated);

	*Out = RealAllocated;
	*OutLen = Cs.TotalPutLength();
}

PVOID AesRandomKey() {
	auto Key = malloc(CryptoPP::AES::MAX_KEYLENGTH);
	auto Rng = CryptoPP::NonblockingRng();
	Rng.GenerateBlock((CryptoPP::byte*)Key, CryptoPP::AES::MAX_KEYLENGTH);
	return Key;
}

PVOID AesRandomIv() {
	auto Iv = malloc(CryptoPP::AES::BLOCKSIZE);
	auto Rng = CryptoPP::NonblockingRng();
	Rng.GenerateBlock((CryptoPP::byte*)Iv, CryptoPP::AES::BLOCKSIZE);
	return Iv;
}

VOID AesFree(PVOID Memory) {
	free(Memory);
}