// ECDSA.KeyGen.cpp : Defines the entry point for the console application.
//

/* Source, Sink */
#include <assert.h>
#include <iostream>
using std::endl;
using std::wcin;
using std::wcout;

#include <string>
using std::string;
using std::wstring;
using namespace std;

#include <sstream>
using std::ostringstream;

#include "cryptopp/osrng.h"
// using CryptoPP::AutoSeededX917RNG;
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/integer.h"
#include "cryptopp/nbtheory.h"
using CryptoPP::Integer;

// Hash funtions
#include "cryptopp/sha.h"
#include "cryptopp/sha3.h"
using CryptoPP::SHA256;
using CryptoPP::SHA512;

// String filter
#include "cryptopp/filters.h"
using CryptoPP::ArraySink;
using CryptoPP::byte;
using CryptoPP::SignatureVerificationFilter;
using CryptoPP::SignerFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include <ctime>

// #include "cryptopp/stdafx.h"

/* RSA cipher*/
#include "cryptopp/rsa.h"
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSA;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;
using CryptoPP::RSAES_PKCS1v15_Decryptor;
using CryptoPP::RSAES_PKCS1v15_Encryptor;

//Genererate keys
#include "cryptopp/cryptlib.h"
using CryptoPP::DecodingResult;
using CryptoPP::Exception;
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;

/*Reading key input from file*/
#include <cryptopp/queue.h>
using CryptoPP::ByteQueue;

/* convert string stream */
#include <sstream>
using std::ostringstream;

// ECC crypto
#include "cryptopp/eccrypto.h"
using CryptoPP::DL_GroupParameters_EC;
using CryptoPP::ECDSA;
using CryptoPP::ECP;

#include <cryptopp/oids.h> //
namespace ASN1 = CryptoPP::ASN1;
using CryptoPP::OID;

#include "cryptopp/hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#include "cryptopp/base64.h"
using CryptoPP::Base64Decoder;
using CryptoPP::Base64Encoder;

/* standard curves*/
#include <cryptopp/asn.h>
// using CryptoPP::ASN1;

// Phan tieng viet
#include <fcntl.h>
/* Convert string*/
#include <locale>
using std::wstring_convert;
#include <codecvt>
using std::codecvt_utf8;

// Convert
wstring string_to_wstring(const std::string &str);
string wstring_to_string(const std::wstring &str);
wstring integer_to_wstring(const CryptoPP::Integer &t);
string integer_to_string(const CryptoPP::Integer &t);
string integer_to_hex(const CryptoPP::Integer &t);

#include "cryptopp/oids.h"
using CryptoPP::OID;

bool GeneratePrivateKey(const OID &oid, ECDSA<ECP, SHA256>::PrivateKey &key);
bool GeneratePublicKey(const ECDSA<ECP, SHA256>::PrivateKey &privateKey, ECDSA<ECP, SHA256>::PublicKey &publicKey);

void SavePrivateKey(const string &filename, const ECDSA<ECP, SHA256>::PrivateKey &key);
void SavePublicKey(const string &filename, const ECDSA<ECP, SHA256>::PublicKey &key);
void LoadPrivateKey(const string &filename, ECDSA<ECP, SHA256>::PrivateKey &key);
void LoadPublicKey(const string &filename, ECDSA<ECP, SHA256>::PublicKey &key);

void PrintDomainParameters(const ECDSA<ECP, SHA256>::PrivateKey &key);
void PrintDomainParameters(const ECDSA<ECP, SHA256>::PublicKey &key);
void PrintDomainParameters(const DL_GroupParameters_EC<ECP> &params);
void PrintPrivateKey(const ECDSA<ECP, SHA256>::PrivateKey &key);
void PrintPublicKey(const ECDSA<ECP, SHA256>::PublicKey &key);

bool SignMessage(const ECDSA<ECP, SHA256>::PrivateKey &key, const string &message, string &signature);
bool VerifyMessage(const ECDSA<ECP, SHA256>::PublicKey &key, const string &message, const string &signature);

//////////////////////////////////////////
// In 2010, use SHA-256 and P-256 curve
//////////////////////////////////////////

int main(int argc, char *argv[])
{
#ifdef __linux__
    setlocale(LC_ALL, "");
#elif _WIN32
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);
#else
#endif
    cout << "Create key";
    AutoSeededRandomPool prng;

    ECDSA<ECP, SHA256>::PrivateKey privateKey;
    ECDSA<ECP, SHA256>::PublicKey publicKey;

    GeneratePrivateKey(CryptoPP::ASN1::secp256r1(), privateKey);
    GeneratePublicKey(privateKey, publicKey);

    PrintDomainParameters(publicKey);
    PrintPrivateKey(privateKey);
    PrintPublicKey(publicKey);

    /////////////////////////////////////////////
    // Save key in PKCS#9 and X.509 format
    SavePrivateKey("ec.private.der", privateKey);
    SavePublicKey("ec.public.der", publicKey);

    return 0;
}

bool GeneratePrivateKey(const OID &oid, ECDSA<ECP, SHA256>::PrivateKey &key)
{
    AutoSeededRandomPool prng;

    key.Initialize(prng, oid);
    assert(key.Validate(prng, 3));

    return key.Validate(prng, 3);
}

bool GeneratePublicKey(const ECDSA<ECP, SHA256>::PrivateKey &privateKey, ECDSA<ECP, SHA256>::PublicKey &publicKey)
{
    AutoSeededRandomPool prng;

    // Sanity check
    assert(privateKey.Validate(prng, 3));

    privateKey.MakePublicKey(publicKey);
    assert(publicKey.Validate(prng, 3));

    return publicKey.Validate(prng, 3);
}

void PrintDomainParameters(const ECDSA<ECP, SHA256>::PrivateKey &key)
{
    PrintDomainParameters(key.GetGroupParameters());
}

void PrintDomainParameters(const ECDSA<ECP, SHA256>::PublicKey &key)
{
    PrintDomainParameters(key.GetGroupParameters());
}

void PrintDomainParameters(const DL_GroupParameters_EC<ECP> &params)
{
    wcout << endl;

    wcout << "Modulus:" << endl;
    wcout << " " << integer_to_wstring(params.GetCurve().GetField().GetModulus()) << endl;

    wcout << "Coefficient A:" << endl;
    wcout << " " << integer_to_wstring(params.GetCurve().GetA()) << endl;

    wcout << "Coefficient B:" << endl;
    wcout << " " << integer_to_wstring(params.GetCurve().GetB()) << endl;

    wcout << "Base Point:" << endl;
    wcout << " X: " << integer_to_wstring(params.GetSubgroupGenerator().x) << endl;
    wcout << " Y: " << integer_to_wstring(params.GetSubgroupGenerator().y) << endl;

    wcout << "Subgroup Order:" << endl;
    wcout << " " << integer_to_wstring(params.GetSubgroupOrder()) << endl;

    wcout << "Cofactor:" << endl;
    wcout << " " << integer_to_wstring(params.GetCofactor()) << endl;
}

void PrintPrivateKey(const ECDSA<ECP, SHA256>::PrivateKey &key)
{
    wcout << endl;
    wcout << "Private Exponent:" << endl;
    wcout << " " << integer_to_wstring(key.GetPrivateExponent()) << endl;
}

void PrintPublicKey(const ECDSA<ECP, SHA256>::PublicKey &key)
{
    wcout << endl;
    wcout << "Public Element:" << endl;
    wcout << " X: " << integer_to_wstring(key.GetPublicElement().x) << endl;
    wcout << " Y: " << integer_to_wstring(key.GetPublicElement().y) << endl;
}

void SavePrivateKey(const string &filename, const ECDSA<ECP, SHA256>::PrivateKey &key)
{
    key.Save(FileSink(filename.c_str(), true /*binary*/).Ref());
}

void SavePublicKey(const string &filename, const ECDSA<ECP, SHA256>::PublicKey &key)
{
    key.Save(FileSink(filename.c_str(), true /*binary*/).Ref());
}

void LoadPrivateKey(const string &filename, ECDSA<ECP, SHA256>::PrivateKey &key)
{
    key.Load(FileSource(filename.c_str(), true /*pump all*/).Ref());
}

void LoadPublicKey(const string &filename, ECDSA<ECP, SHA256>::PublicKey &key)
{
    key.Load(FileSource(filename.c_str(), true /*pump all*/).Ref());
}

bool SignMessage(const ECDSA<ECP, SHA256>::PrivateKey &key, const string &message, string &signature)
{
    AutoSeededRandomPool prng;

    signature.erase();

    StringSource(message, true,
                 new SignerFilter(prng,
                                  ECDSA<ECP, SHA256>::Signer(key),
                                  new StringSink(signature)) // SignerFilter
    );                                                       // StringSource

    return !signature.empty();
}

bool VerifyMessage(const ECDSA<ECP, SHA256>::PublicKey &key, const string &message, const string &signature)
{
    bool result = false;

    StringSource(signature + message, true,
                 new SignatureVerificationFilter(
                     ECDSA<ECP, SHA256>::Verifier(key),
                     new ArraySink((byte *)&result, sizeof(result))) // SignatureVerificationFilter
    );

    return result;
}

/* convert string to wstring */
wstring string_to_wstring(const std::string &str)
{
    wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(str);
}

/* convert wstring to string */
string wstring_to_string(const std::wstring &str)
{
    wstring_convert<codecvt_utf8<wchar_t>> tostring;
    return tostring.to_bytes(str);
}
// Conver integer to string and wstring;
wstring integer_to_wstring(const CryptoPP::Integer &t)
{
    std::ostringstream oss;
    oss.str("");
    oss.clear();
    oss << t;
    std::string encoded(oss.str());
    std::wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(encoded);
}

string integer_to_string(const CryptoPP::Integer &t)
{
    std::ostringstream oss;
    oss.str("");
    oss.clear();
    oss << t;
    std::string encoded(oss.str());
    return encoded;
}

string integer_to_hex(const CryptoPP::Integer &t)
{
    std::ostringstream oss;
    oss.str("");
    oss.clear();
    oss << std::hex << t;
    std::string encoded(oss.str());
    return encoded;
}
