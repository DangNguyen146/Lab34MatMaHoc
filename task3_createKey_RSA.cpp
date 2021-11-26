// g++ -g3 -ggdb -O0 -DDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
/* Work on files*/
#include <cryptopp/files.h>
using CryptoPP::BufferedTransformation;
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::byte;

/* Integer arithmatics*/
#include <cryptopp/integer.h>
using CryptoPP::Integer;

#include <cryptopp/nbtheory.h>
using CryptoPP::ModularSquareRoot;

#include <cryptopp/modarith.h>
using CryptoPP::ModularArithmetic;

#include <sstream>
using std::ostringstream;

#include <iostream>
using std::cerr;
using std::cin;
using std::cout;
using std::endl;

#include <iostream>
using std::cerr;
using std::endl;
using std::wcin;
using std::wcout;

#include <string>
using std::string;
using std::wstring;

#include <cstdlib>
using std::exit;

//Genererate keys
#include "cryptopp/cryptlib.h"
using CryptoPP::DecodingResult;
using CryptoPP::Exception;
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;

#include "cryptopp/hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

/*Reading key input from file*/
#include <cryptopp/queue.h>
using CryptoPP::ByteQueue;

#include "cryptopp/SecBlock.h"
using CryptoPP::SecByteBlock;

#include "cryptopp/filters.h"
using CryptoPP::BufferedTransformation;
using CryptoPP::PK_DecryptorFilter; // Public key decryption
using CryptoPP::PK_EncryptorFilter; // Public key encryption
using CryptoPP::Redirector;         // string to bytes
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "cryptopp/rsa.h"
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSA;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;
using CryptoPP::RSAES_PKCS1v15_Decryptor;
using CryptoPP::RSAES_PKCS1v15_Encryptor;

#include "assert.h"

/* Set _setmode()*/
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#else
#endif
/* Convert string*/
#include <locale>
using std::wstring_convert;
#include <codecvt>
using std::codecvt_utf8;
wstring string_to_wstring(const std::string &str);
string wstring_to_string(const std::wstring &str);
wstring integer_to_wstring(const CryptoPP::Integer &t);
string integer_to_string(const CryptoPP::Integer &t);
string integer_to_hex(const CryptoPP::Integer &t);
void Save(const string &filename, const BufferedTransformation &bt);
void SavePublicKey(const string &filename, const PublicKey &key);
void SavePrivateKey(const string &filename, const PrivateKey &key);
void Save(const string &filename, const BufferedTransformation &bt);
void SavePublicKey(const string &filename, const PublicKey &key);
void SavePrivateKey(const string &filename, const PrivateKey &key);

int main(int argc, char *argv[])
{
    try
    {
/*Set mode support Vietnamese*/
#ifdef _linux_
        setlocale(LC_ALL, "");
#elif _WIN32
        _setmode(_fileno(stdin), _O_U16TEXT);
        _setmode(_fileno(stdout), _O_U16TEXT);
#else
#endif
        wcout << "Create key" << endl;
        // Generate keys
        string encoded;
        // Create a random private keys
        AutoSeededRandomPool rng;
        RSA::PrivateKey privateKey;
        privateKey.GenerateRandomWithKeySize(rng, 3072);
        // Creat the public key
        RSA::PublicKey publicKey(privateKey);
        // Write key to file
        SavePrivateKey("rsa-private.key", privateKey);
        SavePublicKey("rsa-public.key", publicKey);

        // Get system parameters
        Integer modul = privateKey.GetModulus(); // modul n
        Integer prime1 = privateKey.GetPrime1(); // prime p
        Integer prime2 = privateKey.GetPrime2(); // prime p

        wcout << "Module n = p*q: " << integer_to_wstring(modul) << endl;
        wcout << "Prime p: " << integer_to_wstring(prime1) << endl;
        wcout << "Prime q: " << integer_to_wstring(prime2) << endl;

        /* Secret exponent d; public exponent e */
        Integer SK = privateKey.GetPrivateExponent(); // secret exponent d;
        Integer PK = publicKey.GetPublicExponent();   // public exponent e;
        wcout << "Public key e: " << integer_to_wstring(PK) << endl;
        wcout << "Private key d: " << integer_to_wstring(SK) << endl;
    }
    catch (CryptoPP::Exception &e)
    {
        cerr << "Caught Exception..." << endl;
        cerr << e.what() << endl;
    }
    return 0;
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

// Save keys to Files
void Save(const string &filename, const BufferedTransformation &bt)
{
    FileSink file(filename.c_str());
    bt.CopyTo(file);
    file.MessageEnd();
}

void SavePublicKey(const string &filename, const PublicKey &key)
{
    ByteQueue queue;
    key.Save(queue);
    Save(filename, queue);
}

void SavePrivateKey(const string &filename, const PrivateKey &key)
{
    ByteQueue queue;
    key.Save(queue);
    Save(filename, queue);
}

void Load(const string &filename, BufferedTransformation &bt)
{
    FileSource file(filename.c_str(), true /*pumpAll*/);

    file.TransferTo(bt);
    bt.MessageEnd();
}

void LoadPrivateKey(const string &filename, PrivateKey &key)
{
    ByteQueue queue;
    Load(filename, queue);
    key.Load(queue);
}

void LoadPublicKey(const string &filename, PublicKey &key)
{
    ByteQueue queue;
    Load(filename, queue);
    key.Load(queue);
}
