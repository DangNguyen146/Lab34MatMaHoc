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
wstring OpenandReadFile(const char *filename);
void Save(const string &filename, const BufferedTransformation &bt);
void SavePublicKey(const string &filename, const PublicKey &key);
void SavePrivateKey(const string &filename, const PrivateKey &key);
void LoadPrivateKey(const string &filename, PrivateKey &key);
void LoadPublicKey(const string &filename, PublicKey &key);
void Save(const string &filename, const BufferedTransformation &bt);
void SavePublicKey(const string &filename, const PublicKey &key);
void SavePrivateKey(const string &filename, const PrivateKey &key);
void En_RSA();
void De_RSA();

int main(int argc, char *argv[])
{
    try
    {
#ifdef __linux__
        setlocale(LC_ALL, "");
#elif _WIN32
        _setmode(_fileno(stdin), _O_U16TEXT);
        _setmode(_fileno(stdout), _O_U16TEXT);
#else
#endif
        int mode;
        wcout << "(1)Encryption (2)Decryption: ";
        wcin >> mode;
        wcin.ignore();
        wcout << endl;

        switch (mode)
        {
        case 1:
        {
            En_RSA();
            break;
        }
        case 2:
        {
            De_RSA();
            break;
        }
        }
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
wstring OpenandReadFile(const char *filename)
{
    std::wifstream wif(filename);
    wif.imbue(std::locale(std::locale(), new std::codecvt_utf8<wchar_t>));
    std::wstringstream wss;
    wss << wif.rdbuf();
    return wss.str();
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

void LoadPrivateKey(const string &filename, RSA::PrivateKey &key)
{
    key.Load(
        FileSource(filename.c_str(), true, NULL, true /*binary*/).Ref());
}

void LoadPublicKey(const string &filename, RSA::PublicKey &key)
{
    key.Load(
        FileSource(filename.c_str(), true, NULL, true /*binary*/).Ref());
}

void En_RSA()
{
    // Generate keys
    string encoded;

    wstring wplain;
    string plain, cipher, recovered;
    int mode;
    wcout << L"(1)Nhập từ màn hình (2)Nhập từ file plaintext.txt: ";
    wcin >> mode;
    wcin.ignore();
    wcout << endl;
    switch (mode)
    {
    case 1:
    {
        wcout << "Input plaintext: ";
        fflush(stdin);
        getline(wcin, wplain);
        break;
    }
    case 2:
    {
        wplain = OpenandReadFile("plaintext.txt");
        break;
    }
    }
    plain = wstring_to_string(wplain);
    wcout << "Plaintext: " << wplain << endl;

    // Load public key
    RSA::PublicKey publicKey;
    LoadPublicKey("rsa-public.key", publicKey);
    int startCount = clock();
    for (int i = 0; i < 10000; i++)
    {
        cipher.clear();
        // Encryption
        AutoSeededRandomPool rng;
        // Encryption
        RSAES_OAEP_SHA_Encryptor e(publicKey);
        StringSource(plain, true,
                     new PK_EncryptorFilter(rng, e,
                                            new StringSink(cipher)) // PK_EncryptorFilter
        );                                                          // StringSource
                                                                    /* Pretty Print cipher text */
    }
    int stopCount = clock();
    double total = (stopCount - startCount) / double(CLOCKS_PER_SEC) * 1000;
    encoded.clear();
    StringSource(cipher, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    wcout << "cipher text: " << string_to_wstring(encoded) << endl;
    wcout << "\nTotal time for 10.000 rounds: " << total << " ms" << endl;
    wcout << "\nExecution time: " << total / 10000 << " ms" << endl
          << endl;
}
void De_RSA()
{
    wstring wplain;
    string plain, cipher, recovered;
    int mode;
    wcout << L"(1)Nhập từ màn hình (2)Nhập từ file cipher.txt: ";
    wcin >> mode;
    wcin.ignore();
    wcout << endl;
    switch (mode)
    {
    case 1:
    {
        wcout << "Input plaintext: ";
        fflush(stdin);
        getline(wcin, wplain);
        break;
    }
    case 2:
    {
        wplain = OpenandReadFile("cipher.txt");
        break;
    }
    }

    plain = wstring_to_string(wplain);
    wcout << "Plaintext: " << wplain << endl;
    // Load public key
    RSA::PrivateKey privateKey;
    LoadPrivateKey("rsa-private.key", privateKey);
    // Encryption
    AutoSeededRandomPool rng;
    // Encryption
    RSAES_OAEP_SHA_Encryptor e(privateKey);
    StringSource(plain, true,
                 new HexDecoder(
                     new StringSink(cipher))); // StringSource
    // Decryption
    int startCount = clock();
    for (int i = 0; i < 10000; i++)
    {
        // Decryption
        recovered.clear();
        RSAES_OAEP_SHA_Decryptor d(privateKey);
        StringSource(cipher, true,
                     new PK_DecryptorFilter(rng, d,
                                            new StringSink(recovered)) // PK_EncryptorFilter
        );                                                             // StringSource
    }
    int stopCount = clock();
    double total = (stopCount - startCount) / double(CLOCKS_PER_SEC) * 1000;
    wcout << "recovered text:" << string_to_wstring(recovered) << endl;
    wcout << "\nTotal time for 10.000 rounds: " << total << " ms" << endl;
    wcout << "\nExecution time: " << total / 10000 << " ms" << endl
          << endl;
}