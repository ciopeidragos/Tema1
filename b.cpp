#include <iostream>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <string>

#include "encrypt.h"

unsigned char rand_iv[16] = {0x29, 0xea, 0x3e, 0x04, 0xf5, 0x0e, 0x87, 0x61, 0xd6, 0xb8, 0x24, 0x64, 0xd9, 0x0b, 0xb2, 0xb1};
unsigned char k_prim[16] = {0x83, 0xfc, 0x95, 0xc4, 0x65, 0x46, 0x59, 0xc9, 0x02, 0xc7, 0xc5, 0xb3, 0x3a, 0x75, 0x51, 0x56};
unsigned char k[16];
int mode;
#define ECB 0
#define CBC 1
#define UNKOWN -1

void printInHex(unsigned char *const ptr, int size)
{
    for (int i = 0; i < size; i++)
    {
        printf("%02x", ptr[i]);
    }
}

void printReadable(unsigned char *const ptr, int size)
{
    for (int i = 0; i < size; i++)
    {
        printf("%c", (const char)ptr[i]);
    }
}

void requestForKey()
{
    std::cout << "Requesting for key" << std::endl;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1)
    {
        std::cerr << "Cant create socket" << std::endl;
        exit(-1);
    }

    int port = 56000;
    std::string ipAddress = "127.0.0.1";

    sockaddr_in hint;
    hint.sin_family = AF_INET;
    hint.sin_port = htons(port);
    inet_pton(AF_INET, ipAddress.c_str(), &hint.sin_addr);
    int connectRes = connect(sock, (sockaddr *)&hint, sizeof(hint));

    if (connectRes == -1)
    {
        std::cerr << "Cant connect to key server" << std::endl;
        exit(-1);
    }

    unsigned char encrypted_k[16];
    std::string keyRequest = "I need a communication key";

    int sendRes = send(sock, keyRequest.c_str(), keyRequest.size() + 1, 0);

    memset(encrypted_k, 0, 16);
    int bytesReceived = recv(sock, encrypted_k, 16, 0);
    dec_algorithm(k_prim, encrypted_k, k);

    std::cout << "Received encypted key=";
    printInHex(encrypted_k, 16);

    std::cout << " Decrypted as=";
    printInHex(k, 16);

    std::cout << std::endl;
}

void sendKeyAndMode(int sock)
{
    unsigned char enc_k[16];

    enc_algorithm(k_prim, k, enc_k);
    send(sock, enc_k, 16, 0);

    send(sock, &mode, sizeof(mode), 0);
    if (mode == UNKOWN)
    {
        exit(-1);
    }
}

int main(int argc, char **argv)
{
    if (std::string(argv[1]) == "ECB")
    {
        mode = ECB;
    }
    else if (std::string(argv[1]) == "CBC")
    {
        mode = CBC;
    }
    else
    {
        std::cerr << "Unknown encryption mode" << std::endl;
        mode = UNKOWN;
    }

    requestForKey();

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1)
    {
        std::cerr << "Cant create socket" << std::endl;
        return -1;
    }

    int port = 54000;
    std::string ipAddress = "127.0.0.1";

    sockaddr_in hint;
    hint.sin_family = AF_INET;
    hint.sin_port = htons(port);
    inet_pton(AF_INET, ipAddress.c_str(), &hint.sin_addr);
    int connectRes = connect(sock, (sockaddr *)&hint, sizeof(hint));

    if (connectRes == -1)
    {
        std::cerr << "Cant connect" << std::endl;
        return -1;
    }

    sendKeyAndMode(sock);

    unsigned char *buf;
    unsigned char buffer[4096];
    std::string userInput;

    do
    {
        std::cout << "You > ";
        getline(std::cin, userInput);

        if (mode == ECB)
        {
            buf = encrypt_ecb(k, (unsigned char *)userInput.c_str());
        }
        else
        {
            buf = encrypt_cbc(k, rand_iv, (unsigned char *)userInput.c_str());
        }

        std::cout << "[ENC INFO] ";
        std::cout << "Sent message=";
        printInHex((unsigned char *)userInput.c_str(), userInput.size() + 1);
        std::cout << " Encrypted as=";
        printInHex(buf, userInput.size() + 1);
        std::cout << std::endl;

        send(sock, buf, userInput.size() + 1, 0);

        if (userInput == "bye")
        {
            break;
        }

        int bytesReceived = recv(sock, buffer, 4096, 0);

        if (mode == ECB)
        {
            buf = decrypt_ecb(k, buffer);
        }
        else
        {
            buf = decrypt_cbc(k, rand_iv, buffer);
        }

        std::cout << "Other > ";
        printReadable(buf, bytesReceived - 1);
        std::cout << std::endl;

        std::cout << "[ENC INFO] ";
        std::cout << "Received message=";
        printInHex(buffer, bytesReceived);
        std::cout << std::endl;

        if (std::string((const char *)buf) == "bye")
        {
            break;
        }

    } while (true);

    close(sock);

    return 0;
}