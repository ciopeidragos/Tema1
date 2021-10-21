#include <iostream>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <string>
#include "encrypt.h"

unsigned char rand_iv[16] = {0x29, 0xea, 0x3e, 0x04, 0xf5, 0x0e, 0x87, 0x61, 0xd6, 0xb8, 0x24, 0x64, 0xd9, 0x0b, 0xb2, 0xb1};
unsigned char k_prim[16] = {0x83, 0xfc, 0x95, 0xc4, 0x65, 0x46, 0x59, 0xc9, 0x02, 0xc7, 0xc5, 0xb3, 0x3a, 0x75, 0x51, 0x56};
unsigned char k[16];
#define ECB 0
#define CBC 1
#define UNKOWN -1
int mode;

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

void waitForKeyAndMode(int clientSocket)
{
    unsigned char encrypted_k[16];

    recv(clientSocket, encrypted_k, 16, 0);
    recv(clientSocket, &mode, sizeof(mode), 0);

    std::cout << "Received encypted key=";
    printInHex(encrypted_k, 16);

    dec_algorithm(k_prim, encrypted_k, k);

    std::cout << " Decrypted as=";
    printInHex(k, 16);

    std::cout << std::endl;

    if (mode == ECB)
    {
        std::cout << "Decrypting mode will be ECB" << std::endl;
    }
    else if (mode == CBC)
    {
        std::cout << "Decrypting mode will be CBC" << std::endl;
    }
    else if (mode == UNKOWN)
    {
        exit(-1);
    }
}

int main(int argc, char **argv)
{
    int listening = socket(AF_INET, SOCK_STREAM, 0);
    if (listening == -1)
    {
        std::cerr << "Cant create a socket" << std::endl;
        return -1;
    }

    sockaddr_in hint;
    hint.sin_family = AF_INET;
    hint.sin_port = htons(54000);
    inet_pton(AF_INET, "0.0.0.0", &hint.sin_addr);

    if (bind(listening, (sockaddr *)&hint, sizeof(hint)) == -1)
    {
        std::cerr << "Cant bint to IP/port";
        return -1;
    }

    if (listen(listening, SOMAXCONN) == -1)
    {
        std::cerr << "Cant listen!" << std::endl;
        return -1;
    }

    sockaddr_in client;
    socklen_t clientSize = sizeof(client);
    char host[NI_MAXHOST];
    char svc[NI_MAXSERV];

    int clientSocket = accept(listening, (sockaddr *)&client, &clientSize);

    if (clientSocket == -1)
    {
        std::cerr << "Problem with client connecting!" << std::endl;
        return -1;
    }

    close(listening);

    memset(host, 0, NI_MAXHOST);
    memset(svc, 0, NI_MAXSERV);

    int result = getnameinfo((sockaddr *)&client, sizeof(client), host, NI_MAXHOST, svc, NI_MAXSERV, 0);

    if (result)
    {
        std::cout << host << " connected on " << svc << std::endl;
    }
    else
    {
        inet_ntop(AF_INET, &client.sin_addr, host, NI_MAXHOST);
        std::cout << host << " connected on " << ntohs(client.sin_port) << std::endl;
    }

    waitForKeyAndMode(clientSocket);

    unsigned char *buf;
    unsigned char buffer[4096];
    std::string userInput;

    while (true)
    {
        int bytesRecv = recv(clientSocket, buffer, 4096, 0);
        if (bytesRecv == -1)
        {
            std::cerr << "The client disconected" << std::endl;
            break;
        }

        if (mode == ECB)
        {
            buf = decrypt_ecb(k, buffer);
        }
        else
        {
            buf = decrypt_cbc(k, rand_iv, buffer);
        }

        std::cout << "Other > ";
        printReadable(buf, bytesRecv - 1);
        std::cout << std::endl;

        std::cout << "[ENC INFO] ";
        std::cout << "Received message=";
        printInHex(buffer, bytesRecv);
        std::cout << std::endl;

        if (std::string((const char *)buf) == "bye")
        {
            break;
        }

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

        send(clientSocket, buf, userInput.size() + 1, 0);

        std::cout << "[ENC INFO] ";
        std::cout << "Sent message=";
        printInHex((unsigned char *)userInput.c_str(), userInput.size() + 1);
        std::cout << " Encrypted as=";
        printInHex(buf, userInput.size() + 1);
        std::cout << std::endl;

        if (userInput == "bye")
        {
            break;
        }
    }

    close(clientSocket);

    return 0;
}