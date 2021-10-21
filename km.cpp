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
    hint.sin_port = htons(56000);
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

    char buf[4096];
    std::string userInput;

    std::cout << "Wainting for conn" << std::endl;
    memset(buf, 0, 4096);
    int bytesRecv = recv(clientSocket, buf, 4096, 0);
    if (bytesRecv == -1)
    {
        std::cerr << "The client disconected" << std::endl;
        return -1;
    }

    unsigned char rand_key[16];
    if (!RAND_bytes(rand_key, sizeof(rand_key)))
    {
        perror("RAND_bytes() failed");
        exit(-1);
    }

    unsigned char encr_random_key[16];
    enc_algorithm(k_prim, rand_key, encr_random_key);
    std::cout << "Sending key=";
    for (int i = 0; i < 16; i++)
    {
        printf("%02x", (unsigned char)rand_key[i]);
    }

    std::cout << " Encrypted as=";
    for (int i = 0; i < 16; i++)
    {
        printf("%02x", (unsigned char)encr_random_key[i]);
    }
    std::cout << std::endl;

    send(clientSocket, encr_random_key, 16, 0);

    close(clientSocket);

    return 0;
}