#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/rand.h>

int *pad_input(unsigned char *&input);

int enc_algorithm(unsigned char *key, unsigned char *plain_block, unsigned char *enc_block)
{
    for (int i = 0; i < 16; i++)
    {
        enc_block[i] = key[i] ^ plain_block[i];
    }
    return 0;
}

int xor_input(unsigned char *key, unsigned char *plain_block, unsigned char *enc_block)
{
    for (int i = 0; i < 16; i++)
    {
        enc_block[i] = key[i] ^ plain_block[i];
    }
    return 0;
}

int dec_algorithm(unsigned char *key, unsigned char *enc_block, unsigned char *plain_block)
{
    for (int i = 0; i < 16; i++)
    {
        plain_block[i] = key[i] ^ enc_block[i];
    }
    return 0;
}

unsigned char *encrypt_ecb(unsigned char *key, unsigned char *input)
{
    pad_input(input);
    unsigned char *output = new unsigned char[strlen((const char *)input)];
    for (int i = 0; i < strlen((const char *)input); i = i + 16)
    {
        unsigned char *enc_block = new unsigned char[16];

        enc_algorithm(key, input + i, enc_block);
        memcpy(output + i, enc_block, 16);
    }

    return output;
}

unsigned char *decrypt_ecb(unsigned char *key, unsigned char *input)
{
    unsigned char *output = new unsigned char[strlen((const char *)input)];
    for (int i = 0; i < strlen((const char *)input); i = i + 16)
    {
        unsigned char *dec_block = new unsigned char[16];
        dec_algorithm(key, input + i, dec_block);
        memcpy(output + i, dec_block, 16);
    }

    return output;
}

unsigned char *encrypt_cbc(unsigned char *key, unsigned char *iv, unsigned char *input)
{
    pad_input(input);
    unsigned char *output = new unsigned char[strlen((const char *)input)];
    for (int i = 0; i < strlen((const char *)input); i = i + 16)
    {
        unsigned char *enc_block = new unsigned char[16];

        if (i == 0)
        {
            xor_input(iv, input + i, enc_block);
        }
        else
        {
            xor_input(output + i - 16, input + i, enc_block);
        }

        enc_algorithm(key, enc_block, enc_block);
        memcpy(output + i, enc_block, 16);
    }

    return output;
}

unsigned char *decrypt_cbc(unsigned char *key, unsigned char *iv, unsigned char *input)
{
    unsigned char *output = new unsigned char[strlen((const char *)input)];
    for (int i = 0; i < strlen((const char *)input); i = i + 16)
    {
        unsigned char *dec_block = new unsigned char[16];

        if (i == 0)
        {
            xor_input(iv, input + i, dec_block);
        }
        else
        {
            xor_input(input + i - 16, input + i, dec_block);
        }

        dec_algorithm(key, dec_block, dec_block);
        memcpy(output + i, dec_block, 16);
    }

    return output;
}

int *pad_input(unsigned char *&input)
{
    int block_size;
    if (strlen((const char *)input) % 16 != 0)
    {
        block_size = (strlen((const char *)input) / 16) + 1;
    }
    else
    {
        block_size = (strlen((const char *)input) / 16);
    }

    unsigned char *new_input = new unsigned char[block_size * 16];
    for (int i = 0; i < strlen((const char *)input); i++)
    {
        new_input[i] = input[i];
    }
    for (int i = strlen((const char *)input); i < 16 * block_size; i++)
    {
        new_input[i] = (unsigned char)'0';
    }
    input = new_input;

    return 0;
}