#include <stdio.h>
#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#define maxLength 3000

//CLIENT
unsigned char iv[16] = {
    0x2b, 0x7e, 0x15, 0x16,
    0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88,
    0x09, 0xcf, 0x4f, 0x3c
};
unsigned char key[32] = {
    0x2b, 0x7e, 0x15, 0x16,
    0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88,
    0x09, 0xcf, 0x4f, 0x3c,
    0x2b, 0x7e, 0x15, 0x16,
    0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88,
    0x09, 0xcf, 0x4f, 0x3c
};
unsigned char tag[16] = {
    0x1a, 0x47, 0xf0, 0x10, 0x33, 0x6c, 0x14, 0x08,
    0x14, 0xac, 0x38, 0x4f, 0x98, 0x4a, 0xd3, 0xdf
};

unsigned char aad[] = "Additional Authenticated Data";

int gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *ciphertext,
                unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;
    int len = 0;
    int ciphertext_len = 0;
    
    /* Create and initialize the context */
    ctx = EVP_CIPHER_CTX_new();
    
    /* Initialize the encryption operation */
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    
    /* Set IV length */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL);
    
    /* Initialize key and IV */
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    
    /* Provide any AAD data */
    EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len);
    
    /* Provide the message to be encrypted and obtain the encrypted output */
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;
    
    /* Finalize the encryption and generate the authentication tag */
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
    
    /* Get the tag */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
   
    return ciphertext_len;
}


int main(void)
{
    //VARIABLE DEFINITION
    int PORT = 8080;
    const char *IP = "127.0.0.1";
    
    //CREATING SOCKET
    sockaddr_in clientSocketAddress;
    memset(&clientSocketAddress, 0, sizeof(clientSocketAddress));
    clientSocketAddress.sin_family = AF_INET;
    clientSocketAddress.sin_addr.s_addr = inet_addr(IP);
    clientSocketAddress.sin_port = htons(PORT);
    int client = socket(AF_INET, SOCK_STREAM, 0);

    //CONNECTING TO SERVER
    if (connect(client,(sockaddr*) &clientSocketAddress, sizeof(clientSocketAddress))>=0){
        printf("Successfully connected to server\n");
    }

    //DECLARING BUFFERS
    unsigned char serverMessage[maxLength]; 
    unsigned char plaintextBuffer[maxLength];
    unsigned char encryptedBuffer[maxLength];
    while(true)
    {
        //SENDING MESSAGE TO SERVER FROM COMMAND LINE
        printf("Client: ");
        std::string input;
        std::getline(std::cin, input);
        
        //PUTTING INTO BUFFER AND ENCRYPTING
        memcpy(plaintextBuffer, input.c_str(), input.length() + 1);
        int ciphertextLength = gcm_encrypt(plaintextBuffer, input.length(), aad, sizeof(aad),key, iv,sizeof(iv), encryptedBuffer, tag);
        
        //PRINTING CIPHERTEXT AND TAG
        printf("Ciphertext: ");
        for (int i = 0; i < ciphertextLength; ++i) {
            printf("%02x", encryptedBuffer[i]);
        }
        printf("\nTag: ");
        for (int i = 0; i < 16; ++i) {
            printf("%02x", tag[i]);
        }
        printf("\n");
        
        //SENDING CIPHERTEXT AND TAG
        send(client, (char*)encryptedBuffer, ciphertextLength, 0);
        send(client, tag, 16, 0);
        printf("Waiting for server response\n");
        
        // CLEARING BUFFERS FOR NEXT MESSAGE
        memset(&serverMessage, 0, sizeof(serverMessage));
        memset(&plaintextBuffer, 0, sizeof(plaintextBuffer));
        memset(&encryptedBuffer, 0, sizeof(encryptedBuffer)); 
        
        //RECEIVE AND PRINT SERVER RESPONSE
        recv(client, (char*)&serverMessage, sizeof(serverMessage), 0); 
        printf("Server: %s\n", serverMessage);
        
    }
    close(client);
    printf("Socket closed\n");
    return 0;    
}
