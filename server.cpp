#include <stdio.h>
#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

//SERVER
int PORT = 8080;
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

unsigned char aad[] = "Additional Authenticated Data";
int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *outputBuffer,
                unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;
    int len = 0;
    int plaintext_len = 0;
    
    //CREATE INITIALIZE CONTEXT AND DECRYPTION
    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    //SET IV AND KEY
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
    //INITIALIZE AAD
    EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len);
    //PROVIDE CIPHERTEXT AND LENGTH
    EVP_DecryptUpdate(ctx, outputBuffer, &len, ciphertext, ciphertext_len);
    plaintext_len = len;
    //VERIFY TAG
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
    int ret = EVP_DecryptFinal_ex(ctx, outputBuffer + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    if(ret > 0) {
        //SUCCESS
        plaintext_len += len;
        return plaintext_len;
    } else {
        //VERIFICATION FAILED
        printf("Verification failed");
        return -1;
    }   
}
int main(void)
{
    //CREATING SOCKET
    int server = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in servAddr;
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servAddr.sin_port = htons(PORT);
    
    //BINDING SOCKET
    if ((bind(server, (struct sockaddr*) &servAddr, sizeof(servAddr))) < 0){
        printf("Uh oh, socket not binding\n");
        return 1;
    }

    //LISTENING FOR CLIENTS
    listen(server,9);
    sockaddr_in clientSockAddr;
    socklen_t clientSockAddrSize = sizeof(clientSockAddr);
    
    //ACCEPTING CLIENTS
    int client = accept(server, (sockaddr *)&clientSockAddr, &clientSockAddrSize);
    printf("Client connected at port %i\n", PORT);

    char clientMessage[3000];
    unsigned char inputBuffer[3000];
    unsigned char outputBuffer[3000];
    unsigned char tag[16];
    while(true)
    {
        //CLEARING INPUT, OUTPUT, AND TAG
        
        memset(&outputBuffer, 0, sizeof(outputBuffer));
        memset(&inputBuffer, 0, sizeof(inputBuffer));  
        memset(&tag, 0, sizeof(tag));  
        memset(&clientMessage, 0, sizeof(clientMessage));
        

        //RECEIVING CLIENT MESSAGE AND TAG 
        recv(client, clientMessage, sizeof(clientMessage),0);
        recv(client, tag, 16, 0);
        
        //PRINTING TAG
        printf("Received Tag: ");
        for(int i = 0; i < 16; ++i) {
            printf("%02x ", tag[i]);
        }
        printf("\n");

        //COPYING ENCRYPTED MESSAGE AND PRINTING
        memcpy(inputBuffer, clientMessage, strlen(clientMessage));
        printf("Client Encrypted Message: ");
        for (int i = 0; i < strlen(clientMessage); ++i) {
            printf("%02x ", (unsigned char)inputBuffer[i]);
        }
        printf(" \n"); 
    
        //DECRYPTING MESSAGE
        int ciphertextLength = gcm_decrypt(inputBuffer, strlen(clientMessage), aad, sizeof(aad),key, iv,sizeof(iv), outputBuffer, tag);
        if(ciphertextLength < 0) {
            printf("Authentication Failed \n");
            break;
        }
        printf("Authentication Successful \n");
        printf("Client Decrypted Message: %.*s\n",ciphertextLength, outputBuffer);
        //SERVER RESPONSE
        printf("Server: ");
        std::string input;
        getline(std::cin, input);
        memset(&clientMessage, 0, sizeof(clientMessage));
        input.copy(clientMessage, input.length());
        clientMessage[input.length()] = '\0'; 
        send(client, clientMessage, strlen(clientMessage), 0);
    }
    close(client);
    close(server);
    printf("Socket closed\n");
    return 0;   
}
