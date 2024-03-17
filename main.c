#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#define MAX_MESSAGE_LENGTH 1024

int main() {
    char *s = malloc(MAX_MESSAGE_LENGTH);
    if (!s) {
        printf("Failed to allocate memory for the message.\n");
        return 1;
    }

    int op;
    unsigned char key[16];
    unsigned char iv[16];
    char temp;

    while(1) {
        printf("1: Encryption\n2: Decryption\n3: Exit\nSelect Operation => ");
        scanf("%d", &op);
        // To consume newline character left by scanf
        scanf("%c", &temp);

        switch(op) {
            case 1:
                printf("Enter message to Encrypt: ");
                fgets(s, MAX_MESSAGE_LENGTH, stdin);
                s[strcspn(s, "\n")] = 0; // Remove trailing newline

                if(RAND_bytes(key, sizeof(key)) != 1) {
                    printf("Error generating random key.\n");
                    break;
                }

                if(RAND_bytes(iv, sizeof(iv)) != 1) {
                    printf("Error generating random IV.\n");
                    break;
                }

                int len = strlen(s), outlen, tmplen;
                unsigned char outbuf[MAX_MESSAGE_LENGTH];

                EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
                if (!ctx) {
                    printf("Error creating cipher context.\n");
                    break;
                }

                if(!EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) {
                    printf("Error initializing encryption.\n");
                    break;
                }

                if(!EVP_EncryptUpdate(ctx, outbuf, &outlen, s, len)) {
                    printf("Error encrypting message.\n");
                    break;
                }

                if(!EVP_EncryptFinal_ex(ctx, outbuf + outlen, &tmplen)) {
                    printf("Error finalizing encryption.\n");
                    break;
                }

                outlen += tmplen;
                EVP_CIPHER_CTX_free(ctx);

                printf("Encrypted message: ");
                for(int i = 0; i < outlen; i++) {
                    printf("%02x", outbuf[i]);
                }
                printf("\n");

                printf("Key: ");
                for(int i = 0; i < sizeof(key); i++) {
                    printf("%02x", key[i]);
                }
                printf("\n");

                printf("IV: ");
                for(int i = 0; i < sizeof(iv); i++) {
                    printf("%02x", iv[i]);
                }
                printf("\n");
                break;

            case 2:
                printf("Enter Encrypted Message (in hexadecimal): ");
                fgets(s, MAX_MESSAGE_LENGTH, stdin);
                s[strcspn(s, "\n")] = 0; // Remove trailing newline

                int inlen = strlen(s) / 2;
                unsigned char *inbuf = malloc(inlen * sizeof(unsigned char));
                if (!inbuf) {
                    printf("Failed to allocate memory for the input buffer.\n");
                    break;
                }

                for(int i = 0; i < inlen; i++) {
                    sscanf(s + 2*i, "%02hhx", &inbuf[i]);
                }

                printf("Enter Key (16 bytes, in hexadecimal): ");
                for(int i = 0; i < 16; i++) {
                    scanf("%02hhx", &key[i]);
                }

                printf("Enter IV (16 bytes, in hexadecimal): ");
                for(int i = 0; i < 16; i++) {
                    scanf("%02hhx", &iv[i]);
                }

                unsigned char outbuf2[MAX_MESSAGE_LENGTH];
                EVP_CIPHER_CTX *ctx2 = EVP_CIPHER_CTX_new();
                if (!ctx2) {
                    printf("Error creating cipher context.\n");
                    break;
                }

                if(!EVP_DecryptInit_ex(ctx2, EVP_aes_128_cbc(), NULL, key, iv)) {
                    printf("Error initializing decryption.\n");
                    break;
                }

                if(!EVP_DecryptUpdate(ctx2, outbuf2, &outlen, inbuf, inlen)) {
                    printf("Error decrypting message.\n");
                    break;
                }

                if(!EVP_DecryptFinal_ex(ctx2, outbuf2 + outlen, &tmplen)) {
                    printf("Error finalizing decryption.\n");
                    break;
                }

                outlen += tmplen;
                EVP_CIPHER_CTX_free(ctx2);

                printf("Decrypted message: ");
                for(int i = 0; i < outlen; i++) {
                    printf("%c", outbuf2[i]);
                }
                printf("\n");

                free(inbuf);
                break;

            case 3:
                printf("Exiting...\n");
                free(s);
                return 0;

            default:
                printf("Invalid option.\n");
                break;
        }
    }
    free(s);
    return 0;
}