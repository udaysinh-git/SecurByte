#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#define MAX_MESSAGE_LENGTH 1024
#define MAX_PATIENTS 100

typedef struct Patient {
    char prn[16];
    unsigned char key[16];
    unsigned char iv[16];
    unsigned char encrypted_data[MAX_MESSAGE_LENGTH];
    int data_length;
    struct Patient *next;
} Patient;

Patient *head = NULL;

void register_patient() {
    Patient *new_patient = (Patient *)malloc(sizeof(Patient));
    if (!new_patient) {
        printf("Failed to allocate memory for the new patient.\n");
        return;
    }

    printf("Enter PRN for the new patient: ");
    fgets(new_patient->prn, sizeof(new_patient->prn), stdin);
    new_patient->prn[strcspn(new_patient->prn, "\n")] = 0; 

    char data[MAX_MESSAGE_LENGTH];
    printf("Enter medical record data for the new patient (NAME,AGE,SEX,BLOOD): ");
    fgets(data, sizeof(data), stdin);
    data[strcspn(data, "\n")] = 0; 

    if(RAND_bytes(new_patient->key, sizeof(new_patient->key)) != 1) {
        printf("Error generating random key.\n");
        free(new_patient);
        return;
    }

    
    printf("Your decryption key is: ");
    for(int i = 0; i < sizeof(new_patient->key); i++) {
        printf("%02x", new_patient->key[i]);
    }
    printf("\n");

    if(RAND_bytes(new_patient->iv, sizeof(new_patient->iv)) != 1) {
        printf("Error generating random IV.\n");
        free(new_patient);
        return;
    }

    int len = strlen(data), outlen, tmplen;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        printf("Error creating cipher context.\n");
        free(new_patient);
        return;
    }

    if(!EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, new_patient->key, new_patient->iv)) {
        printf("Error initializing encryption.\n");
        EVP_CIPHER_CTX_free(ctx);
        free(new_patient);
        return;
    }

    if(!EVP_EncryptUpdate(ctx, new_patient->encrypted_data, &outlen, data, len)) {
        printf("Error encrypting message.\n");
        EVP_CIPHER_CTX_free(ctx);
        free(new_patient);
        return;
    }

    if(!EVP_EncryptFinal_ex(ctx, new_patient->encrypted_data + outlen, &tmplen)) {
        printf("Error finalizing encryption.\n");
        EVP_CIPHER_CTX_free(ctx);
        free(new_patient);
        return;
    }

    outlen += tmplen;
    new_patient->data_length = outlen;
    EVP_CIPHER_CTX_free(ctx);

    new_patient->next = head;
    head = new_patient;

    printf("Patient registered successfully.\n");
}

void view_patient() {
    char prn[16];
    unsigned char key[16];
    char hex_key[33]; 

    printf("Enter PRN of the patient: ");
    fgets(prn, sizeof(prn), stdin);
    prn[strcspn(prn, "\n")] = 0; 

    printf("Enter your decryption key: ");
    fgets(hex_key, sizeof(hex_key), stdin);
    hex_key[strcspn(hex_key, "\n")] = 0; 

    
    for(int i = 0; i < sizeof(key); i++) {
        sscanf(hex_key + i * 2, "%02hhx", &key[i]);
    }

    Patient *current = head;
    while (current != NULL) {
        if (strcmp(current->prn, prn) == 0) {
            unsigned char decrypted_data[MAX_MESSAGE_LENGTH];
            int outlen, tmplen;
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (!ctx) {
                printf("Error creating cipher context.\n");
                return;
            }

            if(!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, current->iv)) {
                printf("Error initializing decryption.\n");
                EVP_CIPHER_CTX_free(ctx);
                return;
            }

            if(!EVP_DecryptUpdate(ctx, decrypted_data, &outlen, current->encrypted_data, current->data_length)) {
                printf("Error decrypting message.\n");
                EVP_CIPHER_CTX_free(ctx);
                return;
            }

            if(!EVP_DecryptFinal_ex(ctx, decrypted_data + outlen, &tmplen)) {
                printf("Error finalizing decryption.\n");
                EVP_CIPHER_CTX_free(ctx);
                return;
            }

            outlen += tmplen;
            decrypted_data[outlen] = 0; 
            EVP_CIPHER_CTX_free(ctx);

            printf("Medical record data for the patient: %s\n", decrypted_data);
            return;
        }
        current = current->next;
    }

    printf("No patient found with the given PRN.\n");
}

void update_patient() {
    char prn[16];
    unsigned char key[16];
    char hex_key[33]; 

    printf("Enter PRN of the patient to update: ");
    fgets(prn, sizeof(prn), stdin);
    prn[strcspn(prn, "\n")] = 0; 

    printf("Enter your decryption key: ");
    fgets(hex_key, sizeof(hex_key), stdin);
    hex_key[strcspn(hex_key, "\n")] = 0; 

    
    for(int i = 0; i < sizeof(key); i++) {
        sscanf(hex_key + i * 2, "%02hhx", &key[i]);
    }

    Patient *current = head;
    while (current != NULL) {
        if (strcmp(current->prn, prn) == 0) {
            unsigned char decrypted_data[MAX_MESSAGE_LENGTH];
            int outlen, tmplen;
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (!ctx) {
                printf("Error creating cipher context.\n");
                return;
            }

            if(!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, current->iv)) {
                printf("Error initializing decryption.\n");
                EVP_CIPHER_CTX_free(ctx);
                return;
            }

            if(!EVP_DecryptUpdate(ctx, decrypted_data, &outlen, current->encrypted_data, current->data_length)) {
                printf("Error decrypting message.\n");
                EVP_CIPHER_CTX_free(ctx);
                return;
            }

            if(!EVP_DecryptFinal_ex(ctx, decrypted_data + outlen, &tmplen)) {
                printf("Error finalizing decryption.\n");
                EVP_CIPHER_CTX_free(ctx);
                return;
            }

            outlen += tmplen;
            decrypted_data[outlen] = 0; 
            EVP_CIPHER_CTX_free(ctx);

            printf("Current medical record data for the patient: %s\n", decrypted_data);

            char data[MAX_MESSAGE_LENGTH];
            printf("Enter new medical record data for the patient: ");
            int c;
            while ((c = getchar()) != '\n' && c != EOF); 
            fgets(data, sizeof(data), stdin);
            data[strcspn(data, "\n")] = 0; 

            if(RAND_bytes(current->key, sizeof(current->key)) != 1) {
                printf("Error generating new random key.\n");
                return;
            }

            
            printf("Your new decryption key is: ");
            for(int i = 0; i < sizeof(current->key); i++) {
                printf("%02x", current->key[i]);
            }
            printf("\n");

            if(RAND_bytes(current->iv, sizeof(current->iv)) != 1) {
                printf("Error generating new random IV.\n");
                return;
            }

            int len = strlen(data); 
            ctx = EVP_CIPHER_CTX_new();
            if (!ctx) {
                printf("Error creating cipher context.\n");
                return;
            }

            if(!EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, current->key, current->iv)) {
                printf("Error initializing encryption.\n");
                EVP_CIPHER_CTX_free(ctx);
                return;
            }

            if(!EVP_EncryptUpdate(ctx, current->encrypted_data, &outlen, data, len)) {
                printf("Error encrypting message.\n");
                EVP_CIPHER_CTX_free(ctx);
                return;
            }

            if(!EVP_EncryptFinal_ex(ctx, current->encrypted_data + outlen, &tmplen)) {
                printf("Error finalizing encryption.\n");
                EVP_CIPHER_CTX_free(ctx);
                return;
            }

            outlen += tmplen;
            current->data_length = outlen;
            EVP_CIPHER_CTX_free(ctx);

            printf("Patient data updated successfully.\n");
            return;
        }
        current = current->next;
    }

    printf("No patient found with the given PRN.\n");
}

void delete_patient() {
    char prn[16];
    printf("Enter PRN of the patient to delete: ");
    fgets(prn, sizeof(prn), stdin);
    prn[strcspn(prn, "\n")] = 0; 

    Patient *current = head, *prev = NULL;
    while (current != NULL) {
        if (strcmp(current->prn, prn) == 0) {
            if (prev == NULL) {
                head = current->next;
            } else {
                prev->next = current->next;
            }
            free(current);
            printf("Patient deleted successfully.\n");
            return;
        }
        prev = current;
        current = current->next;
    }

    printf("No patient found with the given PRN.\n");
}

void list_patients() {
    Patient *current = head;
    while (current != NULL) {
        printf("PRN: %s\n", current->prn);
        printf("Encrypted data: ");
        for(int i = 0; i < current->data_length; i++) {
            printf("%02x", current->encrypted_data[i]);
        }
        printf("\n");
        current = current->next;
    }
}
int main() {
    int op;
    while(1) {
        printf("\n\n1: Register Patient\n2: View Patient\n3: Update Patient\n4: Delete Patient\n5: List Patients\n6: Exit\nSelect Operation => ");
        scanf("%d", &op);
        getchar(); 

        switch(op) {
            case 1:
                register_patient();
                break;
            case 2:
                view_patient();
                break;
            case 3:
                update_patient();
                break;
            case 4:
                delete_patient();
                break;
            case 5:
                list_patients();
                break;
            case 6:
                printf("Exiting...\n");
                return 0;
            default:
                printf("Invalid option.\n");
                break;
        }
    }
    return 0;
}