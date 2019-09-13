#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <string.h>
#include <stdint.h>
#include <time.h>

void handleErrors(void);
int gcm_encrypt(uint8_t *plaintext, int plaintext_len,
                uint8_t *key,
                uint8_t *iv, int iv_len,
                uint8_t *ciphertext,
                uint8_t *tag);
int gcm_decrypt(uint8_t *ciphertext, int ciphertext_len,
                uint8_t *tag,
                uint8_t *key,
                uint8_t *iv, int iv_len,
                uint8_t *plaintext);

int AES_GCM_RUNS (unsigned int size, unsigned runs)
{

    /* A 256 bit key */
    uint8_t key_a[32]={0};
    uint8_t key_b[32]={0};

    /* A 128 bit IV */
    uint8_t iv[16]={0};
    RAND_bytes(iv, 32);
    size_t iv_len = 16;

    /* Message to be encrypted */
    //uint8_t *plaintext[] =
    //    (uint8_t *)"The quick brown fox jumps over the lazy dog";
    uint8_t *plaintext = (uint8_t*) malloc(size * sizeof(uint8_t));
    

    /*
     * Buffer for ciphertext. Ensure the buffer is long enough for the
     * ciphertext which may be longer than the plaintext, depending on the
     * algorithm and mode.
     */
    //uint8_t ciphertext[size];
    uint8_t *ciphertext_a = (uint8_t*) malloc(size * sizeof(uint8_t));
    uint8_t *ciphertext_b = (uint8_t*) malloc(size * sizeof(uint8_t));

    /* Buffer for the decrypted text */
    //uint8_t decryptedtext[size];
    uint8_t *decryptedtext_a = (uint8_t*) malloc(size * sizeof(uint8_t));
    uint8_t *decryptedtext_b = (uint8_t*) malloc(size * sizeof(uint8_t));

    /* Buffer for the tag */
    uint8_t tag[16];

    clock_t begin, end;

    double time_spent_keygen = 0;
    double time_spent_encrypt = 0;
    double time_spent_re_keygen = 0;
    double time_spent_re_encrypt = 0;
    double time_spent_decrypt = 0;

    int decryptedtext_len, ciphertext_len;

    int i;
    for (i=0; i<runs; i++){
        RAND_bytes(plaintext, size);

        begin = clock();
        RAND_bytes(key_a, 32);
        end = clock();
        time_spent_keygen += (double)(end - begin) / CLOCKS_PER_SEC;

        
        begin = clock();
        /* Encrypt the plaintext */
        ciphertext_len = gcm_encrypt(plaintext, size,
                                     key_a,
                                     iv, iv_len,
                                     ciphertext_a, tag);
        end = clock();
        time_spent_encrypt += (double)(end - begin) / CLOCKS_PER_SEC;

        begin = clock();
        RAND_bytes(key_b, 32);
        end = clock();
        time_spent_re_keygen += (double)(end - begin) / CLOCKS_PER_SEC;

        begin = clock();
        decryptedtext_len = gcm_decrypt(ciphertext_a, size,
                                        tag,
                                        key_a, iv, iv_len,
                                        decryptedtext_a);
        ciphertext_len = gcm_encrypt(plaintext, size,
                                     key_b,
                                     iv, iv_len,
                                     ciphertext_a, tag);
        end = clock();
        time_spent_re_encrypt += (double)(end - begin) / CLOCKS_PER_SEC;

        begin = clock();
        /* Decrypt the ciphertext */
        decryptedtext_len = gcm_decrypt(ciphertext_a, size,
                                        tag,
                                        key_b, iv, iv_len,
                                        decryptedtext_a);
        end = clock();
        time_spent_decrypt += (double)(end - begin) / CLOCKS_PER_SEC;

        int j;
        for (j=0;j<size; j++){
            if (plaintext[j] != decryptedtext_a[j]){
                printf("PLAINTTEXT AND Decrypted text are not the same\n");
                break;
            }
        }

    }


    printf("==================================================");
    printf("\n");
    printf("Runs %d \n",runs);
    printf("Size (in bytes) %d \n",size);
    printf("Keygen %f \n",time_spent_keygen);
    printf("Encrypt %f \n",time_spent_encrypt);
    printf("Re_Keygen %f \n",time_spent_re_keygen);
    printf("Re_Encrypt %f \n",time_spent_re_encrypt);
    printf("Decrypt %f \n",time_spent_decrypt);
    
    
    free(plaintext);
    free(ciphertext_a);
    free(ciphertext_b);
    free(decryptedtext_a);
    free(decryptedtext_b);

    return 0;
}

void main(){
    printf("Start...\n");
    unsigned int size = 10240;
    unsigned runs = 10000;
    AES_GCM_RUNS(size,runs);
    printf("Done...\n");
}

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}


int gcm_encrypt(uint8_t *plaintext, int plaintext_len,
                uint8_t *key,
                uint8_t *iv, int iv_len,
                uint8_t *ciphertext,
                uint8_t *tag)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;


    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors();

    /*
     * Set IV length if default 12 bytes (96 bits) is not appropriate
     */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrors();

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
        handleErrors();

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}


int gcm_decrypt(uint8_t *ciphertext, int ciphertext_len,
                uint8_t *tag,
                uint8_t *key,
                uint8_t *iv, int iv_len,
                uint8_t *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors();

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrors();

    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
        handleErrors();

    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0) {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    } else {
        /* Verify failed */
        return -1;
    }
}
