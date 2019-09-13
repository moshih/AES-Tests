#include <stdio.h>
#include <stdint.h>

#include <time.h>

#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/aes.h>  

#define AES_KEY_256_BIT 256
#define AES_KEY_128_BIT 128
#define AES_OUTSIZE 1024

void encrypt(char *key_seed, char *file_name, char*encrypted_file_name, unsigned int size){
  FILE *read_file;
  if ((read_file = fopen(file_name, "r")))
  {
  }
  else {
    printf("File %s does not exist. \n",file_name);
    return;
  }

  FILE * write_file = fopen(encrypted_file_name, "w");
  if (write_file == NULL)
  {
    printf("Cannot write to file \n");
    fclose(read_file);
    return;
  }

  uint8_t *input_array = (uint8_t*) malloc(size * sizeof(uint8_t));

  if (!fread(input_array, sizeof(uint8_t), size, read_file)){
    printf("Error reading file (encrypt)\n");
  }

  AES_KEY enc_key;
  AES_set_encrypt_key(key_seed, AES_KEY_128_BIT, &enc_key);
  unsigned char iv[128] = {0};

  unsigned char enc_out[256] = {0};

  AES_cbc_encrypt(input_array, input_array, size, &enc_key, iv, AES_ENCRYPT);

  fwrite(input_array,sizeof(uint8_t),size,write_file);

  fclose(read_file);
  fclose(write_file);


  free(input_array);
}


void decrypt(char *key_seed, char *encrypted_file_name, char*decrypted_file_name, unsigned int size){
  FILE *read_file;
  if ((read_file = fopen(encrypted_file_name, "r")))
  {
  }
  else {
    printf("File %s does not exist. \n",encrypted_file_name);
    return;
  }


  FILE * write_file = fopen(decrypted_file_name, "w");
  if (write_file == NULL)
  {
    printf("Cannot write to file \n");
    fclose(write_file);
    return;
  }
  

  uint8_t *input_array = (uint8_t*) malloc(size * sizeof(uint8_t));
  uint8_t *output_array = (uint8_t*) malloc(size * sizeof(uint8_t));

  if (!fread(input_array, sizeof(uint8_t), size, read_file)){
    printf("Error reading file (decrypt)\n");
  }

  AES_KEY dec_key;
  AES_set_decrypt_key(key_seed, AES_KEY_128_BIT, &dec_key);
  unsigned char iv[128] = {0};

  unsigned char enc_out[256] = {0};

  AES_cbc_encrypt(input_array, output_array, size, &dec_key, iv, AES_DECRYPT);

  fwrite(output_array,sizeof(uint8_t),size,write_file);

  fclose(read_file);
  fclose(write_file);


  free(input_array);
  free(output_array);
}

void create_data(char *file_name, uint64_t size){

  FILE *file;

  char *data= malloc(size);
  RAND_bytes(data, size);

  file = fopen(file_name, "w");
  if (file == NULL)
  {
    printf("File does not exists \n");
    return;
  }

  fwrite(data,sizeof(uint8_t),size,file);
  fclose(file);


  free(data);
}

double encrypt_return_time(char *key_seed, char *file_name, char*encrypted_file_name, unsigned int size){
  FILE *read_file;
  if ((read_file = fopen(file_name, "r")))
  {
  }
  else {
    printf("File %s does not exist. \n",file_name);
    return 0;
  }

  FILE * write_file = fopen(encrypted_file_name, "w");
  if (write_file == NULL)
  {
    printf("File does not exists \n");
    fclose(read_file);
    return 0;
  }

  uint8_t *input_array = (uint8_t*) malloc(size * sizeof(uint8_t));

  if (!fread(input_array, sizeof(uint8_t), size, read_file)){
    printf("Error reading file (encrypt)\n");
  }

  clock_t begin, end;
  begin = clock();
  AES_KEY enc_key;
  AES_set_encrypt_key(key_seed, AES_KEY_128_BIT, &enc_key);
  //uint8_t extseed[AES_OUTSIZE]={0};
  unsigned char iv[128] = {0};

  unsigned char enc_out[256] = {0};

  AES_cbc_encrypt(input_array, input_array, size, &enc_key, iv, AES_ENCRYPT);
  end = clock();
  

  fwrite(input_array,sizeof(uint8_t),size,write_file);

  fclose(read_file);
  fclose(write_file);


  free(input_array);

  return (double)(end - begin) / CLOCKS_PER_SEC;
}

void test_aes(int size, unsigned int runs, int show_output){

  char file_name[50];
  char encrypted_file_name[50], encrypted_file_name1[50];
  char decrypted_file_name[50], decrypted_file_name1[50];
  char re_encrypted_file_name[50];

  sprintf(file_name, "data/test_data_%d", size);
  sprintf(encrypted_file_name, "data/encrypted_data_%d", size);
  sprintf(encrypted_file_name1, "data/encrypted_data_%d_1", size);
  sprintf(decrypted_file_name, "data/decrypted_data_%d", size);
  sprintf(decrypted_file_name1, "data/decrypted_data_%d_1", size);
  sprintf(re_encrypted_file_name, "data/re_encrypted_data_%d_1", size);  

  unsigned char key_seed1[32]={0};
  unsigned char key_seed2[32]={0};

  clock_t begin, end;

  double time_spent_keygen = 0;
  double time_spent_encrypt = 0;
  double time_spent_re_keygen = 0;
  double time_spent_re_encrypt = 0;
  double time_spent_decrypt = 0;

  clock_t begin_total = clock();

  for (int i=0; i<runs; i++){
    create_data(file_name,size);

    begin = clock();
    RAND_bytes(key_seed1, 32);
    end = clock();
    time_spent_keygen += (double)(end - begin) / CLOCKS_PER_SEC;
      
      
    
    begin = clock();
    encrypt(key_seed1, file_name, encrypted_file_name, size);
    end = clock();
    time_spent_encrypt += (double)(end - begin) / CLOCKS_PER_SEC;
    
    //time_spent_encrypt +=encrypt_return_time(key_seed1, file_name, encrypted_file_name, size);

    begin = clock();
    RAND_bytes(key_seed2, 32);
    end = clock();
    time_spent_re_keygen += (double)(end - begin) / CLOCKS_PER_SEC;

    begin = clock();
    decrypt(key_seed1, encrypted_file_name, decrypted_file_name1, size);
    encrypt(key_seed2, decrypted_file_name1, encrypted_file_name1, size);
    end = clock();
    time_spent_re_encrypt += (double)(end - begin) / CLOCKS_PER_SEC;

    begin = clock();
    decrypt(key_seed2, encrypted_file_name1, decrypted_file_name, size);
    end = clock();
    time_spent_decrypt += (double)(end - begin) / CLOCKS_PER_SEC;
  }
  
  clock_t end_total = clock();
  double time_spent_total = (double)(end_total - begin_total) / CLOCKS_PER_SEC;

  if (show_output != 0){
  printf("\n");
  printf("Total Run time: %f \n",time_spent_total);
  printf("==================================================");
  printf("\n");
  printf("Runs %d \n",runs);
  printf("Size (in bytes) %d \n",size);
  printf("Keygen %f \n",time_spent_keygen);
  printf("Encrypt %f \n",time_spent_encrypt);
  printf("Re_Keygen %f \n",time_spent_re_keygen);
  printf("Re_Encrypt %f \n",time_spent_re_encrypt);
  printf("Decrypt %f \n",time_spent_decrypt);
  }
  // encrypt
  // send
  // recieve
  // rekeygen
  // reencrypt
  // send
  // recieve
  // decrypt
}

void main(){
  test_aes(10240,10000,1);
}