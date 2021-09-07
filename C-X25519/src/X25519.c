#include <stdio.h>
#include <string.h>
#include <sodium.h>
#include "X25519.h"
#include "sodium/crypto_sign.h"
#include "sodium/crypto_sign_ed25519.h"

int say_hello(){
    printf("Hello, from X25519\n");
    if (sodium_init() < 0) {
        /* panic! the library couldn't be initialized, it is not safe to use */
        printf("Failed to find libsodium!\n");
        return 1;
    }
    return 0;
}

void get_key_pair(struct SerializedKey *key){
    unsigned char publickey[crypto_box_PUBLICKEYBYTES];
    unsigned char privatekey[crypto_box_SECRETKEYBYTES];
    randombytes_buf(key->privatekey, sizeof key->privatekey);
    crypto_scalarmult_base(key->publickey, key->privatekey);
    return;
}

int get_shared_secret(unsigned char *secret_key, unsigned char *our_private_key, unsigned char *peer_public_key, unsigned char *our_nonce, unsigned char *peer_nonce){
    unsigned char xor_nonce[crypto_box_SECRETKEYBYTES];
    unsigned char derived_key[crypto_box_SECRETKEYBYTES];
    randombytes_buf(derived_key, sizeof derived_key);
    randombytes_buf(secret_key, sizeof secret_key);
    if(crypto_scalarmult(derived_key,our_private_key, peer_public_key) !=0){
        return 1; //Error 
    }

    xor(xor_nonce, our_nonce, peer_nonce, crypto_box_SECRETKEYBYTES);
    crypto_generichash_blake2b_salt_personal(secret_key,crypto_box_SECRETKEYBYTES,derived_key,crypto_box_SECRETKEYBYTES,NULL,0,xor_nonce,NULL);
    //sodium_bin2hex(rx_hex,crypto_box_SECRETKEYBYTES*2+1,secret_key,crypto_box_SECRETKEYBYTES);
    //printf("%s\n", rx_hex);
    return 0;
}

int xor(unsigned char* result, const unsigned char* item1, const unsigned char* item2, size_t size_of_item){
    int i;
   // unsigned char result1[size_of_item];
    for(i=0;i<size_of_item;i++){
        result[i] = item1[i] ^ item2[i];
    }
    //result = result1;
    return 0;
}

