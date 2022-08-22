#ifndef X25519_H_
#define X25519_H_


struct SerializedKey 
{
    unsigned char publickey[crypto_box_PUBLICKEYBYTES];
    unsigned char privatekey[crypto_box_SECRETKEYBYTES];
};

int say_hello();  
void get_key_pair(struct SerializedKey *key);

int get_shared_secret(unsigned char *secret_key, unsigned char *our_private_key, unsigned char *peer_public_key, unsigned char *our_nonce, unsigned char *peer_nonce);

int xor(unsigned char* result, const unsigned char* item1, const unsigned char* item2, size_t size_of_item);

#endif // X25519_H_
