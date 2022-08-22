#include <stdio.h>
#include <string.h>
#include <sodium.h>
#include "sodium/crypto_sign.h"
#include "sodium/crypto_sign_ed25519.h"
#include "src/X25519.h"

int main(void)
{
    if (say_hello() == 1) {
        /* panic! the library couldn't be initialized, it is not safe to use */
        return 1;
    }

    struct SerializedKey* our_key = (struct SerializedKey*) malloc(sizeof(struct SerializedKey));
    struct SerializedKey* peer_key = (struct SerializedKey*) malloc(sizeof(struct SerializedKey));
    unsigned char key_pk[65];
    get_key_pair(our_key);
    get_key_pair(peer_key);
    sodium_bin2hex(key_pk,65,our_key->privatekey,32);
    printf("Our private key %s\n", key_pk);
    unsigned char secret_key[32];
    unsigned char our_nonce[32];
    randombytes_buf(our_nonce, 32);
    unsigned char peer_nonce[32];
    randombytes_buf(peer_nonce, 32);
    get_shared_secret(secret_key, our_key->privatekey, peer_key->publickey, our_nonce, peer_nonce);
    sodium_bin2hex(key_pk,65,secret_key,32);
    printf("Our secret key %s\n", key_pk);

    return 0;
}