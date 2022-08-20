/**
 MIT License

Copyright (c) 2022 Sasikumar Ganesan

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
 * */

 /**
  * A sample code to help x25519 key sharing and secret creation
  * 
  * Author: Sasikumar Ganesan
  * */


const  crypto  = require('crypto');

/***
 * XOR the given two values
 */

function getXOR(base64Value1, base64Value2){

  const value1 = Buffer.from(base64Value1, 'base64');
  const value2 = Buffer.from(base64Value2, 'base64');
  let outBuf = Buffer.alloc(value1.length);

  for (let n = 0; n < value1.length; n++)
    outBuf[n] = value1[n] ^ value2[n % value2.length];
  
  return outBuf;
}

/***
 * Create the session key using the secret and xoredNonce
 * 
 * secret - byte array
 * xoredNonce - byte array
 * 
 * returns base64encoded key
 */

function getSessionKey(secret, xoredNonce) {

  const salt = xoredNonce.slice(0,20);
  return Buffer.from(crypto.hkdfSync('sha256', secret, salt, '', 32)).toString('base64');
}

/**
 * Generate key pair for x25519 
 * 
 **/

function generateKeyPair(password){
    const x25519Keys = crypto.generateKeyPairSync('x25519', { publicKeyEncoding: {
      type: 'spki',
      format: 'der'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
      cipher: 'aes-256-cbc',
      passphrase: password
    }
  });
  return x25519Keys;
}




/***
 * Convert the hex private key to jwk encoded key
 */

function getPrivateKeyFromHex(x25519Hex, x25519PublicHex){
  const privateKey = crypto.createPrivateKey({
    key: {
      kty: "OKP",
      crv: "X25519",
      x: Buffer.from(x25519PublicHex, "hex").toString("base64url"),
      d: Buffer.from(x25519Hex, "hex").toString("base64url"),
    },
    format: "jwk"
  })
  return privateKey;
}


/***
 * Convert the hex public key to der encoded key
 */

 function getPublicKeyFromHex(x25519PublicHex){
  const publicKey = crypto.createPublicKey({
    key: {
      kty: "OKP",
      crv: "X25519",
      x: Buffer.from(x25519PublicHex,"hex").toString("base64url")
    },
    format: "jwk"
  });

  return publicKey;
}

/**
 * 
 * Here is the sample that shows how to take advantage of the above function. 
 */

const peerPublicKey = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
const base64RemoteNonce = 'WY9hFnr4WLFd9mVvItMIdBjFygVDpPpoi/BZ3Z3lBfY=';
const base64YourNonce = '2OZz6xYAnS6a83WcOZFLQH/0YVcl1vWE+zespfGAWFo=';

/**
 * Often you may want to load this key from a pem file or auto generate it using a cache. 
 * So feel free to use the logic thats necessary. 
 * generateKeyPair this method will create a key for you when you are in need.
 */
const ourPrivateKey = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
const ourPublicKey = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";

const ourPrivateKeyObject = getPrivateKeyFromHex(ourPrivateKey, ourPublicKey);
const peerPublicKeyBuffer = getPublicKeyFromHex(peerPublicKey);


const secret = crypto.diffieHellman({privateKey: ourPrivateKeyObject, publicKey: peerPublicKeyBuffer});

/**
 * Note: This method could have potential performance bottle neck as the key derivation happens 
 * in sync mode. It would good if any one can test it for performance.
 */
const sharedSecret = getSessionKey(secret, getXOR(base64YourNonce, base64RemoteNonce));

/**
 * The keys used or samples from the RFC. So the shared secret key should be 
 * 4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742
 */
console.log("Secret Key in hex format: " + secret.toString('hex'));

/**
 * For the given xor value the session key should be 
 * 3b434ed3f93ce5ef1115a89955a50c0fa3ef09f449a842fed3bf81c2939f4261
 */

console.log("Shared session key in hex: " + Buffer.from(sharedSecret,'base64').toString('hex') ); 
