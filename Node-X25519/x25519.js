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

/* Convert the given x25519 base64encoded raw key to der format */

function getDER(base64EncodedKey) {
  const key = Buffer.from(base64EncodedKey, 'base64')
 
  // X25519's OID 
  const oid = Buffer.from([0x06, 0x03, 0x2B, 0x65, 0x6E])

  // Create a byte sequence containing the OID and key
  return Buffer.concat([
    Buffer.concat([
      Buffer.from([0x30, 0x2A, 0x30]), // Sequence tag
      Buffer.from([oid.length]),
      oid,
    ]),
    Buffer.concat([
      Buffer.from([0x03]), // Bit tag
      Buffer.from([key.length + 1]),
      Buffer.from([0x00]), // Zero bit
      key,
    ]),
  ])

}


/***
 * Convert a der encoded key into the raw base64 format.
 * Note: This is a crude way of convertion works only for x25519
*/

function getRaw(derEncodedBufferKey) {
  return derEncodedBufferKey.slice(derEncodedBufferKey.length-32,derEncodedBufferKey.length).toString('base64');
}


/**
 * Generate key pair for x25519 
 * 
 **/
const x25519Keys = crypto.generateKeyPairSync('x25519', { publicKeyEncoding: {
    type: 'spki',
    format: 'der'
  },
  privateKeyEncoding: {
    type: 'pkcs8',
    format: 'pem',
    cipher: 'aes-256-cbc',
    passphrase: 'top secret'
  }
});

/**
 * Peer public key 
 **/

const peerPublicKey = "/re98S+QQonKxutHTNsnfX3qbSjZrsiqZ/drbeLbhis=";

const ourPrivateKeyObject = crypto.createPrivateKey({ key: x25519Keys.privateKey , passphrase: 'top secret'});
const peerPublicKeyBuffer = crypto.createPublicKey({ key: getDER(peerPublicKey), format: 'der', type: 'spki' });

const secret = crypto.diffieHellman({privateKey: ourPrivateKeyObject, publicKey: peerPublicKeyBuffer});

console.log("Secret Key in hex format: " + secret.toString('hex'));
console.log("My Public Key " + getRaw(x25519Keys.publicKey));
console.log("Peer Public Key " + getRaw(peerPublicKeyBuffer.export({type:'spki',format:'der'})));

