'use strict';

/*
========================================================
ECC Module 
Purpose:
- Generate ECC keys
- Create shared secrets using ECDH
- Encrypt/decrypt data using derived secret

Curve used: y² = x³ + ax + b (mod p)
Educational curve: y² = x³ - 2x + 2 (mod 23)
a = -2
b = 2
p = 23
Generator point: G = (4,9)
========================================================
*/

// =====================================================
// Section 1: Curve Definition
// =====================================================
const CURVE = {
    // Prime field
    p: 97n,

    // Curve equation:
    // y² = x³ + ax + b
    a: 2n,
    b: 3n,

    // Generator point G
    G: {x:3n,y:6n}
};

// =====================================================
// Section 2: Modular Arithmetic Helpers
// =====================================================
// ECC requires positive modulo.
function mod(value, modulus){
    return ((value % modulus)+modulus)%modulus;
}

// =====================================================
// Extended Euclidean Algorithm
// =====================================================
function extendedGcd(a,b){
    if(b === 0n){
        return {
            gcd:a,
            x:1n,
            y:0n
        };
    }
    let result = extendedGcd(b,a%b);
    return {
        gcd:result.gcd,
        x:result.y,
        y:result.x - (a/b)*result.y
    };
}

// Calculate modular inverse
function modInverse(value,modulus){
    let result = extendedGcd( value, modulus );
    if(result.gcd !== 1n){
        throw Error( "Inverse does not exist" );
    }
    return mod( result.x, modulus);
}

// =====================================================
// Section 3: Elliptic Curve Point Operations
// =====================================================

// -----------------------------------------------------
// Point Addition
// -----------------------------------------------------
function pointAdd(P,Q){
    // Identity rules
    if(P === null)
        return Q;
    if(Q === null)
        return P;

    const x1=P.x;
    const y1=P.y;
    const x2=Q.x;
    const y2=Q.y;

    // P + (-P) = O
    if(x1 === x2 &&mod(y1+y2,CURVE.p) === 0n)
    {
        return null;
    }
    let slope;

    // -----------------------------
    // Point Doubling
    // -----------------------------
    if( x1 === x2 && y1 === y2)
        {
        let numerator = mod( 3n*x1*x1 + CURVE.a, CURVE.p);
        let denominator = modInverse(2n*y1,CURVE.p);
        slope =mod(numerator*denominator,CURVE.p);
        }

    // -----------------------------
    // Normal point addition
    //
    // m =
    // (y2-y1)/(x2-x1)
    // -----------------------------
    else
        {
        let numerator = mod(y2-y1,CURVE.p);
        let denominator =modInverse(x2-x1,CURVE.p);
        slope = mod(numerator*denominator,CURVE.p);
        }

    // Result point:

    // x3 = m²-x1-x2
    let x3 = mod(slope*slope-x1-x2,CURVE.p);

    // y3 = m(x1-x3)-y1
    let y3 = mod(slope*(x1-x3)-y1,CURVE.p);

    return {x:x3,y:y3};
}

// =====================================================
// Section 4: Scalar Multiplication
// =====================================================


function scalarMultiply(k,point){
    let result = null;
    let current = point;
    while(k > 0n){
        // If current bit is 1
        if(k & 1n){
            result =pointAdd(result,current);
        }

        // Double the point
        current = pointAdd(current,current);

        // Move to next bit
        k =
        k >> 1n;
    }
    return result;
}


// =====================================================
// Section 5: ECC Key Generation
// =====================================================
//
// ECC keys:
//
// Private key:
//      random number d
//
// Public key:
//
//      Q = dG
//
// Where:
//      G = generator point
//
// =====================================================

function generatePrivateKey(){

    let privateKey;
    let publicKey;

    do{
        privateKey = BigInt(Math.floor(Math.random()*20)) + 1n;
        publicKey = scalarMultiply(privateKey, CURVE.G);

    }while(publicKey === null || publicKey.y === 0n);

    return privateKey;
}

function generateKeyPair(){
    // Generate private key
    let privateKey = generatePrivateKey();

    // Generate public key:
    // Q = dG
    let publicKey = scalarMultiply(privateKey,CURVE.G);

    return {privateKey,publicKey};
}


// =====================================================
// Section 6: ECDH Shared Secret
// =====================================================
//
// Alice:
//
// privateA
// publicA = privateA * G
//
//
// Bob:
//
// privateB
// publicB = privateB * G
//
//
// Shared secret:
//
// Alice:
//
// privateA * publicB
//
//
// Bob:
//
// privateB * publicA
//
//
// Both produce:
//
// privateA * privateB * G
//
// =====================================================

function generateSharedSecret(privateKey,otherPublicKey)
{
    let sharedPoint = scalarMultiply(privateKey,otherPublicKey);
    if(sharedPoint === null)
    {
        throw Error("Invalid shared secret");
    }
    return sharedPoint;
}

// =====================================================
// Section 7: Key Derivation
// =====================================================
//
// ECC gives us a point:
//
//      (x,y)
//
// We use x coordinate as a secret value.
//
// Convert it into bytes.
//
// This becomes our encryption stream.
//
// =====================================================

function generateKey(sharedSecret){

    // Take x coordinate
    let key = Number(sharedSecret.x);

    return key;

}


// =====================================================
// Section 8: XOR Encryption
// =====================================================
//
// XOR properties:
//
// plaintext XOR key = ciphertext
//
// ciphertext XOR key = plaintext
//
// Same operation performs
// encryption and decryption.
//
// =====================================================

function xorEncrypt(message,key)
{
    let encrypted = "";
    for(let i=0;i<message.length;i++)
        {
        encrypted += String.fromCharCode(message.charCodeAt(i) ^ key);
        }
    return encrypted;
}

// =====================================================
// Section 9: ECC Encryption
// =====================================================
//
// Steps:
//
// 1. Receiver has public key
//
// 2. Sender creates temporary private key
//
// 3. Create temporary public key
//
// 4. Generate shared secret
//
// 5. Encrypt using derived key
//
// Stored:
//
// ephemeral public key
// ciphertext
//
// =====================================================

function encrypt(plaintext, receiverPublicKey
){

    // Temporary private key
    let ephemeralPrivate =generatePrivateKey();

    // Temporary public key:
    // R = kG
    let ephemeralPublic =scalarMultiply(ephemeralPrivate,CURVE.G);

    // Shared secret:
    // S = kQ
    let sharedSecret =generateSharedSecret(ephemeralPrivate,receiverPublicKey);

    // Create encryption key
    let key =generateKey(sharedSecret);

    let ciphertext =xorEncrypt(plaintext,key);

    return {ephemeralPublic,ciphertext};
}

// =====================================================
// Section 10: ECC Decryption
// =====================================================
//
// Steps:
//
// 1. Receive ephemeral public key
//
// 2. Calculate:
//
//      S = dR
//
//
// 3. Generate same key
//
// 4. XOR decrypt
//
// =====================================================

function decrypt( encryptedData, receiverPrivateKey)
{
    let sharedSecret = generateSharedSecret( receiverPrivateKey, encryptedData.ephemeralPublic);

    let key = generateKey(sharedSecret);
    let plaintext =xorEncrypt(encryptedData.ciphertext,key);
    return plaintext;
}

// =====================================================
// Section 11: Export Functions
// =====================================================
module.exports = {
    // Curve
    CURVE,

    // Mathematics
    pointAdd,
    scalarMultiply,
    modInverse,

    // Keys
    generateKeyPair,

    // ECDH
    generateSharedSecret,

    // Encryption
    encrypt,
    decrypt

};