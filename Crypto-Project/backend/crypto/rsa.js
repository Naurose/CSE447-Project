'use strict';

const crypto = require("crypto");

// =====================================================
// Convert normal text into BigInt
// Python equivalent:
// int("Secret".encode("utf-8").hex(),16)
// =====================================================

function stringToBigInt(message){
    const hex = Buffer.from(message,"utf8").toString("hex");
    return BigInt("0x" + hex);
}

// Convert BigInt back to text

function bigIntToString(number){
    let hex = number.toString(16);
    // Make even length
    if(hex.length % 2 !== 0){
        hex = "0" + hex;
    }
    return Buffer.from(hex,"hex").toString("utf8");
}

// =====================================================
// Modular Exponentiation
// Calculates:
//      (base ^ exponent) mod modulus
//
// RSA uses this for:
// Encryption:
//      c = m^e mod n
//
// Decryption:
//      m = c^d mod n
// =====================================================

function modPow(base, exponent, modulus){
    let result = 1n;
    base = base % modulus;
    while(exponent > 0n){
        // If exponent bit is 1
        if(exponent % 2n === 1n){
            result =
            (result * base) % modulus;
        }
        // Square base
        base = (base * base) % modulus;
        // Divide exponent by 2
        exponent = exponent / 2n;
    }
    return result;
}

// =====================================================
// Extended Euclidean Algorithm
// Finds:
// ax + by = gcd(a,b)
//
// Used to calculate private key d
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
        gcd: result.gcd,
        x: result.y,
        y:result.x - (a/b)*result.y
    };
}

// =====================================================
// Modular Inverse
// Finds d such that:
//
// d*e ≡ 1 mod phi
//
// This creates the private key
// =====================================================

function modInverse(e,phi){
    let result = extendedGcd(e,phi);
    if(result.gcd !== 1n){
        throw Error( "Inverse does not exist" );
    }

    return (result.x % phi + phi)%phi;
}

// =====================================================
// Prime Generation
// Simple prime checker
// Used only for demonstration
// =====================================================

function isPrime(number){
    if(number < 2n)
        return false;
    for(let i = 2n; i*i <= number; i++){
        if(number % i === 0n)
            return false;
    }
    return true;
}

// =====================================================
// RSA Key Generation
//
// Public key:
//      (n,e)
//
// Private key:
//      (n,d)
// =====================================================

function generateKeys(){
    // Step 1:
    // Choose two prime numbers
    let p = findPrime(100n);
    let q = findPrime(200n);

    // Step 2:
    // Calculate n
    let n = p*q;

    // Step 3:
    // Calculate Euler's Totient
    let phi =
    (p-1n)*(q-1n);

    // Step 4:
    // Choose public exponent
    let e = 11n;

    // Step 5:
    // Calculate private key
    let d = modInverse(e,phi);
    return {publicKey:{n,e},privateKey:{n,d}};
}

// =====================================================
// RSA Encryption
//
// c = m^e mod n
// =====================================================

function encrypt(message,publicKey){

    let m = typeof message === "bigint"?message:stringToBigInt(message);
    let c = modPow(m,publicKey.e,publicKey.n);
    return c;
}

// =====================================================
// RSA Decryption
//
// m = c^d mod n
// =====================================================

function decrypt(ciphertext,privateKey){
    let message = modPow( ciphertext, privateKey.d, privateKey.n );
    return bigIntToString(message);
}

