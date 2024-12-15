/**
 * ACME Client Module
 * @module ACMEClientModule
 * @description A module for interacting with ACME (Automated Certificate Management Environment) servers for automated SSL/TLS certificate issuance and management.
 * @copyright © 2024 FirstTimeEZ
 * @license Apache-2.0
 */

import { createPrivateKey, createPublicKey, createHash, sign } from 'crypto';
import { generateCSRWithExistingKeys } from 'simple-csr-generator';

const CONTENT_TYPE = "Content-Type";

const DIGEST = "sha256";
const ALG_ECDSA = 'ES256';

const CONTENT_TYPE_JOSE = 'application/jose+json';

const METHOD_GET = "GET";
const METHOD_POST = "POST";
const METHOD_HEAD = "HEAD";
const METHOD_POST_AS_GET = "";
const METHOD_POST_AS_GET_CHALLENGE = {};

const SAN = "identifiers";
const NEXT_URL = "location";
const REPLAY_NONCE = 'replay-nonce';

/**
 * Fetches the directory information from an ACME server.
 * @async
 * @function newDirectoryAsync
 * @param {string} mainDirectoryUrl - The URL of the ACME server's directory endpoint
 * @returns {Promise<Object>} An object containing the directory information or an error
 * @property {Object|null} answer.directory - The parsed directory JSON or null
 * @property {Error} [answer.exception] - An error object if the request fails
 * @property {Response} [answer.error] - The error response if the request was unsuccessful
 */
export async function newDirectoryAsync(mainDirectoryUrl) {
    try {
        const response = await fetchAndRetryUntilOk(mainDirectoryUrl, { method: METHOD_GET });

        if (response.ok) {
            return await response.json().then((result) => { return { answer: { directory: result } } });
        }
        else {
            return { answer: { error: response } };
        }
    } catch (exception) {
        return { answer: { exception: exception } }
    }
}

/**
 * Retrieves a new nonce from the ACME server.
 * @async
 * @function newNonceAsync
 * @param {string} [newNonceUrl] - Optional URL to fetch a new nonce. 
 *                                  If not provided, it will be retrieved from the directory.
 * @returns {Promise<Object>} An object containing the nonce and response details
 * @property {string} [nonce] - The replay nonce retrieved from the server
 * @property {Object} answer - Contains response or error information
 * @property {Response} [answer.response] - The successful response
 * @property {Error} [answer.exception] - An error object if the request fails
 * @property {Response} [answer.error] - The error response if the request was unsuccessful
 */
export async function newNonceAsync(newNonceUrl) {
    try {
        let nonceUrl = newNonceUrl;

        if (newNonceUrl == undefined) {
            const directory = (await newDirectoryAsync()).answer.directory;
            if (directory !== null) {
                nonceUrl = directory.newNonce;
            }
        }

        if (nonceUrl !== null) {
            const response = await fetchAndRetryUntilOk(nonceUrl, { method: METHOD_HEAD });

            if (response.ok) {
                return { answer: { response: response }, nonce: response.headers.get(REPLAY_NONCE) };
            }
            else {
                return { answer: { error: response } };
            }
        } else {
            return { answer: { error: "No directories found or newNonce is not available." } };
        }
    } catch (exception) {
        return { answer: { exception: exception } }
    }
}

/**
 * Creates a JSON Web Key (JWK) from a public key.
 * @async
 * @function createJsonWebKey
 * @param {Object} publicKey - The public key to convert to JWK format
 * @returns {Promise<Object>} An object containing the JWK and its thumbprint
 * @property {Object} key - The JSON Web Key representation
 * @property {string} print - Base64URL encoded thumbprint of the key
 */
export async function createJsonWebKey(publicKey) {
    const jsonWebKey = publicKey.export({ format: 'jwk' });

    return { key: jsonWebKey, print: base64urlEncode(createHash(DIGEST).update(new TextEncoder().encode(JSON.stringify({ crv: jsonWebKey.crv, kty: jsonWebKey.kty, x: jsonWebKey.x, y: jsonWebKey.y }))).digest()) };
}

/**
 * Creates a new account on the ACME server.
 * @async
 * @function createAccount
 * @param {string} nonce - The replay nonce from the server
 * @param {string} newAccountUrl - The URL for creating a new account
 * @param {Object} privateKey - The private key for signing the request
 * @param {Object} jsonWebKey - The JSON Web Key representing the account's public key
 * @returns {Promise<Object>} An object containing the account creation result
 * @property {Object} answer - Contains account details or error information
 * @property {Object} [answer.account] - The created account details
 * @property {string} [answer.location] - The location URL of the created account
 * @property {Object} [answer.error] - Error details if account creation fails
 * @property {Error} [answer.exception] - An error object if an exception occurs
 * @property {string} [nonce] - A new replay nonce for subsequent requests
 */
export async function createAccount(nonce, newAccountUrl, privateKey, jsonWebKey) {
    try {
        const payload = { termsOfServiceAgreed: true };

        const protectedHeader = {
            alg: ALG_ECDSA,
            jwk: jsonWebKey,
            nonce: nonce,
            url: newAccountUrl,
        };

        const signed = await signPayloadJson(payload, protectedHeader, privateKey);

        const response = await fetchRequest(METHOD_POST, newAccountUrl, signed);

        if (response.ok) {
            return {
                answer: { account: await response.json(), location: response.headers.get(NEXT_URL) },
                nonce: response.headers.get(REPLAY_NONCE)
            };
        }
        else {
            return {
                answer: { error: await response.json() },
                nonce: null
            };
        }
    } catch (exception) {
        return { answer: { exception: exception } }
    }
}

/**
 * Creates a new order for certificate issuance on the ACME server.
 * @async
 * @function createOrder
 * @param {string} kid - Key Identifier for the account
 * @param {string} nonce - The replay nonce from the server
 * @param {Object} privateKey - The private key for signing the request
 * @param {string} newOrderUrl - The URL for creating a new order
 * @param {string[]} identifiers - Domain names to be included in the certificate
 * @returns {Promise<Object>} An object containing the order creation result
 * @property {Object} answer - Contains order details or error information
 * @property {Object} [answer.order] - The created order details
 * @property {string} [answer.location] - The location URL of the created order
 * @property {Object} [answer.error] - Error details if order creation fails
 * @property {Error} [answer.exception] - An error object if an exception occurs
 * @property {string} [nonce] - A new replay nonce for subsequent requests
 */
export async function createOrder(kid, nonce, privateKey, newOrderUrl, identifiers) {
    try {
        const payload = { [SAN]: identifiers };

        const protectedHeader = {
            alg: ALG_ECDSA,
            kid: kid,
            nonce: nonce,
            url: newOrderUrl,
        };

        const signed = await signPayloadJson(payload, protectedHeader, privateKey);

        const response = await fetchRequest(METHOD_POST, newOrderUrl, signed);

        if (response.ok) {
            return {
                answer: { order: await response.json(), location: response.headers.get(NEXT_URL) },
                nonce: response.headers.get(REPLAY_NONCE)
            };
        }
        else {
            return {
                answer: { error: await response.json() },
                nonce: null
            };
        }
    } catch (exception) {
        return { answer: { exception: exception } }
    }
}

/**
 * Finalizes a certificate order by submitting a Certificate Signing Request (CSR).
 * @async
 * @function finalizeOrder
 * @param {string} commonName - The primary domain name for the certificate
 * @param {string} kid - Key Identifier for the account
 * @param {string} nonce - The replay nonce from the server
 * @param {Object} privateKey - The private key for signing the request
 * @param {Object} publicKeySign - Public key used for signing the CSR
 * @param {Object} privateKeySign - Private key used for signing the CSR
 * @param {string} finalizeUrl - The URL for finalizing the order
 * @param {string[]} dnsNames - Additional DNS names to be included in the certificate
 * @returns {Promise<Object>} An object containing the order finalization result
 * @property {Object} answer - Contains finalization details or error information
 * @property {Object} [answer.get] - The finalized order details
 * @property {string} [answer.location] - The location URL of the finalized order
 * @property {Object} [answer.error] - Error details if finalization fails
 * @property {Error} [answer.exception] - An error object if an exception occurs
 * @property {string} [nonce] - A new replay nonce for subsequent requests
 */
export async function finalizeOrder(commonName, kid, nonce, privateKey, publicKeySign, privateKeySign, finalizeUrl, dnsNames) {
    try {
        const payload = { csr: await generateCSRWithExistingKeys(commonName, publicKeySign, privateKeySign, dnsNames) };

        const protectedHeader = {
            alg: ALG_ECDSA,
            kid: kid,
            nonce: nonce,
            url: finalizeUrl,
        };

        const signed = await signPayloadJson(payload, protectedHeader, privateKey);

        const response = await fetchRequest(METHOD_POST, finalizeUrl, signed);

        if (response.ok) {
            return {
                answer: { get: await response.json(), location: response.headers.get(NEXT_URL) },
                nonce: response.headers.get(REPLAY_NONCE)
            };
        }
        else {
            return {
                answer: { error: await response.json() },
                nonce: response.headers.get(REPLAY_NONCE)
            };
        }
    } catch (exception) {
        return { answer: { exception: exception } }
    }
}

/**
 * Performs a POST-as-GET request to retrieve order or authorization status.
 * @async
 * @function postAsGet
 * @param {string} kid - Key Identifier for the account
 * @param {string} nonce - The replay nonce from the server
 * @param {Object} privateKey - The private key for signing the request
 * @param {string} url - The URL to retrieve status from
 * @returns {Promise<Object>} An object containing the retrieved information
 * @property {Object} answer - Contains retrieved details or error information
 * @property {Object} [answer.get] - The retrieved resource details
 * @property {string} [answer.location] - The location URL of the resource
 * @property {Object} [answer.error] - Error details if retrieval fails
 * @property {Error} [answer.exception] - An error object if an exception occurs
 * @property {string} [nonce] - A new replay nonce for subsequent requests
 */
export async function postAsGet(kid, nonce, privateKey, url) {
    try {
        const protectedHeader = {
            alg: ALG_ECDSA,
            kid: kid,
            nonce: nonce,
            url: url,
        };

        const signed = await signPayload(METHOD_POST_AS_GET, protectedHeader, privateKey);

        const response = await fetchRequest(METHOD_POST, url, signed);

        if (response.ok) {
            return {
                answer: { get: await response.json(), location: response.headers.get(NEXT_URL) },
                nonce: response.headers.get(REPLAY_NONCE)
            };
        }
        else {
            return {
                answer: { error: await response.json() },
                nonce: null
            };
        }
    } catch (exception) {
        return { answer: { exception: exception } }
    }
}

/**
 * Performs a POST-as-GET request for challenges
 * @async
 * @function postAsGetChal
 * @param {string} kid - Key Identifier for the account
 * @param {string} nonce - The replay nonce from the server
 * @param {Object} privateKey - The private key for signing the request
 * @param {string} url - The URL to retrieve challenge details from
 * @returns {Promise<Object>} An object containing the challenge details
 * @property {Object} answer - Contains challenge details or error information
 * @property {Object} [answer.get] - The retrieved challenge details
 * @property {string} [answer.location] - The location URL of the challenge
 * @property {Object} [answer.error] - Error details if retrieval fails
 * @property {Error} [answer.exception] - An error object if an exception occurs
 * @property {string} [nonce] - A new replay nonce for subsequent requests
 */
export async function postAsGetChal(kid, nonce, privateKey, url) {
    try {
        const protectedHeader = {
            alg: ALG_ECDSA,
            kid: kid,
            nonce: nonce,
            url: url,
        };

        const signed = await signPayloadJson(METHOD_POST_AS_GET_CHALLENGE, protectedHeader, privateKey);

        const response = await fetchRequest(METHOD_POST, url, signed);

        if (response.ok) {
            return {
                answer: { get: await response.json(), location: response.headers.get(NEXT_URL) },
                nonce: response.headers.get(REPLAY_NONCE)
            };
        }
        else {
            return {
                answer: { error: await response.json() },
                nonce: null
            };
        }
    } catch (exception) {
        return { answer: { exception: exception } }
    }
}

/**
 * Signs a JSON payload for ACME server requests.
 * @async
 * @function signPayloadJson
 * @param {Object} payload - The payload to be signed
 * @param {Object} protectedHeader - The protected header containing metadata
 * @param {Object} privateKey - The private key used for signing
 * @returns {Promise<string>} A JSON Web Signature (JWS) string
 */
export async function signPayloadJson(payload, protectedHeader, privateKey) {
    return await signPayload(JSON.stringify(payload), protectedHeader, privateKey);
}

/**
 * Signs a payload for ACME server requests.
 * @async
 * @function signPayload
 * @param {string|Object} payload - The payload to be signed
 * @param {Object} protectedHeader - The protected header containing metadata
 * @param {Object} privateKey - The private key used for signing
 * @returns {Promise<string>} A JSON Web Signature (JWS) string
 */
export async function signPayload(payload, protectedHeader, privateKey) {
    const payload64 = base64urlEncode(new TextEncoder().encode(payload));
    const protected64 = base64urlEncode(new TextEncoder().encode(JSON.stringify(protectedHeader)));

    const jws = {
        signature: base64urlEncode(sign("sha256", `${protected64}${'.'}${payload64}`, { dsaEncoding: 'ieee-p1363', key: privateKey })),
        payload: "",
        protected: protected64
    };

    if (payload.length > 1) {
        jws.payload = payload64
    }

    return JSON.stringify(jws);
}

/**
 * Sends a signed request to the ACME server.
 * @async
 * @function fetchRequest
 * @param {string} method - The HTTP method to use (e.g., 'GET', 'POST')
 * @param {string} url - The URL to send the request to
 * @param {string} signedData - The signed payload to send
 * @returns {Promise<Response>} The response from the server
 */
export async function fetchRequest(method, url, signedData) {
    const request = {
        method: method,
        headers: {
            [CONTENT_TYPE]: CONTENT_TYPE_JOSE
        },
        body: signedData
    };

    return await fetchAndRetryUntilOk(url, request);
}

/**
 * Fetches the suggested renewal window information for a certificate from the specified URL.
 * @async
 * @function fetchSuggestedWindow
 * @param {string} renewalInfoUrl - The base URL for fetching renewal information.
 * @param {string} aki- The Authority Key Identifier in hexadecimal format.
 * @param {string} serial - The serial number in hexadecimal format.
 * @returns {Promise<Object|undefined>} A promise that resolves to the parsed JSON
 * response if the request is successful, or `undefined` if the request fails.
 *
 * @throws {Error} Throws an error if the fetch operation fails.
 */
export async function fetchSuggestedWindow(renewalInfoUrl, aki, serial) {
    const url = `${renewalInfoUrl}/${base64urlEncode(hexToBytes(aki))}.${base64urlEncode(hexToBytes(serial))}`;

    const response = await fetch(url);
    if (response.ok) {
        return await response.json()
    }

    return undefined;
}

/**
 * Formats a PEM-encoded public key to a key object.
 * @function formatPublicKey
 * @param {string} pem - The PEM-encoded public key
 * @returns {Object} A formatted public key object
 */
export function formatPublicKey(pem) {
    return createPublicKey({ key: Buffer.from(pem.replace(/(?:-----(?:BEGIN|END) PUBLIC KEY-----|\s)/g, ''), 'base64'), type: 'spki', format: 'der' });
}

/**
 * Formats a PEM-encoded private key to a key object.
 * @function formatPrivateKey
 * @param {string} pem - The PEM-encoded private key
 * @returns {Object} A formatted private key object
 */
export function formatPrivateKey(pem) {
    return createPrivateKey({ key: Buffer.from(pem.replace(/(?:-----(?:BEGIN|END) PRIVATE KEY-----|\s)/g, ''), 'base64'), type: 'pkcs8', format: 'der' });
}

/**
 * Encodes input to a base64url-encoded string.
 * @function base64urlEncode
 * @param {string|Uint8Array} input - The input to encode
 * @returns {string} A base64url-encoded string
 */
export function base64urlEncode(input) {
    const base64 = Buffer.from(typeof input === 'string' ? new TextEncoder().encode(input) : input).toString('base64');

    return base64
        .replace(/\+/g, '-')   // Replace + with -
        .replace(/\//g, '_')   // Replace / with _
        .replace(/=+$/, '');   // Remove trailing =
}

/**
 * Converts a hexadecimal string to a Uint8Array of bytes.
 * @function hexToBytes
 * @param {string} hex - The hexadecimal string to convert. It should contain an even number of characters.
 * @returns {Uint8Array} A Uint8Array containing the byte values represented by the hexadecimal string.
 * @throws {Error} Throws an error if the input string has an odd length or contains invalid hexadecimal characters.
 */
export function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return bytes;
}

/**
 * Fetch a resource with multiple retry attempts and progressive backoff.
 * 
 * @param {string|Request} fetchInput - The URL or Request object to fetch
 * @param {Object} init - optional fetch init object
 * @param {number} [attempts=6] - Maximum number of fetch attempts
 * @returns {Promise<Response|undefined>} The response or undefined if all attempts fail
 * 
 * @description
 * This function attempts to fetch a resource with the following characteristics:
 * - Starts with one fetch attempt
 * - Increments attempts progressively
 * - Implements an increasing delay between failed attempts (650ms * attempt number)
 * - Logs any caught exceptions
 * - Returns immediately on a successful (ok) response
 * - Returns the last response or undefined if all attempts are exhausted
 * 
 * @example
 * const response = await fetchAndRetyUntilOk('https://api.example.com/data');
 * if (response && response.ok) {
 *   const data = await response.json();
 *   // Process successful response
 * }
 */
export async function fetchAndRetryUntilOk(fetchInput, init, attempts = 6) {
    let a = 1;

    while (a <= attempts) {
        a++;
        try {
            const response = await fetch(fetchInput, init);

            if (response.ok) {
                return response;
            }

            if (a > attempts) {
                return response;
            }

            await new Promise((resolve) => setTimeout(() => { resolve(); }, 650 * a)); // Each failed attempt will delay itself slightly more
        } catch (exception) {
            console.log(a - 1, exception);
        }
    }

    return undefined;
}