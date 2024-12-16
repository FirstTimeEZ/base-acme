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
 * 
 * @param {string} mainDirectoryUrl - The URL of the ACME server's directory endpoint
 * 
 * @returns {Promise<Object>} An object containing the directory information or an error
 * @property {Object|null} answer.directory - The parsed directory JSON or null
 * @property {Response} [answer.error] - The error response if the request was unsuccessful
 */
export async function newDirectory(mainDirectoryUrl) {
    try {
        const response = await fetchAndRetryUntilOk(mainDirectoryUrl, { method: METHOD_GET });

        if (response) {
            if (response.ok) {
                return { answer: { directory: await response.json() } };
            }
            else {
                return { answer: { error: await response.json() } };
            }
        }

        return notCompletedError("newDirectory");
    } catch (exception) {
        return notCompletedError("newDirectory", exception);
    }
}

/**
 * Retrieves a new nonce from the ACME server.
 * @async
 * 
 * @param {string} [newNonceUrl] - Optional URL to fetch a new nonce. If not provided, it will be retrieved from the directory.
 * 
 * @returns {Promise<Object>} An object containing the nonce or error details
 * @property {string} nonce - A new replay nonce for subsequent requests
 * @property {Object} [answer.error] - The error response if the request was unsuccessful
 */
export async function newNonce(newNonceUrl) {
    try {
        let nonceUrl = newNonceUrl;

        if (newNonceUrl == undefined) {
            const directory = (await newDirectory()).answer.directory;
            if (directory !== null) {
                nonceUrl = directory.newNonce;
            }
        }

        if (nonceUrl === null) {
            return { answer: errorTemplate("bac:failed:newNonce", "No acme directory found or newNonce is not available.", 777778) };
        }

        const response = await fetchAndRetryUntilOk(nonceUrl, { method: METHOD_HEAD });

        if (response) {
            if (response.ok) {
                return { answer: null, nonce: response.headers.get(REPLAY_NONCE) };
            }
            else {
                return { answer: { error: await response.json() } };
            }
        }

        return notCompletedError("newNonce");
    } catch (exception) {
        return notCompletedError("newNonce", exception);
    }
}

/**
 * Creates a JSON Web Key (JWK) from a public key.
 * @async
 * 
 * @param {Object} publicKey - The public key to convert to JWK format
 * 
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
 * 
 * @param {string} nonce - The replay nonce from the server
 * @param {string} newAccountUrl - The URL for creating a new account
 * @param {Object} privateKey - The private key for signing the request
 * @param {Object} jsonWebKey - The JSON Web Key representing the account's public key
 * @param {Object} acmeDirectory - The ACME directory containing URLs for ACME operations
 * 
 * @returns {Promise<Object>} An object containing the account creation result
 * @property {Object} answer - Contains account details or error information
 * @property {Object|null} [answer.account] - The created account details
 * @property {string} [answer.location] - The location URL of the created account
 * @property {Object} [answer.error] - Error details if account creation fails
 * @property {string} nonce - A new replay nonce for subsequent requests
 */
export async function createAccount(nonce, privateKey, jsonWebKey, acmeDirectory) {
    try {
        const payload = { termsOfServiceAgreed: true };

        const protectedHeader = {
            alg: ALG_ECDSA,
            jwk: jsonWebKey,
            nonce: nonce,
            url: acmeDirectory.newAccount,
        };

        const response = await fetchAndRetryProtectedUntilOk(payload, protectedHeader, privateKey, acmeDirectory);

        if (response) {
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
        }

        return notCompletedError("createAccount");
    } catch (exception) {
        return notCompletedError("createAccount", exception);
    }
}

/**
 * Creates a new order for certificate issuance on the ACME server.
 * @async
 * 
 * @param {string} kid - Key Identifier for the account
 * @param {string} nonce - The replay nonce from the server
 * @param {Object} privateKey - The private key for signing the request
 * @param {string[]} identifiers - Domain names to be included in the certificate
 * @param {Object} acmeDirectory - The ACME directory containing URLs for ACME operations
 * 
 * @returns {Promise<Object>} An object containing the order creation result
 * @property {Object} answer - Contains order details or error information
 * @property {Object|null} [answer.order] - The created order details
 * @property {string} [answer.location] - The location URL of the created order
 * @property {Object} [answer.error] - Error details if order creation fails
 * @property {string} nonce - A new replay nonce for subsequent requests
 */
export async function createOrder(kid, nonce, privateKey, identifiers, acmeDirectory) {
    try {
        const payload = { [SAN]: identifiers };

        const protectedHeader = {
            alg: ALG_ECDSA,
            kid: kid,
            nonce: nonce,
            url: acmeDirectory.newOrder,
        };

        const response = await fetchAndRetryProtectedUntilOk(payload, protectedHeader, privateKey, acmeDirectory);

        if (response) {
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
        }

        return notCompletedError("createOrder");
    } catch (exception) {
        return notCompletedError("createOrder", exception);
    }
}

/**
 * Finalizes a certificate order by submitting a Certificate Signing Request (CSR).
 * @async
 * 
 * @param {string} commonName - The primary domain name for the certificate
 * @param {string} kid - Key Identifier for the account
 * @param {string} nonce - The replay nonce from the server
 * @param {Object} privateKey - The private key for signing the request
 * @param {Object} publicKeySign - Public key used for signing the CSR
 * @param {Object} privateKeySign - Private key used for signing the CSR
 * @param {string} finalizeUrl - The URL for finalizing the order
 * @param {Object} acmeDirectory - The ACME directory containing URLs for ACME operations
 * @param {string[]} dnsNames - Additional DNS names to be included in the certificate
 * 
 * @returns {Promise<Object>} An object containing the order finalization result
 * @property {Object} answer - Contains finalization details or error information
 * @property {Object|null} [answer.get] - The finalized order details
 * @property {string} [answer.location] - The location URL of the finalized order
 * @property {Object} [answer.error] - Error details if finalization fails
 * @property {string} nonce - A new replay nonce for subsequent requests
 */
export async function finalizeOrder(commonName, kid, nonce, privateKey, publicKeySign, privateKeySign, finalizeUrl, dnsNames, acmeDirectory) {
    try {
        const payload = { csr: await generateCSRWithExistingKeys(commonName, publicKeySign, privateKeySign, dnsNames) };

        const protectedHeader = {
            alg: ALG_ECDSA,
            kid: kid,
            nonce: nonce,
            url: finalizeUrl,
        };

        const response = await fetchAndRetryProtectedUntilOk(payload, protectedHeader, privateKey, acmeDirectory);

        if (response) {
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
        }

        return notCompletedError("finalizeOrder");
    } catch (exception) {
        return notCompletedError("finalizeOrder", exception);
    }
}

/**
 * Performs a POST-as-GET request to retrieve order or authorization status.
 * @async
 * 
 * @param {string} kid - Key Identifier for the account
 * @param {string} nonce - The replay nonce from the server
 * @param {Object} privateKey - The private key for signing the request
 * @param {string} url - The URL to retrieve status from
 * @param {Object} acmeDirectory - The ACME directory containing URLs for ACME operations
 * 
 * @returns {Promise<Object>} An object containing the retrieved information
 * @property {Object} answer - Contains retrieved details or error information
 * @property {Object|null} [answer.get] - The retrieved resource details
 * @property {string} [answer.location] - The location URL of the resource
 * @property {Object} [answer.error] - Error details if retrieval fails
 * @property {string} nonce - A new replay nonce for subsequent requests
 */
export async function postAsGet(kid, nonce, privateKey, url, acmeDirectory) {
    try {
        const protectedHeader = {
            alg: ALG_ECDSA,
            kid: kid,
            nonce: nonce,
            url: url,
        };

        const response = await fetchAndRetryProtectedUntilOk(METHOD_POST_AS_GET, protectedHeader, privateKey, acmeDirectory);

        if (response) {
            if (response.ok) {
                return {
                    answer: { get: await response.json(), location: response.headers.get(NEXT_URL) },
                    nonce: response.headers.get(REPLAY_NONCE)
                };
            }
            else {
                const nextNonce = await newNonce(acmeDirectory.newNonce);

                return {
                    answer: { error: await response.json() },
                    nonce: nextNonce.nonce ? nextNonce.nonce : null
                };
            }
        }

        return notCompletedError("postAsGet");
    } catch (exception) {
        return notCompletedError("postAsGet", exception);
    }
}

/**
 * Performs a POST-as-GET request for challenges
 * @async
 * 
 * @param {string} kid - Key Identifier for the account
 * @param {string} nonce - The replay nonce from the server
 * @param {Object} privateKey - The private key for signing the request
 * @param {string} url - The URL to retrieve challenge details from
 * @param {Object} acmeDirectory - The ACME directory containing URLs for ACME operations
 * 
 * @returns {Promise<Object>} An object containing the challenge details
 * @property {Object} answer - Contains challenge details or error information
 * @property {Object|null} [answer.get] - The retrieved challenge details
 * @property {string} [answer.location] - The location URL of the challenge
 * @property {Object} [answer.error] - Error details if retrieval fails
 * @property {string} nonce - A new replay nonce for subsequent requests
 */
export async function postAsGetChal(kid, nonce, privateKey, url, acmeDirectory) {
    try {
        const protectedHeader = {
            alg: ALG_ECDSA,
            kid: kid,
            nonce: nonce,
            url: url,
        };

        const response = await fetchAndRetryProtectedUntilOk(METHOD_POST_AS_GET_CHALLENGE, protectedHeader, privateKey, acmeDirectory);

        if (response) {
            if (response.ok) {
                return {
                    answer: { get: await response.json(), location: response.headers.get(NEXT_URL) },
                    nonce: response.headers.get(REPLAY_NONCE)
                };
            }
            else {
                const nextNonce = await newNonce(acmeDirectory.newNonce);

                return {
                    answer: { error: await response.json() },
                    nonce: nextNonce.nonce ? nextNonce.nonce : null
                };
            }
        }

        return notCompletedError("postAsGetChal");
    } catch (exception) {
        return notCompletedError("postAsGetChal", exception);
    }
}

/**
 * Signs a JSON payload for ACME server requests.
 * @async
 * 
 * @param {Object} payload - The payload to be signed
 * @param {Object} protectedHeader - The protected header containing metadata
 * @param {Object} privateKey - The private key used for signing
 * 
 * @returns {Promise<string>} A JSON Web Signature (JWS) string
 */
export async function signPayloadJson(payload, protectedHeader, privateKey) {
    return await signPayload(JSON.stringify(payload), protectedHeader, privateKey);
}

/**
 * Signs a payload for ACME server requests.
 * @async
 * 
 * @param {string|Object} payload - The payload to be signed
 * @param {Object} protectedHeader - The protected header containing metadata
 * @param {Object} privateKey - The private key used for signing
 * 
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
 * Formats a PEM-encoded public key to a key object.
 * 
 * @param {string} pem - The PEM-encoded public key
 * 
 * @returns {Object} A formatted public key object
 */
export function formatPublicKey(pem) {
    return createPublicKey({ key: Buffer.from(pem.replace(/(?:-----(?:BEGIN|END) PUBLIC KEY-----|\s)/g, ''), 'base64'), type: 'spki', format: 'der' });
}

/**
 * Formats a PEM-encoded private key to a key object.
 * 
 * @param {string} pem - The PEM-encoded private key
 * 
 * @returns {Object} A formatted private key object
 */
export function formatPrivateKey(pem) {
    return createPrivateKey({ key: Buffer.from(pem.replace(/(?:-----(?:BEGIN|END) PRIVATE KEY-----|\s)/g, ''), 'base64'), type: 'pkcs8', format: 'der' });
}

/**
 * Encodes input to a base64url-encoded string.
 * 
 * @param {string|Uint8Array} input - The input to encode
 * 
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
 * 
 * @param {string} hex - The hexadecimal string to convert. It should contain an even number of characters.
 * 
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
 * Sends a signed request to the ACME server.
 * @async
 * 
 * @param {string} method - The HTTP method to use (e.g., 'GET', 'POST')
 * @param {string} url - The URL to send the request to
 * @param {string} signedData - The signed payload to send
 * 
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

    return await fetch(url, request);
}

/**
 * Fetches the suggested renewal window information for a certificate from the specified URL.
 * @async
 * 
 * @param {string} renewalInfoUrl - The base URL for fetching renewal information.
 * @param {string} aki- The Authority Key Identifier in hexadecimal format.
 * @param {string} serial - The serial number in hexadecimal format.
 * 
 * @returns {Promise<Object>} A promise that resolves to the parsed JSON of the suggested window
 * @property {Object} answer - Contains suggested window or error information
 * @property {Object|null} [answer.get] - The retrieved suggested window
 * @property {Object} [answer.error] - Error details if retrieval fails
 * 
 * @throws {Error} Throws an error if the fetch operation fails.
 */
export async function fetchSuggestedWindow(renewalInfoUrl, aki, serial) {
    try {
        const url = `${renewalInfoUrl}/${base64urlEncode(hexToBytes(aki))}.${base64urlEncode(hexToBytes(serial))}`;

        const response = await fetchAndRetryUntilOk(url);

        if (response && response.ok) {
            return { answer: { get: await response.json() } }
        }

        return notCompletedError("fetchSuggestedWindow");
    } catch (exception) {
        return notCompletedError("fetchSuggestedWindow", exception);
    }
}

/**
 * Fetch a resource with multiple retry attempts and progressive backoff.
 * @async
 * 
 * @param {string|Request} fetchInput - The URL or Request object to fetch
 * @param {Object} init - optional fetch init object
 * @param {number} [attempts=6] - Maximum number of fetch attempts
 * 
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

            console.error(a - 1, "attempt failed, trying again", fetchInput);

            await new Promise((resolve) => setTimeout(() => { resolve(); }, 650 * a)); // Each failed attempt will delay itself slightly more
        } catch (exception) {
            console.error(a - 1, exception);
        }
    }

    return undefined;
}

/**
 * Fetch a protected resource with multiple retry attempts and progressive backoff.
 * @async
 * 
 * @param {Object} payload - The payload to be sent with the request
 * @param {Object} protectedHeader - The protected header containing metadata for the request
 * @param {Object} privateKey - The private key for signing the request
 * @param {Object} acmeDirectory - The ACME directory containing URLs for ACME operations
 * @param {number} [attempts=6] - Maximum number of fetch attempts (default: 6)
 * 
 * @returns {Promise<Response|undefined>} The response or undefined if all attempts fail
 *
 * @description
 * This function attempts to fetch a protected resource with the following characteristics:
 * - Starts with one fetch attempt
 * - Increments attempts progressively
 * - Implements an increasing delay between failed attempts (650ms * attempt number)
 * - Logs any caught exceptions
 * - Returns immediately on a successful (ok) response
 * - Returns the last response or undefined if all attempts are exhausted
 *
 * @example
 * const response = await fetchAndRetryProtectedUntilOk(
 *   payload, 
 *   protectedHeader, 
 *   privateKey, 
 *   acmeDirectory
 * );
 * if (response && response.ok) {
 *   const data = await response.json();
 *   // Process successful response
 * }
 */
export async function fetchAndRetryProtectedUntilOk(payload, protectedHeader, privateKey, acmeDirectory, attempts = 3) {
    let a = 1;

    while (a <= attempts) {
        a++;
        try {
            if (protectedHeader.nonce == undefined) {
                const nextNonce = await newNonce(acmeDirectory.newNonce);

                if (nextNonce.nonce) {
                    protectedHeader.nonce = nextNonce.nonce;
                }
                else {
                    console.log(a - 1, "Could not get the next nonce so the attempt failed");

                    await new Promise((resolve) => setTimeout(() => { resolve(); }, 650 * a)); // Each failed attempt will delay itself slightly more

                    continue;
                }
            }

            const signed = payload != "" ? await signPayloadJson(payload, protectedHeader, privateKey) : await signPayload("", protectedHeader, privateKey);

            const response = await fetchRequest(METHOD_POST, protectedHeader.url, signed);

            if (response.ok) {
                return response;
            }

            if (a > attempts) {
                return response;
            }

            protectedHeader.nonce = undefined;

            console.log(a - 1, "attempt failed, trying again", protectedHeader);

            await new Promise((resolve) => setTimeout(() => { resolve(); }, 2250 * a)); // Each failed attempt will delay itself slightly more
        } catch (exception) {
            console.log(a - 1, exception);
        }
    }

    return undefined;
}

function notCompletedError(error, exception) {
    return {
        answer:
            !exception
                ? errorTemplate(`bac:failed:${error}`, `Could not complete ${error} after multiple attempts`, 777777)
                : errorTemplate(`bac:exception:${error}`, exception, 777777)
    }
}

function errorTemplate(type, details, status) {
    return {
        error: {
            type: type,
            detail: details,
            status: status
        }
    }
}

module.exports = {
    newDirectory,
    newNonce,
    createJsonWebKey,
    createAccount,
    createOrder,
    finalizeOrder,
    postAsGet,
    postAsGetChal,
    signPayloadJson,
    signPayload,
    formatPublicKey,
    formatPrivateKey,
    base64urlEncode,
    hexToBytes,
    fetchRequest,
    fetchSuggestedWindow,
    fetchAndRetryUntilOk,
    fetchAndRetryProtectedUntilOk
};