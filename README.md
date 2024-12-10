# Automatic Certificate Management Environment (ACME)

A module for interacting with [`ACME`](https://datatracker.ietf.org/doc/html/rfc8555) servers for automated SSL/TLS certificate issuance and management.

# Exports

### newDirectoryAsync

```javascript
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
export async function newDirectoryAsync(mainDirectoryUrl) { /*...*/ }
```

### newNonceAsync

```javascript
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
export async function newNonceAsync(newNonceUrl) { /*...*/ }
```

### createJsonWebKey

```javascript
/**
 * Creates a JSON Web Key (JWK) from a public key.
 * @async
 * @function createJsonWebKey
 * @param {Object} publicKey - The public key to convert to JWK format
 * @returns {Promise<Object>} An object containing the JWK and its thumbprint
 * @property {Object} key - The JSON Web Key representation
 * @property {string} print - Base64URL encoded thumbprint of the key
 */
export async function createJsonWebKey(publicKey) { /*...*/ }
```

### createAccount

```javascript
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
export async function createAccount(nonce, newAccountUrl, privateKey, jsonWebKey) { /*...*/ }
```

### createOrder

```javascript
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
export async function createOrder(kid, nonce, privateKey, newOrderUrl, identifiers) { /*...*/ }
```

### finalizeOrder

```javascript
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
export async function finalizeOrder(commonName, kid, nonce, privateKey, publicKeySign, privateKeySign, finalizeUrl, dnsNames) { /*...*/ }
```

### postAsGet

```javascript
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
export async function postAsGet(kid, nonce, privateKey, url) { /*...*/ }
```

### postAsGetChal

```javascript
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
export async function postAsGetChal(kid, nonce, privateKey, url) { /*...*/ }
```

### signPayloadJson

```javascript
/**
 * Signs a JSON payload for ACME server requests.
 * @async
 * @function signPayloadJson
 * @param {Object} payload - The payload to be signed
 * @param {Object} protectedHeader - The protected header containing metadata
 * @param {Object} privateKey - The private key used for signing
 * @returns {Promise<string>} A JSON Web Signature (JWS) string
 */
export async function signPayloadJson(payload, protectedHeader, privateKey) { /*...*/ }
```

### signPayload

```javascript
/**
 * Signs a payload for ACME server requests.
 * @async
 * @function signPayload
 * @param {string|Object} payload - The payload to be signed
 * @param {Object} protectedHeader - The protected header containing metadata
 * @param {Object} privateKey - The private key used for signing
 * @returns {Promise<string>} A JSON Web Signature (JWS) string
 */
export async function signPayload(payload, protectedHeader, privateKey) { /*...*/ }
```

### fetchRequest

```javascript
/**
 * Sends a signed request to the ACME server.
 * @async
 * @function fetchRequest
 * @param {string} method - The HTTP method to use (e.g., 'GET', 'POST')
 * @param {string} url - The URL to send the request to
 * @param {string} signedData - The signed payload to send
 * @returns {Promise<Response>} The response from the server
 */
export async function fetchRequest(method, url, signedData) { /*...*/ }
```

### fetchSuggestedWindow

```javascript
/**
 * Fetches the suggested renewal window information from the specified URL.
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
export async function fetchSuggestedWindow(renewalInfoUrl, aki, serial) { /*...*/ }
```

### formatPublicKey

```javascript
/**
 * Formats a PEM-encoded public key to a key object.
 * @function formatPublicKey
 * @param {string} pem - The PEM-encoded public key
 * @returns {Object} A formatted public key object
 */
export function formatPublicKey(pem) { /*...*/ }
```

### formatPrivateKey

```javascript
/**
 * Formats a PEM-encoded private key to a key object.
 * @function formatPrivateKey
 * @param {string} pem - The PEM-encoded private key
 * @returns {Object} A formatted private key object
 */
export function formatPrivateKey(pem) { /*...*/ }
```

### base64urlEncode

```javascript
/**
 * Encodes input to a base64url-encoded string.
 * @function 
 ### base64urlEncode
 
 * @param {string|Uint8Array} input - The input to encode
 * @returns {string} A base64url-encoded string
 */
export function base64urlEncode(input) { /*...*/ }
```

### hexToBytes

```javascript
/**
 * Converts a hexadecimal string to a Uint8Array of bytes.
 * @function hexToBytes
 * @param {string} hex - The hexadecimal string to convert. It should contain an even number of characters.
 * @returns {Uint8Array} A Uint8Array containing the byte values represented by the hexadecimal string.
 * @throws {Error} Throws an error if the input string has an odd length or contains invalid hexadecimal characters.
 */
export function hexToBytes(hex) { /*...*/ }
```

------

# Full Working Examples

This module is used by [`Lets Encrypt ACME Client`](https://github.com/FirstTimeEZ/acme) and [`Server SSL`](https://github.com/FirstTimeEZ/server-ssl)