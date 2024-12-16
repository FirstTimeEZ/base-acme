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
 * 
 * @returns {Promise<Object>} An object containing the directory information or an error
 * @property {Object|null} answer.directory - The parsed directory JSON or null
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
 * @param {string} [newNonceUrl] - Optional URL to fetch a new nonce. If not provided, it will be retrieved from the directory.
 * 
 * @returns {Promise<Object>} An object containing the nonce or error details
 * @property {string} nonce - A new replay nonce for subsequent requests
 * @property {Object} [answer.error] - The error response if the request was unsuccessful
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
 * 
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
 * @param {Object} acmeDirectory - The ACME directory containing URLs for ACME operations
 * 
 * @returns {Promise<Object>} An object containing the account creation result
 * @property {Object} answer - Contains account details or error information
 * @property {Object|null} [answer.account] - The created account details
 * @property {string} [answer.location] - The location URL of the created account
 * @property {Object} [answer.error] - Error details if account creation fails
 * @property {string} nonce - A new replay nonce for subsequent requests
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
 * @param {Object} acmeDirectory - The ACME directory containing URLs for ACME operations
 * 
 * @returns {Promise<Object>} An object containing the retrieved information
 * @property {Object} answer - Contains retrieved details or error information
 * @property {Object|null} [answer.get] - The retrieved resource details
 * @property {string} [answer.location] - The location URL of the resource
 * @property {Object} [answer.error] - Error details if retrieval fails
 * @property {string} nonce - A new replay nonce for subsequent requests
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
 * @param {Object} acmeDirectory - The ACME directory containing URLs for ACME operations
 * 
 * @returns {Promise<Object>} An object containing the challenge details
 * @property {Object} answer - Contains challenge details or error information
 * @property {Object|null} [answer.get] - The retrieved challenge details
 * @property {string} [answer.location] - The location URL of the challenge
 * @property {Object} [answer.error] - Error details if retrieval fails
 * @property {string} nonce - A new replay nonce for subsequent requests
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
 * 
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
 * 
 * @returns {Promise<string>} A JSON Web Signature (JWS) string
 */
export async function signPayload(payload, protectedHeader, privateKey) { /*...*/ }
```

### formatPublicKey

```javascript
/**
 * Formats a PEM-encoded public key to a key object.
 * @function formatPublicKey
 * @param {string} pem - The PEM-encoded public key
 * 
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
 * 
 * @returns {Object} A formatted private key object
 */
export function formatPrivateKey(pem) { /*...*/ }
```

### base64urlEncode

```javascript
/**
 * Encodes input to a base64url-encoded string.
 * @function base64urlEncode
 * @param {string|Uint8Array} input - The input to encode
 * 
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
 * 
 * @returns {Uint8Array} A Uint8Array containing the byte values represented by the hexadecimal string.
 * @throws {Error} Throws an error if the input string has an odd length or contains invalid hexadecimal characters.
 */
export function hexToBytes(hex) { /*...*/ }
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
 * 
 * @returns {Promise<Response>} The response from the server
 */
export async function fetchRequest(method, url, signedData) { /*...*/ }
```

### fetchSuggestedWindow

```javascript
/**
 * Fetches the suggested renewal window information for a certificate from the specified URL.
 * @async
 * @function fetchSuggestedWindow
 * @param {string} renewalInfoUrl - The base URL for fetching renewal information.
 * @param {string} aki- The Authority Key Identifier in hexadecimal format.
 * @param {string} serial - The serial number in hexadecimal format.
 * 
 * @returns {Promise<Object>} A promise that resolves to the parsed JSON of the suggested window
 * @property {Object} answer - Contains suggested window or error information
 * @property {Object} [answer.get] - The retrieved suggested window
 * @property {Object} [answer.error] - Error details if retrieval fails
 * 
 * @throws {Error} Throws an error if the fetch operation fails.
 */
export async function fetchSuggestedWindow(renewalInfoUrl, aki, serial) { /*...*/ }
```

### fetchAndRetryUntilOk

```javascript
/**
 * Fetch a resource with multiple retry attempts and progressive backoff.
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
export async function fetchAndRetryUntilOk(fetchInput, init, attempts = 6) { /*...*/ }
```

### fetchAndRetryProtectedUntilOk

```javascript
/**
 * Fetch a protected resource with multiple retry attempts and progressive backoff.
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
export async function fetchAndRetryProtectedUntilOk(payload, protectedHeader, privateKey, acmeDirectory, attempts = 3) { /*...*/ }
```

------

# Full Working Examples

This module is used by [`Lets Encrypt ACME Client`](https://github.com/FirstTimeEZ/acme) and [`Server SSL`](https://github.com/FirstTimeEZ/server-ssl)