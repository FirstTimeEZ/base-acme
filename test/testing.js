import * as bac from '../base-acme-client.js';

const directory = await bac.newDirectoryAsync("https://acme-staging-v02.api.letsencrypt.org/directory");

console.log(directory);

const nonce = await bac.newNonceAsync(directory.answer.directory.newNonce);

console.log(nonce);
