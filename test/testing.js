import * as bac from '../base-acme-client.js';

const directory = await bac.newDirectory("https://acme-staging-v02.api.letsencrypt.org/directory");

console.log(directory);

const nonce = await bac.newNonce(directory.answer.directory.newNonce);

console.log(nonce);

const getNext = await bac.getNextNonce(null, directory.answer.directory);

console.log(getNext);