import * as bac from '../base-acme-client.js';

const directory = await bac.newDirectory("https://acme-staging-v02.api.letsencrypt.org/directory");

console.log(directory);

const nonce = await bac.newNonce(directory.get.newNonce);

console.log(nonce);

const getNext = await bac.getNextNonce(null, directory.get);

console.log(getNext);

// base-acme>node ./test/testing.js
// {
//   get: {
//     '8_rKn1gFwoo': 'https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417',
//     keyChange: 'https://acme-staging-v02.api.letsencrypt.org/acme/key-change',
//     meta: {
//       caaIdentities: [Array],
//       termsOfService: 'https://letsencrypt.org/documents/LE-SA-v1.4-April-3-2024.pdf',
//       website: 'https://letsencrypt.org/docs/staging-environment/'
//     },
//     newAccount: 'https://acme-staging-v02.api.letsencrypt.org/acme/new-acct',
//     newNonce: 'https://acme-staging-v02.api.letsencrypt.org/acme/new-nonce',
//     newOrder: 'https://acme-staging-v02.api.letsencrypt.org/acme/new-order',
//     renewalInfo: 'https://acme-staging-v02.api.letsencrypt.org/draft-ietf-acme-ari-03/renewalInfo',
//     revokeCert: 'https://acme-staging-v02.api.letsencrypt.org/acme/revoke-cert'
//   }
// }
// { nonce: 'XCuYn79eoXFBd8Zmu0wnye_YXeDC9uFBtNont7Gwn0usd_mEKC0' }
// J6d90a-tXNteEdQ_J1m1tpQ5qLPv7t5edwt3wxAelXKH_9bNNso