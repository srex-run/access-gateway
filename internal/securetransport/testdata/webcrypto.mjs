import assert from 'node:assert/strict';
import { createInterface } from 'node:readline';
import { sealPayload } from '../../../apps/web/src/shared/api/transport.mjs';

const lines = createInterface({input: process.stdin})[Symbol.asyncIterator]();
const challenge = JSON.parse((await lines.next()).value);
const sealed = await sealPayload(challenge, {password: '密码/🔐', apikey: 'k'.repeat(8192)});
process.stdout.write(JSON.stringify(sealed.body) + '\n');
const response = JSON.parse((await lines.next()).value);
assert.deepEqual(JSON.parse(await sealed.open(response, 200)), {private_key: 'Go/browser-secret'});
await assert.rejects(() => sealed.open(response, 201));
const tampered = {...response, ciphertext: 'AAAA' + response.ciphertext.slice(4)};
await assert.rejects(() => sealed.open(tampered, 200));
process.stdout.write('verified\n');
