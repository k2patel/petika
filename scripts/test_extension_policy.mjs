import assert from 'node:assert/strict';
import {httpsOrigin, authorizeFill} from '../clients/extension/fill.mjs';
assert.equal(httpsOrigin('https://EXAMPLE.test:443/login'),'https://example.test');
assert.equal(authorizeFill('https://example.test/login','https://example.test/account',['https://example.test']),'https://example.test');
for (const [target,item,allowed] of [
  ['http://example.test','http://example.test',['http://example.test']],
  ['https://evil.test','https://example.test',['https://evil.test']],
  ['https://sub.example.test','https://example.test',['https://example.test']],
  ['https://example.test:8443','https://example.test',['https://example.test']],
  ['https://example.test','https://example.test',[]],
  ['https://user:secret@example.test','https://example.test',['https://example.test']],
  ['https://example.test.evil.test','https://example.test',['https://example.test']],
]) assert.throws(() => authorizeFill(target,item,allowed));
console.log('Extension origin policy passed.');
