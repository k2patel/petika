import assert from 'node:assert/strict';
import {totp, parseOtp} from '../clients/web/otp.js';
const base32 = bytes => {
  let value=0, bits=0, output='';
  for (const byte of bytes) { value=(value<<8)|byte; bits+=8; while(bits>=5){bits-=5;output+='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'[(value>>>bits)&31]} }
  if(bits)output+='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'[(value<<(5-bits))&31]; return output;
};
const vectors = [
 [59, '94287082','46119246','90693936'],
 [1111111109,'07081804','68084774','25091201'],
 [1111111111,'14050471','67062674','99943326'],
 [1234567890,'89005924','91819424','93441116'],
 [2000000000,'69279037','90698825','38618901'],
 [20000000000,'65353130','77737706','47863826'],
];
for (const [algorithm,length,index] of [['SHA1',20,1],['SHA256',32,2],['SHA512',64,3]]) {
 const seed=base32(new TextEncoder().encode('1234567890'.repeat(7).slice(0,length)));
 for(const vector of vectors){const value=await totp(`otpauth://totp/RFC?secret=${seed}&algorithm=${algorithm}&digits=8`,vector[0]);assert.equal(value.code,vector[index]);}
}
for(const invalid of ['abc','otpauth://hotp/Test?secret=JBSWY3DPEHPK3PXP','otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&digits=7','otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&period=0'])assert.throws(()=>parseOtp(invalid));
console.log('All 18 RFC 6238 vectors and invalid configurations passed.');
