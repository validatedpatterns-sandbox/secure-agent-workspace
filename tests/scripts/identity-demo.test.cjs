const test = require('node:test');
const assert = require('node:assert/strict');
process.env.ISSUER = 'https://fixture.example';
process.env.ALLOWED_PREFIXES = '[]';
const {sign, localToken} = require('../../charts/identity-demo/files/server.js');

test('signed access claims verify for the intended audience', () => {
  const token = sign({sub:'user',azp:'spiffe://example/sandbox',aud:'protected'});
  const claims = localToken(token,'protected');
  assert.equal(claims.sub,'user');
  assert.equal(claims.azp,'spiffe://example/sandbox');
});
test('rejects wrong audience, issuer, expiry and tampered signatures', () => {
  assert.throws(() => localToken(sign({aud:'other'}),'protected'));
  assert.throws(() => localToken(sign({iss:'https://wrong.example',aud:'protected'}),'protected'));
  assert.throws(() => localToken(sign({aud:'protected',exp:1}),'protected'));
  const token=sign({aud:'protected'}).split('.');
  token[1]=Buffer.from(JSON.stringify({aud:'protected',exp:9999999999,sub:'forged'})).toString('base64url');
  assert.throws(() => localToken(token.join('.'),'protected'));
});
test('rejects unsigned assertions and future not-before', () => {
  const unsigned=Buffer.from('{"alg":"none"}').toString('base64url')+'.'+Buffer.from('{"aud":"protected","exp":9999999999}').toString('base64url')+'.';
  assert.throws(() => localToken(unsigned,'protected'));
  assert.throws(() => localToken(sign({aud:'protected',nbf:9999999999}),'protected'));
});
