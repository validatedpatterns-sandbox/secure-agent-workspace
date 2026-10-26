// Test fixture only. Ephemeral signing keys; no production user authentication.
const http = require('node:http');
const crypto = require('node:crypto');
const {publicKey, privateKey} = crypto.generateKeyPairSync('rsa', {modulusLength: 2048});
const issuer = process.env.ISSUER;
const spiffeIssuer = process.env.SPIFFE_ISSUER;
const allowed = JSON.parse(process.env.ALLOWED_PREFIXES);
const audience = 'saw-protected-service';
const now = () => Math.floor(Date.now()/1000);
const enc = value => Buffer.from(JSON.stringify(value)).toString('base64url');
function sign(claims) {
  const payload = enc({alg:'RS256',typ:'JWT'})+'.'+enc({iss:issuer,iat:now(),exp:now()+300,...claims});
  return payload+'.'+crypto.sign('RSA-SHA256',Buffer.from(payload),privateKey).toString('base64url');
}
function decode(token) {
  if (typeof token !== 'string' || token.length > 32768) throw Error('invalid token');
  const parts=token.split('.'); if(parts.length!==3) throw Error('invalid token');
  return {parts,header:JSON.parse(Buffer.from(parts[0],'base64url')),claims:JSON.parse(Buffer.from(parts[1],'base64url'))};
}
function verifySignature(parsed,key) {
  if(parsed.header.alg!=='RS256') throw Error('unsupported algorithm');
  if(!crypto.verify('RSA-SHA256',Buffer.from(parsed.parts[0]+'.'+parsed.parts[1]),key,Buffer.from(parsed.parts[2],'base64url'))) throw Error('invalid signature');
  if(!Number.isInteger(parsed.claims.exp)||parsed.claims.exp<=now()) throw Error('expired token');
  if(parsed.claims.nbf && parsed.claims.nbf>now()) throw Error('token not yet valid');
}
function hasAudience(claims,expected) {return (Array.isArray(claims.aud)?claims.aud:[claims.aud]).includes(expected);}
function localToken(token,expected) {
  const parsed=decode(token);verifySignature(parsed,publicKey);
  if(parsed.claims.iss!==issuer||!hasAudience(parsed.claims,expected)) throw Error('invalid issuer or audience');
  return parsed.claims;
}
async function svid(token) {
  const parsed=decode(token);
  const response=await fetch(spiffeIssuer+'/keys',{signal:AbortSignal.timeout(5000)});
  if(!response.ok) throw Error('JWKS unavailable');
  const keys=await response.json();const jwk=keys.keys.find(key=>key.kid===parsed.header.kid);
  if(!jwk) throw Error('unknown key');
  verifySignature(parsed,crypto.createPublicKey({key:jwk,format:'jwk'}));
  const claims=parsed.claims;
  if(claims.iss!==spiffeIssuer||!hasAudience(claims,issuer)||!allowed.some(prefix=>claims.sub?.startsWith(prefix+'/'))) throw Error('untrusted workload');
  return claims;
}
async function body(req) {
  let text='';for await(const chunk of req){text+=chunk;if(text.length>65536) throw Error('request too large');}return text;
}
function send(res,status,data){res.writeHead(status,{'content-type':'application/json','cache-control':'no-store'});res.end(JSON.stringify(data));}
const server = http.createServer(async(req,res)=>{
  try {
    if(req.url==='/healthz') return send(res,200,{ready:true});
    if(req.url==='/demo/user-token'&&req.method==='POST') {
      if(req.headers.authorization!=='Bearer '+process.env.ENROLLMENT_TOKEN) return send(res,403,{error:'denied'});
      return send(res,200,{access_token:sign({sub:'demo-alice',aud:'demo-user',kind:'user'}),expires_in:300,token_type:'Bearer'});
    }
    if(req.url==='/protected') {
      const token=(req.headers.authorization||'').replace(/^Bearer /,'');
      const claims=localToken(token,audience);
      if(!claims.azp || claims.kind!=='access') throw Error('missing workload identity');
      return send(res,200,{sub:claims.sub,azp:claims.azp,client_id:claims.client_id,aud:claims.aud,exp:claims.exp});
    }
    if(req.url!=='/token'||req.method!=='POST') return send(res,404,{error:'not_found'});
    const form=new URLSearchParams(await body(req));
    const workload=await svid(form.get('client_assertion'));
    let claims;
    if(form.get('grant_type')==='client_credentials') {
      if(!workload.sub.includes('/ws/')||form.get('audience')!==audience) throw Error('invalid workload or audience');
      claims={sub:workload.sub,azp:workload.sub,client_id:workload.sub,aud:audience,kind:'access'};
    } else if(form.get('grant_type')==='urn:ietf:params:oauth:grant-type:token-exchange') {
      if(workload.sub.endsWith('/gateway')) {
        const user=localToken(form.get('subject_token'),'demo-user');
        const target=form.get('audience');
        if(user.kind!=='user'||!target?.startsWith(workload.sub.slice(0,-8)+'/ws/')) throw Error('invalid delegation');
        claims={sub:user.sub,aud:target,kind:'intermediate',exp:Math.min(user.exp,workload.exp,now()+300)};
      } else {
        const intermediate=localToken(form.get('subject_token'),workload.sub);
        if(intermediate.kind!=='intermediate'||form.get('audience')!==audience) throw Error('invalid exchange');
        claims={sub:intermediate.sub,azp:workload.sub,client_id:workload.sub,aud:audience,kind:'access',exp:Math.min(intermediate.exp,workload.exp,now()+300)};
      }
    } else throw Error('unsupported grant');
    const token=sign(claims);
    return send(res,200,{access_token:token,token_type:'Bearer',expires_in:Math.max(1,(claims.exp||now()+300)-now()),issued_token_type:'urn:ietf:params:oauth:token-type:access_token'});
  } catch(error) {
    // Never reflect/log a token or an arbitrary input in diagnostics.
    return send(res,401,{error:'invalid_grant'});
  }
});
if (require.main === module) server.listen(8080,'0.0.0.0');
module.exports = {sign, localToken, decode, verifySignature, publicKey};
