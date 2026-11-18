import fs from 'node:fs';
import https from 'node:https';
import {randomUUID} from 'node:crypto';
import {setTimeout as sleep} from 'node:timers/promises';

const dir='/exchange/log';
fs.mkdirSync(dir,{recursive:true,mode:0o700});
function request(id, body) {
  return new Promise((resolve,reject) => {
    const req=https.request(new URL('/v1/records/'+id,process.env.WRITER_URL),
      {method:'POST',ca:fs.readFileSync('/trust/service-ca.crt'),timeout:3000,headers:{'content-length':body.length}}, res=>{
        let value='';
        res.setEncoding('utf8');
        res.on('data', chunk => {value+=chunk; if(value.length>128) res.destroy(new Error('oversize receipt'));});
        res.on('error',reject);
        res.on('end',()=>res.statusCode===201 && /^[A-Za-z0-9+/]{86}==$/.test(value)
          ? resolve(value) : reject(new Error('writer refused record')));
      });
    req.on('timeout',()=>req.destroy(new Error('writer timeout')));
    req.on('error',reject); req.end(body);
  });
}
async function forward(file) {
  const id=file.slice(0,-4);
  const fd=fs.openSync(dir+'/'+file,fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK|fs.constants.O_RDONLY);
  const bytes=Buffer.alloc(16385);
  let size;
  try {
    if(!fs.fstatSync(fd).isFile()) return;
    size=fs.readSync(fd,bytes,0,bytes.length,0);
    if(size===bytes.length) return;
  } finally {fs.closeSync(fd);}
  const signature=await request(id,bytes.subarray(0,size));
  const tmp=dir+'/'+randomUUID()+'.tmp';
  fs.writeFileSync(tmp,signature,{flag:'wx',mode:0o600});
  fs.renameSync(tmp,dir+'/'+id+'.ack');
  fs.unlinkSync(dir+'/'+file);
}
for (;;) {
  const files=await fs.promises.opendir(dir);
  for await(const entry of files) {
    if(!entry.isFile() || !/^[0-9a-f-]{36}\.req$/.test(entry.name)) continue;
    try {await forward(entry.name);} catch { /* Retry published requests on the next scan. */ }
  }
  await sleep(100);
}
