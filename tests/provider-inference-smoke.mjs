// Run inside a sandbox with its injected placeholder and normal proxy path.
// Never run this with a real provider key in the sandbox environment.
import {randomUUID} from 'node:crypto';

const [kind, model] = process.argv.slice(1);
const providers = {
  openai: {url:'https://api.openai.com/v1/chat/completions', env:'OPENAI_API_KEY'},
  anthropic: {url:'https://api.anthropic.com/v1/messages', env:'ANTHROPIC_API_KEY'},
  nvidia: {url:'https://integrate.api.nvidia.com/v1/chat/completions', env:'NVIDIA_API_KEY'},
};
const provider = providers[kind];
if (!provider || !/^[A-Za-z0-9][A-Za-z0-9._/-]{0,180}$/.test(model ?? '')) {
  console.error('expected provider (openai|anthropic|nvidia) and approved model');
  process.exit(2);
}
if (!process.env[provider.env]) {
  console.error('sandbox provider placeholder is missing');
  process.exit(2);
}
const nonce = 'SAW_PROVIDER_' + randomUUID().replaceAll('-', '');
const headers = {'content-type':'application/json'};
if (kind === 'anthropic') {
  headers['x-api-key'] = process.env[provider.env];
  headers['anthropic-version'] = '2023-06-01';
} else {
  headers.authorization = 'Bearer ' + process.env[provider.env];
}
const body = {model, messages:[{role:'user',content:'Reply with exactly this token and nothing else: '+nonce}]};
body[kind === 'openai' ? 'max_completion_tokens' : 'max_tokens'] = 128;
try {
  const response = await fetch(provider.url, {
    method:'POST', headers, body:JSON.stringify(body), signal:AbortSignal.timeout(90000),
    redirect:'error',
  });
  // Provider error bodies and headers can contain private account details.
  if (!response.ok) throw new Error('provider HTTP '+response.status);
  const result = await response.json();
  const text = kind === 'anthropic' ? result.content?.filter(c=>c.type==='text').map(c=>c.text).join('')
                                  : result.choices?.[0]?.message?.content;
  const matched = typeof text === 'string' && text.trim() === nonce;
  console.log(JSON.stringify({provider:kind, model, httpStatus:response.status, nonceMatched:matched}));
  if (!matched) process.exitCode = 1;
} catch (error) {
  console.error(error.message?.startsWith('provider HTTP ') ? error.message : 'provider request failed');
  process.exitCode = 1;
}
