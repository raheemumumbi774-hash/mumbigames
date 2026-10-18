// ============================================================
// mumbigames — Seva ndogo ya kubadilisha password (Cloudflare Worker, bure)
// Mtu anaandika: email + namba ya simu + username (alizosajili nazo) + password mpya.
// Seva inalinganisha na taarifa zilizo kwenye Firestore, kisha inabadilisha password.
//
// MIPANGILIO (Cloudflare → Workers → Settings → Variables and Secrets):
//   SERVICE_ACCOUNT_JSON  (Secret)  = yaliyomo yote ya faili la service account kutoka Firebase
// ============================================================

const ALLOWED_ORIGINS = ['https://raheemumumbi774-hash.github.io'];   // tovuti yako
const PROTECTED_EMAILS = ['raheemumumbi774@gmail.com'];                // akaunti ya admin: lazima itumie link ya email
const MAX_FAILS = 5;                 // majaribio mabaya yanayoruhusiwa
const WINDOW_MS = 60 * 60 * 1000;    // ndani ya saa 1

function cors(origin){
  const ok = ALLOWED_ORIGINS.indexOf(origin) !== -1;
  return {
    'Access-Control-Allow-Origin': ok ? origin : ALLOWED_ORIGINS[0],
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Vary': 'Origin'
  };
}
function json(obj, status, origin){
  return new Response(JSON.stringify(obj), {status: status || 200, headers: Object.assign({'Content-Type':'application/json'}, cors(origin))});
}
function b64url(buf){
  const b = buf instanceof ArrayBuffer ? new Uint8Array(buf) : buf;
  let s = ''; for(let i=0;i<b.length;i++) s += String.fromCharCode(b[i]);
  return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
function pemToBuf(pem){
  const b64 = pem.replace(/-----[^-]+-----/g,'').replace(/\s+/g,'');
  const bin = atob(b64); const out = new Uint8Array(bin.length);
  for(let i=0;i<bin.length;i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}
async function getAccessToken(sa){
  const now = Math.floor(Date.now()/1000);
  const enc = new TextEncoder();
  const head = b64url(enc.encode(JSON.stringify({alg:'RS256', typ:'JWT'})));
  const claim = b64url(enc.encode(JSON.stringify({
    iss: sa.client_email, sub: sa.client_email,
    scope: 'https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/datastore',
    aud: 'https://oauth2.googleapis.com/token', iat: now, exp: now + 3600
  })));
  const key = await crypto.subtle.importKey('pkcs8', pemToBuf(sa.private_key), {name:'RSASSA-PKCS1-v1_5', hash:'SHA-256'}, false, ['sign']);
  const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, enc.encode(head + '.' + claim));
  const jwt = head + '.' + claim + '.' + b64url(sig);
  const r = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST', headers: {'Content-Type':'application/x-www-form-urlencoded'},
    body: 'grant_type=' + encodeURIComponent('urn:ietf:params:oauth:grant-type:jwt-bearer') + '&assertion=' + encodeURIComponent(jwt)
  });
  const d = await r.json();
  if(!d.access_token) throw new Error('token');
  return d.access_token;
}
const normPhone = v => { v = String(v||'').replace(/[^0-9]/g,''); if(v.indexOf('255') === 0) v = '0' + v.slice(3); return v; };
const normText = v => String(v||'').trim().toLowerCase().replace(/\s+/g,' ');

async function handle(req, env){
  const origin = req.headers.get('Origin') || '';
  if(req.method === 'OPTIONS') return new Response(null, {status:204, headers: cors(origin)});
  if(req.method !== 'POST') return json({ok:false, error:'bad_request'}, 405, origin);
  if(ALLOWED_ORIGINS.indexOf(origin) === -1) return json({ok:false, error:'forbidden'}, 403, origin);

  let body; try{ body = await req.json(); }catch(e){ return json({ok:false, error:'bad_request'}, 400, origin); }
  const email = normText(body.email), phone = normPhone(body.phone), username = normText(body.username);
  const pw = String(body.newPassword || '');
  if(!email || !phone || !username || pw.length < 6 || pw.length > 128) return json({ok:false, error:'bad_request'}, 400, origin);
  if(PROTECTED_EMAILS.indexOf(email) !== -1) return json({ok:false, error:'protected'}, 403, origin);

  let sa; try{ sa = JSON.parse(env.SERVICE_ACCOUNT_JSON); }catch(e){ return json({ok:false, error:'server'}, 500, origin); }
  const pid = sa.project_id;
  let token; try{ token = await getAccessToken(sa); }catch(e){ return json({ok:false, error:'server'}, 500, origin); }
  const auth = {Authorization: 'Bearer ' + token, 'Content-Type':'application/json'};
  const fsBase = 'https://firestore.googleapis.com/v1/projects/' + pid + '/databases/(default)/documents/';

  // 1) tafuta akaunti kwa email
  const lk = await fetch('https://identitytoolkit.googleapis.com/v1/projects/' + pid + '/accounts:lookup', {method:'POST', headers:auth, body: JSON.stringify({email:[email]})});
  const lkd = await lk.json();
  const uid = lkd && lkd.users && lkd.users[0] && lkd.users[0].localId;
  if(!uid) return json({ok:false, error:'invalid'}, 200, origin);   // hatufichui kama akaunti ipo

  // 2) kikomo cha majaribio mabaya
  const attUrl = fsBase + 'resetAttempts/' + uid;
  let count = 0, first = 0;
  const ar = await fetch(attUrl, {headers:auth});
  if(ar.ok){ const ad = await ar.json(); count = parseInt((ad.fields && ad.fields.count && ad.fields.count.integerValue) || '0', 10); first = parseInt((ad.fields && ad.fields.first && ad.fields.first.integerValue) || '0', 10); }
  const now = Date.now();
  if(first && now - first > WINDOW_MS){ count = 0; first = 0; }
  if(count >= MAX_FAILS) return json({ok:false, error:'locked'}, 429, origin);
  const saveAttempts = (c, f) => fetch(attUrl + '?updateMask.fieldPaths=count&updateMask.fieldPaths=first', {method:'PATCH', headers:auth, body: JSON.stringify({fields:{count:{integerValue:String(c)}, first:{integerValue:String(f)}}})});

  // 3) linganisha na taarifa zilizosajiliwa
  const ur = await fetch(fsBase + 'users/' + uid, {headers:auth});
  const ud = ur.ok ? await ur.json() : null;
  const f = (ud && ud.fields) || {};
  const regPhone = normPhone(f.phone && f.phone.stringValue);
  const regUser = normText(f.username && f.username.stringValue);
  if(!regPhone || !regUser || regPhone !== phone || regUser !== username){
    await saveAttempts(count + 1, first || now);
    return json({ok:false, error:'invalid'}, 200, origin);
  }

  // 4) badilisha password
  const up = await fetch('https://identitytoolkit.googleapis.com/v1/projects/' + pid + '/accounts:update', {method:'POST', headers:auth, body: JSON.stringify({localId: uid, password: pw})});
  if(!up.ok) return json({ok:false, error:'server'}, 500, origin);
  await saveAttempts(0, 0);
  return json({ok:true}, 200, origin);
}

export default { fetch: (req, env) => handle(req, env).catch(() => json({ok:false, error:'server'}, 500, req.headers.get('Origin') || '')) };
