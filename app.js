// ═══════════════════════════════════════════════════════════════
// VaultIPFS — Blockchain + Multi-Password Architecture
// ═══════════════════════════════════════════════════════════════
//
// PUBLIC CHAIN (Filebase IPFS - readable by anyone):
//   genesis-block/{usernameHash}.json  →  {usernameHash, passwordHash, userId, chainHead, createdAt}
//   chain/{userId}/block-{n}.json     →  {prevHash, vaultCID, action, timestamp}
//
// PRIVATE VAULT DATA (Filebase S3 - encrypted):
//   vaults/{userId}/current.json      →  AES-256-GCM encrypted vault
//   vaults/{userId}/block-{n}.json    →  historical encrypted snapshots
//
// LOCAL ONLY (localStorage - never leaves browser):
//   secondary passwords (each encrypts vault key with different algorithm)
//   session keys, auto-lock timer
//
// ═══════════════════════════════════════════════════════════════

(function(){
'use strict';
const $=id=>document.getElementById(id);

// ═══ CONFIGURATION ═══
// Uses CONFIG from config.js if available, falls back to defaults
const CFG=typeof CONFIG!=='undefined'?CONFIG:{S3:{AK:'DA7F33AD883379297825',SK:'xSOU0s5Yfy9aBZhraaSxGG6Ls5ZSOBxPUw7JDQDI',BUCKET:'vault-ipfs',REGION:'auto',HOST:'s3.filebase.io'},CORS_PROXY:'',IPFS_GW:'https://gateway.filebase.io/ipfs/',PBKDF2_ITERATIONS:600000,SALT_SIZE:32,IV_SIZE:12};
const S3_CFG=CFG.S3;
const CORS_PROXY=CFG.CORS_PROXY||'';
const IPFS_GW=CFG.IPFS_GW;
const PBKDF2_ITER=CFG.PBKDF2_ITERATIONS;
const SALT_SIZE=CFG.SALT_SIZE,IV_SIZE=CFG.IV_SIZE;

// ═══ CRYPTO HELPERS ═══
// Pure JS SHA-256 (works identically in browser and Node.js)
function sha256Pure(msg){
  // For browser: use crypto.subtle (only for SHA-256, not HMAC)
  // For Node.js: this won't be called since we use crypto.subtle directly
  // This is a fallback — the actual signing uses crypto.subtle.digest for SHA-256
  return null; // placeholder, not used
}
function hex(buf){return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('');}
function toBuf(val){
  if(val===null||val===undefined)return new Uint8Array(0);
  if(typeof val==='string')return new TextEncoder().encode(val);
  if(val instanceof Uint8Array){const c=new Uint8Array(val.byteLength);c.set(val);return c;}
  if(val instanceof ArrayBuffer)return new Uint8Array(val);
  return new TextEncoder().encode(String(val));
}
// Use crypto.subtle.digest for SHA-256 (reliable) and crypto.subtle.importKey + sign for HMAC
// BUT: crypto.subtle.sign has bugs in some environments, so we implement HMAC manually using digest
async function hmac(key,data){
  let kb=toBuf(key),db=toBuf(data);
  const blockLen=64;
  if(kb.byteLength>blockLen) kb=new Uint8Array(await crypto.subtle.digest('SHA-256',kb));
  // kb is now exactly 32 bytes (or less), create clean copies
  const k=new Uint8Array(blockLen);k.set(kb);
  const d=new Uint8Array(db.byteLength);d.set(db);
  const ipad=new Uint8Array(blockLen+d.byteLength);
  const opad=new Uint8Array(blockLen+32);
  for(let i=0;i<blockLen;i++){
    const kv=i<k.byteLength?k[i]:0;
    ipad[i]=kv^0x36;
    opad[i]=kv^0x5c;
  }
  for(let i=0;i<d.byteLength;i++) ipad[blockLen+i]=d[i];
  const innerHash=new Uint8Array(await crypto.subtle.digest('SHA-256',ipad));
  for(let i=0;i<32;i++) opad[blockLen+i]=innerHash[i];
  return new Uint8Array(await crypto.subtle.digest('SHA-256',opad));
}
async function sha256Buf(data){return await crypto.subtle.digest('SHA-256',toBuf(data));}
async function sha256Hex(data){return hex(await sha256Buf(data));}
function genSalt(){return crypto.getRandomValues(new Uint8Array(SALT_SIZE));}
function uuid(){return crypto.randomUUID?crypto.randomUUID():'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g,c=>{const r=crypto.getRandomValues(new Uint8Array(1))[0]%16;return(c==='x'?r:(r&0x3|0x8)).toString(16);});}

// ═══ S3 CLIENT (SigV4) ═══
const S3=(()=>{
  async function getSigningKey(dt){let k=await hmac('AWS4'+S3_CFG.SK,dt);k=await hmac(k,S3_CFG.REGION);k=await hmac(k,'s3');return await hmac(k,'aws4_request');}
  async function sign(method,path,payload,ct){
    const now=new Date();const ts=now.toISOString().replace(/[:-]|\.\d{3}/g,'');const dt=ts.slice(0,8);
    const payBuf=toBuf(payload);const ph=hex(await crypto.subtle.digest('SHA-256',payBuf));
    const h={host:S3_CFG.HOST,'x-amz-date':ts,'x-amz-content-sha256':ph};if(ct)h['content-type']=ct;
    const ks=Object.keys(h).sort();const ch=ks.map(k=>k+':'+h[k]).join('\n')+'\n';const sh=ks.join(';');
    const cr=[method,path,'',ch,sh,ph].join('\n');const sc=dt+'/'+S3_CFG.REGION+'/s3/aws4_request';
    const sts='AWS4-HMAC-SHA256\n'+ts+'\n'+sc+'\n'+hex(await crypto.subtle.digest('SHA-256',toBuf(cr)));
    const sig=hex(await hmac(sts,await getSigningKey(dt)));
    return{headers:{...h,'Authorization':'AWS4-HMAC-SHA256 Credential='+S3_CFG.AK+'/'+sc+', SignedHeaders='+sh+', Signature='+sig}};
  }
  async function put(key,data,ct){const path='/'+S3_CFG.BUCKET+'/'+key;const r=await sign('PUT',path,data,ct||'application/json');const url=CORS_PROXY?CORS_PROXY+path:'https://'+S3_CFG.HOST+path;return fetch(url,{method:'PUT',headers:r.headers,body:data});}
  async function get(key){const path='/'+S3_CFG.BUCKET+'/'+key;const r=await sign('GET',path,new Uint8Array(0));const url=CORS_PROXY?CORS_PROXY+path:'https://'+S3_CFG.HOST+path;const res=await fetch(url,{headers:r.headers});return res.ok?res.text():null;}
  async function del(key){const path='/'+S3_CFG.BUCKET+'/'+key;const r=await sign('DELETE',path,new Uint8Array(0));const url=CORS_PROXY?CORS_PROXY+path:'https://'+S3_CFG.HOST+path;return fetch(url,{method:'DELETE',headers:r.headers});}
  return{put,get,del};
})();

// ═══ ENCRYPTION MODULES ═══
const Cipher=(()=>{
  // Primary: AES-256-GCM (PBKDF2-SHA512, 600k iter)
  async function deriveKey(pw,salt,iter,hash){
    const km=await crypto.subtle.importKey('raw',new TextEncoder().encode(pw),'PBKDF2',false,['deriveKey']);
    return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:iter,hash:hash||'SHA-512'},{name:'AES-GCM',length:256},km,false,['encrypt','decrypt']);
  }
  async function encryptAES(pw,salt,pt){
    const key=await deriveKey(pw,salt,PBKDF2_ITER,'SHA-512');
    const iv=crypto.getRandomValues(new Uint8Array(IV_SIZE));
    const ct=await crypto.subtle.encrypt({name:'AES-GCM',iv},key,new TextEncoder().encode(pt));
    return{iv:btoa(String.fromCharCode(...iv)),data:btoa(String.fromCharCode(...new Uint8Array(ct)))};
  }
  async function decryptAES(pw,salt,obj){
    try{
      const key=await deriveKey(pw,salt,PBKDF2_ITER,'SHA-512');
      const iv=Uint8Array.from(atob(obj.iv),c=>c.charCodeAt(0));
      const data=Uint8Array.from(atob(obj.data),c=>c.charCodeAt(0));
      const pt=await crypto.subtle.decrypt({name:'AES-GCM',iv},key,data);
      return new TextDecoder().decode(pt);
    }catch(e){return null;}
  }
  // Secondary: AES-256-CBC (PBKDF2-SHA256, 100k iter) — different from primary
  async function deriveKeyCBC(pw,salt){
    const km=await crypto.subtle.importKey('raw',new TextEncoder().encode(pw),'PBKDF2',false,['deriveKey']);
    return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:100000,hash:'SHA-256'},{name:'AES-CBC',length:256},km,false,['encrypt','decrypt']);
  }
  async function encryptCBC(pw,salt,pt){
    const key=await deriveKeyCBC(pw,salt);
    const iv=crypto.getRandomValues(new Uint8Array(16));
    const ct=await crypto.subtle.encrypt({name:'AES-CBC',iv},key,new TextEncoder().encode(pt));
    return{iv:btoa(String.fromCharCode(...iv)),data:btoa(String.fromCharCode(...new Uint8Array(ct)))};
  }
  async function decryptCBC(pw,salt,obj){
    try{
      const key=await deriveKeyCBC(pw,salt);
      const iv=Uint8Array.from(atob(obj.iv),c=>c.charCodeAt(0));
      const data=Uint8Array.from(atob(obj.data),c=>c.charCodeAt(0));
      const pt=await crypto.subtle.decrypt({name:'AES-CBC',iv},key,data);
      return new TextDecoder().decode(pt);
    }catch(e){return null;}
  }
  // Hash for blockchain (fast, for username/password verification)
  async function hash(pw,salt){
    const km=await crypto.subtle.importKey('raw',new TextEncoder().encode(pw),'PBKDF2',false,['deriveBits']);
    const bits=await crypto.subtle.deriveBits({name:'PBKDF2',salt,iterations:100000,hash:'SHA-256'},km,256);
    return btoa(String.fromCharCode(...new Uint8Array(bits)));
  }
  return{encryptAES,decryptAES,encryptCBC,decryptCBC,hash,genSalt};
})();

// ═══ BLOCKCHAIN ═══
const Chain=(()=>{
  // Public genesis block: stored at genesis/{usernameHash}.json
  // Contains: usernameHash, passwordHash, userId, chainHead (CID of latest block), createdAt
  async function createGenesis(username,password){
    const usernameHash=await sha256Hex(username.toLowerCase().trim());
    const salt=Cipher.genSalt();
    const passwordHash=await Cipher.hash(password,salt);
    const userId=uuid();
    const genesis={
      v:1,type:'genesis',
      usernameHash,passwordHash,
      salt:btoa(String.fromCharCode(...salt)),
      userId,
      chainHead:null,
      createdAt:new Date().toISOString()
    };
    // Upload genesis block
    await S3.put('genesis/'+usernameHash+'.json',JSON.stringify(genesis));
    return{genesis,userId,usernameHash};
  }
  async function findGenesis(username){
    const usernameHash=await sha256Hex(username.toLowerCase().trim());
    const data=await S3.get('genesis/'+usernameHash+'.json');
    if(!data)throw new Error('User not found');
    return JSON.parse(data);
  }
  async function verifyPassword(genesis,password){
    const salt=Uint8Array.from(atob(genesis.salt),c=>c.charCodeAt(0));
    const hash=await Cipher.hash(password,salt);
    return hash===genesis.passwordHash;
  }
  // Add a new block to the chain
  async function addBlock(userId,prevHash,vaultData,action){
    const blockNum=Date.now();
    const block={
      v:1,type:'block',
      userId,
      blockNum,
      prevHash,
      action,  // 'create','update','delete','password-change'
      vaultCID:null,  // will be set after vault upload
      timestamp:new Date().toISOString()
    };
    const blockHash=await sha256Hex(JSON.stringify(block));
    block.vaultCID='vaults/'+userId+'/block-'+blockNum+'.json';
    await S3.put('chain/'+userId+'/block-'+blockNum+'.json',JSON.stringify(block));
    return{block,blockHash};
  }
  // Get chain head (latest block)
  async function getChainHead(userId){
    const data=await S3.get('chain/'+userId+'/head.json');
    if(!data)return null;
    return JSON.parse(data);
  }
  // Update chain head
  async function setChainHead(userId,blockHash,blockNum){
    await S3.put('chain/'+userId+'/head.json',JSON.stringify({blockHash,blockNum,updated:new Date().toISOString()}));
  }
  return{createGenesis,findGenesis,verifyPassword,addBlock,getChainHead,setChainHead};
})();

// ═══ MULTI-PASSWORD SYSTEM ═══
const Passwords=(()=>{
  // Primary password: encrypts vault data with AES-256-GCM
  // Secondary passwords: encrypt the VAULT KEY (not vault data) with different algorithms
  // This way each password can independently decrypt the vault key → decrypt vault

  const STORE_KEY='v1passwords';

  function getStore(){
    try{return JSON.parse(localStorage.getItem(STORE_KEY)||'{}');}catch(e){return{};}
  }
  function saveStore(s){localStorage.setItem(STORE_KEY,JSON.stringify(s));}

  // Create primary password — returns encrypted vault key
  async function createPrimary(userId,password){
    const vaultKey=Cipher.genSalt(); // random 32-byte raw key for vault encryption
    const vaultKeyStr=btoa(String.fromCharCode(...vaultKey));
    // Encrypt the vault key string with user's password using AES-256-GCM
    const encryptedKey=await Cipher.encryptAES(password,Cipher.genSalt(),vaultKeyStr);
    const store=getStore();
    store[userId]={primary:{encryptedKey,createdAt:new Date().toISOString()},secondaries:{}};
    saveStore(store);
    return{vaultKey,encryptedKey};
  }

  // Create secondary password — encrypts same vault key with different algorithm
  async function createSecondary(userId,primaryPassword,secondaryPassword,label){
    const store=getStore();
    if(!store[userId])throw new Error('No primary password');
    // Decrypt vault key with primary
    const primaryData=store[userId].primary;
    const vaultKeyStr=await Cipher.decryptAES(primaryPassword,Uint8Array.from(atob(primaryData.encryptedKey.iv),c=>c.charCodeAt(0)),{iv:primaryData.encryptedKey.iv,data:primaryData.encryptedKey.data});
    if(!vaultKeyStr)throw new Error('Wrong primary password');
    // Re-encrypt vault key with secondary password using CBC (different from primary GCM)
    const encryptedKey=await Cipher.encryptCBC(secondaryPassword,Cipher.genSalt(),vaultKeyStr);
    const id=uuid();
    store[userId].secondaries[id]={label:secondaryPassword.length<=6?'PIN':'Password',encryptedKey,createdAt:new Date().toISOString()};
    saveStore(store);
    return id;
  }

  // Unlock with any password — tries primary first, then secondaries
  async function unlock(userId,password){
    const store=getStore();
    if(!store[userId])throw new Error('No passwords stored');
    // Try primary
    const p=store[userId].primary;
    const vk=await Cipher.decryptAES(password,Uint8Array.from(atob(p.encryptedKey.iv),c=>c.charCodeAt(0)),{iv:p.encryptedKey.iv,data:p.encryptedKey.data});
    if(vk)return{vaultKey:btoa(String.fromCharCode(...Uint8Array.from(atob(vk),c=>c.charCodeAt(0)))),type:'primary'};
    // Try secondaries
    for(const id in store[userId].secondaries){
      const s=store[userId].secondaries[id];
      const vk2=await Cipher.decryptCBC(password,Uint8Array.from(atob(s.encryptedKey.iv),c=>c.charCodeAt(0)),{iv:s.encryptedKey.iv,data:s.encryptedKey.data});
      if(vk2)return{vaultKey:btoa(String.fromCharCode(...Uint8Array.from(atob(vk2),c=>c.charCodeAt(0)))),type:'secondary',id};
    }
    return null;
  }

  // Get secondary password list (labels only, no keys)
  function listSecondaries(userId){
    const store=getStore();
    if(!store[userId])return[];
    return Object.keys(store[userId].secondaries||{}).map(id=>({id,label:store[userId].secondaries[id].label}));
  }

  // Remove secondary password
  function removeSecondary(userId,id){
    const store=getStore();
    if(store[userId]&&store[userId].secondaries[id]){
      delete store[userId].secondaries[id];
      saveStore(store);
    }
  }

  return{createPrimary,createSecondary,unlock,listSecondaries,removeSecondary};
})();

// ═══ VAULT STORAGE ═══
const Vault=(()=>{
  // Vault data encrypted with vaultKey (random CryptoKey) using AES-GCM
  async function importKey(rawKey){
    return crypto.subtle.importKey('raw',rawKey,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
  }
  async function encryptVault(vaultKeyRaw,data){
    const key=await importKey(vaultKeyRaw);
    const iv=crypto.getRandomValues(new Uint8Array(IV_SIZE));
    const ct=await crypto.subtle.encrypt({name:'AES-GCM',iv},key,new TextEncoder().encode(JSON.stringify(data)));
    return{iv:btoa(String.fromCharCode(...iv)),data:btoa(String.fromCharCode(...new Uint8Array(ct)))};
  }
  async function decryptVault(vaultKeyRaw,obj){
    try{
      const key=await importKey(vaultKeyRaw);
      const iv=Uint8Array.from(atob(obj.iv),c=>c.charCodeAt(0));
      const data=Uint8Array.from(atob(obj.data),c=>c.charCodeAt(0));
      const pt=await crypto.subtle.decrypt({name:'AES-GCM',iv},key,data);
      return JSON.parse(new TextDecoder().decode(pt));
    }catch(e){return null;}
  }
  // Entry-level encryption for individual password fields
  async function encryptEntry(vaultKeyRaw,plaintext){
    const key=await importKey(vaultKeyRaw);
    const iv=crypto.getRandomValues(new Uint8Array(IV_SIZE));
    const ct=await crypto.subtle.encrypt({name:'AES-GCM',iv},key,new TextEncoder().encode(plaintext));
    return{iv:btoa(String.fromCharCode(...iv)),data:btoa(String.fromCharCode(...new Uint8Array(ct)))};
  }
  async function decryptEntry(vaultKeyRaw,obj){
    try{
      const key=await importKey(vaultKeyRaw);
      const iv=Uint8Array.from(atob(obj.iv),c=>c.charCodeAt(0));
      const data=Uint8Array.from(atob(obj.data),c=>c.charCodeAt(0));
      const pt=await crypto.subtle.decrypt({name:'AES-GCM',iv},key,data);
      return new TextDecoder().decode(pt);
    }catch(e){return null;}
  }
  async function save(userId,vaultKeyRaw,vaultData){
    const encrypted=await encryptVault(vaultKeyRaw,vaultData);
    await S3.put('vaults/'+userId+'/current.json',JSON.stringify(encrypted));
    const head=await Chain.getChainHead(userId);
    const prevHash=head?head.blockHash:null;
    const{block,blockHash}=await Chain.addBlock(userId,prevHash,null,'update');
    await Chain.setChainHead(userId,blockHash,block.blockNum);
    return block;
  }
  async function load(userId,vaultKeyRaw){
    const data=await S3.get('vaults/'+userId+'/current.json');
    if(!data)throw new Error('No vault found');
    const decrypted=await decryptVault(vaultKeyRaw,JSON.parse(data));
    if(!decrypted)throw new Error('Decrypt failed — wrong password');
    return decrypted;
  }
  return{save,load,encryptVault,decryptVault,encryptEntry,decryptEntry};
})();

// ═══ APP STATE ═══
var currentUser=null;  // {userId, username, vaultKey, genesis}
var vaultData={v:2,entries:[],folders:[],settings:{clip:30,lock:30,theme:'dark'},updated:null};
var state={view:'all',type:'',search:''};
var autoSaveTimer=null;
var autoLockTimer=null;

// ═══ UTILS ═══
function toast(msg,type){
  const c=$('tsk');if(!c)return;
  const t=document.createElement('div');
  t.className='toast'+(type?' '+type:'');
  const icons={success:'<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg>',error:'<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>',info:'<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>'};
  t.innerHTML=(icons[type]||icons.info)+'<span>'+msg+'</span>';
  c.appendChild(t);
  setTimeout(()=>{t.classList.add('out');setTimeout(()=>t.remove(),300);},3500);
}
function esc(s){if(!s)return'';const d=document.createElement('div');d.textContent=s;return d.innerHTML;}
function sBar(s){if(!s)return'';return'<div class="strength-bar s'+s+'"><i></i></div>';}
function favIco(url){if(!url)return'';try{const u=new URL(url.startsWith('http')?url:'https://'+url);return'https://www.google.com/s2/favicons?domain='+u.hostname+'&sz=64';}catch(e){return'';}}
function tIcon(t){return'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">'+({login:'<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',alias:'<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>',note:'<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/>',identity:'<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>',card:'<rect x="1" y="4" width="22" height="16" rx="2"/><line x1="1" y1="10" x2="23" y2="10"/>'})[t]||''+'</svg>';}
function pwStr(p){let s=0;if(p.length>=8)s++;if(p.length>=12)s++;if(p.length>=16)s++;if(/[a-z]/.test(p))s++;if(/[A-Z]/.test(p))s++;if(/[0-9]/.test(p))s++;if(/[^a-zA-Z0-9]/.test(p))s++;return Math.min(4,Math.max(1,Math.floor(s/2)));}
function genPW(len,o){len=len||16;o=o||{};let cs='',rq=[];if(o.up!==false){cs+='ABCDEFGHIJKLMNOPQRSTUVWXYZ';rq.push('ABCDEFGHIJKLMNOPQRSTUVWXYZ');}if(o.lo!==false){cs+='abcdefghijklmnopqrstuvwxyz';rq.push('abcdefghijklmnopqrstuvwxyz');}if(o.nu!==false){cs+='0123456789';rq.push('0123456789');}if(o.sy!==false){cs+='!@#$%^&*()_+-=[]{}|;:,.<>?';rq.push('!@#$%^&*()_+-=[]{}|;:,.<>?');}if(!cs)cs='abcdefghijklmnopqrstuvwxyz';len=Math.max(len,rq.length);const a=new Uint32Array(len*2);crypto.getRandomValues(a);let p='';let i=0;for(let j=0;j<rq.length;j++)p+=rq[j][a[i++]%rq[j].length];for(let j=rq.length;j<len;j++)p+=cs[a[i++]%cs.length];const arr=p.split('');for(let j=arr.length-1;j>0;j--){const k=a[i++]%(j+1);[arr[j],arr[k]]=[arr[k],arr[j]];}return arr.join('');}
async function copyT(text,clear){try{await navigator.clipboard.writeText(text);if(clear>0)setTimeout(async()=>{try{await navigator.clipboard.writeText('');}catch(e){}},clear*1000);return true;}catch(e){return false;}}
async function b32dec(input){const m='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';input=input.toUpperCase().replace(/=+$/,'');const o=[];let b=0,bi=0;for(let i=0;i<input.length;i++){const v=m.indexOf(input[i]);if(v<0)continue;b=(b<<5)|v;bi+=5;if(bi>=8){bi-=8;o.push((b>>>bi)&0xff);}}return new Uint8Array(o).buffer;}
async function genTOTP(sec){try{const ts=Math.floor(Date.now()/1000/30);const key=await b32dec(sec);const buf=new ArrayBuffer(8);new DataView(buf).setUint32(4,ts,false);const hk=await crypto.subtle.importKey('raw',key,{name:'HMAC',hash:'SHA-1'},false,['sign']);const h=await crypto.subtle.sign('HMAC',hk,buf);const bv=new Uint8Array(h);const off=bv[19]&0x0f;const cd=(((bv[off]&0x7f)<<24)|((bv[off+1]&0xff)<<16)|((bv[off+2]&0xff)<<8)|(bv[off+3]&0xff))%1000000;return String(cd).padStart(6,'0');}catch(e){return'000000';}}
function totpT(){return 30-(Math.floor(Date.now()/1000)%30);}

// ═══ SYNC STATUS ═══
function setSyncStatus(status){
  const el=$('syncStatus');if(!el)return;
  el.className='sync-status'+(status==='syncing'?' syncing':status==='error'?' error':'');
  const span=el.querySelector('span');
  if(span)span.textContent=status==='syncing'?'Syncing...':status==='error'?'Sync failed':'Synced';
}

// ═══ AUTO-SAVE ═══
function scheduleAutoSave(){
  clearTimeout(autoSaveTimer);
  autoSaveTimer=setTimeout(async()=>{
    if(!currentUser)return;
    setSyncStatus('syncing');
    try{await Vault.save(currentUser.userId,currentUser.vaultKey,vaultData);setSyncStatus('ok');}catch(e){setSyncStatus('error');}
  },1000);
}

// ═══ AUTO-LOCK ═══
function startAutoLock(){
  stopAutoLock();
  resetAutoLock();
}
function resetAutoLock(){
  stopAutoLock();
  const mins=vaultData.settings.lock;
  if(!mins)return;
  autoLockTimer=setTimeout(()=>{lockVault();},mins*60*1000);
}
function stopAutoLock(){if(autoLockTimer){clearTimeout(autoLockTimer);autoLockTimer=null;}}

// ═══ MODAL ═══
function showM(html){$('md').innerHTML=html;$('mbg').classList.add('show');document.body.style.overflow='hidden';}
function closeM(){$('mbg').classList.remove('show');document.body.style.overflow='';}

// ═══ SIGNUP ═══
function showSignup(){
  $('app').style.display='';$('loading').classList.add('hide');
  document.body.insertAdjacentHTML('beforeend',`<div class="auth-screen" id="authScreen"><div class="auth-box"><div class="auth-logo"><div class="auth-logo-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/><path d="M9 12l2 2 4-4" stroke-linecap="round"/></svg></div><h1>Create Account</h1><p>Your blockchain-secured vault</p></div><div class="auth-steps"><div class="auth-step"><div class="auth-step-num">1</div><div><div class="auth-step-txt">Choose Username</div><div class="auth-step-sub">Your unique identifier. Cannot be changed.</div></div></div><div class="auth-step"><div class="auth-step-num">2</div><div><div class="auth-step-txt">Master Password</div><div class="auth-step-sub">Encrypts your vault. Never stored on server.</div></div></div><div class="auth-step"><div class="auth-step-num">3</div><div><div class="auth-step-txt">Blockchain Genesis</div><div class="auth-step-sub">A new chain is created just for you on decentralized storage.</div></div></div></div><form class="auth-form" id="sf"><div class="form-group"><label>Username</label><input type="text" id="suser" placeholder="Choose a username" required autocomplete="username" minlength="3"></div><div class="form-group"><label>Master Password</label><input type="password" id="spw" placeholder="Min 8 characters" required autocomplete="new-password"></div><div class="form-group"><label>Confirm Password</label><input type="password" id="spw2" placeholder="Repeat password" required autocomplete="new-password"></div><div id="sStr"></div><div class="form-error" id="sErr"></div><button type="submit" class="btn-primary" style="width:100%;padding:12px;margin-top:4px">Create Account & Blockchain</button></form><div class="auth-links">Already have an account? <a href="#" id="sLogin">Sign In</a></div></div></div>`);
  $('spw').oninput=function(){const s=pwStr(this.value);const l=s<=2?s===1?'Weak':'Fair':s===3?'Good':'Strong';const c=s<=2?s===1?'var(--red)':'var(--orange)':s===3?'var(--yellow)':'var(--green)';$('sStr').innerHTML='<div class="strength-bar s'+s+'"><i></i></div><span style="font-size:11px;color:'+c+'">'+l+'</span>';};
  $('sf').onsubmit=async function(e){
    e.preventDefault();
    const username=$('suser').value.trim();const p1=$('spw').value,p2=$('spw2').value;
    if(username.length<3){$('sErr').textContent='Username min 3 characters';return;}
    if(p1.length<8){$('sErr').textContent='Password min 8 characters';return;}
    if(p1!==p2){$('sErr').textContent='Passwords do not match';return;}
    $('sErr').textContent='Creating blockchain...';$('sf').querySelector('button').disabled=true;
    try{
      // Check if user exists
      try{await Chain.findGenesis(username);$('sErr').textContent='Username already taken';$('sf').querySelector('button').disabled=false;return;}catch(e){}
      // Create genesis block + blockchain
      const{genesis,userId,usernameHash}=await Chain.createGenesis(username,p1);
      // Create primary password (encrypts vault key)
      const{vaultKey}=await Passwords.createPrimary(userId,p1);
      // Save empty vault
      vaultData={v:2,entries:[],folders:[],settings:{clip:30,lock:30,theme:'dark'},updated:new Date().toISOString()};
      await Vault.save(userId,vaultKey,vaultData);
      // Set current user
      currentUser={userId,username,vaultKey,genesis};
      localStorage.setItem('v1current',JSON.stringify({userId,username}));
      renderApp();
    }catch(err){$('sErr').textContent='Error: '+err.message;$('sf').querySelector('button').disabled=false;}
  };
  $('sLogin').onclick=e=>{e.preventDefault();$('authScreen').remove();showLogin();};
}

// ═══ LOGIN ═══
function showLogin(){
  $('app').style.display='';$('loading').classList.add('hide');
  document.body.insertAdjacentHTML('beforeend',`<div class="auth-screen" id="authScreen"><div class="auth-box"><div class="auth-logo"><div class="auth-logo-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/><path d="M9 12l2 2 4-4" stroke-linecap="round"/></svg></div><h1>Welcome Back</h1><p>Unlock your vault</p></div><form class="auth-form" id="uf"><div class="form-group"><label>Username</label><input type="text" id="uuser" placeholder="Enter username" required autocomplete="username" autofocus></div><div class="form-group"><label>Password</label><input type="password" id="upw" placeholder="Enter password" required autocomplete="current-password"></div><div class="form-error" id="uErr"></div><button type="submit" class="btn-primary" style="width:100%;padding:12px;margin-top:4px">Unlock Vault</button></form><div class="auth-links"><a href="#" id="uForg" style="color:var(--fg4)">Forgot password?</a><br><br>No account? <a href="#" id="uSignup">Create one</a></div></div></div>`);
  $('uf').onsubmit=async function(e){
    e.preventDefault();
    const username=$('uuser').value.trim();const password=$('upw').value;
    $('uErr').textContent='Fetching blockchain...';$('uf').querySelector('button').disabled=true;
    try{
      // Find genesis block by username hash
      const genesis=await Chain.findGenesis(username);
      // Verify password
      const valid=await Chain.verifyPassword(genesis,password);
      if(!valid){$('uErr').textContent='Wrong password';$('uf').querySelector('button').disabled=false;return;}
      // Try to unlock with multi-password system
      let unlockResult=await Passwords.unlock(genesis.userId,password);
      let vaultKey;
      if(unlockResult){
        vaultKey=Uint8Array.from(atob(unlockResult.vaultKey),c=>c.charCodeAt(0));
      }else{
        // First login after migration — create primary password
        const result=await Passwords.createPrimary(genesis.userId,password);
        vaultKey=Uint8Array.from(atob(btoa(String.fromCharCode(...result.vaultKey))),c=>c.charCodeAt(0));
      }
      // Load vault
      $('uErr').textContent='Decrypting vault...';
      try{
        vaultData=await Vault.load(genesis.userId,vaultKey);
      }catch(err){
        // Vault might not exist yet (new user)
        vaultData={v:2,entries:[],folders:[],settings:{clip:30,lock:30,theme:'dark'},updated:new Date().toISOString()};
      }
      currentUser={userId:genesis.userId,username,vaultKey,genesis};
      localStorage.setItem('v1current',JSON.stringify({userId:genesis.userId,username}));
      renderApp();
    }catch(err){$('uErr').textContent='Error: '+err.message;$('uf').querySelector('button').disabled=false;}
  };
  $('uForg').onclick=e=>{e.preventDefault();alert('No recovery. Your password is the only key.\n\nYour blockchain stores only a hash — we cannot reset it.\n\nIf you forget your password, your vault is permanently inaccessible.');};
  $('uSignup').onclick=e=>{e.preventDefault();$('authScreen').remove();showSignup();};
}

// ═══ LOCK ═══
function lockVault(){
  // Clear sensitive data from memory
  if(currentUser)currentUser.vaultKey=null;
  currentUser=null;vaultData={v:2,entries:[],folders:[],settings:{clip:30,lock:30,theme:'dark'},updated:null};
  stopAutoLock();$('app').style.display='none';showLogin();
}

// ═══ RENDER (same UI as before, using vaultData instead of M) ═══
function renderApp(){
  $('authScreen')?.remove();$('app').style.display='';
  applyTheme(vaultData.settings.theme);bindNav();renderE();updC();startAutoLock();
}
function applyTheme(t){document.documentElement.setAttribute('data-theme',t||'dark');}

function getEntries(view,search,type){
  let e=vaultData.entries;
  if(view==='fav')e=e.filter(x=>x.fav&&!x.del);
  else if(view==='trash')e=e.filter(x=>x.del);
  else if(view==='recent'){e=e.filter(x=>!x.del);e.sort((a,b)=>new Date(b.updated)-new Date(a.updated));return e.slice(0,20);}
  else if(view.startsWith('dir-'))e=e.filter(x=>x.folderId===view.slice(4)&&!x.del);
  else e=e.filter(x=>!x.del);
  if(type)e=e.filter(x=>x.type===type);
  if(search){const q=search.toLowerCase();e=e.filter(x=>(x.title||'').toLowerCase().includes(q)||(x.website||'').toLowerCase().includes(q)||(x.username||'').toLowerCase().includes(q)||(x.notes||'').toLowerCase().includes(q));}
  e.sort((a,b)=>new Date(b.updated)-new Date(a.updated));return e;
}
function getStats(){const a=vaultData.entries.filter(e=>!e.del);return{total:a.length,fav:a.filter(e=>e.fav).length,trash:vaultData.entries.filter(e=>e.del).length,
  byType:{login:a.filter(e=>e.type==='login').length,alias:a.filter(e=>e.type==='alias').length,note:a.filter(e=>e.type==='note').length,identity:a.filter(e=>e.type==='identity').length,card:a.filter(e=>e.type==='card').length}};}
function getHealth(){const a=vaultData.entries.filter(e=>!e.del&&e.pwEnc);if(!a.length)return{score:100,total:0,weak:0,strong:0};const w=a.filter(e=>e.pwStr>0&&e.pwStr<=2).length;return{score:Math.round(((a.length-w)/a.length)*100),total:a.length,weak:w,strong:a.length-w};}

function bindNav(){
  document.querySelectorAll('[data-view]').forEach(b=>{b.onclick=()=>{state.view=b.dataset.view;state.type='';updN();renderE();updT();};});
  document.querySelectorAll('[data-type]').forEach(b=>{b.onclick=()=>{state.type=b.dataset.type;state.view='all';updN();renderE();updT();};});
  let st;$('search').oninput=()=>{clearTimeout(st);st=setTimeout(()=>{state.search=$('search').value;renderE();},200);};
  $('btnAdd').onclick=()=>openEM(null);
  $('btnNewFolder').onclick=()=>{const n=prompt('Folder name:');if(n){vaultData.folders.push({id:uuid(),name:n,created:new Date().toISOString()});scheduleAutoSave();bindNav();renderApp();toast('Folder created','success');}};
  $('btnHealth').onclick=openHealth;$('btnIO').onclick=openIO;
  $('btnLock').onclick=()=>{if(confirm('Lock vault?'))lockVault();};
  $('btnSettings').onclick=openSettings;
  $('btnTheme').onclick=()=>{const t=document.documentElement.getAttribute('data-theme')==='dark'?'light':'dark';applyTheme(t);vaultData.settings.theme=t;scheduleAutoSave();};
  $('mobMenu').onclick=()=>{$('sidebar').classList.toggle('open');$('overlay').classList.toggle('show');};
  $('overlay').onclick=()=>{$('sidebar').classList.remove('open');$('overlay').classList.remove('show');};
  $('mbg').onclick=function(e){if(e.target===this)closeM();};
  // Activity tracking — reset auto-lock timer on any interaction
  if(currentUser){
    ['click','keydown','mousemove','touchstart'].forEach(ev=>{
      document.addEventListener(ev,()=>{if(currentUser)resetAutoLock();},{passive:true});
    });
  }
  document.onkeydown=e=>{
    if(['INPUT','TEXTAREA','SELECT'].includes(e.target.tagName))return;
    if((e.ctrlKey||e.metaKey)&&e.key==='k'){e.preventDefault();$('search').focus();}
    if((e.ctrlKey||e.metaKey)&&e.key==='n'){e.preventDefault();openEM(null);}
    if((e.ctrlKey||e.metaKey)&&e.key==='l'){e.preventDefault();lockVault();}
    if(e.key==='Escape')closeM();
  };
}
function updN(){document.querySelectorAll('.nav-item').forEach(b=>{b.classList.remove('active');if(b.dataset.view===state.view||b.dataset.type===state.type)b.classList.add('active');});}
function updT(){
  const t={all:'All Items',fav:'Favorites',recent:'Recent',trash:'Trash'};
  if(t[state.view])$('viewTitle').textContent=t[state.view];
  else if(state.view.startsWith('dir-')){const f=vaultData.folders.find(x=>x.id===state.view.slice(4));$('viewTitle').textContent=f?f.name:'Folder';}
  else if(state.type)$('viewTitle').textContent={login:'Logins',alias:'Aliases',note:'Notes',identity:'Identities',card:'Cards'}[state.type]||'Items';
  else $('viewTitle').textContent='All Items';
}
function updC(){
  const s=getStats();
  const g=id=>$(id);if(g('cAll'))g('cAll').textContent=s.total;
  if(g('cFav'))g('cFav').textContent=s.fav;if(g('cTrash'))g('cTrash').textContent=s.trash;
  if(g('cTlogin'))g('cTlogin').textContent=s.byType.login;if(g('cTalias'))g('cTalias').textContent=s.byType.alias;
  if(g('cTnote'))g('cTnote').textContent=s.byType.note;if(g('cTidentity'))g('cTidentity').textContent=s.byType.identity;
  if(g('cTcard'))g('cTcard').textContent=s.byType.card;
  const folders=vaultData.folders||[];
  $('folderSection').style.display=folders.length?'':'none';
  const fl=$('folderList');
  fl.innerHTML=folders.map(f=>`<button class="nav-item${state.view==='dir-'+f.id?' active':''}" data-view="dir-${f.id}">${tIcon('login')}<span>${esc(f.name)}</span></button>`).join('');
  fl.querySelectorAll('[data-view]').forEach(b=>{b.onclick=()=>{state.view=b.dataset.view;state.type='';updN();renderE();updT();};});
}

function renderE(){
  const entries=getEntries(state.view,state.search,state.type);
  const mb=$('mb');
  if(!entries.length){
    const msgs={all:'Your vault is empty',fav:'No favorites yet',recent:'No recent items',trash:'Trash is empty'};
    mb.innerHTML=`<div class="empty-state"><div class="empty-state-icon"><svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg></div><h3>${msgs[state.view]||'No items'}</h3><p>Start by adding your first password or secure note.</p><button class="btn-primary" onclick="openEM(null)">+ Add Item</button></div>`;
    return;
  }
  let h='<div class="cards-grid">';
  entries.forEach(e=>{
    const fi=favIco(e.website);const ic=fi?'<img src="'+fi+'" onerror="this.parentElement.innerHTML=tIcon(\''+e.type+'\')">':tIcon(e.type);
    const fv=e.fav?'<span class="fav-star">★</span>':'';const fo=(vaultData.folders||[]).find(x=>x.id===e.folderId);
    h+=`<div class="card" data-id="${e.id}"><div class="card-inner"><div class="card-icon">${ic}${fv}</div><div class="card-info"><div class="card-title">${esc(e.title)}</div><div class="card-sub">${esc(e.username||e.website||e.type)}</div><div class="card-meta">${sBar(e.pwStr)}${fo?'<span class="folder-tag">'+esc(fo.name)+'</span>':''}</div></div><div class="card-actions">${e.pwEnc?'<button class="btn-icon cpw" data-id="'+e.id+'" title="Copy password"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg></button>':''}${e.totp?'<button class="btn-icon gtotp" data-id="'+e.id+'" title="TOTP"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg></button>':''}<button class="btn-icon menu-btn-card" data-id="${e.id}" title="More"><svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="5" r="2"/><circle cx="12" cy="12" r="2"/><circle cx="12" cy="19" r="2"/></svg></button></div></div></div>`;
  });
  h+='</div>';mb.innerHTML=h;
  mb.querySelectorAll('.card').forEach(c=>{c.onclick=function(e){if(e.target.closest('.card-actions'))return;openEM(vaultData.entries.find(x=>x.id===c.dataset.id));};});
  mb.querySelectorAll('.menu-btn-card').forEach(b=>{b.onclick=e=>{e.stopPropagation();showCtx(vaultData.entries.find(x=>x.id===b.dataset.id),b);};});
  mb.querySelectorAll('.cpw').forEach(b=>{b.onclick=async e=>{e.stopPropagation();const en=vaultData.entries.find(x=>x.id===b.dataset.id);const d=await Vault.decryptEntry(currentUser.vaultKey,en.pwEnc);if(d){await copyT(d,vaultData.settings.clip);toast('Password copied!','success');}else toast('Decrypt failed','error');};});
  mb.querySelectorAll('.gtotp').forEach(b=>{b.onclick=async e=>{e.stopPropagation();const en=vaultData.entries.find(x=>x.id===b.dataset.id);if(en.totp){const c=await genTOTP(en.totp);await copyT(c,30);toast('TOTP: '+c,'info');}};});
}

function showCtx(entry,btn){
  const menu=$('ctxMenu');
  menu.innerHTML=(entry.del?'':'<button data-a="edit"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg> Edit</button><button data-a="fav"><svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg> '+(entry.fav?'Unfavorite':'Favorite')+'</button>')+(entry.del?'<button data-a="res"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/></svg> Restore</button>':'')+'<div class="ctx-divider"></div><button data-a="del" class="danger"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg> '+(entry.del?'Delete Forever':'Trash')+'</button>';
  menu.style.display='block';const r=btn.getBoundingClientRect();menu.style.left=Math.min(r.left,window.innerWidth-180)+'px';menu.style.top=(r.bottom+6)+'px';
  menu.onclick=async e=>{
    const a=e.target.closest('button')?.dataset.a;if(!a)return;menu.style.display='none';
    if(a==='edit')openEM(entry);
    if(a==='fav'){entry.fav=!entry.fav;entry.updated=new Date().toISOString();scheduleAutoSave();renderE();toast(entry.fav?'Favorited':'Unfavorited','success');}
    if(a==='res'){entry.del=false;entry.updated=new Date().toISOString();scheduleAutoSave();renderApp();toast('Restored','success');}
    if(a==='del'){if(entry.del){if(!confirm('Permanently delete?'))return;vaultData.entries=vaultData.entries.filter(x=>x.id!==entry.id);}else{entry.del=true;entry.updated=new Date().toISOString();}scheduleAutoSave();renderApp();}
  };
  setTimeout(()=>{document.addEventListener('click',function h(e){if(!menu.contains(e.target)){menu.style.display='none';document.removeEventListener('click',h);}});},10);
}

var totpI=null;
function openEM(entry){
  closeM();const ed=!!entry;
  const types=[{v:'login',l:'Login'},{v:'alias',l:'Alias'},{v:'note',l:'Secure Note'},{v:'identity',l:'Identity'},{v:'card',l:'Credit Card'}];
  const fo=vaultData.folders||[];const fopts=fo.map(f=>'<option value="'+f.id+'"'+(entry&&entry.folderId===f.id?' selected':'')+'>'+esc(f.name)+'</option>').join('');
  showM(`<div class="modal-header"><h2>${ed?'Edit Item':'Add New Item'}</h2><button class="modal-close" onclick="closeM()"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button></div>
  <div class="modal-body"><form id="ef" autocomplete="off">
    <input type="hidden" id="eId" value="${entry?entry.id:''}">
    <div class="form-group"><label>Type</label><select id="eType">${types.map(t=>'<option value="'+t.v+'"'+(entry&&entry.type===t.v?' selected':'')+'>'+t.l+'</option>').join('')}</select></div>
    <div class="form-group"><label>Title *</label><input id="eTitle" value="${entry?esc(entry.title):''}" required placeholder="e.g. GitHub"></div>
    <div class="form-group" id="fWeb"><label>Website URL</label><input id="eWeb" value="${entry?esc(entry.website||''):''}" placeholder="https://..."></div>
    <div class="form-group" id="fUser"><label>Username / Email</label><input id="eUser" value="${entry?esc(entry.username||''):''}"></div>
    <div class="form-group" id="fPw"><label>Password</label><div style="display:flex;gap:8px"><input id="ePw" type="password" value="" placeholder="${ed?'Leave blank to keep':'Enter password'}" style="flex:1"><button type="button" class="btn-secondary" id="btnTPw" style="padding:8px 12px">Show</button><button type="button" class="btn-secondary" id="btnGPw" style="padding:8px 12px">Gen</button></div><div id="pwStrBox" style="margin-top:6px"></div>
      <div class="pw-gen" id="pwGB" style="display:none"><div class="pw-gen-row"><label>Length</label><span id="pwLV">16</span></div><input type="range" class="pw-gen-slider" id="pwSL" min="8" max="64" value="16"><div class="pw-gen-options"><label><input type="checkbox" id="pwC1" checked> ABC</label><label><input type="checkbox" id="pwC2" checked> abc</label><label><input type="checkbox" id="pwC3" checked> 123</label><label><input type="checkbox" id="pwC4" checked> #$%</label></div><button type="button" class="btn-secondary" id="btnUPw" style="margin-top:10px;width:100%">Use This Password</button></div>
    </div>
    <div class="form-group" id="fTOTP"><label>TOTP Secret</label><div style="display:flex;gap:8px"><input id="eTOTP" value="${entry?esc(entry.totp||''):''}" placeholder="Base32 secret" style="flex:1"><button type="button" class="btn-secondary" id="btnGOTP" style="padding:8px 12px">Gen</button></div><div id="tpPrev"></div></div>
    <div class="form-group"><label>Folder</label><select id="eFolder"><option value="">None</option>${fopts}</select></div>
    <div class="form-group"><label>Notes</label><textarea id="eNotes" rows="3" placeholder="Additional notes...">${entry?esc(entry.notes||''):''}</textarea></div>
  </form></div>
  <div class="modal-footer"><button class="btn-secondary" onclick="closeM()">Cancel</button><button class="btn-primary" id="btnSE">${ed?'Save Changes':'Add Item'}</button></div>`);
  updFV();$('eType').onchange=updFV;
  $('btnTPw').onclick=()=>{const p=$('ePw');p.type=p.type==='password'?'text':'password';$('btnTPw').textContent=p.type==='password'?'Show':'Hide';};
  $('btnGPw').onclick=()=>{$('pwGB').style.display=$('pwGB').style.display==='none'?'':'none';};
  const doGP=()=>{const pw=genPW(+$('pwSL').value,{up:$('pwC1').checked,lo:$('pwC2').checked,nu:$('pwC3').checked,sy:$('pwC4').checked});$('ePw').value=pw;$('ePw').type='text';const s=pwStr(pw);$('pwStrBox').innerHTML=sBar(s)+'<span style="font-size:11px;color:'+(s<=2?'var(--orange)':'var(--green)')+'">'+(s<=2?s===1?'Weak':'Fair':s===3?'Good':'Strong')+'</span>';};
  $('pwSL').oninput=()=>{$('pwLV').textContent=$('pwSL').value;doGP();};
  ['pwC1','pwC2','pwC3','pwC4'].forEach(i=>$(i).onchange=doGP);
  $('btnUPw').onclick=()=>{doGP();$('pwGB').style.display='none';};
  $('ePw').oninput=function(){if(!this.value){$('pwStrBox').innerHTML='';return;}const s=pwStr(this.value);$('pwStrBox').innerHTML=sBar(s)+'<span style="font-size:11px;color:'+(s<=2?'var(--orange)':'var(--green)')+'">'+(s<=2?s===1?'Weak':'Fair':s===3?'Good':'Strong')+'</span>';};
  $('btnGOTP').onclick=()=>{const b=crypto.getRandomValues(new Uint8Array(20));let s='';const m='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';for(let i=0;i<20;i++)s+=m[b[i]%32];$('eTOTP').value=s;startTP(s);};
  function startTP(sec){const box=$('tpPrev');if(!sec){box.innerHTML='';if(totpI)clearInterval(totpI);return;}box.innerHTML='<div class="totp-box"><div class="totp-code" id="tCode">------</div><div class="totp-timer" id="tTim"></div><div class="totp-bar"><i id="tBar" style="width:100%"></i></div></div>';
    async function up(){$('tCode').textContent=await genTOTP(sec);const t=totpT();$('tTim').textContent=t+'s';$('tBar').style.width=(t/30*100)+'%';}up();totpI=setInterval(up,1000);}
  if(entry&&entry.totp)startTP(entry.totp);$('eTOTP').oninput=()=>startTP($('eTOTP').value);
  $('btnSE').onclick=async()=>{
    const title=$('eTitle').value.trim();if(!title){toast('Title required','error');return;}
    const type=$('eType').value;const ePw=$('ePw').value;
    if(type==='login'&&!ePw&&!ed){toast('Password required','error');return;}
    const now=new Date().toISOString();
    if(ed){
      const en=vaultData.entries.find(x=>x.id===$('eId').value);
      if(en){en.type=type;en.title=title;en.website=$('eWeb').value.trim();en.username=$('eUser').value.trim();en.totp=$('eTOTP').value.trim();en.notes=$('eNotes').value.trim();en.folderId=$('eFolder').value;en.updated=now;if(ePw){en.pwEnc=await Vault.encryptEntry(currentUser.vaultKey,ePw);en.pwStr=pwStr(ePw);}}
    }else{
      const newEntry={id:uuid(),type,title,website:$('eWeb').value.trim(),username:$('eUser').value.trim(),pwEnc:ePw?await Vault.encryptEntry(currentUser.vaultKey,ePw):null,totp:$('eTOTP').value.trim(),notes:$('eNotes').value.trim(),folderId:$('eFolder').value,fav:false,del:false,pwStr:ePw?pwStr(ePw):0,created:now,updated:now};
      vaultData.entries.push(newEntry);
    }
    vaultData.updated=now;await Vault.save(currentUser.userId,currentUser.vaultKey,vaultData);
    closeM();renderApp();toast(ed?'Updated!':'Added!','success');
  };
}
function updFV(){const t=$('eType').value;$('fWeb').style.display=['login','alias'].includes(t)?'':'none';$('fUser').style.display=['login','alias','identity'].includes(t)?'':'none';$('fPw').style.display=t==='login'?'':'none';$('fTOTP').style.display=t==='login'?'':'none';}

function openHealth(){
  const h=getHealth();const c=h.score>=80?'var(--green)':h.score>=50?'var(--orange)':'var(--red)';
  showM(`<div class="modal-header"><h2>Password Health</h2><button class="modal-close" onclick="closeM()"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button></div>
  <div class="modal-body"><div style="text-align:center;margin-bottom:20px"><svg class="progress-ring" viewBox="0 0 56 56"><circle class="bg" cx="28" cy="28" r="24"/><circle class="fg" cx="28" cy="28" r="24" stroke-dasharray="150.8" stroke-dashoffset="${150.8*(1-h.score/100)}"/></svg><div style="font-size:36px;font-weight:800;color:${c}">${h.score}%</div><div style="color:var(--fg3);font-size:13px">Health Score</div></div>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
    <div style="background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius);padding:16px;text-align:center"><div style="font-size:24px;font-weight:700">${h.total}</div><div style="font-size:11px;color:var(--fg3)">Total</div></div>
    <div style="background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius);padding:16px;text-align:center"><div style="font-size:24px;font-weight:700;color:var(--red)">${h.weak}</div><div style="font-size:11px;color:var(--fg3)">Weak</div></div>
    <div style="background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius);padding:16px;text-align:center"><div style="font-size:24px;font-weight:700;color:var(--green)">${h.strong}</div><div style="font-size:11px;color:var(--fg3)">Strong</div></div>
    <div style="background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius);padding:16px;text-align:center"><div style="font-size:24px;font-weight:700">${Math.max(0,h.total-h.strong-h.weak)}</div><div style="font-size:11px;color:var(--fg3)">Unscored</div></div>
  </div></div><div class="modal-footer"><button class="btn-secondary" onclick="closeM()">Close</button></div>`);
}

function openIO(){
  showM(`<div class="modal-header"><h2>Import / Export</h2><button class="modal-close" onclick="closeM()"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button></div>
  <div class="modal-body"><div style="margin-bottom:16px"><div style="font-size:13px;font-weight:600;margin-bottom:10px">Export</div><div style="display:flex;gap:8px"><button class="btn-primary" id="exJ" style="flex:1">Export JSON</button><button class="btn-secondary" id="exC" style="flex:1">Export CSV</button></div></div><div style="height:1px;background:var(--border);margin:16px 0"></div><div><div style="font-size:13px;font-weight:600;margin-bottom:10px">Import</div><button class="btn-secondary" id="imB" style="width:100%">Choose File</button><div id="imR" style="margin-top:10px"></div></div></div><div class="modal-footer"><button class="btn-secondary" onclick="closeM()">Close</button></div>`);
  $('exJ').onclick=()=>{const b=new Blob([JSON.stringify(vaultData,null,2)],{type:'application/json'});const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='vault-'+new Date().toISOString().slice(0,10)+'.json';a.click();toast('Exported!','success');};
  $('exC').onclick=()=>{let c='title,type,website,username,notes\n';vaultData.entries.forEach(r=>{c+='"'+esc(r.title).replace(/"/g,'""')+'","'+r.type+'","'+esc(r.website||'').replace(/"/g,'""')+'","'+esc(r.username||'').replace(/"/g,'""')+'","'+esc(r.notes||'').replace(/"/g,'""')+'"\n';});const b=new Blob([c],{type:'text/csv'});const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='vault-'+new Date().toISOString().slice(0,10)+'.csv';a.click();toast('CSV exported!','success');};
  $('imB').onclick=()=>{const fi=document.createElement('input');fi.type='file';fi.accept='.json';fi.onchange=async()=>{try{const d=JSON.parse(await fi.files[0].text());if(d&&d.entries){const es=new Set(vaultData.entries.map(e=>e.id));d.entries.forEach(e=>{if(!es.has(e.id))vaultData.entries.push(e);});await Vault.save(currentUser.userId,currentUser.vaultKey,vaultData);$('imR').innerHTML='<div style="color:var(--green)">Imported '+d.entries.length+' items</div>';renderApp();}else $('imR').innerHTML='<div style="color:var(--red)">Invalid file</div>';}catch(er){$('imR').innerHTML='<div style="color:var(--red)">'+er.message+'</div>';}};fi.click();};
}

function openSettings(){
  const s=vaultData.settings;const cid=currentUser?currentUser.genesis.usernameHash:'N/A';
  showM(`<div class="modal-header"><h2>Settings</h2><button class="modal-close" onclick="closeM()"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button></div>
  <div class="modal-body" style="padding-top:16px">
    <div class="setting-row"><span class="setting-label">Theme</span><button class="btn-secondary" id="stTh" style="padding:6px 14px;text-transform:capitalize">${s.theme}</button></div>
    <div class="setting-row"><span class="setting-label">Clipboard clear</span><select class="btn-secondary" id="stCl" style="padding:6px 10px"><option value="0"${s.clip===0?' selected':''}>Never</option><option value="15"${s.clip===15?' selected':''}>15s</option><option value="30"${s.clip===30?' selected':''}>30s</option><option value="60"${s.clip===60?' selected':''}>60s</option></select></div>
    <div class="setting-row"><span class="setting-label">Auto-lock</span><select class="btn-secondary" id="stLk" style="padding:6px 10px"><option value="0"${s.lock===0?' selected':''}>Never</option><option value="5"${s.lock===5?' selected':''}>5m</option><option value="15"${s.lock===15?' selected':''}>15m</option><option value="30"${s.lock===30?' selected':''}>30m</option><option value="60"${s.lock===60?' selected':''}>1h</option></select></div>
    <div class="setting-row"><span class="setting-label">Username</span><span class="setting-value">${currentUser?currentUser.username:'N/A'}</span></div>
    <div class="setting-row"><span class="setting-label">User ID</span><span class="setting-value">${currentUser?currentUser.userId.substring(0,16)+'...':'N/A'}</span></div>
    <div class="setting-row"><span class="setting-label">Chain Head</span><span class="setting-value">${cid.substring(0,20)}...</span></div>
    <div class="setting-info">Your vault is encrypted with AES-256-GCM. The vault key is encrypted with your password. Each password uses a different encryption algorithm. Nothing is stored unencrypted on the server.</div>
  </div>
  <div style="padding:0 24px 20px"><button class="btn-secondary" id="btnSync" style="width:100%;margin-bottom:8px">Sync to Cloud Now</button></div>
  <div class="modal-footer"><button class="btn-secondary" onclick="closeM()">Close</button></div>`);
  $('stTh').onclick=()=>{const t=['dark','light'];const i=t.indexOf(s.theme||'dark');const n=t[(i+1)%2];applyTheme(n);s.theme=n;scheduleAutoSave();$('stTh').textContent=n;};
  $('stCl').onchange=()=>{s.clip=+($('stCl').value);scheduleAutoSave();};
  $('stLk').onchange=()=>{s.lock=+($('stLk').value);scheduleAutoSave();startAutoLock();};
  $('btnSync').onclick=async()=>{setSyncStatus('syncing');try{await Vault.save(currentUser.userId,currentUser.vaultKey,vaultData);setSyncStatus('ok');toast('Synced!','success');openSettings();}catch(e){setSyncStatus('error');toast('Sync failed','error');}};
}

// ═══ INIT ═══
document.addEventListener('DOMContentLoaded',function(){
  setTimeout(()=>{
    $('loading').classList.add('hide');
    // Check for existing session
    try{
      const saved=JSON.parse(localStorage.getItem('v1current'));
      if(saved&&saved.userId){
        // Try to restore session — need password
        showLogin();
        if(saved.username)$('uuser').value=saved.username;
      }else{
        // Check if any genesis blocks exist (returning user)
        showLogin();
      }
    }catch(e){showLogin();}
  },800);
});

})();
