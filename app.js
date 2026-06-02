(function(){
'use strict';
const $=id=>document.getElementById(id);

// ═══ CRYPTO ═══
const Crypto=(()=>{
  const ITER=600000,SALT=32,IV=12;
  async function derive(pw,salt){
    const km=await crypto.subtle.importKey('raw',new TextEncoder().encode(pw),'PBKDF2',false,['deriveKey']);
    return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:ITER,hash:'SHA-512'},{name:'AES-GCM',length:256},km,false,['encrypt','decrypt']);
  }
  function genSalt(){return crypto.getRandomValues(new Uint8Array(SALT));}
  async function enc(pw,salt,pt){
    const key=await derive(pw,salt);
    const iv=crypto.getRandomValues(new Uint8Array(IV));
    const ct=await crypto.subtle.encrypt({name:'AES-GCM',iv},key,new TextEncoder().encode(pt));
    return{iv:btoa(String.fromCharCode(...iv)),data:btoa(String.fromCharCode(...new Uint8Array(ct)))};
  }
  async function dec(pw,salt,obj){
    try{
      const key=await derive(pw,salt);
      const iv=Uint8Array.from(atob(obj.iv),c=>c.charCodeAt(0));
      const data=Uint8Array.from(atob(obj.data),c=>c.charCodeAt(0));
      const pt=await crypto.subtle.decrypt({name:'AES-GCM',iv},key,data);
      return new TextDecoder().decode(pt);
    }catch(e){return null;}
  }
  async function hash(pw,salt){
    const km=await crypto.subtle.importKey('raw',new TextEncoder().encode(pw),'PBKDF2',false,['deriveBits']);
    const bits=await crypto.subtle.deriveBits({name:'PBKDF2',salt,iterations:100000,hash:'SHA-256'},km,256);
    return btoa(String.fromCharCode(...new Uint8Array(bits)));
  }
  return{genSalt,enc,dec,hash,bufToB64:b=>btoa(String.fromCharCode(...new Uint8Array(b))),
    b64toBuf:s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0)).buffer};
})();

// ═══ FILEBASE S3 (browser SigV4) ═══
const S3=(()=>{
  const AK='F06A596A2552D11D018C';const SK='HmOUdPtZVOLRmy0sqyOMPAznybclyTIjKce7oltv';
  const BUCKET='vault-storage';const REGION='us-east-1';const HOST='s3.filebase.com';
  function hex(buf){return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('');}
  async function hmac(key,data){
    const kb=typeof key==='string'?new TextEncoder().encode(key):(key instanceof Uint8Array?key.buffer:key);
    const db=typeof data==='string'?new TextEncoder().encode(data):(data instanceof Uint8Array?data.buffer:data);
    const k=await crypto.subtle.importKey('raw',kb,{name:'HMAC',hash:'SHA-256'},false,['sign']);
    return new Uint8Array(await crypto.subtle.sign('HMAC',k,db));
  }
  async function getSigningKey(dt){
    let k=await hmac('AWS4'+SK,dt);k=await hmac(k,REGION);k=await hmac(k,'s3');return await hmac(k,'aws4_request');
  }
  async function sign(method,path,payload,ct){
    const now=new Date();const ts=now.toISOString().replace(/[:-]|\.\d{3}/g,'');const dt=ts.slice(0,8);
    const payBuf=typeof payload==='string'?new TextEncoder().encode(payload):new TextEncoder().encode('');
    const ph=hex(await crypto.subtle.digest('SHA-256',payBuf));
    const h={host:HOST,'x-amz-date':ts,'x-amz-content-sha256':ph};
    if(ct)h['content-type']=ct;
    const ks=Object.keys(h).sort();
    const ch=ks.map(k=>k+':'+h[k]).join('\n')+'\n';
    const sh=ks.join(';');
    const cr=[method,path,'',ch,sh,ph].join('\n');
    const sc=dt+'/'+REGION+'/s3/aws4_request';
    const sts='AWS4-HMAC-SHA256\n'+ts+'\n'+sc+'\n'+hex(await crypto.subtle.digest('SHA-256',cr));
    const sk=await getSigningKey(dt);
    const sig=hex(await hmac(sts,sk));
    return{headers:{...h,'Authorization':'AWS4-HMAC-SHA256 Credential='+AK+'/'+sc+', SignedHeaders='+sh+', Signature='+sig}};
  }
  async function put(key,data){
    const path='/'+BUCKET+'/'+key;
    const r=await sign('PUT',path,data,'application/json');
    return fetch('https://'+HOST+path,{method:'PUT',headers:r.headers,body:data});
  }
  async function get(key){
    const path='/'+BUCKET+'/'+key;
    const r=await sign('GET',path,'');
    const res=await fetch('https://'+HOST+path,{headers:r.headers});
    return res.ok?res.text():null;
  }
  return{put,get};
})();

// ═══ BROWSER IDENTITY ═══
const Identity=(()=>{
  const KEY='v1identity';
  function get(){
    let id=localStorage.getItem(KEY);
    if(!id){
      const nav=navigator;
      id=btoa([
        nav.userAgent,nav.language,nav.hardwareConcurrency||'',
        screen.width+'x'+screen.height,nav.platform,new Date().getTimezoneOffset()
      ].join('|')).substring(0,32);
      localStorage.setItem(KEY,id);
    }
    return id;
  }
  function getLabel(){
    const nav=navigator;
    const os=nav.platform||'Unknown';
    const lang=nav.language||'';
    return os+' / '+lang;
  }
  return{get,getLabel};
})();

// ═══ STORAGE ═══
const Store=(()=>{
  const K={CID:'v1cid',SALT:'v1salt',CACHE:'v1cache',HASH:'v1hash'};
  async function upload(data){
    try{
      const key=Identity.get()+'/vault-'+Date.now()+'.json';
      const res=await S3.put(key,JSON.stringify(data));
      if(res.ok){localStorage.setItem(K.CACHE,JSON.stringify(data));return key;}
    }catch(e){}
    const cid='local_'+Date.now();localStorage.setItem(K.CACHE,JSON.stringify(data));return cid;
  }
  async function download(key){
    if(key.startsWith('local_')){const c=localStorage.getItem(K.CACHE);return c?JSON.parse(c):null;}
    try{const c=localStorage.getItem(K.CACHE);if(c)return JSON.parse(c);}catch(e){}
    try{const d=await S3.get(key);if(d){const parsed=JSON.parse(d);localStorage.setItem(K.CACHE,JSON.stringify(parsed));return parsed;}}catch(e){}
    try{const c=localStorage.getItem(K.CACHE);if(c)return JSON.parse(c);}catch(e){}
    throw new Error('Cannot load vault from storage');
  }
  return{upload,download,
    saveCID:c=>localStorage.setItem(K.CID,c),getCID:()=>localStorage.getItem(K.CID),
    saveSalt:s=>localStorage.setItem(K.SALT,Crypto.bufToB64(s)),
    getSalt:()=>{const s=localStorage.getItem(K.SALT);return s?Crypto.b64toBuf(s):null},
    saveHash:h=>localStorage.setItem(K.HASH,h),getHash:()=>localStorage.getItem(K.HASH),
    exists:()=>!!localStorage.getItem(K.SALT),
    clear:()=>Object.values(K).forEach(k=>localStorage.removeItem(k))
  };
})();

// ═══ MODEL ═══
const M=(()=>{
  let data={v:2,entries:[],folders:[],settings:{clip:30,lock:30,theme:'dark'},updated:null};
  function uuid(){return crypto.randomUUID?crypto.randomUUID():'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g,c=>{const r=crypto.getRandomValues(new Uint8Array(1))[0]%16;return(c==='x'?r:(r&0x3|0x8)).toString(16);});}
  function touch(){data.updated=new Date().toISOString();}
  return{
    createEntry(d){const e={id:uuid(),type:d.type||'login',title:d.title||'',website:d.website||'',username:d.username||'',pwEnc:d.pwEnc||null,totp:d.totp||'',notes:d.notes||[],folderId:d.folderId||'',fav:false,del:false,pwStr:d.pwStr||0,created:new Date().toISOString(),updated:new Date().toISOString()};data.entries.push(e);touch();return e;},
    getEntry(id){return data.entries.find(e=>e.id===id);},
    updateEntry(id,u){const e=this.getEntry(id);if(!e)return null;Object.keys(u).forEach(k=>{if(k!=='id'&&k!=='created')e[k]=u[k];});e.updated=new Date().toISOString();touch();return e;},
    deleteEntry(id){const e=this.getEntry(id);if(e){e.del=true;e.updated=new Date().toISOString();touch();}},
    restoreEntry(id){const e=this.getEntry(id);if(e){e.del=false;e.updated=new Date().toISOString();touch();}},
    purgeEntry(id){data.entries=data.entries.filter(e=>e.id!==id);touch();},
    toggleFav(id){const e=this.getEntry(id);if(e){e.fav=!e.fav;e.updated=new Date().toISOString();touch();return e;}return null;},
    createFolder(name){const f={id:uuid(),name:name||'Folder',created:new Date().toISOString()};data.folders.push(f);touch();return f;},
    deleteFolder(id){data.folders=data.folders.filter(f=>f.id!==id);data.entries.forEach(e=>{if(e.folderId===id)e.folderId='';});touch();},
    getFolder(id){return data.folders.find(f=>f.id===id);},
    getFolders(){return[...data.folders];},
    getEntries(view,search,type){
      let e=data.entries;
      if(view==='fav')e=e.filter(x=>x.fav&&!x.del);
      else if(view==='trash')e=e.filter(x=>x.del);
      else if(view==='recent'){e=e.filter(x=>!x.del);e.sort((a,b)=>new Date(b.updated)-new Date(a.updated));return e.slice(0,20);}
      else if(view.startsWith('dir-'))e=e.filter(x=>x.folderId===view.slice(4)&&!x.del);
      else e=e.filter(x=>!x.del);
      if(type)e=e.filter(x=>x.type===type);
      if(search){const q=search.toLowerCase();e=e.filter(x=>(x.title||'').toLowerCase().includes(q)||(x.website||'').toLowerCase().includes(q)||(x.username||'').toLowerCase().includes(q)||(x.notes||'').toLowerCase().includes(q));}
      e.sort((a,b)=>new Date(b.updated)-new Date(a.updated));return e;
    },
    getStats(){const a=data.entries.filter(e=>!e.del);return{total:a.length,fav:a.filter(e=>e.fav).length,trash:data.entries.filter(e=>e.del).length,
      byType:{login:a.filter(e=>e.type==='login').length,alias:a.filter(e=>e.type==='alias').length,note:a.filter(e=>e.type==='note').length,identity:a.filter(e=>e.type==='identity').length,card:a.filter(e=>e.type==='card').length}};},
    getHealth(){const a=data.entries.filter(e=>!e.del&&e.pwEnc);if(!a.length)return{score:100,total:0,weak:0,strong:0};const w=a.filter(e=>e.pwStr>0&&e.pwStr<=2).length;return{score:Math.round(((a.length-w)/a.length)*100),total:a.length,weak:w,strong:a.length-w};},
    exportJSON(){return JSON.parse(JSON.stringify(data));},
    importJSON(d,mrg){if(!mrg){data={v:2,entries:d.entries||[],folders:d.folders||[],settings:d.settings||data.settings,updated:new Date().toISOString()};}else{const es=new Set(data.entries.map(e=>e.id));(d.entries||[]).forEach(e=>{if(!es.has(e.id))data.entries.push(e);});const fs=new Set(data.folders.map(f=>f.id));(d.folders||[]).forEach(f=>{if(!fs.has(f.id))data.folders.push(f);});}touch();},
    getSettings(){return{...data.settings};},setSettings(u){Object.assign(data.settings,u);touch();},
    getData(){return JSON.parse(JSON.stringify(data));},
    setData(d){if(d&&typeof d==='object'){data=JSON.parse(JSON.stringify(d));data.v=2;touch();return true;}return false;}
  };
})();

// ═══ STATE ═══
var pw=null,salt=null;
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
function sBar(s){if(!s)return'';const c=s<=2?s===1?'var(--red)':'var(--orange)':s===3?'var(--yellow)':'var(--green)';return'<div class="strength-bar s'+s+'"><i></i></div>';}
function favIco(url){if(!url)return'';try{const u=new URL(url.startsWith('http')?url:'https://'+url);return'https://www.google.com/s2/favicons?domain='+u.hostname+'&sz=64';}catch(e){return'';}}
function tIcon(t){return'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">'+({login:'<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',alias:'<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>',note:'<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/>',identity:'<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>',card:'<rect x="1" y="4" width="22" height="16" rx="2"/><line x1="1" y1="10" x2="23" y2="10"/>'})[t]||''+'</svg>';}
function pwStr(p){let s=0;if(p.length>=8)s++;if(p.length>=12)s++;if(p.length>=16)s++;if(/[a-z]/.test(p))s++;if(/[A-Z]/.test(p))s++;if(/[0-9]/.test(p))s++;if(/[^a-zA-Z0-9]/.test(p))s++;return Math.min(4,Math.max(1,Math.floor(s/2)));}
function genPW(len,o){len=len||16;o=o||{};let cs='',rq=[];if(o.up!==false){cs+='ABCDEFGHIJKLMNOPQRSTUVWXYZ';rq.push('ABCDEFGHIJKLMNOPQRSTUVWXYZ');}if(o.lo!==false){cs+='abcdefghijklmnopqrstuvwxyz';rq.push('abcdefghijklmnopqrstuvwxyz');}if(o.nu!==false){cs+='0123456789';rq.push('0123456789');}if(o.sy!==false){cs+='!@#$%^&*()_+-=[]{}|;:,.<>?';rq.push('!@#$%^&*()_+-=[]{}|;:,.<>?');}if(!cs)cs='abcdefghijklmnopqrstuvwxyz';len=Math.max(len,rq.length);const a=new Uint32Array(len*2);crypto.getRandomValues(a);let p='';let i=0;for(let j=0;j<rq.length;j++)p+=rq[j][a[i++]%rq[j].length];for(let j=rq.length;j<len;j++)p+=cs[a[i++]%cs.length];const arr=p.split('');for(let j=arr.length-1;j>0;j--){const k=a[i++]%(j+1);[arr[j],arr[k]]=[arr[k],arr[j]];}return arr.join('');}
async function copyT(text,clear){try{await navigator.clipboard.writeText(text);if(clear>0)setTimeout(async()=>{try{await navigator.clipboard.writeText('');}catch(e){}},clear*1000);return true;}catch(e){return false;}}
async function b32dec(input){const m='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';input=input.toUpperCase().replace(/=+$/,'');const o=[];let b=0,bi=0;for(let i=0;i<input.length;i++){const v=m.indexOf(input[i]);if(v<0)continue;b=(b<<5)|v;bi+=5;if(bi>=8){bi-=8;o.push((b>>>bi)&0xff);}}return new Uint8Array(o).buffer;}
async function genTOTP(sec){try{const ts=Math.floor(Date.now()/1000/30);const key=await b32dec(sec);const buf=new ArrayBuffer(8);new DataView(buf).setUint32(4,ts,false);const hk=await crypto.subtle.importKey('raw',key,{name:'HMAC',hash:'SHA-1'},false,['sign']);const h=await crypto.subtle.sign('HMAC',hk,key);const bv=new Uint8Array(h);const off=bv[19]&0x0f;const cd=(((bv[off]&0x7f)<<24)|((bv[off+1]&0xff)<<16)|((bv[off+2]&0xff)<<8)|(bv[off+3]&0xff))%1000000;return String(cd).padStart(6,'0');}catch(e){return'000000';}}
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
    if(!pw)return;
    setSyncStatus('syncing');
    try{await saveV();setSyncStatus('ok');}catch(e){setSyncStatus('error');}
  },800);
}

// ═══ AUTO-LOCK ═══
function startAutoLock(){
  stopAutoLock();
  const mins=M.getSettings().lock;
  if(!mins)return;
  autoLockTimer=setTimeout(()=>{
    if(confirm('Auto-lock: Vault has been idle for '+mins+' minutes. Lock now?')){
      lockVault();
    }else{startAutoLock();}
  },mins*60*1000);
}
function stopAutoLock(){if(autoLockTimer){clearTimeout(autoLockTimer);autoLockTimer=null;}}

// ═══ MODAL ═══
function showM(html){$('md').innerHTML=html;$('mbg').classList.add('show');document.body.style.overflow='hidden';}
function closeM(){$('mbg').classList.remove('show');document.body.style.overflow='';}

// ═══ SETUP ═══
function showSetup(){
  $('app').style.display='';$('loading').classList.add('hide');
  document.body.insertAdjacentHTML('beforeend',`<div class="auth-screen" id="authScreen"><div class="auth-box"><div class="auth-logo"><div class="auth-logo-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/><path d="M9 12l2 2 4-4" stroke-linecap="round"/></svg></div><h1>VaultIPFS</h1><p>Zero Trust Password Manager</p></div><div class="auth-steps"><div class="auth-step"><div class="auth-step-num">1</div><div><div class="auth-step-txt">Master Password</div><div class="auth-step-sub">Encrypts everything. Never leaves your browser.</div></div></div><div class="auth-step"><div class="auth-step-num">2</div><div><div class="auth-step-txt">Encrypted Cloud Storage</div><div class="auth-step-sub">AES-256-GCM encrypted. Stored on decentralized storage.</div></div></div><div class="auth-step"><div class="auth-step-num">3</div><div><div class="auth-step-txt">Zero Knowledge</div><div class="auth-step-sub">Only you hold the key. No one can read your passwords.</div></div></div></div><form class="auth-form" id="sf"><div class="form-group"><label>Master Password</label><input type="password" id="spw" placeholder="Min 8 characters" required autocomplete="new-password"></div><div class="form-group"><label>Confirm Password</label><input type="password" id="spw2" placeholder="Repeat password" required autocomplete="new-password"></div><div id="sStr"></div><div class="form-error" id="sErr"></div><button type="submit" class="btn-primary" style="width:100%;padding:12px;margin-top:4px">Create Vault</button></form><div class="auth-links"><a href="#" id="sImp">Import existing vault</a></div><input type="file" id="sF" accept=".json" style="display:none"></div></div>`);
  $('spw').oninput=function(){const s=pwStr(this.value);const l=s<=2?s===1?'Weak':'Fair':s===3?'Good':'Strong';const c=s<=2?s===1?'var(--red)':'var(--orange)':s===3?'var(--yellow)':'var(--green)';$('sStr').innerHTML='<div class="strength-bar s'+s+'"><i></i></div><span style="font-size:11px;color:'+c+'">'+l+'</span>';};
  $('sf').onsubmit=async function(e){
    e.preventDefault();const p1=$('spw').value,p2=$('spw2').value;
    if(p1.length<8){$('sErr').textContent='Min 8 characters';return;}
    if(p1!==p2){$('sErr').textContent='Passwords do not match';return;}
    salt=Crypto.genSalt();pw=p1;Store.saveSalt(salt);Store.saveHash(await Crypto.hash(pw,salt));
    M.setData({v:2,entries:[],folders:[],settings:{clip:30,lock:30,theme:'dark'},updated:new Date().toISOString()});
    await saveV();renderApp();
  };
  $('sImp').onclick=e=>{e.preventDefault();$('sF').click();};
  $('sF').onchange=async function(){const f=this.files[0];if(!f)return;const d=JSON.parse(await f.text());if(d&&d.entries){const p=prompt('Master password:');if(!p)return;salt=Crypto.genSalt();pw=p;Store.saveSalt(salt);Store.saveHash(await Crypto.hash(p,salt));M.setData(d);await saveV();renderApp();}else toast('Invalid file','error');};
}

// ═══ UNLOCK ═══
function showUnlock(){
  $('app').style.display='';$('loading').classList.add('hide');
  const sc=Store.getCID()||'';
  document.body.insertAdjacentHTML('beforeend',`<div class="auth-screen" id="authScreen"><div class="auth-box"><div class="auth-logo"><div class="auth-logo-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/><path d="M9 12l2 2 4-4" stroke-linecap="round"/></svg></div><h1>VaultIPFS</h1><p>Enter your master password</p></div><form class="auth-form" id="uf"><div class="form-group"><label>Master Password</label><input type="password" id="upw" placeholder="Enter master password" required autofocus autocomplete="current-password"></div><div class="form-group"><label>Storage Key <span style="font-weight:400;color:var(--fg4)">(optional — loads specific version)</span></label><input type="text" id="ucid" placeholder="vault-..." value="${sc}" style="font-family:monospace;font-size:12px"></div><div class="form-error" id="uErr"></div><button type="submit" class="btn-primary" style="width:100%;padding:12px;margin-top:4px">Unlock</button></form><div class="auth-links"><a href="#" id="uImp">Import file</a> &middot; <a href="#" id="uRes" style="color:var(--red)">Reset vault</a><br><br><a href="#" id="uForg" style="color:var(--fg4)">Forgot password?</a></div><input type="file" id="uF" accept=".json" style="display:none"></div></div>`);
  $('uf').onsubmit=async function(e){
    e.preventDefault();const p=$('upw').value;const cid=$('ucid').value.trim()||null;
    salt=Store.getSalt();const sh=Store.getHash();
    if(sh){const ih=await Crypto.hash(p,salt);if(ih!==sh){$('uErr').textContent='Wrong master password';return;}}
    pw=p;try{await loadV(cid);renderApp();}catch(err){$('uErr').textContent=err.message||'Failed to load';pw=null;}
  };
  $('uImp').onclick=e=>{e.preventDefault();$('uF').click();};
  $('uF').onchange=async function(){const f=this.files[0];if(!f)return;const d=JSON.parse(await f.text());if(d&&d.entries){const p=prompt('Master password:');if(!p)return;salt=Crypto.genSalt();pw=p;Store.saveSalt(salt);Store.saveHash(await Crypto.hash(p,salt));M.setData(d);await saveV();renderApp();}else toast('Invalid file','error');};
  $('uRes').onclick=e=>{e.preventDefault();if(!confirm('⚠️ DELETE all local data? MUST have backup!'))return;if(!confirm('ABSOLUTELY sure?'))return;Store.clear();pw=null;salt=null;toast('Vault reset','info');setTimeout(()=>location.reload(),600);};
  $('uForg').onclick=e=>{e.preventDefault();alert('No recovery. Master password is the only key.\n\nExport a backup file regularly.\n\nIf you lose your password, your vault is gone forever.');};
}

// ═══ SAVE/LOAD ═══
async function saveV(){
  const d=M.getData();const e=await Crypto.enc(pw,salt,JSON.stringify(d));
  e._m={v:2,t:new Date().toISOString()};const cid=await Store.upload(e);Store.saveCID(cid);return cid;
}
async function loadV(cidOvr){const cid=cidOvr||Store.getCID();if(!cid)throw new Error('No storage key');let e=await Store.download(cid);if(!e)throw new Error('No data');const d=await Crypto.dec(pw,salt,e);if(!d)throw new Error('Decrypt failed');M.setData(JSON.parse(d));}

// ═══ LOCK ═══
function lockVault(){
  pw=null;salt=null;stopAutoLock();
  $('app').style.display='none';showUnlock();
}

// ═══ RENDER ═══
function renderApp(){
  $('authScreen')?.remove();
  $('app').style.display='';
  applyTheme(M.getSettings().theme);
  bindNav();renderE();updC();
  startAutoLock();
}

function applyTheme(t){document.documentElement.setAttribute('data-theme',t||'dark');}

// ═══ NAV ═══
function bindNav(){
  document.querySelectorAll('[data-view]').forEach(b=>{b.onclick=()=>{state.view=b.dataset.view;state.type='';updN();renderE();updT();};});
  document.querySelectorAll('[data-type]').forEach(b=>{b.onclick=()=>{state.type=b.dataset.type;state.view='all';updN();renderE();updT();};});
  let st;$('search').oninput=()=>{clearTimeout(st);st=setTimeout(()=>{state.search=$('search').value;renderE();},200);};
  $('btnAdd').onclick=()=>openEM(null);
  $('btnNewFolder').onclick=()=>{const n=prompt('Folder name:');if(n){M.createFolder(n);bindNav();renderApp();toast('Folder created','success');}};
  $('btnHealth').onclick=openHealth;
  $('btnIO').onclick=openIO;
  $('btnLock').onclick=()=>{if(confirm('Lock vault?'))lockVault();};
  $('btnSettings').onclick=openSettings;
  $('btnTheme').onclick=()=>{const t=document.documentElement.getAttribute('data-theme')==='dark'?'light':'dark';applyTheme(t);M.setSettings({theme:t});};
  $('mobMenu').onclick=()=>{$('sidebar').classList.toggle('open');$('overlay').classList.toggle('show');};
  $('overlay').onclick=()=>{$('sidebar').classList.remove('open');$('overlay').classList.remove('show');};
  $('mbg').onclick=function(e){if(e.target===this)closeM();};
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
  else if(state.view.startsWith('dir-')){const f=M.getFolder(state.view.slice(4));$('viewTitle').textContent=f?f.name:'Folder';}
  else if(state.type)$('viewTitle').textContent={login:'Logins',alias:'Aliases',note:'Notes',identity:'Identities',card:'Cards'}[state.type]||'Items';
  else $('viewTitle').textContent='All Items';
}
function updC(){
  const s=M.getStats();
  const g=id=>$(id);if(g('cAll'))g('cAll').textContent=s.total;
  if(g('cFav'))g('cFav').textContent=s.fav;
  if(g('cTrash'))g('cTrash').textContent=s.trash;
  if(g('cTlogin'))g('cTlogin').textContent=s.byType.login;
  if(g('cTalias'))g('cTalias').textContent=s.byType.alias;
  if(g('cTnote'))g('cTnote').textContent=s.byType.note;
  if(g('cTidentity'))g('cTidentity').textContent=s.byType.identity;
  if(g('cTcard'))g('cTcard').textContent=s.byType.card;
  const folders=M.getFolders();
  $('folderSection').style.display=folders.length?'':'none';
  const fl=$('folderList');
  fl.innerHTML=folders.map(f=>`<button class="nav-item${state.view==='dir-'+f.id?' active':''}" data-view="dir-${f.id}">${tIcon('login')}<span>${esc(f.name)}</span><button onclick="event.stopPropagation();if(confirm('Delete?')){M.deleteFolder('${f.id}');renderApp();}" style="background:none;border:none;color:var(--fg4);font-size:14px;opacity:0;transition:opacity .15s">&times;</button></button>`).join('');
  fl.querySelectorAll('[data-view]').forEach(b=>{b.onclick=()=>{state.view=b.dataset.view;state.type='';updN();renderE();updT();};});
  fl.querySelectorAll('.nav-item').forEach(b=>{b.onmouseenter=()=>{const btn=b.querySelector('button[onclick]');if(btn)btn.style.opacity=1;};b.onmouseleave=()=>{const btn=b.querySelector('button[onclick]');if(btn)btn.style.opacity=0;};});
}

// ═══ ENTRIES ═══
function renderE(){
  const entries=M.getEntries(state.view,state.search,state.type);
  const mb=$('mb');
  if(!entries.length){
    const msgs={all:'Your vault is empty',fav:'No favorites yet',recent:'No recent items',trash:'Trash is empty'};
    mb.innerHTML=`<div class="empty-state"><div class="empty-state-icon"><svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg></div><h3>${msgs[state.view]||'No items'}</h3><p>Start by adding your first password or secure note.</p><button class="btn-primary" onclick="openEM(null)">+ Add Item</button></div>`;
    return;
  }
  let h='<div class="cards-grid">';
  entries.forEach(e=>{
    const fi=favIco(e.website);
    const ic=fi?'<img src="'+fi+'" onerror="this.parentElement.innerHTML=tIcon(\''+e.type+'\')">':tIcon(e.type);
    const fv=e.fav?'<span class="fav-star">★</span>':'';
    const fo=M.getFolder(e.folderId);
    h+=`<div class="card" data-id="${e.id}"><div class="card-inner"><div class="card-icon">${ic}${fv}</div><div class="card-info"><div class="card-title">${esc(e.title)}</div><div class="card-sub">${esc(e.username||e.website||e.type)}</div><div class="card-meta">${sBar(e.pwStr)}${fo?'<span class="folder-tag">'+esc(fo.name)+'</span>':''}</div></div><div class="card-actions">${e.pwEnc?'<button class="btn-icon cpw" data-id="'+e.id+'" title="Copy password"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg></button>':''}${e.totp?'<button class="btn-icon gtotp" data-id="'+e.id+'" title="TOTP"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg></button>':''}<button class="btn-icon menu-btn-card" data-id="${e.id}" title="More"><svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="5" r="2"/><circle cx="12" cy="12" r="2"/><circle cx="12" cy="19" r="2"/></svg></button></div></div></div>`;
  });
  h+='</div>';mb.innerHTML=h;
  mb.querySelectorAll('.card').forEach(c=>{c.onclick=function(e){if(e.target.closest('.card-actions'))return;openEM(M.getEntry(c.dataset.id));};});
  mb.querySelectorAll('.menu-btn-card').forEach(b=>{b.onclick=e=>{e.stopPropagation();showCtx(M.getEntry(b.dataset.id),b);};});
  mb.querySelectorAll('.cpw').forEach(b=>{b.onclick=async e=>{e.stopPropagation();const en=M.getEntry(b.dataset.id);const d=await Crypto.dec(pw,salt,en.pwEnc);if(d){await copyT(d,M.getSettings().clip);toast('Password copied!','success');}else toast('Decrypt failed','error');};});
  mb.querySelectorAll('.gtotp').forEach(b=>{b.onclick=async e=>{e.stopPropagation();const en=M.getEntry(b.dataset.id);if(en.totp){const c=await genTOTP(en.totp);await copyT(c,30);toast('TOTP: '+c,'info');}};});
}

// ═══ CONTEXT MENU ═══
function showCtx(entry,btn){
  const menu=$('ctxMenu');
  menu.innerHTML=(entry.del?'':'<button data-a="edit"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg> Edit</button><button data-a="fav"><svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg> '+(entry.fav?'Unfavorite':'Favorite')+'</button>')+(entry.del?'<button data-a="res"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/></svg> Restore</button>':'')+'<div class="ctx-divider"></div><button data-a="del" class="danger"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg> '+(entry.del?'Delete Forever':'Trash')+'</button>';
  menu.style.display='block';
  const r=btn.getBoundingClientRect();
  menu.style.left=Math.min(r.left,window.innerWidth-180)+'px';
  menu.style.top=(r.bottom+6)+'px';
  menu.onclick=async e=>{
    const a=e.target.closest('button')?.dataset.a;if(!a)return;
    menu.style.display='none';
    if(a==='edit')openEM(entry);
    if(a==='fav'){M.toggleFav(entry.id);scheduleAutoSave();renderE();toast(entry.fav?'Removed from favorites':'Added to favorites','success');}
    if(a==='res'){M.restoreEntry(entry.id);scheduleAutoSave();renderApp();toast('Restored','success');}
    if(a==='del'){if(entry.del){if(!confirm('Permanently delete?'))return;M.purgeEntry(entry.id);}else{if(!confirm('Move to trash?'))return;M.deleteEntry(entry.id);}scheduleAutoSave();renderApp();}
  };
  setTimeout(()=>{document.addEventListener('click',function h(e){if(!menu.contains(e.target)){menu.style.display='none';document.removeEventListener('click',h);}});},10);
}

// ═══ ENTRY MODAL ═══
var totpI=null;
function openEM(entry){
  closeM();const ed=!!entry;
  const types=[{v:'login',l:'Login'},{v:'alias',l:'Alias'},{v:'note',l:'Secure Note'},{v:'identity',l:'Identity'},{v:'card',l:'Credit Card'}];
  const fo=M.getFolders();const fopts=fo.map(f=>'<option value="'+f.id+'"'+(entry&&entry.folderId===f.id?' selected':'')+'>'+esc(f.name)+'</option>').join('');
  showM(`<div class="modal-header"><h2>${ed?'Edit Item':'Add New Item'}</h2><button class="modal-close" onclick="closeM()"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button></div>
  <div class="modal-body"><form id="ef" autocomplete="off">
    <input type="hidden" id="eId" value="${entry?entry.id:''}">
    <div class="form-group"><label>Type</label><select id="eType">${types.map(t=>'<option value="'+t.v+'"'+(entry&&entry.type===t.v?' selected':'')+'>'+t.l+'</option>').join('')}</select></div>
    <div class="form-group"><label>Title *</label><input id="eTitle" value="${entry?esc(entry.title):''}" required placeholder="e.g. GitHub"></div>
    <div class="form-group" id="fWeb"><label>Website URL</label><input id="eWeb" value="${entry?esc(entry.website||''):''}" placeholder="https://..."></div>
    <div class="form-group" id="fUser"><label>Username / Email</label><input id="eUser" value="${entry?esc(entry.username||''):''}"></div>
    <div class="form-group" id="fPw"><label>Password</label><div style="display:flex;gap:8px"><input id="ePw" type="password" value="" placeholder="${ed?'Leave blank to keep':'Enter password'}" style="flex:1"><button type="button" class="btn-secondary" id="btnTPw" style="padding:8px 12px">Show</button><button type="button" class="btn-secondary" id="btnGPw" style="padding:8px 12px">Gen</button></div><div id="pwStrBox" style="margin-top:6px"></div>
      <div class="pw-gen" id="pwGB" style="display:none">
        <div class="pw-gen-row"><label>Length</label><span id="pwLV">16</span></div>
        <input type="range" class="pw-gen-slider" id="pwSL" min="8" max="64" value="16">
        <div class="pw-gen-options"><label><input type="checkbox" id="pwC1" checked> ABC</label><label><input type="checkbox" id="pwC2" checked> abc</label><label><input type="checkbox" id="pwC3" checked> 123</label><label><input type="checkbox" id="pwC4" checked> #$%</label></div>
        <button type="button" class="btn-secondary" id="btnUPw" style="margin-top:10px;width:100%">Use This Password</button>
      </div>
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
    const ed2={type,title,website:$('eWeb').value.trim(),username:$('eUser').value.trim(),pwEnc:ePw?await Crypto.enc(pw,salt,ePw):(entry?entry.pwEnc:null),totp:$('eTOTP').value.trim(),notes:$('eNotes').value.trim(),folderId:$('eFolder')?.value||'',pwStr:ePw?pwStr(ePw):(entry?entry.pwStr:0)};
    if(ed)M.updateEntry(entry.id,ed2);else M.createEntry(ed2);
    await saveV();closeM();renderApp();toast(ed?'Updated!':'Added!','success');
  };
}
function updFV(){const t=$('eType').value;$('fWeb').style.display=['login','alias'].includes(t)?'':'none';$('fUser').style.display=['login','alias','identity'].includes(t)?'':'none';$('fPw').style.display=t==='login'?'':'none';$('fTOTP').style.display=t==='login'?'':'none';}

// ═══ HEALTH ═══
function openHealth(){
  const h=M.getHealth();const c=h.score>=80?'var(--green)':h.score>=50?'var(--orange)':'var(--red)';
  showM(`<div class="modal-header"><h2>Password Health</h2><button class="modal-close" onclick="closeM()"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button></div>
  <div class="modal-body"><div style="text-align:center;margin-bottom:20px"><svg class="progress-ring" viewBox="0 0 56 56"><circle class="bg" cx="28" cy="28" r="24"/><circle class="fg" cx="28" cy="28" r="24" stroke-dasharray="150.8" stroke-dashoffset="${150.8*(1-h.score/100)}"/></svg><div style="font-size:36px;font-weight:800;color:${c}">${h.score}%</div><div style="color:var(--fg3);font-size:13px">Health Score</div></div>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
    <div style="background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius);padding:16px;text-align:center"><div style="font-size:24px;font-weight:700">${h.total}</div><div style="font-size:11px;color:var(--fg3)">Total</div></div>
    <div style="background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius);padding:16px;text-align:center"><div style="font-size:24px;font-weight:700;color:var(--red)">${h.weak}</div><div style="font-size:11px;color:var(--fg3)">Weak</div></div>
    <div style="background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius);padding:16px;text-align:center"><div style="font-size:24px;font-weight:700;color:var(--green)">${h.strong}</div><div style="font-size:11px;color:var(--fg3)">Strong</div></div>
    <div style="background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius);padding:16px;text-align:center"><div style="font-size:24px;font-weight:700">${Math.max(0,h.total-h.strong-h.weak)}</div><div style="font-size:11px;color:var(--fg3)">Unscored</div></div>
  </div></div><div class="modal-footer"><button class="btn-secondary" onclick="closeM()">Close</button></div>`);
}

// ═══ IMPORT/EXPORT ═══
function openIO(){
  showM(`<div class="modal-header"><h2>Import / Export</h2><button class="modal-close" onclick="closeM()"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button></div>
  <div class="modal-body">
    <div style="margin-bottom:16px"><div style="font-size:13px;font-weight:600;margin-bottom:10px">Export</div><div style="display:flex;gap:8px"><button class="btn-primary" id="exJ" style="flex:1">Export JSON</button><button class="btn-secondary" id="exC" style="flex:1">Export CSV</button></div></div>
    <div style="height:1px;background:var(--border);margin:16px 0"></div>
    <div><div style="font-size:13px;font-weight:600;margin-bottom:10px">Import</div><button class="btn-secondary" id="imB" style="width:100%">Choose File</button><div style="font-size:11px;color:var(--fg4);margin-top:8px">Requires master password from original vault</div><div id="imR" style="margin-top:10px"></div></div>
  </div><div class="modal-footer"><button class="btn-secondary" onclick="closeM()">Close</button></div>`);
  $('exJ').onclick=()=>{const d=M.exportJSON();const b=new Blob([JSON.stringify(d,null,2)],{type:'application/json'});const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='vault-'+new Date().toISOString().slice(0,10)+'.json';a.click();toast('Exported!','success');};
  $('exC').onclick=()=>{const e=M.getEntries();let c='title,type,website,username,notes\n';e.forEach(r=>{c+='"'+esc(r.title).replace(/"/g,'""')+'","'+r.type+'","'+esc(r.website||'').replace(/"/g,'""')+'","'+esc(r.username||'').replace(/"/g,'""')+'","'+esc(r.notes||'').replace(/"/g,'""')+'"\n';});const b=new Blob([c],{type:'text/csv'});const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='vault-'+new Date().toISOString().slice(0,10)+'.csv';a.click();toast('CSV exported!','success');};
  $('imB').onclick=()=>{const fi=document.createElement('input');fi.type='file';fi.accept='.json';fi.onchange=async()=>{try{const d=JSON.parse(await fi.files[0].text());if(d&&d.entries){M.importJSON(d,false);await saveV();$('imR').innerHTML='<div style="color:var(--green);font-size:13px">Imported '+d.entries.length+' items</div>';renderApp();}else $('imR').innerHTML='<div style="color:var(--red);font-size:13px">Invalid file</div>';}catch(er){$('imR').innerHTML='<div style="color:var(--red);font-size:13px">'+er.message+'</div>';}};fi.click();};
}

// ═══ SETTINGS ═══
function openSettings(){
  const s=M.getSettings();const cid=Store.getCID()||'Not saved';
  showM(`<div class="modal-header"><h2>Settings</h2><button class="modal-close" onclick="closeM()"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button></div>
  <div class="modal-body" style="padding-top:16px">
    <div class="setting-row"><span class="setting-label">Theme</span><button class="btn-secondary" id="stTh" style="padding:6px 14px;text-transform:capitalize">${s.theme}</button></div>
    <div class="setting-row"><span class="setting-label">Clipboard clear</span><select class="btn-secondary" id="stCl" style="padding:6px 10px"><option value="0"${s.clip===0?' selected':''}>Never</option><option value="15"${s.clip===15?' selected':''}>15s</option><option value="30"${s.clip===30?' selected':''}>30s</option><option value="60"${s.clip===60?' selected':''}>60s</option></select></div>
    <div class="setting-row"><span class="setting-label">Auto-lock</span><select class="btn-secondary" id="stLk" style="padding:6px 10px"><option value="0"${s.lock===0?' selected':''}>Never</option><option value="5"${s.lock===5?' selected':''}>5m</option><option value="15"${s.lock===15?' selected':''}>15m</option><option value="30"${s.lock===30?' selected':''}>30m</option><option value="60"${s.lock===60?' selected':''}>1h</option></select></div>
    <div class="setting-row"><span class="setting-label">Browser ID</span><span class="setting-value">${Identity.get().substring(0,16)}...</span></div>
    <div class="setting-row"><span class="setting-label">Storage Key</span><span class="setting-value">${cid.length>30?cid.substring(0,30)+'...':cid}</span></div>
    <div class="setting-info">Your vault is encrypted with AES-256-GCM and stored on Filebase S3 (IPFS-backed decentralized storage). Only you hold the master password.</div>
  </div>
  <div style="padding:0 24px 20px"><button class="btn-secondary" id="btnSync" style="width:100%;margin-bottom:8px">Sync to Cloud Now</button></div>
  <div class="modal-footer"><button class="btn-secondary" onclick="closeM()">Close</button></div>`);
  $('stTh').onclick=()=>{const t=['dark','light'];const i=t.indexOf(s.theme||'dark');const n=t[(i+1)%2];M.setSettings({theme:n});applyTheme(n);$('stTh').textContent=n;};
  $('stCl').onchange=()=>M.setSettings({clip:+($('stCl').value)});
  $('stLk').onchange=()=>{M.setSettings({lock:+($('stLk').value)});startAutoLock();};
  $('btnSync').onclick=async()=>{setSyncStatus('syncing');try{await saveV();setSyncStatus('ok');toast('Synced to cloud!','success');openSettings();}catch(e){setSyncStatus('error');toast('Sync failed: '+e.message,'error');}};
}

// ═══ INIT ═══
document.addEventListener('DOMContentLoaded',function(){
  setTimeout(()=>{
    $('loading').classList.add('hide');
    if(Store.exists()){showUnlock();}else{showSetup();}
  },800);
});

})();
