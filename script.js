const $=id=>document.getElementById(id);
const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const API=(window.API_URL||'').replace(/\/$/,'');
const tok={get:()=>{try{return sessionStorage.getItem('sa_t')}catch{return null}},set:v=>{try{sessionStorage.setItem('sa_t',v)}catch{}},clear:()=>{try{sessionStorage.removeItem('sa_t')}catch{}}};
let me=null,pend=null;

// LOCAL-START  (modo local: funciona sem servidor, dados salvos no navegador)
const LOCAL=API==='local';
const lk={get:(k,d)=>{try{return JSON.parse(localStorage.getItem(k))??d}catch{return d}},set:(k,v)=>{try{localStorage.setItem(k,JSON.stringify(v))}catch{}}};
const enc=new TextEncoder(),hex=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join(''),unhex=t=>new Uint8Array(t.match(/../g).map(x=>parseInt(x,16)));
const B32='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
async function pbk(pw,salt){const k=await crypto.subtle.importKey('raw',enc.encode(pw),'PBKDF2',false,['deriveBits']);return hex(await crypto.subtle.deriveBits({name:'PBKDF2',salt:unhex(salt),iterations:100000,hash:'SHA-256'},k,256))}
function newSecret(){let bits='',s='';crypto.getRandomValues(new Uint8Array(20)).forEach(x=>bits+=x.toString(2).padStart(8,'0'));for(let i=0;i<160;i+=5)s+=B32[parseInt(bits.slice(i,i+5),2)];return s}
function b32dec(s){let bits='';for(const c of s)bits+=B32.indexOf(c).toString(2).padStart(5,'0');return new Uint8Array(bits.match(/.{8}/g).map(x=>parseInt(x,2)))}
async function totp(secret,t){const c=new Uint8Array(8);new DataView(c.buffer).setUint32(4,Math.floor(t/30000));const k=await crypto.subtle.importKey('raw',b32dec(secret),{name:'HMAC',hash:'SHA-1'},false,['sign']);const h=new Uint8Array(await crypto.subtle.sign('HMAC',k,c));const o=h[19]&15;return String(((h[o]&127)<<24|h[o+1]<<16|h[o+2]<<8|h[o+3])%1e6).padStart(6,'0')}
async function checkCode(secret,code){const n=Date.now();for(const d of[-30000,0,30000])if(await totp(secret,n+d)===code)return true;return false}
async function mkU(nome,email,pw,perfil,id){const salt=hex(crypto.getRandomValues(new Uint8Array(16)));return{id,nome,email,perfil,salt,hash:await pbk(pw,salt),secret:null}}
const mask=e=>e.replace(/^(.).*(@.*)$/,'$1***$2');
async function enviarEmail(u,code){
  const c=window.EMAILJS||{};
  if(!c.serviceId||!c.templateId||!c.publicKey)return{ok:false,erro:'O envio de e-mail ainda não foi configurado (config.js).'};
  try{
    const r=await fetch('https://api.emailjs.com/api/v1.0/email/send',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({service_id:c.serviceId,template_id:c.templateId,user_id:c.publicKey,template_params:{to_email:u.email,nome:u.nome,codigo:code}})});
    if(r.ok)return{ok:true};
    return{ok:false,erro:'Não foi possível enviar o e-mail ('+r.status+'). Tente novamente.'};
  }catch{return{ok:false,erro:'Não foi possível enviar o e-mail. Verifique a conexão.'}}
}
async function enviarCodigo(x,ss,t,now,env){
  const code=String(crypto.getRandomValues(new Uint32Array(1))[0]%1e6).padStart(6,'0'),salt=hex(crypto.getRandomValues(new Uint8Array(16)));
  const e=await enviarEmail(x,code);
  if(!e.ok&&!window.DEMO_MFA)return{erro:e.erro};
  ss[t]={id:x.id,exp:now+5*60000,ok:false,tent:(ss[t]&&ss[t].tent)||0,metodo:'email',salt,ch:await pbk(code,salt),env:env||0};
  return{demo:e.ok?undefined:code};
}
async function localApi(path,method,b,token){
  b=b||{};const R=(st,d)=>({ok:st<400,status:st,d});
  let us=lk.get('sa_users2',null);
  if(!us){us=[];lk.set('sa_users2',us)}
  const ss=lk.get('sa_sess2',{}),now=Date.now();
  for(const k in ss)if(ss[k].exp<now)delete ss[k];
  const save=()=>{lk.set('sa_users2',us);lk.set('sa_sess2',ss)};
  const s=token&&ss[token],u=s&&us.find(x=>x.id===s.id),full=!!(s&&s.ok&&u),key=method+' '+path;
  if(key==='POST /cadastro'){
    const nome=String(b.nome||'').trim(),email=String(b.email||'').trim().toLowerCase(),senha=String(b.senha||'');
    if(!nome||!/^\S+@\S+\.\S+$/.test(email))return R(400,{erro:'Informe nome e e-mail válidos.'});
    if(senha.length<8)return R(400,{erro:'A senha precisa ter ao menos 8 caracteres.'});
    if(us.some(x=>x.email===email))return R(409,{erro:'E-mail já cadastrado.'});
    const pf=(window.PERFIS_POR_EMAIL||{})[email];us.push(await mkU(nome,email,senha,['gestor','administrador'].includes(pf)?pf:'usuario',us.reduce((m,x)=>Math.max(m,x.id),0)+1));save();return R(201,{ok:true});
  }
  if(key==='POST /login'){
    const email=String(b.email||'').trim().toLowerCase(),x=us.find(y=>y.email===email);
    if(!x||await pbk(String(b.senha||''),x.salt)!==x.hash)return R(401,{erro:'E-mail ou senha incorretos.'});
    const t=hex(crypto.getRandomValues(new Uint8Array(32)));
    if(window.MFA_MODE==='email'){const e=await enviarCodigo(x,ss,t,now);if(e.erro)return R(502,{erro:e.erro});save();return R(200,{token:t,metodo:'email',email:mask(x.email),codigoDemo:e.demo})}
    const setup=!x.secret,temp=setup?newSecret():null;
    ss[t]={id:x.id,exp:now+5*60000,ok:false,temp,tent:0};save();
    const d={token:t,setup,secret:temp,otpauth:setup?`otpauth://totp/SmartAutomation:${encodeURIComponent(x.email)}?secret=${temp}&issuer=SmartAutomation`:null};
    if(window.DEMO_MFA)d.codigoDemo=await totp(x.secret||temp,now);
    return R(200,d);
  }
  if(key==='POST /mfa'){
    if(!s||s.ok||!u)return R(401,{erro:'Sessão expirada. Faça login novamente.',reiniciar:true});
    const code=String(b.codigo||'').replace(/\D/g,'');s.tent++;
    const okc=code.length===6&&(s.metodo==='email'?(await pbk(code,s.salt)===s.ch):await checkCode(u.secret||s.temp,code));
    if(okc){if(s.metodo!=='email'&&!u.secret)u.secret=s.temp;s.ok=true;s.temp=null;s.exp=now+30*60000;save();return R(200,{ok:true})}
    if(s.tent>=3){delete ss[token];save();return R(401,{erro:'Muitas tentativas. Faça login novamente.',reiniciar:true})}
    save();return R(401,{erro:`Código inválido. Tentativas restantes: ${3-s.tent}.`});
  }
  if(key==='POST /reenviar'){
    if(!s||s.ok||!u||s.metodo!=='email')return R(401,{erro:'Sessão expirada. Faça login novamente.',reiniciar:true});
    if((s.env||0)>=3)return R(429,{erro:'Limite de reenvios atingido. Faça login novamente.'});
    const e=await enviarCodigo(u,ss,token,now,(s.env||0)+1);if(e.erro)return R(502,{erro:e.erro});
    save();return R(200,{ok:true,codigoDemo:e.demo});
  }
  if(key==='POST /logout'){if(token)delete ss[token];save();return R(200,{ok:true})}
  if(!full)return R(401,{erro:'Não autenticado.'});
  if(key==='GET /perfil')return R(200,{nome:u.nome,email:u.email,perfil:u.perfil,id:u.id});
  if(key==='GET /resumo'){if(u.perfil==='usuario')return R(403,{erro:'Acesso negado para o seu perfil.'});const c={};us.forEach(x=>c[x.perfil]=(c[x.perfil]||0)+1);return R(200,c)}
  if(u.perfil!=='administrador')return R(403,{erro:'Acesso negado para o seu perfil.'});
  if(key==='GET /usuarios')return R(200,us.map(x=>({id:x.id,nome:x.nome,email:x.email,perfil:x.perfil,mfa:!!x.secret})));
  const m=path.match(/^\/usuarios\/(\d+)(\/perfil|\/reset-mfa)?$/);
  if(m){
    const id=Number(m[1]),i=us.findIndex(x=>x.id===id);if(i<0)return R(404,{erro:'Usuário não encontrado.'});
    if(method==='PATCH'&&m[2]==='/perfil'){if(id===u.id)return R(400,{erro:'Você não pode alterar o próprio perfil.'});if(!['usuario','gestor','administrador'].includes(b.perfil))return R(400,{erro:'Perfil inválido.'});us[i].perfil=b.perfil;save();return R(200,{ok:true})}
    if(method==='POST'&&m[2]==='/reset-mfa'){us[i].secret=null;if(id!==u.id)for(const k in ss)if(ss[k].id===id)delete ss[k];save();return R(200,{ok:true})}
    if(method==='DELETE'&&!m[2]){if(id===u.id)return R(400,{erro:'Você não pode excluir a própria conta.'});us.splice(i,1);for(const k in ss)if(ss[k].id===id)delete ss[k];save();return R(200,{ok:true})}
  }
  return R(404,{erro:'Rota não encontrada.'});
}
// LOCAL-END


async function api(path,method='GET',body,token=tok.get()){
  if(LOCAL)return localApi(path,method,body,token);
  try{
    const r=await fetch(API+'/api'+path,{method,headers:{'Content-Type':'application/json',...(token?{Authorization:'Bearer '+token}:{})},body:body?JSON.stringify(body):undefined});
    const d=await r.json().catch(()=>({}));
    return{ok:r.ok,status:r.status,d};
  }catch{return{ok:false,status:0,d:{erro:'Não foi possível conectar ao servidor.'}}}
}

function go(v){
  if(v!=='auth'&&!me)return loginView();
  $('site').style.display=v==='site'?'block':'none';
  $('auth').style.display=v==='auth'?'block':'none';
  $('painel').style.display=v==='painel'?'block':'none';
  scrollTo(0,0);nav();
}
function nav(){
  $('nav').innerHTML=me?'<a href="#solucoes" onclick="go(\'site\')">Soluções</a><a href="#planos" onclick="go(\'site\')">Planos</a><a href="#equipe" onclick="go(\'site\')">Equipe</a><button onclick="go(\'painel\');painel()">Meu painel</button><button class="sec" onclick="logout()">Sair</button>':'';
}
function msg(t,ok){const m=$('msg');if(m){m.textContent=t;m.className='msg '+(ok?'ok':'err')}}

function loginView(mode='login'){
  pend=null;go('auth');const L=mode==='login';
  $('authBox').innerHTML=`<h2>${L?'Entrar':'Criar conta'}</h2><p class="sub" style="margin:6px 0 0">${L?'Acesse com e-mail e senha. Depois, confirme com '+(window.MFA_MODE==='email'?'o código enviado ao seu e-mail':'o código do autenticador')+'.':'Novas contas são criadas com perfil de usuário.'+(window.MFA_MODE==='email'?' Use um e-mail real: o código de verificação será enviado para ele.':'')}</p>
<div class="tabs"><button class="${L?'':'sec'}" onclick="loginView('login')">Login</button><button class="${L?'sec':''}" onclick="loginView('cad')">Cadastro</button></div>
${L?'':'<label>Nome</label><input id="nome" autocomplete="name">'}
<label>E-mail</label><input id="email" type="email" autocomplete="email"><label>Senha</label><input id="senha" type="password" autocomplete="${L?'current-password':'new-password'}">
<button id="go">${L?'Entrar':'Cadastrar'}</button><div class="msg" id="msg"></div>
`;
  $('go').onclick=L?doLogin:doCad;
}

async function doCad(){
  $('go').disabled=true;
  const r=await api('/cadastro','POST',{nome:$('nome').value,email:$('email').value,senha:$('senha').value},null);
  if(!r.ok){$('go').disabled=false;return msg(r.d.erro||'Erro ao cadastrar.')}
  loginView('login');msg('Cadastro realizado! Faça login.',true);
}

async function doLogin(){
  $('go').disabled=true;
  const r=await api('/login','POST',{email:$('email').value,senha:$('senha').value},null);
  if(!r.ok){$('go').disabled=false;return msg(r.d.erro||'Erro ao entrar.')}
  pend=r.d;mfaView();
}

function mfaView(){
  const S=pend.setup;
  if(pend.metodo==='email'){
    $('authBox').innerHTML=`<h2>Confirmação por e-mail</h2><p class="sub" style="margin:6px 0">Enviamos um código de 6 dígitos para <b>${esc(pend.email)}</b>. Ele vale por 5 minutos. Se não encontrar, olhe a caixa de spam.</p>${pend.codigoDemo?`<div class="card" style="margin-top:14px;text-align:center"><p>Modo demonstração: seu código é</p><div class="preco" style="letter-spacing:4px">${esc(pend.codigoDemo)}</div></div>`:''}<label>Código</label><input id="cod" inputmode="numeric" maxlength="8" autocomplete="one-time-code" value="${esc(pend.codigoDemo||'')}"><button id="go">Verificar</button><button class="sec" id="re">Reenviar código</button><div class="msg" id="msg"></div>`;
    $('go').onclick=doMfa;$('re').onclick=reenviar;return;
  }
  $('authBox').innerHTML=`<h2>Verificação em duas etapas</h2>
${S?`<p class="sub" style="margin:6px 0">Primeiro acesso: escaneie o QR code no Google Authenticator, Microsoft Authenticator ou Authy.</p><div id="qr"></div><p style="font-size:12px;color:var(--cinza)">Ou digite a chave manualmente:<br><code>${esc(pend.secret)}</code></p>`:'<p class="sub" style="margin:6px 0">Digite o código de 6 dígitos do seu aplicativo autenticador.</p>'}
${pend.codigoDemo?`<div class="card" style="margin-top:14px;text-align:center"><p>Modo demonstração: seu código agora é</p><div class="preco" style="letter-spacing:4px">${esc(pend.codigoDemo)}</div><p>Já preenchemos abaixo. Basta clicar em Verificar.</p></div>`:''}
<input id="cod" inputmode="numeric" maxlength="8" autocomplete="one-time-code" value="${esc(pend.codigoDemo||'')}"><button id="go">Verificar</button><div class="msg" id="msg"></div>`;
  if(S&&window.QRCode)new QRCode($('qr'),{text:pend.otpauth,width:160,height:160});
  $('go').onclick=doMfa;
}

async function reenviar(){
  const r=await api('/reenviar','POST',{},pend.token);
  if(r.ok){if(r.d.codigoDemo){pend.codigoDemo=r.d.codigoDemo;mfaView()}msg('Novo código enviado.',true)}
  else{if(r.d.reiniciar)loginView();msg(r.d.erro,false)}
}
async function doMfa(){
  const r=await api('/mfa','POST',{codigo:$('cod').value.replace(/\D/g,'')},pend.token);
  if(r.ok){
    tok.set(pend.token);pend=null;
    const p=await api('/perfil');me=p.d;go('painel');painel();return;
  }
  if(r.d.reiniciar){loginView();return msg(r.d.erro,false)}
  msg(r.d.erro||'Erro ao verificar o código.');
}

async function logout(){
  await api('/logout','POST');
  tok.clear();me=null;loginView();
}

async function painel(){
  const p=await api('/perfil');
  if(!p.ok){tok.clear();me=null;return loginView()}
  me=p.d;const u=me;
  const g=['gestor','administrador'].includes(u.perfil),a=u.perfil==='administrador';
  let extra='';
  if(a){
    const r=await api('/usuarios');
    const us=r.ok?r.d:[];
    extra=`<div class="card" style="margin-top:16px"><h3>Gestão de identidade e acesso (IAM)</h3><p>Defina o grupo de cada usuário, redefina o MFA ou exclua contas.</p><div style="overflow-x:auto"><table><tr><th>Nome</th><th>E-mail</th><th>Grupo</th><th>MFA</th><th>Ações</th></tr>${us.map(x=>{const eu=x.id===u.id;return `<tr><td>${esc(x.nome)}</td><td>${esc(x.email)}</td><td><select onchange="setPerfil(${x.id},this.value)" ${eu?'disabled':''}>${['usuario','gestor','administrador'].map(q=>`<option ${q===x.perfil?'selected':''}>${q}</option>`).join('')}</select></td><td>${x.mfa?'Ativo':'Pendente'}</td><td><button class="sec" onclick="resetMfa(${x.id})">Resetar MFA</button><button class="sec" onclick="delUser(${x.id})" ${eu?'disabled':''}>Excluir</button></td></tr>`}).join('')}</table></div></div>`;
  }else if(g){
    const r=await api('/resumo'),s=r.ok?r.d:{};
    extra=`<div class="card" style="margin-top:16px"><h3>Resumo de usuários</h3><p>Usuários: ${s.usuario||0} • Gestores: ${s.gestor||0} • Administradores: ${s.administrador||0}</p></div>`;
  }
  $('painel').innerHTML=`<div style="max-width:900px;margin:auto"><h2>Olá, ${esc(u.nome)}</h2><p class="sub">${esc(u.email)} • Perfil: <span class="tag">${esc(u.perfil)}</span></p>
<div class="grid">
<div class="card"><h3>Área do usuário</h3><p>Funcionalidades básicas do sistema.</p></div>
<div class="card ${g?'':'lock'}"><h3>Área de gestão ${g?'':'🔒'}</h3><p>${g?'Acesso liberado: acompanhamento de clientes, contratos e agenda.':'Requer perfil gestor ou administrador.'}</p></div>
<div class="card ${a?'':'lock'}"><h3>Área administrativa ${a?'':'🔒'}</h3><p>${a?'Acesso liberado: gestão de usuários abaixo.':'Requer perfil administrador.'}</p></div></div>${extra}</div>`;
}

async function setPerfil(id,perfil){const r=await api('/usuarios/'+id+'/perfil','PATCH',{perfil});if(!r.ok)alert(r.d.erro);painel()}
async function resetMfa(id){const r=await api('/usuarios/'+id+'/reset-mfa','POST');if(!r.ok)alert(r.d.erro);painel()}
async function delUser(id){if(!confirm('Excluir este usuário?'))return;const r=await api('/usuarios/'+id,'DELETE');if(!r.ok)alert(r.d.erro);painel()}

(async()=>{
  if(tok.get()){const p=await api('/perfil');if(p.ok){me=p.d;return go('site')}tok.clear()}
  loginView();
})();
