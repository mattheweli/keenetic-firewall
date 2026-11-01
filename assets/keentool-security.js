/* KeenTool Security UI v1.0.3 — 2026-11-01. Public diagnostics, authenticated writes. */
(() => {
 'use strict';
 let snapshot=null,pending=null,loading=false,lastGuardPoll=0,guardPolling=false;
 const byId=id=>document.getElementById(id);
 const number=value=>window.KTFormat.number(value,0,3);
 const stamp=epoch=>epoch?new Date(epoch*1000).toLocaleString('en-GB'):'Unavailable';
 // Disk capacity keeps decimal units; database files use explicitly labelled binary units.
 function storageSize(bytes,binary=false){
  if(typeof bytes!=='number'||!Number.isFinite(bytes)||bytes<0)return 'Unavailable';
  const base=binary?1024:1000,units=binary?['B','KiB','MiB','GiB','TiB','PiB']:['B','KB','MB','GB','TB','PB'];let unit=0,value=bytes;
  while(value>=base&&unit<units.length-1){value/=base;unit++;}
  if(Math.round(value*10)/10>=base&&unit<units.length-1){value/=base;unit++;}
  return value.toLocaleString('de-DE',{maximumFractionDigits:1})+' '+units[unit];
 }
 function renderDatabaseSizes(databases){
  const entries=Object.entries(databases||{}),valid=size=>Number.isSafeInteger(size)&&size>=0;
  table('security_databases',entries.map(([name,size])=>[name,valid(size)?storageSize(size,true):'Unavailable']));
  const body=byId('security_databases');
  entries.forEach(([,size],index)=>{
   const cell=body?.children[index]?.children[1];if(!cell||!valid(size))return;
   const exact=window.KTFormat.integer(size)+' bytes';
   cell.title=exact;cell.tabIndex=0;cell.setAttribute('aria-label',cell.textContent+' ('+exact+')');
  });
 }
 function healthResult(id,text,status){const element=byId(id);element.textContent=text;element.dataset.health=status;}
 function table(id,rows){const body=byId(id);if(!body)return;body.replaceChildren();for(const row of rows){const tr=document.createElement('tr');for(const value of row){const td=document.createElement('td');td.textContent=value==null?'Unavailable':String(value);tr.appendChild(td);}body.appendChild(tr);}if(!rows.length){const tr=document.createElement('tr'),td=document.createElement('td');td.textContent='No records available';td.colSpan=body.closest?.('table')?.querySelector('thead tr')?.children.length||1;tr.appendChild(td);body.appendChild(tr);}}
 function delta(current,previous){return !previous?(current?'New activity':'0%'):window.KTFormat.number((current-previous)/previous*100,1,1)+'%';}
 function renderEvents(){if(!snapshot)return;const category=byId('security_category')?.value||'all';const rows=(snapshot.events||[]).filter(e=>category==='all'||e.category===category);table('security_events',rows.map(e=>[stamp(e.time),e.category,e.event,e.target||'',e.outcome,e.detail||(e.category==='blocklist'&&e.outcome==='error'?'Failure reason was not recorded by the previous updater.':'')]));}
 function renderComparison(){if(!snapshot)return;const period=byId('security_compare_range')?.value||'day',data=snapshot.comparisons?.[period];
  if(!data){byId('security_comparison_note').textContent=snapshot.comparisons?.error||'Comparison pending';return;}
  const span=Number(data.seconds)||(period==='week'?604800:86400),end=Number(data.current_end||snapshot.system?.time)||Math.floor(Date.now()/1000),start=Number(data.current_start)||end-span,previous=Number(data.previous_start)||start-span;
  const currentLabel=period==='week'?'Last 7 days':'Last 24h',previousLabel=period==='week'?'Preceding 7 days':'Preceding 24h';
  for(const prefix of ['country','port']){if(byId('security_'+prefix+'_current_heading'))byId('security_'+prefix+'_current_heading').textContent=currentLabel;if(byId('security_'+prefix+'_previous_heading'))byId('security_'+prefix+'_previous_heading').textContent=previousLabel;}
  if(byId('security_comparison_periods'))byId('security_comparison_periods').textContent=currentLabel+': '+stamp(start)+' — '+stamp(end)+'. '+previousLabel+': '+stamp(previous)+' — '+stamp(start)+'. Times use your browser local time zone.';
  const total=data.summary||{};byId('security_comparison_note').textContent=currentLabel+': '+number(total.current)+' recorded hits · '+previousLabel+': '+number(total.previous)+' · change '+delta(Number(total.current),Number(total.previous))+'. Equal-length rolling periods ending at the snapshot time.';
  table('security_country_compare',(data.countries||[]).map(v=>[v.country==='XX'?'Unknown (XX)':v.country,number(v.current),number(v.previous),delta(Number(v.current),Number(v.previous))]));
  table('security_port_compare',(data.ports||[]).map(v=>[v.port,number(v.current),number(v.previous),delta(Number(v.current),Number(v.previous))]));
 }
 async function loadSecurityOverview(){
  if(!byId('view_security'))return;
  if(loading)return;loading=true;
  try{const response=await fetch('/firewall/security-data.json?t='+Date.now(),{cache:'no-store',credentials:'same-origin'});if(!response.ok)throw Error('Security snapshot not generated yet');snapshot=await response.json();const s=snapshot.system||{};
   const freshness=window.getKTSecurityFreshness?.(s.time,s.monitor_interval);
   byId('security_updated').textContent='Checked: '+stamp(s.time)+(freshness?.stale?' · snapshot older than '+freshness.label:'');
   const fwStatus=s.firewall?.healthy===true?'ok':s.firewall?.healthy===false?'error':'unknown';
   healthResult('security_fw',fwStatus==='ok'?(s.firewall.enabled?'Rules verified':'Intentionally disabled'):fwStatus==='error'?'Verification failed':'Not verified',fwStatus);
   const free=s.disk?.free,total=s.disk?.total,diskKnown=Number.isFinite(free)&&free>=0&&Number.isFinite(total)&&total>0;
   healthResult('security_disk',diskKnown?storageSize(free)+' free'+(free/total<0.05?' · Low space':''):'Unavailable',diskKnown?(free/total>=0.05?'ok':'error'):'unknown');
   healthResult('security_web',s.web_privileges||'Not verified',s.web_privileges==='unprivileged detected'?'ok':s.web_privileges==='root detected'?'error':'unknown');
   if(byId('security_web_note'))byId('security_web_note').textContent=s.isolation_configured?'Isolation configured. The process check must also show unprivileged detected.':'Web isolation has not been activated. Run firewall_security harden-web --check, then --apply from the router shell.';
   byId('security_backup_title').textContent=s.latest_verified_smb_backup?'Latest verified SMB backup':'Latest source backup';
   healthResult('security_backup',stamp(s.latest_verified_smb_backup?.time||s.latest_verified_source_backup||s.latest_source_backup),(s.latest_verified_smb_backup?.time||s.latest_verified_source_backup)?'ok':'unknown');
   byId('security_backup_note').textContent=s.latest_verified_smb_backup?'Read-back verified at upload: '+s.latest_verified_smb_backup.folder+'. Remote presence is not rechecked by this snapshot.':s.backup_note||'';
   renderDatabaseSizes(s.databases);
   table('security_services',Object.entries(s.services||{}).map(([name,up])=>[name,up?'Running':'Not detected']));
   table('security_lists',Object.entries(s.lists||{}).map(([name,row])=>[name,row.installed==null?'Count unavailable':number(row.installed),row.result==='rejected'?'Not applied':window.KTFormat.number(row.delta_percent,0,1)+'%',(row.result==='installed'&&row.baseline?'New baseline':row.result)+(row.warning?' · warning':''),[row.detail,row.source_warning].filter(Boolean).join(' ')||(row.result==='rejected'?'Failure reason was not recorded by the previous updater.':'No additional details recorded.'),stamp(row.time)]));
   table('security_manual',Object.entries(s.manual_bans||{}).map(([ip,row])=>[ip,row.expires?stamp(row.expires):'Permanent',stamp(row.created)]));
   byId('security_manual').querySelectorAll('tr').forEach(row=>{const ip=row.firstElementChild?.textContent;if(!ip||!/^[0-9a-fA-F:.\/]+$/.test(ip))return;const td=document.createElement('td');const details=document.createElement('button');details.type='button';details.className='btn-action';details.textContent='Details';details.onclick=()=>window.explainIP(ip);td.appendChild(details);const remove=document.createElement('button');remove.type='button';remove.className='btn-action';remove.textContent='Unban';remove.setAttribute('data-admin-only','');remove.hidden=typeof adminAuthenticated==='undefined'||!adminAuthenticated;remove.onclick=()=>unbanIP(ip);td.appendChild(remove);row.appendChild(td);});
   const review=byId('security_policy');review.textContent=Object.entries(s.bypasses||{}).map(([key,value])=>key+': '+value).join('\n')+'\n\nAdditional protected management networks: '+(s.management_networks||[]).join(', ')+'\n\nBypasses return control to subsequent router rules; they are not unconditional ACCEPT rules. WAN input interface and established connection state also matter.';
   renderEvents();renderComparison();
   window.KT_SECURITY_DATA={updated:s.time,monitorInterval:s.monitor_interval,status:'ready'};
  }catch(e){byId('security_updated').textContent=e.message;for(const id of ['security_fw','security_disk','security_web','security_backup'])healthResult(id,'Unavailable','unknown');window.KT_SECURITY_DATA={status:'error'};}finally{loading=false;window.updateKTDataState?.();}
 }
 window.loadSecurityOverview=loadSecurityOverview;
 window.policyGuardUpdate=function(data){
  pending=data?.pending||(data?.pending_id?data:null);const banner=byId('policy_guard');if(!banner)return;banner.hidden=!pending;
  if(pending)byId('policy_guard_text').textContent='Policy change pending. Confirm from this working connection before '+stamp(pending.confirm_before)+', otherwise the previous configuration will be restored.';
 };
 window.confirmPolicy=async function(){try{await refreshAdminAuth();await authRequest('confirm_policy',{pending_id:pending?.pending_id||''});pending=null;byId('policy_guard').hidden=true;await checkFirewallStatus();}catch(e){alert(e.message);}};
 window.rollbackPolicy=async function(){try{await refreshAdminAuth();await authRequest('rollback_policy',{});pending=null;byId('policy_guard').hidden=true;await checkFirewallStatus();}catch(e){alert(e.message);}};
 window.explainIP=async function(ip){
  const request=++modalRequest;currentModalDownloadName='ip_diagnostics_'+ip.replace(/[^a-zA-Z0-9_.-]/g,'_')+'.txt';
  byId('modalTitle').innerText='IP / subnet diagnostics: '+ip;byId('modalBody').innerText='Checking local firewall state...';byId('ipModal').style.display='block';
  try{const response=await fwFetch('/firewall/firewall_api.php?action=lookup&ip='+encodeURIComponent(ip));const data=await response.json();if(data.status!=='success')throw Error(data.message||'Lookup failed');
   const lines=['Address: '+data.ip,'Matching blocking lists: '+(data.lists?.join(', ')||'None'),'Whitelisted: '+(data.whitelisted?'yes':'no'),'Matching network bypasses: '+(data.bypass_networks?.join(', ')||'None'),'Firewall healthy: '+(data.health?.healthy?'yes':'no'),''];
   for(const row of data.matches||[])lines.push(row.set+(row.member?' · member '+row.member:'')+' · timeout '+(row.timeout_remaining===null?'unavailable':row.timeout_remaining===0?'permanent':row.timeout_remaining+'s')+' · packets '+(row.packets===null?'unavailable':number(row.packets))+' · bytes '+(row.bytes===null?'unavailable':number(row.bytes)));
   lines.push('\nMetadata:\n'+JSON.stringify(data.metadata,null,2),'\nRecorded IP/subnet hit totals (timestamps may be bucketed):\n'+JSON.stringify(data.counters,null,2),'\nMatching installed rules:\n'+(data.rules||[]).join('\n'),'\n'+data.explanation);
   if(request===modalRequest)byId('modalBody').innerText=lines.join('\n');
  }catch(e){if(request===modalRequest)byId('modalBody').innerText=e.message;}
 };
 window.attachIPDiagnostics=function(){document.querySelectorAll('a[href^="https://www.abuseipdb.com/check/"]').forEach(link=>{
  if(link.dataset.ktExplain)return;link.dataset.ktExplain='1';const ip=decodeURIComponent(link.href.split('/check/')[1]||'');if(!/^[0-9a-fA-F:.\/]+$/.test(ip))return;
  const button=document.createElement('button');button.type='button';button.className='kt-ip-details';button.textContent='Details';button.setAttribute('aria-label','Explain firewall state for '+ip);button.onclick=()=>window.explainIP(ip);link.after(button);
 });};
 window.loadSecurityAudit=async function(){try{await refreshAdminAuth();const data=await authRequest('audit');table('security_audit',(data.events||[]).map(e=>[stamp(e.time),e.event,e.actor,e.target,e.outcome,e.note]));}catch(e){alert(e.message);}};
 byId('security_category')?.addEventListener('change',renderEvents);byId('security_compare_range')?.addEventListener('change',renderComparison);
 window.attachIPDiagnostics();
 loadSecurityOverview();
 if(byId('view_security'))window.ktRefreshPage=()=>loadSecurityOverview();
 setInterval(()=>{if(!pending)return;const remaining=Math.max(0,pending.confirm_before-Math.floor(Date.now()/1000));byId('policy_guard_countdown').textContent=remaining+'s';if(!guardPolling&&Date.now()-lastGuardPoll>=5000){lastGuardPoll=Date.now();guardPolling=true;Promise.resolve(checkFirewallStatus()).finally(()=>{guardPolling=false;});}},1000);
})();
