// fabric.mjs — Vi-Smart Agent Fabric Orchestrator (Node>=18)
// v1.3: CI-safe (skip compose/deb via env), service wrapper auto, pattern mining esteso

import { readFile, writeFile, mkdir, chmod } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { spawn } from 'node:child_process';
import path from 'node:path';

const ROOT = process.cwd();
const VI = path.join(ROOT, '.vi-smart');
const CONTEXT = path.join(VI, 'context.json');
const JOURNAL = path.join(VI, 'journal.ndjson');
const ADR_DIR = path.join(VI, 'adr');
const PATTERNS = path.join(VI, 'patterns.json');

// CI/flags (saltano step "operativi" dentro le pipeline)
const SKIP_COMPOSE = process.env.VI_SMART_SKIP_COMPOSE === '1' || process.env.CI === 'true';
const SKIP_DEB     = process.env.VI_SMART_SKIP_DEB === '1'     || process.env.CI === 'true';
const SKIP_SBOM    = process.env.VI_SMART_SKIP_SBOM === '1';

function rand(){ return Math.random().toString(36).slice(2)+Date.now().toString(36); }
async function ensurePaths(){
  if(!existsSync(VI)) await mkdir(VI,{recursive:true});
  if(!existsSync(ADR_DIR)) await mkdir(ADR_DIR,{recursive:true});
  if(!existsSync(CONTEXT)){
    const ctx = {
      version: 1, project: 'vi-smart', session_id: rand(), task_id: rand(),
      objective: 'bootstrap fabric', assumptions: [], env: { os: 'ubuntu-22.04', runtime: 'node18' },
      tools_used: [], files_touched: [], decisions: [],
      progress: { phase: 'Acquire', step_index: 0, completed: [] },
      backlog_next: [], errors_seen: [], versions: {},
      timestamps: { created: new Date().toISOString(), updated: new Date().toISOString() }
    };
    await writeFile(CONTEXT, JSON.stringify(ctx,null,2));
  }
  if(!existsSync(JOURNAL)) await writeFile(JOURNAL,'');
  if(!existsSync(PATTERNS)) await writeFile(PATTERNS, JSON.stringify({rules:[],stats:{}},null,2));
}
async function loadContext(){ return JSON.parse(await readFile(CONTEXT,'utf8')); }
async function saveContext(ctx){ ctx.timestamps.updated = new Date().toISOString(); await writeFile(CONTEXT, JSON.stringify(ctx,null,2)); }
async function journal(ev){ await writeFile(JOURNAL, JSON.stringify({ts:new Date().toISOString(),...ev})+'\n', {flag:'a'}); }
async function loadPatterns(){ try{ return JSON.parse(await readFile(PATTERNS,'utf8')); }catch{ return {rules:[],stats:{}}; } }
async function savePatterns(p){ await writeFile(PATTERNS, JSON.stringify(p,null,2)); }

// ---- Minimal MCP client ----
function mcpCall(proc, method, params, id){
  return new Promise((resolve) => {
    const body = JSON.stringify({jsonrpc:"2.0", id, method, params});
    const msg = `Content-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`;
    let buf=''; const onData=(chunk)=>{
      buf += chunk.toString('utf8');
      for(;;){
        const i = buf.indexOf('\r\n\r\n'); if (i<0) break;
        const m = /Content-Length:\s*(\d+)/i.exec(buf.slice(0,i));
        const len = m ? parseInt(m[1],10) : 0;
        const start = i+4; if (buf.length - start < len) break;
        const body = buf.slice(start, start+len);
        buf = buf.slice(start+len);
        try{ const msg = JSON.parse(body); if (msg.id === id) { proc.stdout.off('data', onData); resolve(msg.result || msg.error); } }catch{}
      }
    };
    proc.stdout.on('data', onData);
    proc.stdin.write(msg);
  });
}
async function mcpStart(){
  const p = spawn('node', ['super-mcp.js'], { stdio: ['pipe','pipe','inherit'] });
  await mcpCall(p, 'initialize', {}, 1);
  return p;
}

// ---- Pattern Mining (basilare + esteso)
function minePatterns(text){
  const patterns = [
    { id:'node_cannot_find_module', re:/Cannot find module/i, remedy:'Esegui npm ci / verifica package.json / percorsi import.' },
    { id:'py_module_not_found',     re:/ModuleNotFoundError/i,  remedy:'pip install dipendenze; attiva venv corretto.' },
    { id:'eslint_error',            re:/ESLint.*(error|warning)/i, remedy:'Correggi regole o usa npx eslint --fix; aggiorna .eslintrc.' },
    { id:'ruff_error',              re:/ruff.*\d+\s+(error|violation)/i, remedy:'Allinea ruff.toml e format; isola regole ruvide.' },
    { id:'npm_audit_vuln',          re:/\b(moderate|high|critical)\b vulnerabilities/i, remedy:'npm audit fix / aggiorna dipendenze a minor sicuri.' },
    { id:'pytest_fail',             re:/===.*failed,?/i, remedy:'Aggiungi test di regressione e correggi il percorso del codice.' },
    { id:'jest_fail',               re:/Tests? failed/i, remedy:'Allinea jest config e mock dipendenze.' }
  ];
  const hits = patterns.filter(p => p.re.test(text||'')).map(p => ({id:p.id, remedy:p.remedy}));
  return hits;
}

// ---- Guilds (APL → Tools MCP)
const Guild = {
  async Code_globalScan(proc, ctx, { root='.', exts=['.js','.ts','.py'] }){
    const hits = {};
    for (const ext of exts){
      const res = await mcpCall(proc, 'tools/call', { name:'fs_find', arguments:{ root, ext } }, id());
      const arr = JSON.parse(res.content?.[0]?.text || '[]');
      hits[ext] = arr;
    }
    ctx.progress.completed.push('scan'); await saveContext(ctx);
    await journal({event:'code_global_scan',hits:Object.fromEntries(Object.entries(hits).map(([k,v])=>[k,v.length]))});
    return { issues_map: { core: Object.values(hits).some(a=>a.length>0), files: hits } };
  },

  async QA_lint(proc, ctx, { type, path='.' }){
    const res = await mcpCall(proc, 'tools/call', { name:'qa_lint', arguments:{ type, path } }, id());
    const out = (res.content?.[0]?.text||'');
    const mined = minePatterns(out);
    if (mined.length){ const patt = await loadPatterns(); patt.rules.push(...mined); await savePatterns(patt); }
    await journal({event:'qa_lint', out:out.slice(0,400), patterns:mined.map(m=>m.id)});
    return res;
  },

  async QA_test(proc, ctx, { type, path='.' }){
    const res = await mcpCall(proc, 'tools/call', { name:'qa_test', arguments:{ type, path } }, id());
    const out = (res.content?.[0]?.text||'');
    const mined = minePatterns(out);
    if (mined.length){ const patt = await loadPatterns(); patt.rules.push(...mined); await savePatterns(patt); }
    await journal({event:'qa_test', out:out.slice(0,400), patterns:mined.map(m=>m.id)});
    return res;
  },

  async DevOps_composeScaffold(proc, ctx, { path='docker-compose.yml', services }){
    const res = await mcpCall(proc, 'tools/call', { name:'devops_compose_scaffold', arguments:{ path, services } }, id());
    ctx.files_touched.push({ path, pre:null, post:'generated' });
    await journal({event:'compose_scaffold', path});
    return res;
  },
  async DevOps_composeApply(proc, ctx, { file='docker-compose.yml', action='up', project, detach=true }){
    if (SKIP_COMPOSE) { await journal({event:'compose_skip_ci'}); return {content:[{type:'text',text:'compose apply skipped (CI/SKIP flag)'}]}; }
    const res = await mcpCall(proc, 'tools/call', { name:'docker_compose', arguments:{ file, action, project, detach } }, id());
    await journal({event:'compose_'+action, file});
    return res;
  },

  async DevOps_serviceWrapper(_proc, ctx, { dist='dist', commandHint }){
    const dst = path.join(ROOT, dist);
    if (!existsSync(dst)) { await mkdir(dst, {recursive:true}); }
    const candidates = [
      { cmd: 'node server.js',  when: () => existsSync(path.join(ROOT,'server.js')) },
      { cmd: 'node index.js',   when: () => existsSync(path.join(ROOT,'index.js')) },
      { cmd: 'python3 main.py', when: () => existsSync(path.join(ROOT,'main.py')) },
      { cmd: commandHint || 'node index.js', when: () => true }
    ];
    const chosen = candidates.find(c => c.when())?.cmd || 'node index.js';
    const script = [
      '#!/usr/bin/env bash',
      'set -euo pipefail',
      'cd \"$(dirname \"$0\")/..\"',
      'export NODE_ENV=production',
      'export PYTHONUNBUFFERED=1',
      chosen
    ].join('\n')+'\n';
    const fp = path.join(dst, 'start.sh');
    await writeFile(fp, script, 'utf8');
    await chmod(fp, 0o755);
    ctx.files_touched.push({ path: fp, pre:null, post:'generated+x' });
    await saveContext(ctx);
    await journal({event:'service_wrapper', path: fp, cmd: chosen});
    return {content:[{type:'text',text:`service wrapper scritto: ${fp} (${chosen})`}]};
  },

  async DevOps_debBuild(proc, ctx, { name='vi-smart', version='0.1.0', arch='amd64', input_dir='dist', out_dir='out', service=null, description }){
    if (SKIP_DEB) { await journal({event:'deb_skip_ci'}); return {content:[{type:'text',text:'deb build skipped (CI/SKIP flag)'}]}; }
    const res = await mcpCall(proc,'tools/call',{ name:'devops_deb_build', arguments:{
      name, version, arch, input_dir, out_dir, description, systemd_service: service
    }}, id());
    await journal({event:'deb_build', name, version});
    return res;
  },

  async DevOps_sbom(proc, ctx, { target='.' , format='cyclonedx-json', output }){
    if (SKIP_SBOM) { await journal({event:'sbom_skip'}); return {content:[{type:'text',text:'SBOM skipped (SKIP flag)'}]}; }
    const res = await mcpCall(proc,'tools/call',{ name:'devops_sbom', arguments:{ target, format, output }}, id());
    await journal({event:'sbom', target});
    return res;
  },

  async Security_audit(proc, ctx, { type='node', path='.' }){
    const res = await mcpCall(proc,'tools/call',{ name:'security_audit', arguments:{ type, path }}, id());
    const out = (res.content?.[0]?.text||'');
    const mined = minePatterns(out);
    if (mined.length){ const patt = await loadPatterns(); patt.rules.push(...mined); await savePatterns(patt); }
    await journal({event:'security_audit', out: out.slice(0,400), patterns:mined.map(m=>m.id)});
    return res;
  },

  async OpenAPI_lint(proc, ctx, { spec_path }){
    const res = await mcpCall(proc,'tools/call',{ name:'openapi_lint_spectral', arguments:{ spec_path }}, id());
    await journal({event:'openapi_lint', spec_path, out:(res.content?.[0]?.text||'').slice(0,400)});
    return res;
  },

  async Research_web(proc, ctx, { queries, limit=4 }){
    const all = [];
    for (const q of queries){
      const r = await mcpCall(proc,'tools/call',{ name:'web_search', arguments:{ q, limit }}, id());
      try {
        const arr = JSON.parse(r.content?.[0]?.text||'{"results":[]}').results || [];
        all.push(...arr.map(it=>({title: it.title, url: it.url})));
      } catch {}
    }
    return dedupUrls(all).slice(0,8);
  },

  async Docs_ADR(proc, ctx, { title, context, decision, consequences, sources }){
    const res = await mcpCall(proc,'tools/call',{ name:'docs_adr_write', arguments:{ title, context, decision, consequences, sources, dir: ADR_DIR }}, id());
    ctx.decisions.push({ id: title, summary: decision, timestamp: new Date().toISOString() });
    await saveContext(ctx);
    return res;
  },

  async Docs_README(proc, ctx, { context_path=CONTEXT, adr_dir=ADR_DIR, output='README.md' }){
    const res = await mcpCall(proc,'tools/call',{ name:'docs_readme_synth', arguments:{ context_path, adr_dir, output }}, id());
    await journal({event:'readme_synth', file: output});
    return res;
  }
};

function id(){ return Math.random().toString(36).slice(2); }
function dedupUrls(arr){ const seen=new Set(); const out=[]; for(const x of arr){ if(!seen.has(x.url)){ seen.add(x.url); out.push(x); } } return out; }

// ---- Planner: APL dinamica ----
async function deriveAPL(){
  const steps = [{ id:'scan', do:'code.global_scan', with:{ root:'.' } }];

  const hasPkg = existsSync(path.join(ROOT, 'package.json'));
  const hasPy  = existsSync(path.join(ROOT, 'pyproject.toml')) || existsSync(path.join(ROOT,'requirements.txt'));
  if (hasPkg) steps.push({ id:'lint_node', do:'qa.lint', with:{ type:'node', path:'.' } });
  if (hasPy)  steps.push({ id:'lint_py',   do:'qa.lint', with:{ type:'python', path:'.' } });
  if (hasPkg) steps.push({ id:'test_node', do:'qa.test', with:{ type:'node', path:'.' } });
  if (hasPy)  steps.push({ id:'test_py',   do:'qa.test', with:{ type:'python', path:'.' } });

  // Compose auto (solo scaffold in CI)
  if (existsSync(path.join(ROOT, 'Dockerfile'))){
    steps.push({ id:'compose_scaffold', do:'devops.compose_scaffold', with:{ path:'docker-compose.yml' } });
    if (!SKIP_COMPOSE) {
      steps.push({ id:'compose_up', do:'devops.compose_apply', with:{ file:'docker-compose.yml', action:'up', project:'vi-smart', detach:true } });
    }
  }

  // Service wrapper prima del .deb
  steps.push({ id:'service_wrapper', do:'devops.service_wrapper', with:{ dist:'dist' } });

  // OpenAPI lint (se presente)
  const openapi = ['openapi.yaml','openapi.yml','openapi.json'].map(f=>path.join(ROOT,f)).find(f=>existsSync(f));
  if (openapi) steps.push({ id:'openapi_lint', do:'openapi.lint', with:{ spec_path: openapi } });

  // SBOM (skippabile)
  steps.push({ id:'sbom', do:'devops.sbom', with:{ target:'.', format:'cyclonedx-json' } });

  // Security audit
  const hasPkg = existsSync(path.join(ROOT, 'package.json'));
  const hasPy2  = existsSync(path.join(ROOT, 'pyproject.toml')) || existsSync(path.join(ROOT,'requirements.txt'));
  if (hasPkg) steps.push({ id:'audit_node', do:'security.audit', with:{ type:'node', path:'.' } });
  if (hasPy2)  steps.push({ id:'audit_py',   do:'security.audit', with:{ type:'python', path:'.' } });

  // Packaging .deb (solo fuori CI)
  if (!SKIP_DEB) {
    const distDir = path.join(ROOT,'dist');
    if (existsSync(distDir)){
      const service = [
        '[Unit]','Description=vi-smart service','After=network.target','',
        '[Service]','Type=simple','ExecStart=/opt/vi-smart/start.sh','Restart=on-failure','User=root','',
        '[Install]','WantedBy=multi-user.target'
      ].join('\n');
      steps.push({ id:'deb_build', do:'devops.deb_build', with:{ name:'vi-smart', version:'0.1.0', input_dir:'dist', out_dir:'out', service } });
    }
  }

  // Web MAX + ADR + README synth
  steps.push({ id:'research', do:'research.web', with:{ queries:[
    'docker compose best practices 2024',
    'fpm deb packaging systemd best practices',
    'lint strategy monorepo 2024',
    'openapi spectral lint rules modern'
  ]}});
  steps.push({ id:'adr', do:'docs.adr', with:{
    title:'Tooling baseline (Compose + Service Wrapper + .deb + Lint/Test + SBOM + Audit)',
    context:'Baseline riproducibile cross-stack per Vi-Smart con orchestrazione locale, service wrapper per .deb, qualità e sicurezza.',
    decision:'Compose per orchestrazione, wrapper start.sh in /opt, fpm per .deb, lint/test per stack node/python, SBOM via syft e audit deps.',
    consequences:'Setup coerente; rischi: dipendenze locali; mitigazione: flag CI/skip e ADR.',
  }});
  steps.push({ id:'readme', do:'docs.readme', with:{} });

  return steps;
}

// ---- Orchestrator ----
async function runStep(proc, ctx, step, memo){
  await journal({event:'step_start', step:step.id});
  let res;
  switch(step.do){
    case 'code.global_scan':           res = await Guild.Code_globalScan(proc, ctx, step.with||{}); break;
    case 'qa.lint':                    res = await Guild.QA_lint(proc, ctx, step.with||{}); break;
    case 'qa.test':                    res = await Guild.QA_test(proc, ctx, step.with||{}); break;
    case 'devops.compose_scaffold':    res = await Guild.DevOps_composeScaffold(proc, ctx, step.with||{}); break;
    case 'devops.compose_apply':       res = await Guild.DevOps_composeApply(proc, ctx, step.with||{}); break;
    case 'devops.service_wrapper':     res = await Guild.DevOps_serviceWrapper(null, ctx, step.with||{}); break;
    case 'devops.deb_build':           res = await Guild.DevOps_debBuild(proc, ctx, step.with||{}); break;
    case 'devops.sbom':                res = await Guild.DevOps_sbom(proc, ctx, step.with||{}); break;
    case 'security.audit':             res = await Guild.Security_audit(proc, ctx, step.with||{}); break;
    case 'openapi.lint':               res = await Guild.OpenAPI_lint(proc, ctx, step.with||{}); break;
    case 'research.web': {
      const cites = await Guild.Research_web(proc, ctx, step.with||{});
      memo.web_sources = cites; res = { cites };
      break;
    }
    case 'docs.adr': {
      const payload = { ...(step.with||{}), sources: (step.with?.sources && step.with.sources.length? step.with.sources : (memo.web_sources||[])) };
      res = await Guild.Docs_ADR(proc, ctx, payload); break;
    }
    case 'docs.readme': {
      res = await Guild.Docs_README(proc, ctx, step.with||{});
      break;
    }
    default:
      res = { content:[{type:'text',text:'noop'}] };
  }
  ctx.progress.completed.push(step.id);
  await saveContext(ctx);
  await journal({event:'step_ok', step:step.id});
  return res;
}

async function main(){
  await ensurePaths();
  const ctx = await loadContext();
  const proc = await mcpStart();
  const apl = await deriveAPL();

  let memo = {};
  for (let i = ctx.progress.step_index; i < apl.length; i++){
    const step = apl[i];
    try{
      await runStep(proc, ctx, step, memo);
      ctx.progress.step_index = i+1;
      await saveContext(ctx);
    }catch(e){
      ctx.errors_seen.push({when: step.id, stderr_snippet: String(e), resolution: 'retry/backoff pending'});
      await saveContext(ctx);
      await journal({event:'step_error', step:step.id, error:String(e)});
      break;
    }
  }
  await journal({event:'run_done'});
}

main().catch(async (e)=>{ await journal({event:'fatal', error:String(e)}); console.error(e); });