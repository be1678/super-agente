// super-mcp.js
// Vi-Smart Super MCP Server (Node>=18, single-file, stdio JSON-RPC 2.0)
// v1.3: aggiunto docs_adr_write + fix minori
(() => {
  const os = require('os');
  const cp = require('child_process');
  const fs = require('fs');
  const fsp = require('fs/promises');
  const path = require('path');
  const crypto = require('crypto');

  // ---------- framing JSON-RPC via stdio ----------
  const encLen = (s) => Buffer.byteLength(s, 'utf8');
  function send(id, result, error) {
    const msg = error ? { jsonrpc: '2.0', id, error } : { jsonrpc: '2.0', id, result };
    const s = JSON.stringify(msg);
    process.stdout.write('Content-Length: ' + encLen(s) + '\r\n\r\n' + s);
  }
  let buf = '';
  process.stdin.on('data', (chunk) => {
    buf += chunk.toString('utf8');
    for (;;) {
      const i = buf.indexOf('\r\n\r\n');
      if (i < 0) break;
      const head = buf.slice(0, i);
      const m = /Content-Length:\s*(\d+)/i.exec(head);
      if (!m) { buf = buf.slice(i + 4); continue; }
      const len = parseInt(m[1], 10);
      const start = i + 4;
      if (buf.length - start < len) break;
      const body = buf.slice(start, start + len);
      buf = buf.slice(start + len);
      try { handle(JSON.parse(body)); } catch {}
    }
  });

  // ---------- helpers ----------
  const has = (bin) => new Promise((r) => {
    const cmd = os.platform() === 'win32' ? 'where' : 'which';
    cp.exec(cmd + ' ' + bin, (e, so) => r(!e && !!so.toString().trim()));
  });
  const which = (bin) => new Promise((r) => {
    const cmd = os.platform() === 'win32' ? 'where' : 'which';
    cp.exec(cmd + ' ' + bin, (e, so) => r(!e ? so.toString().trim().split(/\r?\n/)[0] : ''));
  });
  function run(cmd, args = [], opt = {}) {
    return new Promise((res) => {
      const p = cp.spawn(cmd, args, { cwd: opt.cwd || process.cwd(), shell: false });
      let so = '', se = '', killed = false, t;
      if (opt.timeoutMs) t = setTimeout(() => { killed = true; try{p.kill();}catch{}; res({code:-1,stdout:so,stderr:'TIMEOUT'}); }, opt.timeoutMs);
      p.stdout.on('data', d => so += d.toString());
      p.stderr.on('data', d => se += d.toString());
      p.on('close', c => { if (t) clearTimeout(t); res({ code: killed?-1:(c??0), stdout: so, stderr: se }); });
      p.on('error', e => { if (t) clearTimeout(t); res({ code: -1, stdout: so, stderr: String(e) }); });
    });
  }

  const ALLOW_SHELL = (process.env.SUPER_MCP_ALLOW_SHELL ?? 'true').toLowerCase() !== 'false';
  const RAW_ALLOWLIST = (process.env.SUPER_MCP_SHELL_ALLOWLIST ||
    'bash,sh,pwsh,powershell,python,node,uv,pip,pip3,npm,pnpm,yarn,git,docker,docker-compose,ffmpeg,ffprobe,convert,magick,zip,unzip,ls,dir,pwd,echo,cat,grep,sed,awk,sha256sum,go,make,tar,gs,syft,fpm,npx')
    .split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
  function shellAllowed(cmd){ if(!ALLOW_SHELL) return false; if (RAW_ALLOWLIST.includes('*')) return true; return RAW_ALLOWLIST.includes(path.basename(cmd).toLowerCase()); }

  // ---------- core/tools ----------
  const tools = {
    env_check: {
      description: 'OS/arch/cwd/allowlist/binari presenti',
      inputSchema: { type: 'object', properties: {}, additionalProperties: false },
      run: async () => {
        const bins = ['git','docker','ffmpeg','ffprobe','convert','magick','zip','unzip','syft','gs','python','pip','node','npx','fpm'];
        const presence = {}; for (const b of bins) presence[b] = await which(b);
        return { content: [{ type: 'text', text: JSON.stringify({ platform: os.platform(), arch: os.arch(), node: process.version, cwd: process.cwd(), shellAllowed: ALLOW_SHELL, allowlist: RAW_ALLOWLIST, binaries: presence }, null, 2) }] };
      }
    },

    http_request: {
      description: 'HTTP(S) request (Node fetch)',
      inputSchema: { type:'object',properties:{method:{type:'string'},url:{type:'string'},headers:{type:'object'},body:{type:'string'},timeout_ms:{type:'number'}},required:['url'],additionalProperties:false },
      run: async ({method,url,headers,body,timeout_ms}) => {
        const ac = new AbortController(); let t;
        try { if (timeout_ms) t = setTimeout(() => ac.abort(), timeout_ms);
          const r = await fetch(url, { method: method || 'GET', headers, body, signal: ac.signal });
          const text = await r.text();
          return { content: [{ type:'text', text: JSON.stringify({ ok:r.ok,status:r.status,headers:Object.fromEntries(r.headers.entries()), body:text.slice(0,200000)},null,2) }] };
        } catch (e) { return { content: [{ type:'text', text: String(e) }] }; }
        finally { if (t) clearTimeout(t); }
      }
    },

    web_search: {
      description: 'Ricerca web (DuckDuckGo HTML parse)',
      inputSchema: { type:'object',properties:{q:{type:'string'},limit:{type:'number'}},required:['q'],additionalProperties:false },
      run: async ({q,limit}) => {
        const url='https://duckduckgo.com/html/?q='+encodeURIComponent(q)+'&kl=wt-wt';
        try{
          const res=await fetch(url); const html=await res.text();
          const re=/<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)<\/a>[\s\S]*?<a[^>]+class="result__snippet"[^>]*>(.*?)<\/a>/g;
          let m,items=[]; while((m=re.exec(html)) && items.length<(limit||5)){ items.push({url:m[1],title:m[2].replace(/<[^>]+>/g,''),snippet:m[3].replace(/<[^>]+>/g,'')}); }
          return { content:[{type:'text',text:JSON.stringify({query:q,results:items},null,2)}] };
        }catch(e){ return { content:[{type:'text',text:String(e)}] }; }
      }
    },

    // FS base
    fs_read:   { description:'Leggi file', inputSchema:{type:'object',properties:{path:{type:'string'},encoding:{type:'string','enum':['utf-8','base64']},max_bytes:{type:'number'}},required:['path'],additionalProperties:false},
      run: async ({path:p,encoding,max_bytes}) => { const b=await fsp.readFile(p); const data=max_bytes?b.slice(0,max_bytes):b; return {content:[{type:'text',text:(encoding==='base64'?data.toString('base64'):data.toString('utf8'))}]}; } },
    fs_write:  { description:'Scrivi file (mkdirp)', inputSchema:{type:'object',properties:{path:{type:'string'},content:{type:'string'},encoding:{type:'string','enum':['utf-8','base64']},mkdirp:{type:'boolean'}},required:['path','content'],additionalProperties:false},
      run: async ({path:p,content,encoding,mkdirp}) => { if(mkdirp) await fsp.mkdir(path.dirname(p),{recursive:true}); const buf=encoding==='base64'?Buffer.from(content,'base64'):Buffer.from(content,'utf8'); await fsp.writeFile(p,buf); return {content:[{type:'text',text:'Wrote '+buf.length+' bytes to '+p}]}; } },
    fs_list:   { description:'Lista dir', inputSchema:{type:'object',properties:{dir:{type:'string'}},required:['dir'],additionalProperties:false},
      run: async ({dir}) => { const items=await fsp.readdir(dir,{withFileTypes:true}); return {content:[{type:'text',text:JSON.stringify(items.map(i=>({name:i.name,type:i.isDirectory()?'dir':'file'})),null,2)}]}; } },
    fs_find:   { description:'Find ricorsivo per estensione', inputSchema:{type:'object',properties:{root:{type:'string'},ext:{type:'string'}},required:['root','ext'],additionalProperties:false},
      run: async ({root,ext}) => { async function walk(d,acc){ const list=await fsp.readdir(d,{withFileTypes:true}); for(const e of list){ const p=path.join(d,e.name); if(e.isDirectory()) await walk(p,acc); else if(e.isFile()&&p.toLowerCase().endsWith(ext.toLowerCase())) acc.push(p);} } const acc=[]; await walk(root,acc); return {content:[{type:'text',text:JSON.stringify(acc,null,2)}]}; } },

    // Shell / Git / Docker
    shell_run: {
      description:'Esegui comando (allowlist)',
      inputSchema:{type:'object',properties:{cmd:{type:'string'},args:{type:'array','items':{'type':'string'}},cwd:{type:'string'},timeout_ms:{type:'number'},dry_run:{type:'boolean'}},required:['cmd'],additionalProperties:false},
      run: async ({cmd,args,cwd,timeout_ms,dry_run}) => {
        if(!ALLOW_SHELL) return {content:[{type:'text',text:'Shell disabilitata (SUPER_MCP_ALLOW_SHELL=false)'}]};
        if(!shellAllowed(cmd)) return {content:[{type:'text',text:`Comando non in allowlist: ${path.basename(cmd)}. Consentiti: ${RAW_ALLOWLIST.join(', ')}`}]};
        if(dry_run) return {content:[{type:'text',text:`DRY RUN: ${cmd} ${(args||[]).join(' ')} (cwd=${cwd||process.cwd()})`}]};
        const r=await run(cmd,args||[],{cwd,timeoutMs:timeout_ms||120000});
        return {content:[{type:'text',text:JSON.stringify(r,null,2)}]};
      }
    },
    git_clone:  { description:'git clone',  inputSchema:{type:'object',properties:{repo:{type:'string'},dest:{type:'string'}},required:['repo','dest'],additionalProperties:false}, run: async ({repo,dest}) => { await fsp.mkdir(dest,{recursive:true}); const r=await run('git',['clone',repo,dest],{}); return {content:[{type:'text',text:r.stdout||r.stderr}]}; } },
    git_status: { description:'git status', inputSchema:{type:'object',properties:{dir:{type:'string'}},required:['dir'],additionalProperties:false}, run: async ({dir}) => { const r=await run('git',['-C',dir,'status','--porcelain','-b'],{}); return {content:[{type:'text',text:r.stdout||r.stderr}]}; } },
    git_pull:   { description:'git pull',   inputSchema:{type:'object',properties:{dir:{type:'string'}},required:['dir'],additionalProperties:false}, run: async ({dir}) => { const r=await run('git',['-C',dir,'pull'],{}); return {content:[{type:'text',text:r.stdout||r.stderr}]}; } },

    // Docker/Compose + scaffold
    docker_build: { description:'docker build', inputSchema:{type:'object',properties:{context:{type:'string'},tag:{type:'string'}},required:['context','tag'],additionalProperties:false}, run: async ({context,tag}) => { const r=await run('docker',['build','-t',tag,context],{timeoutMs:3600000}); return {content:[{type:'text',text:r.stdout||r.stderr}]}; } },
    docker_compose: {
      description:'docker compose up/down',
      inputSchema:{type:'object',properties:{file:{type:'string'},action:{type:'string','enum':['up','down']},project:{type:'string'},detach:{type:'boolean'}},additionalProperties:false},
      run: async ({file,action,project,detach}) => { const args=['compose']; if(project){args.unshift('-p',project)} if(file) args.push('-f',file); args.push(action||'up'); if((action||'up')==='up' && (detach??true)) args.push('-d'); const r=await run('docker',args,{timeoutMs:600000}); return {content:[{type:'text',text:r.stdout||r.stderr}]}; }
    },
    devops_compose_scaffold: {
      description:'Genera docker-compose.yml (auto se Dockerfile)',
      inputSchema:{type:'object',properties:{path:{type:'string'},services:{type:'array',items:{type:'object'}}},additionalProperties:false},
      run: async ({path:fp='docker-compose.yml',services})=>{
        let svc = services;
        if(!svc || !svc.length){
          if (fs.existsSync('./Dockerfile')) {
            svc = [{ name:'app', build:'.', ports:['8080:8080'], env:{} }];
          } else {
            return {content:[{type:'text',text:'Nessun servizio fornito e nessun Dockerfile trovato'}]};
          }
        }
        const lines = ['version: "3.9"','services:'];
        for (const s of svc){
          lines.push(`  ${s.name}:`);
          if (s.build) lines.push(`    build: ${s.build}`);
          if (s.image) lines.push(`    image: ${s.image}`);
          if (s.command) lines.push(`    command: ${JSON.stringify(s.command)}`);
          if (s.ports?.length){ lines.push('    ports:'); for(const p of s.ports) lines.push(`      - "${p}"`); }
          if (s.env && Object.keys(s.env).length){ lines.push('    environment:'); for(const [k,v] of Object.entries(s.env)) lines.push(`      ${k}: "${v}"`); }
          if (s.volumes?.length){ lines.push('    volumes:'); for(const v of s.volumes) lines.push(`      - ${v}`); }
          if (s.depends_on?.length){ lines.push('    depends_on:'); for(const d of s.depends_on) lines.push(`      - ${d}`); }
          if (s.restart) lines.push(`    restart: ${s.restart}`);
        }
        await fsp.writeFile(fp, lines.join('\n'), 'utf8');
        return {content:[{type:'text',text:`compose scritto: ${fp}`} ]};
      }
    },

    // Packaging .deb (con maintainer scripts & systemd)
    devops_deb_build: {
      description: 'Crea .deb con fpm (+ systemd + postinst/prerm/postrm)',
      inputSchema: {
        type:'object',
        properties: {
          name:{type:'string'}, version:{type:'string'}, arch:{type:'string'},
          input_dir:{type:'string'}, out_dir:{type:'string'},
          systemd_service:{type:'string'}, description:{type:'string'}
        },
        required:['name','version','input_dir','out_dir'],
        additionalProperties:false
      },
      run: async ({name,version,arch='amd64',input_dir,out_dir,systemd_service,description})=>{
        if(!await has('fpm')) return {content:[{type:'text',text:'fpm non presente. Installa: gem install --no-document fpm'}]};
        await fsp.mkdir(out_dir,{recursive:true});
        const prefix = `/opt/${name}`;
        const tmp = path.join(process.cwd(), `.tmp-deb-${Date.now()}`);
        await fsp.mkdir(tmp,{recursive:true});

        // maintainer scripts
        const postinst = [
          '#!/bin/sh',
          'set -e',
          systemd_service ? `systemctl daemon-reload || true` : '',
          systemd_service ? `systemctl enable ${name}.service || true` : '',
          systemd_service ? `systemctl restart ${name}.service || true` : '',
          'exit 0'
        ].filter(Boolean).join('\n');
        const prerm = [
          '#!/bin/sh',
          'set -e',
          systemd_service ? `systemctl stop ${name}.service || true` : '',
          'exit 0'
        ].filter(Boolean).join('\n');
        const postrm = [
          '#!/bin/sh',
          'set -e',
          systemd_service ? `systemctl disable ${name}.service || true` : '',
          'exit 0'
        ].filter(Boolean).join('\n');

        const postinstPath = path.join(tmp,'postinst'); await fsp.writeFile(postinstPath,postinst,{mode:0o755});
        const prermPath    = path.join(tmp,'prerm');    await fsp.writeFile(prermPath,prerm,{mode:0o755});
        const postrmPath   = path.join(tmp,'postrm');   await fsp.writeFile(postrmPath,postrm,{mode:0o755});

        let args = ['-s','dir','-t','deb','-n',name,'-v',version,'--architecture',arch,'--prefix',prefix,
          '--after-install', postinstPath, '--before-remove', prermPath, '--after-remove', postrmPath];
        if (description) args.push('--description', description);

        if (systemd_service){
          const unitPath = path.join(tmp, `${name}.service`);
          await fsp.writeFile(unitPath, systemd_service, 'utf8');
          args.push('--deb-systemd', unitPath);
        }
        args.push(input_dir + '/=.');
        const r=await run('fpm', args, {timeoutMs:600000});
        return {content:[{type:'text',text:r.stdout || r.stderr || ('deb creato in '+out_dir)}]};
      }
    },

    // QA Guild
    qa_lint: {
      description:'Lint generico (ruff/eslint se presenti)',
      inputSchema:{type:'object',properties:{type:{type:'string','enum':['python','node']},path:{type:'string'}},required:['type'],additionalProperties:false},
      run: async ({type,path:dir='.'})=>{
        if (type==='python'){
          if (!await has('ruff')) return {content:[{type:'text',text:'ruff non presente'}]};
          const r = await run('ruff', ['check', dir], {});
          return {content:[{type:'text',text:r.stdout || r.stderr}]};
        } else {
          if (!await has('npx')) return {content:[{type:'text',text:'npx non presente'}]};
          const r = await run('npx', ['eslint', dir, '--ext', '.js,.ts,.tsx'], {});
          return {content:[{type:'text',text:r.stdout || r.stderr}]};
        }
      }
    },
    qa_test: {
      description:'Test generico (pytest/jest se presenti)',
      inputSchema:{type:'object',properties:{type:{type:'string','enum':['python','node']},path:{type:'string'}},required:['type'],additionalProperties:false},
      run: async ({type,path:dir='.'})=>{
        if (type==='python'){
          if (!await has('pytest')) return {content:[{type:'text',text:'pytest non presente'}]};
          const r = await run('pytest', ['-q', dir], {timeoutMs:600000});
          return {content:[{type:'text',text:r.stdout || r.stderr}]};
        } else {
          if (!await has('npx')) return {content:[{type:'text',text:'npx non presente'}]};
          const r = await run('npx', ['jest', '--coverage', dir], {timeoutMs:600000});
          return {content:[{type:'text',text:r.stdout || r.stderr}]};
        }
      }
    },

    // Security & SBOM
    devops_sbom: {
      description:'SBOM con syft (wrapper)',
      inputSchema:{type:'object',properties:{target:{type:'string'},format:{type:'string','enum':['cyclonedx-json','spdx-json']},output:{type:'string'}},required:['target'],additionalProperties:false},
      run: async ({target,format,output}) => {
        if(!await has('syft')) return {content:[{type:'text',text:'syft non presente'}]};
        const fmt=format||'cyclonedx-json'; const out=output||path.join(process.cwd(),'sbom.'+fmt+'.json');
        const r=await run('syft',[target,'-o',fmt,'-q'],{}); if(r.code!==0) return {content:[{type:'text',text:r.stderr||r.stdout}]};
        await fsp.writeFile(out,r.stdout,'utf8'); return {content:[{type:'text',text:'SBOM scritto: '+out}]};
      }
    },
    security_audit: {
      description:'Audit dipendenze (npm audit / pip-audit fallback)',
      inputSchema:{type:'object',properties:{type:{type:'string','enum':['node','python']},path:{type:'string'}},required:['type'],additionalProperties:false},
      run: async ({type,path:dir='.'})=>{
        if (type==='node'){
          if (!await has('npm')) return {content:[{type:'text',text:'npm non presente'}]};
          const r = await run('npm', ['audit','--json','--audit-level=moderate'], {cwd:dir,timeoutMs:600000});
          return {content:[{type:'text',text:r.stdout || r.stderr}]};
        } else {
          if (await has('pip-audit')){
            const r = await run('pip-audit', ['-f','json'], {cwd:dir,timeoutMs:600000});
            return {content:[{type:'text',text:r.stdout || r.stderr}]};
          } else {
            const r = await run('pip', ['list','--outdated','--format','json'], {cwd:dir,timeoutMs:600000});
            return {content:[{type:'text',text:r.stdout || r.stderr}]};
          }
        }
      }
    },

    // OpenAPI lint (spectral) + fallback
    openapi_validate: {
      description:'Check OpenAPI (JSON/YAML)',
      inputSchema:{type:'object',properties:{spec_path:{type:'string'}},required:['spec_path'],additionalProperties:false},
      run: async ({spec_path})=>{ try{ let raw=await fsp.readFile(spec_path,'utf8'); let obj=null;
        try{ obj=JSON.parse(raw);}catch{ try{ const y2j=await tools.yaml_to_json.run({yaml:raw}); obj=JSON.parse(y2j.content?.[0]?.text||'{}'); }catch{ obj=null; } }
        const ok=!!(obj&&(obj.openapi||obj.swagger)); return {content:[{type:'text',text:JSON.stringify({ok,version:(obj&&(obj.openapi||obj.swagger))||null},null,2)}]}; }catch(e){ return {content:[{type:'text',text:String(e)}]}; } }
    },
    openapi_lint_spectral: {
      description:'Lint OpenAPI con Spectral (npx @stoplight/spectral-cli)',
      inputSchema:{type:'object',properties:{spec_path:{type:'string'}},required:['spec_path'],additionalProperties:false},
      run: async ({spec_path})=>{
        if(!await has('npx')) return {content:[{type:'text',text:'npx non presente'}]};
        const r = await run('npx', ['-y','@stoplight/spectral-cli','lint', spec_path, '-f','json'], {timeoutMs:600000});
        if ((r.stdout||'').trim()) return {content:[{type:'text',text:r.stdout}]};
        // fallback a validate
        return tools.openapi_validate.run({spec_path});
      }
    },

    // YAML/JSON bridge & media
    yaml_to_json: { description:'YAML→JSON (PyYAML)', inputSchema:{type:'object',properties:{yaml:{type:'string'}},required:['yaml'],additionalProperties:false}, run: async ({yaml})=>{ if(!await has('python')) return {content:[{type:'text',text:'python non presente'}]}; const py='import sys,json\\ntry:\\n import yaml\\n data=yaml.safe_load(sys.stdin.read())\\n print(json.dumps(data))\\nexcept Exception as e:\\n print(str(e), file=sys.stderr)\\n sys.exit(1)'; const r=cp.spawnSync('python',['-c',py],{input:yaml,encoding:'utf8'}); if(r.status===0) return {content:[{type:'text',text:r.stdout.trim()}]}; return {content:[{type:'text',text:'Errore PyYAML: '+(r.stderr||'')}]}; } },
    json_to_yaml: { description:'JSON→YAML (PyYAML)', inputSchema:{type:'object',properties:{json:{type:'string'}},required:['json'],additionalProperties:false}, run: async ({json})=>{ if(!await has('python')) return {content:[{type:'text',text:'python non presente'}]}; const py='import sys,json,yaml\\nprint(yaml.safe_dump(json.loads(sys.stdin.read()),allow_unicode=True,sort_keys=False))'; const r=cp.spawnSync('python',['-c',py],{input:json,encoding:'utf8'}); if(r.status===0) return {content:[{type:'text',text:r.stdout}]}; return {content:[{type:'text',text:'Errore PyYAML: '+(r.stderr||'')}]}; } },

    ffmpeg_run: { description:'ffmpeg', inputSchema:{type:'object',properties:{args:{type:'array',items:{type:'string'}}},required:['args'],additionalProperties:false}, run: async ({args})=>{ const r=await run('ffmpeg',['-y',...(args||[])],{timeoutMs:600000}); return {content:[{type:'text',text:r.stdout||r.stderr}]}; } },
    video_thumbnail: { description:'thumbnail da video', inputSchema:{type:'object',properties:{input:{type:'string'},output:{type:'string'},time:{type:'string'}},required:['input','output'],additionalProperties:false}, run: async ({input,output,time})=>{ const r=await run('ffmpeg',['-y','-ss',time||'00:00:01','-i',input,'-frames:v','1',output],{}); return {content:[{type:'text',text:r.stdout||r.stderr||('Wrote '+output)}]}; } },
    audio_waveform: { description:'waveform→PNG', inputSchema:{type:'object',properties:{input:{type:'string'},output:{type:'string'},size:{type:'string'}},required:['input','output'],additionalProperties:false}, run: async ({input,output,size})=>{ const r=await run('ffmpeg',['-y','-i',input,'-filter_complex',`showwavespic=s=${size||'1280x200'}`,'-frames:v','1',output],{}); return {content:[{type:'text',text:r.stdout||r.stderr||('Wrote '+output)}]}; } },
    magick_run: { description:'ImageMagick', inputSchema:{type:'object',properties:{args:{type:'array',items:{type:'string'}}},required:['args'],additionalProperties:false}, run: async ({args})=>{ const bin=(await has('magick'))?'magick':'convert'; const r=await run(bin,args||[],{}); return {content:[{type:'text',text:r.stdout||r.stderr}]}; } },
    zip_create: { description:'zip -r', inputSchema:{type:'object',properties:{inputs:{type:'array',items:{type:'string'}},output:{type:'string'}},required:['inputs','output'],additionalProperties:false}, run: async ({inputs,output})=>{ if(!await has('zip')) return {content:[{type:'text',text:'zip non presente'}]}; const r=await run('zip',['-r',output,...inputs],{}); return {content:[{type:'text',text:r.stdout||r.stderr}]}; } },
    zip_extract: { description:'unzip', inputSchema:{type:'object',properties:{zip_path:{type:'string'},dest:{type:'string'}},required:['zip_path','dest'],additionalProperties:false}, run: async ({zip_path,dest})=>{ await fsp.mkdir(dest,{recursive:true}); if(!await has('unzip')) return {content:[{type:'text',text:'unzip non presente'}]}; const r=await run('unzip',[zip_path,'-d',dest],{}); return {content:[{type:'text',text:r.stdout||r.stderr}]}; } },
    pdf_merge: { description:'merge PDF (gs)', inputSchema:{type:'object',properties:{inputs:{type:'array',items:{type:'string'}},output:{type:'string'}},required:['inputs','output'],additionalProperties:false}, run: async ({inputs,output})=>{ if(!await has('gs')) return {content:[{type:'text',text:'gs non presente'}]}; const args=['-dBATCH','-dNOPAUSE','-q','-sDEVICE=pdfwrite','-sOutputFile='+output,...inputs]; const r=await run('gs',args,{timeoutMs:600000}); return {content:[{type:'text',text:r.stdout||r.stderr||('Merged to '+output)}]}; } },

    // Docs Guild: ADR write + README synth
    docs_adr_write: {
      description:'Scrive un ADR markdown in .vi-smart/adr/',
      inputSchema:{type:'object',properties:{ title:{type:'string'}, context:{type:'string'}, decision:{type:'string'}, consequences:{type:'string'}, sources:{type:'array','items':{'type':'object'}}, dir:{type:'string'}},required:['title'],additionalProperties:false},
      run: async ({title, context, decision, consequences, sources=[], dir='.vi-smart/adr'})=>{
        await fsp.mkdir(dir,{recursive:true});
        const slug = title.toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-+|-+$/g,'');
        const ts = new Date().toISOString().replace(/[:.]/g,'-');
        const fp = path.join(dir, `${ts}-${slug}.md`);
        const lines = [
          `# ADR: ${title}`,'',
          `Date: ${new Date().toISOString()}`,'',
          '## Context', (context||'-'), '',
          '## Decision', (decision||'-'), '',
          '## Consequences', (consequences||'-'), '',
          sources && sources.length ? '## Sources' : '',
          ...(sources||[]).map(s => `- ${s.title || s.url || ''} ${s.url?`<${s.url}>`:''}`),
          ''
        ].filter(Boolean);
        await fsp.writeFile(fp, lines.join('\n'), 'utf8');
        return { content:[{type:'text',text:`ADR scritto: ${fp}`}] };
      }
    },
    docs_readme_synth: {
      description:'Genera/aggiorna README.md da context + ADR',
      inputSchema:{type:'object',properties:{context_path:{type:'string'},adr_dir:{type:'string'},output:{type:'string'}},additionalProperties:false},
      run: async ({context_path='.vi-smart/context.json', adr_dir='.vi-smart/adr', output='README.md'})=>{
        let ctx={}; try{ ctx=JSON.parse(await fsp.readFile(context_path,'utf8')); }catch{}
        let adrs=[]; try{ const files=await fsp.readdir(adr_dir); for(const f of files){ if(f.endsWith('.md')) adrs.push(f); } }catch{}
        const lines=[
          '# Vi-Smart Agent Fabric',
          '',
          'Orchestratore con Guilds (Code/DevOps/QA/Docs), APL, packaging `.deb`, compose auto, ADR & memoria persistente.',
          '',
          '## Stato',
          '- Obiettivo: ' + (ctx.objective||'-'),
          '- Sessione: ' + (ctx.session_id||'-'),
          '- Step completati: ' + (ctx.progress?.completed?.length||0),
          '',
          '## ADR',
          ...(adrs.length? adrs.map(a=>`- .vi-smart/adr/${a}`) : ['- (nessuna ADR ancora)']),
          '',
          '## Esecuzione',
          '```bash',
          'make run',
          'make context-dump',
          '```',
          ''
        ];
        await fsp.writeFile(output, lines.join('\n'), 'utf8');
        return {content:[{type:'text',text:`README aggiornato: ${output}`}]};
      }
    }
  };

  const toolList = () => Object.entries(tools).map(([name,t]) => ({ name, description: t.description, inputSchema: t.inputSchema }));

  function isReq(x){ return x && x.jsonrpc==='2.0' && x.method; }
  async function handle(req){
    if(!isReq(req)) return;
    const {id,method,params}=req;
    try{
      if(method==='initialize') return send(id,{protocolVersion:'2024-11-05',serverInfo:{name:'vi-super-mcp',version:'1.3.0'},capabilities:{tools:{}}});
      if(method==='tools/list') return send(id,{tools: toolList()});
      if(method==='tools/call'){
        const {name,arguments:args}=params||{};
        if(!name||!tools[name]) return send(id,null,{code:-32602,message:'Tool non trovato: '+name});
        const out = await tools[name].run(args||{});
        return send(id,{content: out.content || [{type:'text',text:'OK'}]});
      }
      if(method==='notifications/initialized') return send(id,{});
      if(method==='ping') return send(id,{});
      return send(id,null,{code:-32601,message:'Metodo non supportato: '+method});
    }catch(e){
      return send(id,null,{code:-32000,message:String(e)});
    }
  }

  process.stdin.resume();
})();