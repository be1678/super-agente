# Vi-Smart Agent Fabric

Orchestratore con Guilds (Code/DevOps/QA/Docs), APL dinamica, packaging `.deb`, compose auto, ADR e memoria persistente.

## Avvio
```bash
make run         # esegue la pipeline, crea .vi-smart/*, ADR e aggiorna README
make context-dump
```

Richiede Node 18+; strumenti opzionali: docker, fpm, ffmpeg, ghostscript, imagemagick, syft, python+PyYAML.
