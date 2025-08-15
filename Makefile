.PHONY: run resume context-dump context-clear compose-up compose-down deb ci

run:
\tNODE_NO_WARNINGS=1 node fabric.mjs

resume:
\tNODE_NO_WARNINGS=1 node fabric.mjs

ci:
\tVI_SMART_SKIP_COMPOSE=1 VI_SMART_SKIP_DEB=1 NODE_NO_WARNINGS=1 node fabric.mjs

context-dump:
\t@cat .vi-smart/context.json | sed -e 's/\\</</g'

context-clear:
\t@mkdir -p .vi-smart/archive; \
\tdate +%Y%m%d-%H%M%S > /tmp/vi_ts; TS=$$(cat /tmp/vi_ts); \
\t[ -f .vi-smart/context.json ] && mv .vi-smart/context.json .vi-smart/archive/context-$$TS.json || true; \
\t[ -f .vi-smart/journal.ndjson ] && mv .vi-smart/journal.ndjson .vi-smart/archive/journal-$$TS.ndjson || true; \
\tprintf '{ "version":1, "project":"vi-smart", "session_id":"reset", "task_id":"reset", "objective":"reset", "assumptions":[], "env":{"os":"ubuntu-22.04","runtime":"node18"}, "tools_used":[], "files_touched":[], "decisions":[], "progress":{"phase":"Acquire","step_index":0,"completed":[]}, "backlog_next":[], "errors_seen":[], "versions":{}, "timestamps":{"created":"%s","updated":"%s"} }\n' "$$(date -Iseconds)" "$$(date -Iseconds)" > .vi-smart/context.json

compose-up:
\tdocker compose -f docker-compose.yml up -d

compose-down:
\tdocker compose -f docker-compose.yml down

deb:
\tnode fabric.mjs
