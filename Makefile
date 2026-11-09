# Recompute every number and figure in the paper from runs/.
# Public snapshot notes:
#  - attack/polish prompts and attack submission code are withheld (see README);
#    redacted bank records keep all metadata, so every target below still reproduces.
#  - `excerpts` is not in the chain: analysis/out/full/excerpts.md is the curated
#    two-transcript version quoted in the paper; regenerating against the redacted
#    bank would overwrite it with redacted code.
PY := .venv/bin/python
STAGE1 := $(wildcard runs/stage1_mon*/scores.jsonl)  # mon* only: stage1_logic must NOT leak into the telemetry matrix (see RUN_INDEX)
STAGE1B := $(wildcard runs/stage1b_*/scores.jsonl)
STAGE1C := $(wildcard runs/stage1c_*/scores.jsonl)
RAW := $(wildcard runs/stage1raw_*/scores.jsonl)
BANKS := runs/bank_cheap3_v2 runs/bank_rest4

.PHONY: recompute hashes banks full robustness figure told para raw strengthen control matched reasons para-ds committee mech familiarity heldout expanded

recompute: hashes banks full robustness figure told para raw strengthen control matched reasons para-ds committee mech familiarity heldout expanded

hashes:
	$(PY) -c "import json,hashlib,pathlib; h=json.load(open('prompts/HASHES.json')); \
	have={n:v for n,v in h.items() if pathlib.Path(f'prompts/{n}.txt').exists()}; \
	bad=[n for n,v in have.items() if hashlib.sha256(pathlib.Path(f'prompts/{n}.txt').read_text(encoding='utf-8').strip().encode()).hexdigest()!=v]; \
	wh=sorted(set(h)-set(have)); \
	print(('prompt hashes OK' if not bad else f'HASH MISMATCH: {bad}') + f'; {len(wh)} withheld (private appendix): {wh}')"

banks:
	$(PY) analysis/bank_tables.py --banks $(BANKS) --out analysis/out/banks > /dev/null && echo "banks -> analysis/out/banks"

full:
	@if [ -n "$(STAGE1)" ]; then \
	  $(PY) analysis/calibrate.py --scores $(STAGE1) --out analysis/out/full > /dev/null && \
	  $(PY) analysis/fit.py --scores $(STAGE1) --out analysis/out/full --perms 2000 2>/dev/null > /dev/null && echo "full -> analysis/out/full"; fi

robustness:
	@if [ -n "$(STAGE1)" ]; then $(PY) analysis/robustness.py --scores $(STAGE1) --out analysis/out/full 2>/dev/null > /dev/null && echo "robustness -> analysis/out/full/robustness.md"; fi

figure:
	@if [ -f analysis/out/full/fit.json ]; then $(PY) analysis/figures.py --cells analysis/out/full/cells.csv --fit analysis/out/full/fit.json --out analysis/out/full/fig1.png \
	  --title "Catch rate of successful attacks, blind monitors (34 tasks, 650 attacks, 698 benign)"; fi

told:
	@if [ -n "$(STAGE1B)" ]; then $(PY) analysis/deltas.py told --blind $(STAGE1) --told $(STAGE1B) --out analysis/out/told > /dev/null && echo "told -> analysis/out/told/deltas.md"; fi

para:
	@if [ -n "$(STAGE1C)" ]; then $(PY) analysis/deltas.py para --orig $(STAGE1) --para $(STAGE1C) --out analysis/out/para > /dev/null && echo "para -> analysis/out/para/deltas.md"; fi

raw:
	@if [ -n "$(RAW)" ]; then \
	  $(PY) analysis/calibrate.py --scores $(STAGE1) $(RAW) --attack-stage raw --out analysis/out/raw > /dev/null && \
	  $(PY) analysis/fit.py --scores $(STAGE1) $(RAW) --attack-stage raw --out analysis/out/raw --perms 2000 2>/dev/null > /dev/null && \
	  $(PY) analysis/robustness.py --scores $(STAGE1) $(RAW) --attack-stage raw --out analysis/out/raw 2>/dev/null > /dev/null && echo "raw (pre-polish attacks) -> analysis/out/raw"; fi

strengthen:
	@if [ -n "$(STAGE1)" ]; then $(PY) analysis/strengthen.py --scores $(STAGE1) --banks $(BANKS) --out analysis/out/strengthen --boots 500 2>/dev/null > /dev/null && echo "strengthen -> analysis/out/strengthen/strengthen.md, fig2_residuals.png"; fi

control:
	@if [ -n "$(STAGE1)" ]; then $(PY) analysis/control.py --scores $(STAGE1) --out analysis/out/control 2>/dev/null > /dev/null && echo "control -> analysis/out/control/control.md, fig3_audit_budget.png"; fi

matched:
	@if [ -n "$(STAGE1)" ]; then $(PY) analysis/matched_fpr.py --telemetry $(STAGE1) --logic runs/stage1_logic/scores.jsonl --out analysis/out/matched 2>/dev/null > /dev/null && $(PY) analysis/block_fit.py --scores $(STAGE1) --out analysis/out/matched 2>/dev/null > /dev/null && echo "matched-FPR + gemma-block fit -> analysis/out/matched"; fi

reasons:
	@if [ -n "$(STAGE1)" ]; then $(PY) analysis/reasons.py --scores $(STAGE1) --cells analysis/out/full/cells.csv --out analysis/out/reasons 2>/dev/null > /dev/null && echo "reasons -> analysis/out/reasons/reasons.md"; fi

para-ds:
	@if [ -f runs/stage1e_ds/scores.jsonl ]; then $(PY) analysis/deltas.py para --orig $(STAGE1) --para runs/stage1e_ds/scores.jsonl --out analysis/out/para_ds > /dev/null && echo "para_ds (deepseek paraphraser control) -> analysis/out/para_ds/deltas.md"; fi

expanded:
	@if [ -d runs/stage1h_monA ]; then $(PY) analysis/expanded_calibration.py 2>/dev/null > /dev/null && echo "expanded calibration -> analysis/out/expanded/expanded.md" || echo "expanded: FAILED"; fi

heldout:
	@$(PY) analysis/heldout.py 2>/dev/null > /dev/null && echo "held-out calibration -> analysis/out/heldout/heldout.md" || echo "heldout: FAILED"

committee:
	@$(PY) analysis/committee.py 2>/dev/null > /dev/null && echo "committee -> analysis/out/committee/fig4_deployment.png" || echo "committee: FAILED"

mech:
	@$(PY) analysis/mechanism_fig.py 2>/dev/null > /dev/null && echo "mechanism chain -> analysis/out/mech/fig5_mechanism.png" || echo "mech: FAILED"

familiarity:
	@$(PY) analysis/familiarity.py 2>/dev/null > /dev/null && echo "familiarity -> analysis/out/familiarity/familiarity.md" || echo "familiarity: FAILED"
