#!/usr/bin/env bash
# Live status of running experiment processes and their recorded progress.
cd "$(dirname "$0")/.."
echo "$(date +%T)  running agent processes:"
ps -axww -o pid=,etime=,command= | grep "bin/bluesec1-agent --experiment" | grep -v grep \
  | awk '{print "  pid " $1 "  up " $2 "  " $NF}'
echo
printf "%-28s %6s %8s %8s %7s %6s %6s %8s\n" run tasks reward quality effic calls err% cost$
for d in $(ls -d runs/2*/ 2>/dev/null | tail -8); do
  [ -f "$d/summary.json" ] || continue
  python3 - "$d" <<'PY'
import json, sys, pathlib
d = pathlib.Path(sys.argv[1]); s = json.loads((d / "summary.json").read_text())
tasks = [json.loads(l) for l in (d / "tasks.jsonl").open()] if (d / "tasks.jsonl").exists() else []
review = sum(t.get("review_model_cost_usd") or 0 for t in tasks)
name = d.name.split("-", 2)[-1][:28]
print(f"{name:<28} {s['tasks']:>3}/30 {s['mean_total_reward']:>8.1f} {s['mean_quality_score']:>8.3f} "
      f"{s['mean_efficiency_score']:>7.3f} {s['mean_tool_calls']:>6.1f} {s['error_call_rate']:>6.3f} "
      f"{s['total_cost_usd'] + review:>8.3f}")
PY
done
