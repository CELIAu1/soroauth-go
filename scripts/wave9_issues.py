#!/usr/bin/env python3
"""Create and maintain the Drips Wave 9 issue backlog on GitHub.

docs/WAVE9_BACKLOG.json is the source of truth for the new issues, and
docs/ISSUE_BACKLOG.md for the 21 that already exist. Issue bodies are rendered
from those files, so the published issues cannot drift from the documents they
were reviewed as.

Dry run by default: prints everything it would do and changes nothing.

    ./scripts/wave9_issues.py                 # show the plan
    ./scripts/wave9_issues.py --apply         # create new + re-render existing
    ./scripts/wave9_issues.py --apply --new-only
    ./scripts/wave9_issues.py --apply --update-only

`gh issue create` is not idempotent: a second --apply --new-only run produces
duplicates. Check the issue list before re-running.
"""
import argparse, json, os, re, subprocess, sys

REPO = "soroauth/soroauth-go"
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

POINTS = {"high": 200, "medium": 150, "trivial": 100}
DRIPS_NAME = {"high": "High", "medium": "Medium", "trivial": "Trivial"}

LABELS = [
    ("complexity:trivial", "c2e0c6", "Trivial — 100 points. Small, self-contained."),
    ("complexity:medium",  "fbca04", "Medium — 150 points. Standard feature or involved fix."),
    ("complexity:high",    "d93f0b", "High — 200 points. New subsystem, integration or refactor."),
    ("area:signers",       "1d76db", "Signer implementations and the Signer interface"),
    ("area:testing",       "5319e7", "Golden vectors, fuzzing, parity, benchmarks, e2e"),
    ("area:api",           "0e8a16", "Exported library API"),
    ("area:docs",          "006b75", "Documentation and guides"),
    ("area:tooling",       "bfd4f2", "CLI, CI, scripts, release automation"),
    ("area:integrations",  "d4c5f9", "WASM, browser, wallets, RPC, fixture contracts"),
    ("area:protocol",      "e99695", "CAP support and protocol compatibility"),
]

BEFORE_YOU_START = """## 📚 Before You Start
- Read [CONTRIBUTING.md](https://github.com/{repo}/blob/main/CONTRIBUTING.md) for local setup, commit format, and the PR checklist.
- Skim [ARCHITECTURE.md](https://github.com/{repo}/blob/main/ARCHITECTURE.md) for the signing flow, the package map, and the delegate model.
- Anything that changes the bytes soroauth emits must cite the CAP that requires it and ship a golden vector. Never edit a vector by hand."""

ADDITIONAL = """## 📋 Additional Notes
**Complexity: {level} ({points} points)**

- **Get assigned first.** Comment *I'd like to work on this* and wait for assignment. Unassigned PRs may duplicate someone else's work.
- **48-hour progress rule.** You have 48 hours from assignment to show meaningful progress: a draft PR, a status update on the issue, or a question. Issues that go silent for 48h may be reassigned to keep the Wave moving. If you need more time, just say so on the issue.
- **PR description must link this issue** with `Closes #`, describe what you changed, and state how you verified it.
- **Keep the PR to this issue's scope.** Unrelated fixes you spot along the way are welcome as separate issues or PRs.
- **CI must be green** before requesting review. `main` requires a pull request and both status checks.
- **If the work turns out materially larger** than the assigned complexity once you're in the code, say so on the issue rather than absorbing it silently."""


def render(issue):
    parts = ["## 📘 Description", issue["description"]]
    if issue.get("why"):
        parts += ["", "**Why this matters:** " + issue["why"]]
    parts += ["", "## ✅ Acceptance Criteria"]
    parts += ["- [ ] " + c for c in issue["criteria"]]
    parts += ["", "## 🔧 Implementation Guidance"]
    parts += ["- " + g for g in issue["guidance"]]
    parts += ["", BEFORE_YOU_START.format(repo=REPO), "",
              ADDITIONAL.format(level=DRIPS_NAME[issue["complexity"]],
                                points=POINTS[issue["complexity"]])]
    return "\n".join(parts)


def parse_markdown_backlog(path):
    """Parse docs/ISSUE_BACKLOG.md into the same shape as the JSON spec."""
    text = open(path).read()
    area_for = {"Signers": "area:signers", "Correctness and testing": "area:testing",
                "API": "area:api", "Documentation": "area:docs", "Tooling": "area:tooling"}
    out, area = [], None
    blocks = re.split(r"\n(?=## |### \d+\. )", text)
    for block in blocks:
        if block.startswith("## "):
            head = block.split("\n", 1)[0][3:].strip()
            if head in area_for:
                area = area_for[head]
            continue
        m = re.match(r"### \d+\. (.+)", block)
        if not m:
            continue
        title = m.group(1).strip()
        cx = re.search(r"\*\*Complexity:\*\* *(\w+)", block)
        body = block.split("\n", 1)[1] if "\n" in block else ""
        body = re.sub(r"\*\*Complexity:\*\* *\w+\n?", "", body)
        summary, criteria = body, []
        if "**Acceptance criteria**" in body:
            summary, crit = body.split("**Acceptance criteria**", 1)
            for line in crit.split("\n"):
                if line.startswith("- "):
                    criteria.append(line[2:].strip())
                elif criteria and line.startswith("  "):
                    criteria[-1] += " " + line.strip()
        summary = summary.strip().rstrip("-").strip()
        out.append(dict(title=title, complexity=(cx.group(1) if cx else "medium"),
                        area=area or "area:api", description=summary, why=None,
                        criteria=criteria or ["Scope agreed on the issue before starting."],
                        guidance=["See CONTRIBUTING.md for setup, the test expectations and the PR checklist.",
                                  "If this turns out materially larger than its assigned complexity once you are in the code, say so on the issue."]))
    return out


def gh(*args, capture=True):
    return subprocess.run(["gh", *args], check=True,
                          capture_output=capture, text=True).stdout


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--apply", action="store_true", help="actually create and update")
    p.add_argument("--new-only", action="store_true")
    p.add_argument("--update-only", action="store_true")
    p.add_argument("--limit", type=int, default=0, help="only show/create the first N new issues")
    args = p.parse_args()

    new = json.load(open(os.path.join(ROOT, "docs", "WAVE9_BACKLOG.json")))
    for i in new:
        i["area"] = "area:" + i["area"]
    existing_spec = parse_markdown_backlog(os.path.join(ROOT, "docs", "ISSUE_BACKLOG.md"))

    # ---- labels ----
    print("== labels ==")
    for name, color, desc in LABELS:
        if args.apply and not args.update_only:
            gh("label", "create", name, "--repo", REPO, "--color", color,
               "--description", desc, "--force")
            print("  ensured %s" % name)
        else:
            print("  would ensure %-22s #%s  %s" % (name, color, desc))
    print()

    # ---- re-render the existing issues ----
    if not args.new_only:
        live = json.loads(gh("issue", "list", "--repo", REPO, "--state", "all",
                             "--limit", "300", "--json", "number,title"))
        by_title = {x["title"]: x["number"] for x in live}
        print("== re-render %d existing issues ==" % len(existing_spec))
        for spec in existing_spec:
            num = by_title.get(spec["title"])
            if num is None:
                print("  SKIP (not found on GitHub): %s" % spec["title"])
                continue
            if args.apply:
                gh("issue", "edit", str(num), "--repo", REPO, "--body", render(spec))
                print("  updated #%-3d %s" % (num, spec["title"]))
            else:
                print("  would update #%-3d [%s] %s" % (num, spec["complexity"], spec["title"]))
        print()

    # ---- create the new issues ----
    if not args.update_only:
        todo = new[: args.limit] if args.limit else new
        print("== create %d new issues ==" % len(todo))
        for issue in todo:
            labels = ["complexity:" + issue["complexity"], issue["area"]]
            if args.apply:
                url = gh("issue", "create", "--repo", REPO, "--title", issue["title"],
                         "--body", render(issue),
                         "--label", labels[0], "--label", labels[1]).strip()
                print("  %s  %s" % (url, issue["title"]))
            else:
                print("=" * 70)
                print("would create: %s" % issue["title"])
                print("labels:       %s" % ", ".join(labels))
                print("-" * 70)
                print(render(issue))
                print()
        print()

    pts = sum(POINTS[i["complexity"]] for i in new)
    ex = sum(POINTS[i["complexity"]] for i in existing_spec)
    print("=" * 70)
    print("new issues:      %3d  =  %5d points" % (len(new), pts))
    print("existing issues: %3d  =  %5d points" % (len(existing_spec), ex))
    print("program total:          %5d points" % (pts + ex))
    if not args.apply:
        print("\nDRY RUN — nothing was changed. Re-run with --apply.")


if __name__ == "__main__":
    sys.exit(main())
