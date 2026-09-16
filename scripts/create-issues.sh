#!/usr/bin/env bash
#
# Create the contributor issue backlog on GitHub.
#
# Reads docs/ISSUE_BACKLOG.md and creates one issue per entry. The backlog file
# is the source of truth: titles, summaries and acceptance criteria are taken
# from it verbatim rather than duplicated here, so the two cannot drift.
#
# Dry run by default — it prints exactly what it would create and touches
# nothing. Pass --apply to actually create the labels and issues.
#
#   ./scripts/create-issues.sh            # show what would be created
#   ./scripts/create-issues.sh --apply    # create it
#
# Creating 21 issues is not something to do twice by accident: `gh issue create`
# has no idempotency, so a second --apply run produces 21 duplicates. Check the
# repo's issue list before re-running.

set -euo pipefail

REPO="soroauth/soroauth-go"
BACKLOG="docs/ISSUE_BACKLOG.md"

APPLY=false
for arg in "$@"; do
  case "$arg" in
    --apply) APPLY=true ;;
    -h|--help) sed -n '2,20p' "$0" | sed 's|^# \{0,1\}||'; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

cd "$(dirname "$0")/.."

if [[ ! -f "$BACKLOG" ]]; then
  echo "cannot find $BACKLOG; run this from anywhere in the repo" >&2
  exit 1
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "gh is not installed: https://cli.github.com" >&2
  exit 1
fi

if $APPLY && ! gh auth status >/dev/null 2>&1; then
  echo "gh is not authenticated; run 'gh auth login'" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Labels
# ---------------------------------------------------------------------------
#
# Created first so the issues below can reference them. --force makes this
# idempotent: it updates an existing label rather than failing.

create_label() {
  local name="$1" color="$2" description="$3"
  if $APPLY; then
    gh label create "$name" --repo "$REPO" --color "$color" \
      --description "$description" --force
  else
    printf 'would create label  %-22s #%s  %s\n' "$name" "$color" "$description"
  fi
}

echo "== labels =="
create_label "complexity:trivial" "c2e0c6" "Self-contained, no protocol knowledge required"
create_label "complexity:medium"  "fbca04" "Needs familiarity with the codebase or the auth flow"
create_label "complexity:high"    "d93f0b" "Touches signing, the wire format, or cryptography"
create_label "area:signers"       "1d76db" "Signer implementations and the Signer interface"
create_label "area:testing"       "5319e7" "Golden vectors, fuzzing, benchmarks, e2e"
create_label "area:api"           "0e8a16" "Exported library API"
create_label "area:docs"          "006b75" "Documentation and guides"
create_label "area:tooling"       "bfd4f2" "CLI, scripts, release automation"
echo

# ---------------------------------------------------------------------------
# Issues
# ---------------------------------------------------------------------------
#
# Each "### N. Title" in the backlog becomes an issue. Its area comes from the
# enclosing "## Section", its complexity from the "**Complexity:**" line, its
# summary from the prose before "**Acceptance criteria**", and its acceptance
# criteria from the bullets after it, rewritten as task-list checkboxes.

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

awk -v dir="$WORKDIR" '
  function flush() {
    if (n > 0) {
      print title    > (dir "/" sprintf("%02d", n) ".title")
      print recarea  > (dir "/" sprintf("%02d", n) ".area")
      print cplx     > (dir "/" sprintf("%02d", n) ".complexity")
      printf "%s",  summary  > (dir "/" sprintf("%02d", n) ".summary")
      printf "%s",  criteria > (dir "/" sprintf("%02d", n) ".criteria")
      close(dir "/" sprintf("%02d", n) ".title")
      close(dir "/" sprintf("%02d", n) ".area")
      close(dir "/" sprintf("%02d", n) ".complexity")
      close(dir "/" sprintf("%02d", n) ".summary")
      close(dir "/" sprintf("%02d", n) ".criteria")
    }
  }

  # Section heading decides the area label.
  /^## / {
    section = substr($0, 4)
    if (section ~ /^Signers/)                  area = "area:signers"
    else if (section ~ /^Correctness and test/) area = "area:testing"
    else if (section ~ /^API/)                 area = "area:api"
    else if (section ~ /^Documentation/)       area = "area:docs"
    else if (section ~ /^Tooling/)             area = "area:tooling"
    next
  }

  # A numbered issue heading starts a new record.
  /^### [0-9]+\. / {
    flush()
    n++
    title = substr($0, index($0, ". ") + 2)
    # Capture the area now, not at flush time: the last issue of a section is
    # flushed only after the next "## Section" heading has already been read,
    # so reading the live variable then would label it with the next section.
    recarea = area
    cplx = ""; summary = ""; criteria = ""; mode = "summary"
    next
  }

  n == 0 { next }

  /^\*\*Complexity:\*\*/ {
    cplx = $0
    sub(/^\*\*Complexity:\*\* */, "", cplx)
    next
  }

  /^\*\*Acceptance criteria\*\*/ { mode = "criteria"; next }

  # Horizontal rules and stray blank runs are not content.
  /^---$/ { next }

  {
    if (mode == "criteria") {
      line = $0
      # Top-level bullets become checkboxes; wrapped continuation lines are
      # kept as they are so the text stays verbatim.
      if (line ~ /^- /) sub(/^- /, "- [ ] ", line)
      criteria = criteria line "\n"
    } else {
      summary = summary $0 "\n"
    }
  }

  END { flush() }
' "$BACKLOG"

trim_blank_edges() {
  awk 'BEGIN{started=0} {lines[NR]=$0} END{
    first=1; last=NR
    while (first<=NR && lines[first] ~ /^[[:space:]]*$/) first++
    while (last>=1   && lines[last]  ~ /^[[:space:]]*$/) last--
    for (i=first; i<=last; i++) print lines[i]
  }'
}

count=0
for titlefile in "$WORKDIR"/*.title; do
  base="${titlefile%.title}"

  title="$(cat "$titlefile")"
  area="$(cat "$base.area")"
  complexity="$(cat "$base.complexity")"
  summary="$(trim_blank_edges < "$base.summary")"
  criteria="$(trim_blank_edges < "$base.criteria")"

  case "$complexity" in
    trivial) complexity_label="complexity:trivial" ;;
    medium)  complexity_label="complexity:medium" ;;
    high)    complexity_label="complexity:high" ;;
    *) echo "issue '$title' has an unrecognised complexity: '$complexity'" >&2; exit 1 ;;
  esac

  body="$(printf '## Summary\n\n%s\n\n## Acceptance criteria\n\n%s\n\n---\n\nFrom [`docs/ISSUE_BACKLOG.md`](https://github.com/%s/blob/main/docs/ISSUE_BACKLOG.md). Anything that changes the bytes soroauth emits must cite the CAP requiring it and ship a golden vector.\n' \
    "$summary" "$criteria" "$REPO")"

  count=$((count + 1))

  if $APPLY; then
    gh issue create \
      --repo "$REPO" \
      --title "$title" \
      --label "$complexity_label" \
      --label "$area" \
      --body "$body"
  else
    echo "=============================================================="
    echo "would create issue: $title"
    echo "labels:             $complexity_label, $area"
    echo "--------------------------------------------------------------"
    echo "$body"
    echo
  fi
done

echo "=============================================================="
if $APPLY; then
  echo "created $count issues in $REPO"
else
  echo "$count issues would be created in $REPO"
  echo "nothing was changed. re-run with --apply to create them."
fi
