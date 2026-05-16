#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# apply-docs-triage.sh
#
# Applies the 38-file triage from docs/untracked-files-triage.md with safety
# rails: default dry-run, per-phase confirmation, rollback plan printed
# upfront, and a backup step before any deletion.
#
# Categories (from triage report, 2026-04-18):
#   TRACK       14 files  (git add -f; 6 docs/plans/* + 8 docs/*.md)
#   KEEP-LOCAL   8 files  (annotate only, stay ignored)
#   MOVE        16 files  (mv to .local/ subtree; 14 drafts + 2 archives)
#   DELETE       2 files  (.bak backup + rm)
#
# Usage:
#   bash scripts/apply-docs-triage.sh            # dry-run (default)
#   bash scripts/apply-docs-triage.sh --apply    # real run, with Y/n prompts
#
# This script is intentionally UNTRACKED (see project gitignore policy).
# DO NOT `git add` this file.
# -----------------------------------------------------------------------------

set -u
set -o pipefail

# ---------------------------- Config & flags ---------------------------------

DRY_RUN=1
if [[ "${1:-}" == "--apply" ]]; then
  DRY_RUN=0
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || { echo "FATAL: cannot cd to $REPO_ROOT" >&2; exit 1; }

LOG_DIR="docs"
LOG_FILE="${LOG_DIR}/triage-applied-$(date +%Y%m%d-%H%M%S).log"

# ---------------------------- Pretty printing --------------------------------

BOLD=$'\033[1m'
DIM=$'\033[2m'
GREEN=$'\033[32m'
YELLOW=$'\033[33m'
RED=$'\033[31m'
BLUE=$'\033[34m'
RESET=$'\033[0m'

# Disable colors if stdout is not a TTY
if [[ ! -t 1 ]]; then
  BOLD=""; DIM=""; GREEN=""; YELLOW=""; RED=""; BLUE=""; RESET=""
fi

log() {
  # Echo to stdout AND append to log file (log file captured in apply mode only,
  # but we still tee in dry-run to a temp buffer so user can review it).
  local msg="$*"
  echo "${msg}"
  if [[ $DRY_RUN -eq 0 ]]; then
    printf '%s %s\n' "$(date +%Y-%m-%dT%H:%M:%S%z)" "$msg" >> "$LOG_FILE"
  fi
}

step() { log "${BLUE}${BOLD}[*]${RESET} $*"; }
okay() { log "${GREEN}[ok]${RESET} $*"; }
warn() { log "${YELLOW}[warn]${RESET} $*"; }
fail() { log "${RED}[fail]${RESET} $*"; }
info() { log "${DIM}$*${RESET}"; }

banner() {
  log ""
  log "${BOLD}==============================================================${RESET}"
  log "${BOLD} $* ${RESET}"
  log "${BOLD}==============================================================${RESET}"
  log ""
}

# ---------------------------- Safety prompts ---------------------------------

confirm() {
  # Prompt the user Y/n. Default = no. Returns 0 on Y/y, 1 otherwise.
  local prompt="$1"
  if [[ $DRY_RUN -eq 1 ]]; then
    info "(dry-run) would prompt: $prompt  [auto-accept]"
    return 0
  fi
  local reply
  read -r -p "${BOLD}${prompt} [y/N]:${RESET} " reply
  case "${reply,,}" in
    y|yes) return 0 ;;
    *) return 1 ;;
  esac
}

would() {
  # In dry-run, print what WOULD happen. In apply mode, execute the op.
  local op="$1"; shift
  local desc="$*"
  if [[ $DRY_RUN -eq 1 ]]; then
    log "  ${DIM}would:${RESET} ${op} ${desc}"
  else
    log "  ${GREEN}doing:${RESET} ${op} ${desc}"
  fi
}

run_or_print() {
  # Execute the given command in apply mode, print it in dry-run.
  if [[ $DRY_RUN -eq 1 ]]; then
    log "  ${DIM}\$${RESET} $*"
  else
    log "  ${DIM}\$${RESET} $*"
    eval "$@"
  fi
}

# ---------------------------- File lists -------------------------------------
# Sourced verbatim from docs/untracked-files-triage.md (2026-04-18 triage),
# amended per docs/delete-candidates-verification.md (2026-04-18): the 2 edge-case
# DELETE candidates (05-readme-outline.md + 2026-04-01-audit-trail.md) are
# reversed to MOVE → .local/*-archive/ to preserve retrospective value.
# 14 TRACK + 8 KEEP-LOCAL + 16 MOVE (14 drafts + 2 archives) + 2 DELETE = 40.

TRACK_FILES=(
  "docs/PRIVACY.md"
  "docs/TERMS.md"
  "docs/algo2go-tm-search.md"
  "docs/callback-deep-dive-13-levels.md"
  "docs/chatgpt-apps-validation.md"
  "docs/deferred-items.md"
  "docs/dpdp-reply-templates.md"
  "docs/gitignore-policy-analysis.md"
  "docs/mcp-registry-prepublish-checklist.md"
  "docs/superpowers/plans/2026-04-03-elicitation-order-confirmation.md"
  "docs/superpowers/plans/2026-04-03-paper-trading.md"
  "docs/superpowers/plans/2026-04-03-riskguard-phase1.md"
  "docs/superpowers/plans/2026-04-04-htmx-overview-poc.md"
  "docs/superpowers/plans/2026-04-05-dashboard-auth-separation.md"
)

KEEP_LOCAL_FILES=(
  "docs/consistency-audit-2026-04-18.md"
  "docs/renusharma-email-cleanup-report.md"
  "docs/worktree-merge-sequence-v2.md"
  "docs/drafts/foss-united-grant-email.md"
  "docs/drafts/indiafoss-2026-cfp.md"
  "docs/drafts/zerodha-compliance-email.md"
  "docs/untracked-files-triage.md"
  "docs/triage-execution-guide.md"
)

# MOVE entries: "<src>|<dst>" — pipe-delimited so src and dst can differ.
MOVE_FILES=(
  "docs/engagement-mr-karan.md|.local/outreach/engagement-mr-karan.md"
  "docs/kite-forum-replies.md|.local/outreach/kite-forum-replies.md"
  "docs/rainmatter-onepager.md|.local/outreach/rainmatter-onepager.md"
  "docs/drafts/jethwani-shenoy-dms.md|.local/outreach/jethwani-shenoy-dms.md"
  "docs/drafts/vishal-dhawan-dms.md|.local/outreach/vishal-dhawan-dms.md"
  "docs/reddit-buildlog-posts.md|.local/launch-drafts/reddit-buildlog-posts.md"
  "docs/show-hn-post.md|.local/launch-drafts/show-hn-post.md"
  "docs/twitter-launch-kit.md|.local/launch-drafts/twitter-launch-kit.md"
  "docs/launch/01-tradingqna-post.md|.local/launch-drafts/tradingqna-post.md"
  "docs/launch/03-twitter-thread.md|.local/launch-drafts/twitter-thread.md"
  "docs/launch/04-demo-video-script.md|.local/launch-drafts/demo-video-script.md"
  "docs/substack-week-1-options-greeks.md|.local/cohort-1/substack-week-1.md"
  "docs/cohort-1-landing.md|.local/cohort-1/landing.md"
  "docs/cohort-1-surveys-emails.md|.local/cohort-1/surveys-emails.md"
  "docs/launch/05-readme-outline.md|.local/launch-drafts-archive/05-readme-outline.md"
  "docs/superpowers/plans/2026-04-01-audit-trail.md|.local/superpowers-archive/2026-04-01-audit-trail.md"
)

DELETE_FILES=(
  "docs/worktree-merge-sequence.md"
  "docs/launch/02-reddit-isb-post.md"
)

# ---------------------------- Pre-flight checks ------------------------------

preflight() {
  banner "PRE-FLIGHT CHECKS"

  # 1. Inside a git repo?
  if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    fail "Not inside a git work tree (cwd: $PWD)"
    exit 1
  fi
  okay "Inside git repo: $(git rev-parse --show-toplevel)"

  # 2. Tracked files clean?
  #    We allow untracked files (the triage is about untracked), but tracked
  #    modifications would risk data loss if something goes wrong. Refuse.
  if ! git diff --quiet HEAD -- 2>/dev/null; then
    if [[ $DRY_RUN -eq 0 ]]; then
      fail "Tracked files have uncommitted modifications. Commit or stash before --apply."
      log ""
      log "Offending files:"
      git diff --name-only HEAD | sed 's/^/  /'
      exit 1
    else
      warn "Tracked files have uncommitted modifications (dry-run: continuing, but --apply would refuse)"
    fi
  else
    okay "Tracked files are clean (no uncommitted diffs)"
  fi

  # 3. Staged files?
  if ! git diff --cached --quiet 2>/dev/null; then
    if [[ $DRY_RUN -eq 0 ]]; then
      fail "There are staged changes. Commit or unstage before --apply."
      git diff --cached --name-only | sed 's/^/  /'
      exit 1
    else
      warn "Staged changes present (dry-run: continuing)"
    fi
  else
    okay "No staged changes"
  fi

  # 4. Triage report present?
  if [[ ! -f "docs/untracked-files-triage.md" ]]; then
    fail "docs/untracked-files-triage.md not found — required source of truth"
    exit 1
  fi
  okay "Triage report present"

  # 5. Expected files exist on disk (TRACK + MOVE + DELETE only; KEEP-LOCAL is optional).
  local missing=0
  for f in "${TRACK_FILES[@]}"; do
    [[ -f "$f" ]] || { warn "TRACK target missing on disk: $f"; missing=$((missing+1)); }
  done
  for spec in "${MOVE_FILES[@]}"; do
    local src="${spec%%|*}"
    [[ -f "$src" ]] || { warn "MOVE source missing on disk: $src"; missing=$((missing+1)); }
  done
  for f in "${DELETE_FILES[@]}"; do
    [[ -f "$f" ]] || { warn "DELETE target missing on disk: $f (harmless if already removed)"; }
  done
  if [[ $missing -gt 0 ]]; then
    warn "$missing expected files missing. Re-run triage analysis if this is unexpected."
  else
    okay "All TRACK/MOVE source files present"
  fi

  # 6. Log file writable?
  if [[ $DRY_RUN -eq 0 ]]; then
    mkdir -p "$LOG_DIR"
    if ! touch "$LOG_FILE" 2>/dev/null; then
      fail "Cannot create log file: $LOG_FILE"
      exit 1
    fi
    okay "Log file: $LOG_FILE"
  fi
}

# ---------------------------- Rollback plan ----------------------------------

print_rollback_plan() {
  banner "ROLLBACK PLAN (read BEFORE confirming any phase)"

  cat <<'ROLLBACK'
If anything goes wrong MID-EXECUTION, recover with:

  Phase 1 (.gitignore patch) rollback:
    git checkout -- .gitignore

  Phase 2 (TRACK force-add) rollback — un-stage without touching files:
    git reset HEAD -- docs/PRIVACY.md docs/TERMS.md  # etc.
    # Files return to untracked state; no data loss.

  Phase 4 (MOVE) rollback — move files back:
    mv .local/outreach/*.md docs/
    mv .local/launch-drafts/reddit-buildlog-posts.md docs/
    mv .local/launch-drafts/show-hn-post.md docs/
    mv .local/launch-drafts/twitter-launch-kit.md docs/
    mv .local/launch-drafts/tradingqna-post.md docs/launch/01-tradingqna-post.md
    mv .local/launch-drafts/twitter-thread.md docs/launch/03-twitter-thread.md
    mv .local/launch-drafts/demo-video-script.md docs/launch/04-demo-video-script.md
    mv .local/cohort-1/substack-week-1.md docs/substack-week-1-options-greeks.md
    mv .local/cohort-1/landing.md docs/cohort-1-landing.md
    mv .local/cohort-1/surveys-emails.md docs/cohort-1-surveys-emails.md
    mv .local/outreach/jethwani-shenoy-dms.md docs/drafts/
    mv .local/outreach/vishal-dhawan-dms.md docs/drafts/
    mv .local/launch-drafts-archive/05-readme-outline.md docs/launch/05-readme-outline.md
    mv .local/superpowers-archive/2026-04-01-audit-trail.md docs/superpowers/plans/2026-04-01-audit-trail.md
    rmdir .local/outreach .local/launch-drafts .local/cohort-1 .local/launch-drafts-archive .local/superpowers-archive .local 2>/dev/null

  Phase 6 (DELETE) rollback — restore from .bak files created this run:
    mv docs/worktree-merge-sequence.md.bak docs/worktree-merge-sequence.md
    mv docs/launch/02-reddit-isb-post.md.bak docs/launch/02-reddit-isb-post.md

  Full-script rollback (nuclear option, ONLY if .gitignore still uncommitted):
    git checkout -- .gitignore
    git reset HEAD
    # Then manually restore with the commands above.

  AFTER commits have been made, rollback needs:
    git revert <commit-sha>   # safe; creates a new commit that undoes changes
    git reset --hard <sha>    # DANGEROUS; only if you alone own the branch

ROLLBACK
}

# ---------------------------- Phase 1: .gitignore ----------------------------

phase_1_gitignore() {
  banner "PHASE 1 — .gitignore patch (remove 'docs/' rule, add '.local/')"

  log "Diff to apply:"
  log "  - line 65-66:  '# Documentation build artifacts' + 'docs/'"
  log "  + replacement: '# Local drafts, outreach, cohort material' + '.local/'"
  log "  + append:      '*.bak' and 'docs/triage-applied-*.log' (Phase-6/log hygiene)"
  log ""

  if ! confirm "Apply .gitignore patch?"; then
    warn "Phase 1 skipped by user."
    return 1
  fi

  if [[ $DRY_RUN -eq 0 ]]; then
    # Use sed to do the in-place replacement. Keep a .bak for safety.
    cp .gitignore .gitignore.bak
    # Line-number-anchored replacement: change lines 65+66 to new comment + rule.
    # Uses awk to be portable across GNU/BSD sed quirks on Windows bash.
    # Also append *.bak and triage log patterns so Phase-6 backups and the
    # timestamped log file (which land in docs/) don't become trackable once
    # the docs/ ignore rule is removed.
    awk '
      NR==65 { print "# Local drafts, outreach targets, cohort material —"; next }
      NR==66 {
        print "# user-specific material kept outside the public repo."
        print ".local/"
        print ""
        print "# Triage script artefacts (see scripts/apply-docs-triage.sh):"
        print "*.bak"
        print "docs/triage-applied-*.log"
        next
      }
      { print }
    ' .gitignore.bak > .gitignore
    okay "Patched .gitignore (backup: .gitignore.bak)"
  else
    log "  ${DIM}would: awk-replace lines 65-66 of .gitignore + append *.bak / triage log rule (backup to .gitignore.bak)${RESET}"
  fi
}

# ---------------------------- Phase 2: TRACK ---------------------------------

phase_2_track() {
  banner "PHASE 2 — TRACK (git add -f, ${#TRACK_FILES[@]} files)"

  log "Files to force-add (escape the docs/ ignore rule):"
  for f in "${TRACK_FILES[@]}"; do
    log "  + $f"
  done
  log ""

  if ! confirm "Force-add all ${#TRACK_FILES[@]} TRACK files?"; then
    warn "Phase 2 skipped by user."
    return 1
  fi

  for f in "${TRACK_FILES[@]}"; do
    if [[ ! -f "$f" ]]; then
      warn "  skipping (not on disk): $f"
      continue
    fi
    if [[ $DRY_RUN -eq 1 ]]; then
      log "  ${DIM}would: git add -f${RESET} $f"
    else
      if git add -f -- "$f"; then
        okay "  staged: $f"
      else
        fail "  FAILED: $f  (continuing with rest)"
      fi
    fi
  done
}

# ---------------------------- Phase 3: .local/ scaffold ----------------------

phase_3_scaffold() {
  banner "PHASE 3 — Create .local/ directory scaffold"

  local dirs=(".local" ".local/outreach" ".local/launch-drafts" ".local/cohort-1" ".local/launch-drafts-archive" ".local/superpowers-archive")
  for d in "${dirs[@]}"; do
    if [[ -d "$d" ]]; then
      info "  exists: $d"
    else
      if [[ $DRY_RUN -eq 1 ]]; then
        log "  ${DIM}would: mkdir -p${RESET} $d"
      else
        mkdir -p "$d"
        okay "  created: $d"
      fi
    fi
  done
}

# ---------------------------- Phase 4: MOVE ----------------------------------

phase_4_move() {
  banner "PHASE 4 — MOVE to .local/ (${#MOVE_FILES[@]} files)"

  log "Files to relocate:"
  for spec in "${MOVE_FILES[@]}"; do
    local src="${spec%%|*}"
    local dst="${spec##*|}"
    log "  $src"
    log "    -> $dst"
  done
  log ""

  if ! confirm "Move all ${#MOVE_FILES[@]} files to .local/?"; then
    warn "Phase 4 skipped by user."
    return 1
  fi

  for spec in "${MOVE_FILES[@]}"; do
    local src="${spec%%|*}"
    local dst="${spec##*|}"
    if [[ ! -f "$src" ]]; then
      warn "  skipping (source missing): $src"
      continue
    fi
    if [[ -e "$dst" ]]; then
      warn "  skipping (destination exists): $dst"
      continue
    fi
    if [[ $DRY_RUN -eq 1 ]]; then
      log "  ${DIM}would: mv${RESET} $src -> $dst"
    else
      if mv -n -- "$src" "$dst"; then
        okay "  moved: $src -> $dst"
      else
        fail "  FAILED: $src -> $dst"
      fi
    fi
  done
}

# ---------------------------- Phase 5: KEEP-LOCAL annotate -------------------

phase_5_keep_local() {
  banner "PHASE 5 — KEEP-LOCAL annotate (${#KEEP_LOCAL_FILES[@]} files)"

  log "These files stay where they are; the ignore rule keeps them local."
  log "Phase 5 takes no destructive action — this is a notification phase."
  log ""
  for f in "${KEEP_LOCAL_FILES[@]}"; do
    if [[ -f "$f" ]]; then
      log "  [keep-local] $f"
    else
      info "  (not present) $f"
    fi
  done
  log ""

  if ! confirm "Acknowledge KEEP-LOCAL list (no action taken)?"; then
    warn "Phase 5 not acknowledged. Nothing changed — moving on anyway."
  fi
}

# ---------------------------- Phase 6: DELETE (with backup) ------------------

phase_6_delete() {
  banner "PHASE 6 — DELETE (${#DELETE_FILES[@]} files, with .bak backup first)"

  log "Files to delete (backup to <path>.bak first):"
  for f in "${DELETE_FILES[@]}"; do
    log "  - $f"
  done
  log ""
  warn "This is destructive. .bak files are created BEFORE rm."
  log ""

  if ! confirm "Proceed with DELETE phase?"; then
    warn "Phase 6 skipped by user."
    return 1
  fi

  # Second confirmation for destructive ops
  if [[ $DRY_RUN -eq 0 ]]; then
    if ! confirm "  Really delete ${#DELETE_FILES[@]} files? (double-check)"; then
      warn "Phase 6 aborted at second confirm."
      return 1
    fi
  fi

  for f in "${DELETE_FILES[@]}"; do
    if [[ ! -f "$f" ]]; then
      info "  skipping (not present): $f"
      continue
    fi
    if [[ $DRY_RUN -eq 1 ]]; then
      log "  ${DIM}would: cp${RESET} $f $f.bak && ${DIM}rm${RESET} $f"
    else
      if cp -- "$f" "$f.bak" && rm -- "$f"; then
        okay "  deleted: $f (backup at $f.bak)"
      else
        fail "  FAILED: $f"
      fi
    fi
  done
}

# ---------------------------- Phase 7: Stage gitignore + summary -------------

phase_7_stage() {
  banner "PHASE 7 — Stage .gitignore patch"

  if [[ $DRY_RUN -eq 1 ]]; then
    log "  ${DIM}would: git add .gitignore${RESET}"
    return 0
  fi

  if git add -- .gitignore; then
    okay "Staged: .gitignore"
  else
    fail "Could not stage .gitignore"
  fi
}

# ---------------------------- Phase 8: Verification --------------------------

phase_8_verify() {
  banner "PHASE 8 — Post-execute verification"

  # 1. .local/ is ignored
  log "${BOLD}Check 1:${RESET} .local/ should be ignored"
  if [[ $DRY_RUN -eq 0 ]]; then
    if git check-ignore -v .local/ 2>&1 | grep -q '\.local/'; then
      okay "  .local/ is correctly ignored"
    else
      warn "  .local/ does NOT appear ignored — check .gitignore"
    fi
  else
    log "  ${DIM}would run: git check-ignore -v .local/${RESET}"
  fi

  # 2. docs/ file count
  log ""
  log "${BOLD}Check 2:${RESET} docs/ tracked file count"
  if [[ $DRY_RUN -eq 0 ]]; then
    local tracked_count
    tracked_count="$(git ls-files docs/ 2>/dev/null | wc -l | tr -d ' ')"
    okay "  git ls-files docs/ | wc -l = $tracked_count (expect: baseline + 14)"
  else
    log "  ${DIM}would run: git ls-files docs/ | wc -l${RESET}"
  fi

  # 3. docs/ total file count on disk
  log ""
  log "${BOLD}Check 3:${RESET} docs/ disk file count"
  if [[ $DRY_RUN -eq 0 ]]; then
    local disk_count
    disk_count="$(find docs -type f 2>/dev/null | wc -l | tr -d ' ')"
    okay "  find docs -type f | wc -l = $disk_count"
  else
    log "  ${DIM}would run: find docs -type f | wc -l${RESET}"
  fi

  # 4. .local/ disk file count
  log ""
  log "${BOLD}Check 4:${RESET} .local/ disk file count"
  if [[ $DRY_RUN -eq 0 ]]; then
    local local_count
    local_count="$(find .local -type f 2>/dev/null | wc -l | tr -d ' ')"
    okay "  find .local -type f | wc -l = $local_count (expect: 15)"
  else
    log "  ${DIM}would run: find .local -type f | wc -l${RESET}"
  fi

  # 5. No staged deletions accidentally
  log ""
  log "${BOLD}Check 5:${RESET} No stray staged deletions"
  if [[ $DRY_RUN -eq 0 ]]; then
    local staged_dels
    staged_dels="$(git diff --cached --name-only --diff-filter=D 2>/dev/null | wc -l | tr -d ' ')"
    if [[ "$staged_dels" == "0" ]]; then
      okay "  No staged deletions (expected)"
    else
      warn "  $staged_dels staged deletions — review with: git diff --cached --name-only --diff-filter=D"
    fi
  else
    log "  ${DIM}would run: git diff --cached --name-only --diff-filter=D${RESET}"
  fi
}

# ---------------------------- Final summary ---------------------------------

final_summary() {
  banner "SUMMARY"

  log "Phases run:"
  log "  Phase 1  .gitignore patch              (docs/ removed, .local/ added)"
  log "  Phase 2  TRACK force-add               (${#TRACK_FILES[@]} files)"
  log "  Phase 3  .local/ scaffold              (5 subdirs)"
  log "  Phase 4  MOVE to .local/               (${#MOVE_FILES[@]} files)"
  log "  Phase 5  KEEP-LOCAL annotate           (${#KEEP_LOCAL_FILES[@]} files, no-op)"
  log "  Phase 6  DELETE with .bak backup        (${#DELETE_FILES[@]} files)"
  log "  Phase 7  Stage .gitignore"
  log "  Phase 8  Verification checks"
  log ""

  log "${BOLD}Recommended commit sequence${RESET} (NOT run automatically):"
  log ""
  log "  1. git commit -m \"chore(gitignore): remove docs/ rule, add .local/\""
  log "  2. git commit -m \"docs: track 14 previously-untracked reference docs\""
  log ""
  log "${DIM}(The first commit should only contain .gitignore. The second"
  log " should contain the 14 newly-tracked docs. Review with"
  log " 'git status' and 'git diff --cached' before either commit.)${RESET}"
  log ""

  if [[ $DRY_RUN -eq 1 ]]; then
    log "${YELLOW}${BOLD}This was a DRY RUN.${RESET} No files were modified."
    log "To apply for real:  bash scripts/apply-docs-triage.sh --apply"
  else
    log "${GREEN}${BOLD}Apply complete.${RESET}  Log: $LOG_FILE"
    log ""
    log "Next steps for Sundeep:"
    log "  1. Review: git status"
    log "  2. Review: git diff --cached"
    log "  3. Commit per sequence above"
    log "  4. Optional: delete .gitignore.bak and *.bak files after verification"
  fi
}

# ---------------------------- Main -------------------------------------------

main() {
  banner "apply-docs-triage.sh — $(if [[ $DRY_RUN -eq 1 ]]; then echo "DRY-RUN MODE"; else echo "APPLY MODE"; fi)"

  log "Repo:      $REPO_ROOT"
  log "Source:    docs/untracked-files-triage.md"
  log "Date:      $(date)"
  if [[ $DRY_RUN -eq 0 ]]; then
    log "Log file:  $LOG_FILE"
  fi
  log ""
  log "Counts:    TRACK=${#TRACK_FILES[@]}  KEEP-LOCAL=${#KEEP_LOCAL_FILES[@]}  MOVE=${#MOVE_FILES[@]}  DELETE=${#DELETE_FILES[@]}"
  log ""

  preflight
  print_rollback_plan

  if [[ $DRY_RUN -eq 0 ]]; then
    log ""
    if ! confirm "Start applying the 8 phases?"; then
      warn "Aborted before Phase 1."
      exit 0
    fi
  fi

  phase_1_gitignore || true
  phase_2_track     || true
  phase_3_scaffold  || true
  phase_4_move      || true
  phase_5_keep_local || true
  phase_6_delete    || true
  phase_7_stage     || true
  phase_8_verify    || true

  final_summary
}

main "$@"
