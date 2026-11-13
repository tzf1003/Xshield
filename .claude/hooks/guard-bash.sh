#!/usr/bin/env bash
# PreToolUse hook for the Bash tool (.claude/settings.json). It enforces the three
# AGENTS.md rules that are cheap to check mechanically, so they do not depend on the
# agent remembering them:
#
#   1. no `git push --force` / `-f` / `+refspec` (`--force-with-lease` is fine)
#   2. no push to main or master: changes reach main through a pull request, so CI runs
#   3. no `git commit` while Rust sources fail `cargo fmt --check` (CI rejects it later)
#
# It reads the hook JSON on stdin and answers with a permissionDecision of "deny" and a
# reason the agent can act on. Everything else passes untouched. Without jq the hook
# cannot read its input and lets the command through: it is a seat belt for agents,
# not an access control. Branch protection on GitHub is the real gate.
#
# Test it by hand:
#   echo '{"tool_input":{"command":"git push -f origin x"}}' | .claude/hooks/guard-bash.sh
set -u

command -v jq >/dev/null 2>&1 || exit 0
input=$(cat)
cmd=$(jq -r '.tool_input.command // empty' <<<"$input" 2>/dev/null) || exit 0
[ -n "$cmd" ] || exit 0

deny() {
    jq -n --arg reason "$1" '{
        hookSpecificOutput: {
            hookEventName: "PreToolUse",
            permissionDecision: "deny",
            permissionDecisionReason: $reason
        }
    }'
    exit 0
}

repo=${CLAUDE_PROJECT_DIR:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}

# Look at each simple command of a compound line (`a && b; c | d`) separately, so a
# flag of one command is not read as a flag of another.
while IFS= read -r segment; do
    # `git [-C dir | -c k=v | --opt]... <subcommand> <rest>`
    if [[ ! $segment =~ (^|[[:space:]\(])git(([[:space:]]+-[^[:space:]]+([[:space:]]+[^-[:space:]][^[:space:]]*)?)*)[[:space:]]+(push|commit)([[:space:]]+(.*))?$ ]]; then
        continue
    fi
    subcommand=${BASH_REMATCH[5]}
    rest=" ${BASH_REMATCH[7]:-} "

    if [ "$subcommand" = push ]; then
        if [[ $rest =~ [[:space:]](--force|-[a-zA-Z]*f[a-zA-Z]*)[[:space:]] ]] ||
            [[ $rest =~ [[:space:]]\+[^[:space:]]+ ]]; then
            deny "AGENTS.md: no force push. To rewrite your own branch use 'git push --force-with-lease'; never rewrite main."
        fi
        if [[ $rest =~ [[:space:]:](refs/heads/)?(main|master)[[:space:]] ]]; then
            deny "AGENTS.md: changes reach main through a pull request so CI runs. Push your branch and open a PR instead."
        fi
        branch=$(git -C "$repo" rev-parse --abbrev-ref HEAD 2>/dev/null || true)
        if [[ $branch == main || $branch == master ]]; then
            deny "AGENTS.md: the current branch is $branch. Create a branch, push it and open a PR instead of pushing $branch."
        fi
    fi

    if [ "$subcommand" = commit ] && command -v cargo >/dev/null 2>&1; then
        changed=$(git -C "$repo" status --porcelain -- '*.rs' 2>/dev/null)
        [ -n "$changed" ] || continue
        if ! (cd "$repo" && cargo fmt --all --check) >/dev/null 2>&1; then
            deny "Rust sources are not formatted (cargo fmt --all --check failed). Run 'cargo fmt --all', stage the result and commit again."
        fi
        if grep -q ' fuzz/' <<<"$changed" && ! (cd "$repo/fuzz" && cargo fmt --check) >/dev/null 2>&1; then
            deny "fuzz/ is not formatted (it is its own workspace). Run 'cargo fmt' inside fuzz/, stage the result and commit again."
        fi
    fi
done < <(sed -E 's/(&&|\|\||[;|])/\n/g' <<<"$cmd")

exit 0
