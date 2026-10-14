#!/usr/bin/env bash
# Weekly base image digest check, run by .github/workflows/base-image-watch.yml.
#
# Finds every image pinned as image:tag@sha256:<digest> in the repo's
# Dockerfiles (any file named Dockerfile or Dockerfile.*) and in the image:
# lines of .github/workflows/*.yml. For each pinned image:tag it asks the
# registry once for the digest the tag points at now. When that differs from
# the pin, it opens an issue "Base image update: <image:tag>", or comments on
# the open one if the digest has moved again since it last reported. It never
# changes files and never opens pull requests.
#
# Usage, from the repo root:
#   .github/scripts/base-image-watch.sh              check this repo
#   .github/scripts/base-image-watch.sh --self-test  test the parsing and
#                                                    compare logic, no network
#
# Environment:
#   DRY_RUN       "false" opens and comments on issues. Anything else (and the
#                 default) prints what would happen and creates nothing.
#   LOOKUP_TOOL   docker (docker buildx imagetools) or crane. Default: docker
#                 when installed, else crane.
#   RETRY_DELAYS  seconds to wait before each retry of a failed lookup.
#                 Default "30 60 120": three retries.
#   GH_TOKEN, GH_REPO  for gh. Issues are read in a dry run and written only
#                 in a real run.
#   GITHUB_STEP_SUMMARY  the summary table is appended here when set.
#
# Exit status: 0 when every pin could be checked, 1 when a lookup still failed
# after the retries, a pin is malformed, or an issue could not be handled.
# Registry output is untrusted: a digest is used only after it matches
# ^sha256:[0-9a-f]{64}$.

# Backticks in the printf formats are Markdown code spans, not commands.
# shellcheck disable=SC2016

set -euo pipefail

DIGEST_RE='^sha256:[0-9a-f]{64}$'
# Docker reference grammar, simplified: lowercase path components, an optional
# registry port, and the tag character set.
NAME_RE='^[a-z0-9]+([._-]+[a-z0-9]+)*(:[0-9]+)?(/[a-z0-9]+([._-]+[a-z0-9]+)*)*$'
TAG_RE='^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$'
LOCATION_RE='^[A-Za-z0-9_.][A-Za-z0-9_./-]*:[0-9]+$'
# Lookup errors that will not go away on a retry.
PERMANENT_RE='not found|manifest unknown|name unknown|invalid reference'
MARKER='base-image-watch reported'
TITLE_PREFIX='Base image update: '

DRY_RUN=${DRY_RUN:-true}
RETRY_DELAYS=${RETRY_DELAYS:-30 60 120}
LOOKUP_TOOL=${LOOKUP_TOOL:-}
ISSUE_BACKEND=gh

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
RECORDS="$WORK/records"
: > "$RECORDS"

declare -A STAGES=()
declare -a KEYS=() ROWS=()
declare -A KEY_SEEN=() ROW_KIND=() ROW_REF=() ROW_KEY=() ROW_PIN=() ROW_LOCS=()
declare -A CURRENT=() LOOKUP_FAILED=()
FAILURES=0

log() { printf '%s\n' "$*"; }

# First line of a file, printable characters only, at most 200 of them. Used
# for registry and gh error text, which is untrusted.
first_line() { head -n 1 "$1" | tr -cd '[:print:]' | cut -c1-200; }

short() { if [[ -n $1 ]]; then printf 'sha256:%s' "${1:7:12}"; else printf -- '-'; fi; }

# ── Finding pins ────────────────────────────────────────────────────────────

# emit KIND NAME TAG DIGEST LOCATION
# KIND is pinned, notag, unpinned or malformed. Fields are separated by "|",
# which the name, tag, digest and location patterns never allow.
emit() {
    local loc=$5
    [[ $loc =~ $LOCATION_RE ]] || loc="(unusual-file-name)"
    printf '%s|%s|%s|%s|%s\n' "$1" "$2" "$3" "$4" "$loc" >> "$RECORDS"
}

# classify_ref REF LOCATION
classify_ref() {
    local ref=$1 loc=$2 name_tag digest="" name tag="" last
    if [[ $ref == *@* ]]; then
        name_tag=${ref%%@*}
        digest=${ref#*@}
    else
        name_tag=$ref
    fi
    # A tag is a colon in the last path component. A colon before the last
    # slash is a registry port.
    last=${name_tag##*/}
    if [[ $last == *:* ]]; then
        tag=${last##*:}
        name=${name_tag%:*}
    else
        name=$name_tag
    fi

    if [[ -n $digest && ! $digest =~ $DIGEST_RE ]]; then
        emit malformed "" "" "" "$loc"
        return 0
    fi
    if [[ ! $name =~ $NAME_RE || $last == *:*:* ]] || [[ -n $tag && ! $tag =~ $TAG_RE ]]; then
        # Unreadable, for example a build argument or a workflow expression.
        if [[ -n $digest ]]; then
            emit malformed "" "" "" "$loc"
        else
            emit unpinned "" "" "" "$loc"
        fi
        return 0
    fi
    if [[ -z $digest ]]; then
        emit unpinned "$name" "$tag" "" "$loc"
    elif [[ -z $tag ]]; then
        emit notag "$name" "" "$digest" "$loc"
    else
        emit pinned "$name" "$tag" "$digest" "$loc"
    fi
}

# parse_docker_line FILE LINENO LINE
# Reads FROM lines and the --from= option of COPY, ADD and RUN. Earlier stage
# names, stage numbers and scratch are not images. Reset STAGES per file.
parse_docker_line() {
    local file=$1 n=$2 line=${3%$'\r'} ref="" stage="" i word
    local -a w=()
    read -r -a w <<< "$line" || true
    [[ ${#w[@]} -gt 0 ]] || return 0
    case ${w[0],,} in
        from)
            for ((i = 1; i < ${#w[@]}; i++)); do
                [[ ${w[i]} == --* ]] && continue
                ref=${w[i]}
                break
            done
            if ((i + 2 < ${#w[@]})) && [[ ${w[i + 1],,} == as ]]; then
                stage=${w[i + 2],,}
            fi
            ;;
        copy | add | run)
            for word in "${w[@]:1}"; do
                [[ $word == --from=* ]] && ref=${word#--from=}
            done
            ;;
    esac
    if [[ -n $ref ]]; then
        local lower=${ref,,}
        if [[ $lower != scratch && -z ${STAGES[$lower]+x} && ! $ref =~ ^[0-9]+$ ]]; then
            classify_ref "$ref" "$file:$n"
        fi
    fi
    [[ -z $stage ]] || STAGES[$stage]=1
}

# parse_workflow_line FILE LINENO LINE
parse_workflow_line() {
    local file=$1 n=$2 line=${3%$'\r'} value
    [[ $line =~ ^[[:space:]]*(-[[:space:]]+)?image:[[:space:]]*(.*)$ ]] || return 0
    value=${BASH_REMATCH[2]}
    value=${value%%[[:space:]]#*}
    value=${value%"${value##*[![:space:]]}"}
    if [[ ${#value} -ge 2 && ( ($value == \"*\" ) || ($value == \'*\') ) ]]; then
        value=${value:1:${#value}-2}
    fi
    [[ -n $value ]] || return 0
    classify_ref "$value" "$file:$n"
}

scan_file() { # KIND FILE
    local kind=$1 file=$2 i
    local -a lines=()
    mapfile -t lines < "$file"
    STAGES=()
    for i in "${!lines[@]}"; do
        if [[ $kind == docker ]]; then
            parse_docker_line "$file" "$((i + 1))" "${lines[i]}"
        else
            parse_workflow_line "$file" "$((i + 1))" "${lines[i]}"
        fi
    done
}

# Tracked files only, so build output and node_modules are never read.
scan_repo() {
    local file base
    while IFS= read -r -d '' file; do
        base=${file##*/}
        if [[ $base == Dockerfile || $base == Dockerfile.* ]]; then
            scan_file docker "$file"
        fi
    done < <(git ls-files -z)
    while IFS= read -r -d '' file; do
        [[ $file == .github/workflows/*.yml && $file != .github/workflows/*/* ]] || continue
        scan_file workflow "$file"
    done < <(git ls-files -z -- .github/workflows)
}

# ── Grouping ────────────────────────────────────────────────────────────────

add_row() { # ID KIND REF KEY PIN LOCATION
    if [[ -z ${ROW_KIND[$1]+x} ]]; then
        ROWS+=("$1")
        ROW_KIND[$1]=$2 ROW_REF[$1]=$3 ROW_KEY[$1]=$4 ROW_PIN[$1]=$5 ROW_LOCS[$1]=$6
    else
        ROW_LOCS[$1]+=" $6"
    fi
}

# One row per image:tag+digest (or per image+digest, or per unpinned
# reference). One lookup per image:tag, whatever digests it is pinned at.
group_records() {
    local kind name tag digest loc key
    while IFS='|' read -r kind name tag digest loc; do
        case $kind in
            pinned)
                key="$name:$tag"
                add_row "p|$key@$digest" pinned "$key" "$key" "$digest" "$loc"
                if [[ -z ${KEY_SEEN[$key]+x} ]]; then
                    KEY_SEEN[$key]=1
                    KEYS+=("$key")
                fi
                ;;
            notag) add_row "n|$name@$digest" notag "$name" "" "$digest" "$loc" ;;
            unpinned)
                key=${name:+$name${tag:+:$tag}}
                add_row "u|${key:-?}" unpinned "${key:-(unreadable reference)}" "" "" "$loc"
                ;;
            malformed) add_row "m|$loc" malformed "(malformed pin)" "" "" "$loc" ;;
        esac
    done < "$RECORDS"
}

# ── Lookups ─────────────────────────────────────────────────────────────────

pick_lookup_tool() {
    if [[ -z $LOOKUP_TOOL ]]; then
        if command -v docker > /dev/null 2>&1; then LOOKUP_TOOL=docker; else LOOKUP_TOOL=crane; fi
    fi
    case $LOOKUP_TOOL in
        docker | crane | fake) ;;
        *) log "LOOKUP_TOOL must be docker or crane"; exit 1 ;;
    esac
}

# lookup_once IMAGE:TAG prints the digest of what the tag points at: the index
# digest for a multi-platform image. Errors go to stderr.
lookup_once() {
    case $LOOKUP_TOOL in
        docker) docker buildx imagetools inspect "$1" --format '{{json .Manifest}}' | jq -r '.digest // .Digest // empty' ;;
        crane) crane digest "$1" ;;
        fake) fake_lookup "$1" ;;
    esac
}

# lookup KEY sets CURRENT[KEY] or LOOKUP_FAILED[KEY]. Retries a 429 or network
# error once per entry in RETRY_DELAYS. A "not found" error or an answer that
# is not a digest is not retried.
lookup() {
    local key=$1 attempt=0 out err="$WORK/lookup.err"
    local -a delays=()
    read -r -a delays <<< "$RETRY_DELAYS" || true
    while :; do
        attempt=$((attempt + 1))
        if out=$(lookup_once "$key" 2> "$err"); then
            out=${out%$'\r'}
            if [[ $out =~ $DIGEST_RE ]]; then
                CURRENT[$key]=$out
                log "  $key: $(short "$out") (attempt $attempt)"
                return 0
            fi
            log "  $key: attempt $attempt: the answer is not a sha256 digest"
            break
        fi
        log "  $key: attempt $attempt failed: $(first_line "$err")"
        if grep -qiE "$PERMANENT_RE" "$err"; then
            break
        fi
        if ((attempt > ${#delays[@]})); then
            break
        fi
        log "  $key: retrying in ${delays[attempt - 1]} s"
        sleep "${delays[attempt - 1]}"
    done
    LOOKUP_FAILED[$key]=1
    FAILURES=$((FAILURES + 1))
    log "  $key: lookup failed"
}

row_result() { # ID
    local id=$1
    case ${ROW_KIND[$id]} in
        pinned)
            if [[ -n ${LOOKUP_FAILED[${ROW_KEY[$id]}]+x} ]]; then
                printf 'lookup failed'
            elif [[ ${CURRENT[${ROW_KEY[$id]}]} == "${ROW_PIN[$id]}" ]]; then
                printf 'up to date'
            else
                printf 'update available'
            fi
            ;;
        notag) printf 'cannot check, no tag' ;;
        unpinned) printf 'not pinned' ;;
        malformed) printf 'malformed pin' ;;
    esac
}

current_of() { # ID
    local key=${ROW_KEY[$1]}
    if [[ -n $key && -n ${CURRENT[$key]+x} ]]; then short "${CURRENT[$key]}"; else printf -- '-'; fi
}

write_summary() { # FILE
    local id loc locs mode="real run"
    local -a list=()
    [[ $DRY_RUN == false ]] || mode="dry run, nothing created"
    {
        printf '## Base image digest watch (%s)\n\n' "$mode"
        if [[ ${#ROWS[@]} -eq 0 ]]; then
            printf 'No image references found.\n'
            return 0
        fi
        printf '| Image:tag | Pinned digest | Current digest | Result | Pinned in |\n'
        printf '|---|---|---|---|---|\n'
        for id in "${ROWS[@]}"; do
            locs=""
            read -r -a list <<< "${ROW_LOCS[$id]}"
            for loc in "${list[@]}"; do locs+="${locs:+, }\`$loc\`"; done
            printf '| `%s` | `%s` | `%s` | %s | %s |\n' "${ROW_REF[$id]}" "$(short "${ROW_PIN[$id]}")" \
                "$(current_of "$id")" "$(row_result "$id")" "$locs"
        done
    } >> "$1"
}

# ── Issues ──────────────────────────────────────────────────────────────────

# issue_find TITLE prints the number of the open issue with exactly that
# title, or nothing.
issue_find() {
    if [[ $ISSUE_BACKEND == fake ]]; then fake_issue_find "$1"; return; fi
    local num title
    gh issue list --state open --limit 1000 --json number,title \
        --jq '.[] | "\(.number)\t\(.title)"' > "$WORK/issues" || return 1
    while IFS=$'\t' read -r num title; do
        if [[ $title == "$1" && $num =~ ^[0-9]+$ ]]; then
            printf '%s' "$num"
            return 0
        fi
    done < "$WORK/issues"
}

# issue_reported NUMBER prints the last digest this workflow reported on the
# issue. Only the body and comments written by the Actions bot count, so a
# marker pasted by someone else cannot silence the next report.
issue_reported() {
    if [[ $ISSUE_BACKEND == fake ]]; then fake_issue_reported "$1"; return; fi
    gh issue view "$1" --json author,body,comments --jq '
        def bot: .author.login | test("^(app/)?github-actions(\\[bot\\])?$");
        (if bot then .body else empty end), (.comments[] | select(bot) | .body)' \
        > "$WORK/issue-text" || return 1
    { grep -oE "$MARKER sha256:[0-9a-f]{64}" "$WORK/issue-text" || true; } | tail -n 1 | sed "s/^$MARKER //"
}

LABELS_READY=0
ensure_labels() {
    [[ $LABELS_READY -eq 0 ]] || return 0
    local name color description
    gh label list --limit 1000 --json name --jq '.[].name' > "$WORK/labels" || return 1
    while IFS='|' read -r name color description; do
        if ! grep -qxF "$name" "$WORK/labels"; then
            log "  creating label $name"
            gh label create "$name" --color "$color" --description "$description" || return 1
        fi
    done <<'EOF'
dependencies|0366d6|Pull requests that update a dependency file
docker|21ceff|Pull requests that update Docker code
EOF
    LABELS_READY=1
}

# pin_lines KEY lists each file and line that pins KEY, with its digest.
pin_lines() {
    local key=$1 id loc state
    local -a list=()
    for id in "${ROWS[@]}"; do
        [[ ${ROW_KIND[$id]} == pinned && ${ROW_KEY[$id]} == "$key" ]] || continue
        state="needs the update"
        [[ ${ROW_PIN[$id]} != "${CURRENT[$key]}" ]] || state="already current"
        read -r -a list <<< "${ROW_LOCS[$id]}"
        for loc in "${list[@]}"; do
            printf -- '- `%s` pins `%s` (%s)\n' "$loc" "${ROW_PIN[$id]}" "$state"
        done
    done
}

run_line() {
    if [[ -n ${GITHUB_RUN_ID:-} && ${GITHUB_RUN_ID} =~ ^[0-9]+$ ]]; then
        printf 'Found by run %s/%s/actions/runs/%s\n' "${GITHUB_SERVER_URL:-https://github.com}" \
            "${GITHUB_REPOSITORY:-}" "$GITHUB_RUN_ID"
    fi
}

# handle_issue KEY: open, comment or leave alone, as described at the top.
handle_issue() {
    local key=$1 new=${CURRENT[$1]} title num reported body="$WORK/body" today
    title="$TITLE_PREFIX$key"
    today=$(date -u +%Y-%m-%d)
    if ! num=$(issue_find "$title"); then
        log "  $key: could not list issues"
        return 1
    fi

    if [[ -z $num ]]; then
        {
            printf 'The tag `%s` now points at a different image than the one this repo pins.\n\n' "$key"
            printf -- '- Pinned digest: `%s`\n' "$(pinned_digests "$key")"
            printf -- '- Current digest: `%s`\n' "$new"
            printf -- '- Checked: %s (UTC)\n\n' "$today"
            printf 'Files and lines that pin it:\n\n'
            pin_lines "$key"
            printf '\nTo take the update, change each pin to the current digest in a pull request and let CI build it. '
            printf 'This workflow never edits files or opens pull requests, and it does not close this issue.\n\n'
            run_line
            printf '\n<!-- %s %s -->\n' "$MARKER" "$new"
        } > "$body"
        if [[ $DRY_RUN != false ]]; then
            log "  $key: DRY RUN, would open issue \"$title\" with labels dependencies, docker:"
            sed 's/^/    | /' "$body"
            return 0
        fi
        ensure_labels || { log "  $key: could not set up labels"; return 1; }
        gh issue create --title "$title" --label dependencies --label docker --body-file "$body" > /dev/null \
            || { log "  $key: could not open the issue"; return 1; }
        log "  $key: opened issue \"$title\""
        return 0
    fi

    if ! reported=$(issue_reported "$num"); then
        log "  $key: could not read issue #$num"
        return 1
    fi
    if [[ $reported == "$new" ]]; then
        log "  $key: issue #$num already reports $(short "$new"), nothing to do"
        return 0
    fi
    {
        printf 'The tag `%s` has moved again.\n\n' "$key"
        printf -- '- Current digest: `%s`\n' "$new"
        printf -- '- Last reported here: `%s`\n' "${reported:-none}"
        printf -- '- Checked: %s (UTC)\n\n' "$today"
        printf 'Files and lines that pin it:\n\n'
        pin_lines "$key"
        printf '\n'
        run_line
        printf '\n<!-- %s %s -->\n' "$MARKER" "$new"
    } > "$body"
    if [[ $DRY_RUN != false ]]; then
        log "  $key: DRY RUN, would comment on issue #$num:"
        sed 's/^/    | /' "$body"
        return 0
    fi
    gh issue comment "$num" --body-file "$body" > /dev/null \
        || { log "  $key: could not comment on issue #$num"; return 1; }
    log "  $key: commented on issue #$num"
}

pinned_digests() { # KEY, the distinct pinned digests joined by "`, `"
    local key=$1 id out=""
    for id in "${ROWS[@]}"; do
        [[ ${ROW_KIND[$id]} == pinned && ${ROW_KEY[$id]} == "$key" && ${ROW_PIN[$id]} != "${CURRENT[$key]}" ]] || continue
        out+="${out:+\`, \`}${ROW_PIN[$id]}"
    done
    printf '%s' "$out"
}

# ── Main ────────────────────────────────────────────────────────────────────

check() { # SUMMARY_FILE
    local key id summary=$1 malformed=0
    group_records
    log "Pinned image:tags to look up: ${#KEYS[@]}"
    for key in "${KEYS[@]}"; do lookup "$key"; done

    write_summary "$WORK/summary"
    cat "$WORK/summary"
    [[ -z $summary ]] || cat "$WORK/summary" >> "$summary"

    log ""
    log "Issues:"
    local updates=0
    for key in "${KEYS[@]}"; do
        [[ -z ${LOOKUP_FAILED[$key]+x} ]] || continue
        for id in "${ROWS[@]}"; do
            if [[ ${ROW_KIND[$id]} == pinned && ${ROW_KEY[$id]} == "$key" && ${ROW_PIN[$id]} != "${CURRENT[$key]}" ]]; then
                updates=$((updates + 1))
                handle_issue "$key" || FAILURES=$((FAILURES + 1))
                break
            fi
        done
    done
    [[ $updates -gt 0 ]] || log "  no updates available"

    for id in "${ROWS[@]}"; do
        [[ ${ROW_KIND[$id]} != malformed ]] || malformed=$((malformed + 1))
    done
    if [[ $malformed -gt 0 ]]; then
        log "Malformed pins: $malformed. A pin needs a valid image name and tag, and a digest of sha256: and 64 lowercase hex characters."
        FAILURES=$((FAILURES + malformed))
    fi
    if [[ $FAILURES -gt 0 ]]; then
        log "FAILED: $FAILURES problem(s), see above."
        return 1
    fi
    log "Done."
}

# ── Self-test ───────────────────────────────────────────────────────────────

TESTS_FAILED=0
expect() { # DESCRIPTION EXPECTED ACTUAL
    if [[ $2 == "$3" ]]; then
        log "ok    $1"
    else
        log "FAIL  $1"
        log "      expected: $2"
        log "      actual:   $3"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

expect_line() { # DESCRIPTION FILE FIXED_STRING
    if grep -qF -- "$3" "$2"; then
        log "ok    $1"
    else
        log "FAIL  $1: no line with: $3"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

hex() { printf "%0${2:-64}d" 0 | tr 0 "$1"; }

# Fake registry answers, one word per attempt, the last word repeating.
# "err:TEXT" is a failed attempt with TEXT on stderr (underscores for spaces).
declare -A FAKE_ANSWERS=()
fake_lookup() {
    local ref=$1 n answer
    local -a answers=()
    printf '%s\n' "$ref" >> "$WORK/attempts"
    n=$(grep -cxF -- "$ref" "$WORK/attempts")
    read -r -a answers <<< "${FAKE_ANSWERS[$ref]:-err:not_found}"
    answer=${answers[n - 1]:-${answers[${#answers[@]} - 1]}}
    if [[ $answer == err:* ]]; then
        printf '%s\n' "${answer#err:}" | tr _ ' ' >&2
        return 1
    fi
    printf '%s\n' "$answer"
}
declare -A FAKE_ISSUES=() FAKE_REPORTED=()
fake_issue_find() { printf '%s' "${FAKE_ISSUES[$1]:-}"; }
fake_issue_reported() { printf '%s' "${FAKE_REPORTED[$1]:-}"; }

attempts() { grep -cxF -- "$1" "$WORK/attempts" || true; }

self_test() {
    local A B C D E F G H I PY TOOL NODE out status
    A=sha256:$(hex a) B=sha256:$(hex b) C=sha256:$(hex c) D=sha256:$(hex d) E=sha256:$(hex e)
    F=sha256:$(hex f) G=sha256:$(hex 1) H=sha256:$(hex 2) I=sha256:$(hex 3)
    PY=public.ecr.aws/docker/library/python:3.12-slim-trixie
    TOOL=ghcr.io/example/tool:1.2.3
    NODE=public.ecr.aws/docker/library/node:24-trixie-slim

    log "Parsing"
    STAGES=()
    local -a docker_lines=(
        "# syntax=docker/dockerfile:1"
        "FROM $PY@$A AS build"
        "RUN pip install --no-cache-dir app"
        "FROM --platform=linux/amd64 $PY@$A"
        "COPY --from=build /app /app"
        "FROM build AS test"
        "FROM scratch"
        "COPY --from=0 /a /b"
        "COPY --from=docker.io/library/busybox:1.37 /bin/busybox /busybox"
        "FROM localhost:5000/team/base@$B"
        "from python:3.11@sha256:abc123"
        "FROM python:3.10@sha256:$(hex A)"
        "FROM $NODE@$H"
        "FROM registry.example.com/down:1@$G"
        "FROM registry.example.com/liar:2@$G"
    )
    local i
    for i in "${!docker_lines[@]}"; do
        parse_docker_line sample/Dockerfile "$((i + 1))" "${docker_lines[i]}"
    done
    local -a workflow_lines=(
        "        image: postgres:16"
        "        image: adobe/s3mock@$C   # no tag"
        "      - image: \"$TOOL@$D\"  # quoted, with a comment"
        "        image: \${{ matrix.image }}"
        "        image: 'evil:1;touch x@$D'"
        "        image: $PY@$E"
        "        name: not an image line $PY@$E"
    )
    for i in "${!workflow_lines[@]}"; do
        parse_workflow_line .github/workflows/sample.yml "$((i + 1))" "${workflow_lines[i]}"
    done

    out=$(cat "$RECORDS")
    expect "every reference is classified, stages and scratch skipped" "pinned|public.ecr.aws/docker/library/python|3.12-slim-trixie|$A|sample/Dockerfile:2
pinned|public.ecr.aws/docker/library/python|3.12-slim-trixie|$A|sample/Dockerfile:4
unpinned|docker.io/library/busybox|1.37||sample/Dockerfile:9
notag|localhost:5000/team/base||$B|sample/Dockerfile:10
malformed||||sample/Dockerfile:11
malformed||||sample/Dockerfile:12
pinned|public.ecr.aws/docker/library/node|24-trixie-slim|$H|sample/Dockerfile:13
pinned|registry.example.com/down|1|$G|sample/Dockerfile:14
pinned|registry.example.com/liar|2|$G|sample/Dockerfile:15
unpinned|postgres|16||.github/workflows/sample.yml:1
notag|adobe/s3mock||$C|.github/workflows/sample.yml:2
pinned|ghcr.io/example/tool|1.2.3|$D|.github/workflows/sample.yml:3
unpinned||||.github/workflows/sample.yml:4
malformed||||.github/workflows/sample.yml:5
pinned|public.ecr.aws/docker/library/python|3.12-slim-trixie|$E|.github/workflows/sample.yml:6" "$out"

    log ""
    log "Compare (fake registry, fake issues, dry run)"
    LOOKUP_TOOL=fake ISSUE_BACKEND=fake DRY_RUN=true RETRY_DELAYS="0 0 0"
    : > "$WORK/attempts"
    FAKE_ANSWERS[$PY]=$A
    FAKE_ANSWERS[$TOOL]="err:429_Too_Many_Requests err:dial_tcp:_connection_reset_by_peer $F"
    FAKE_ANSWERS[$NODE]=$I
    FAKE_ANSWERS[registry.example.com/down:1]="err:429_Too_Many_Requests"
    FAKE_ANSWERS[registry.example.com/liar:2]='sha256:<script>alert(1)</script>'
    FAKE_ISSUES["${TITLE_PREFIX}$PY"]=8
    FAKE_REPORTED[8]=$B
    FAKE_ISSUES["${TITLE_PREFIX}$TOOL"]=7
    FAKE_REPORTED[7]=$F

    status=0
    check "" > "$WORK/out" 2>&1 || status=$?
    sed 's/^/    > /' "$WORK/out"

    expect "the run fails (two lookups failed, three pins malformed)" 1 "$status"
    expect "python pinned in three places, looked up once" 1 "$(attempts "$PY")"
    expect "429 then network error then success: three attempts" 3 "$(attempts "$TOOL")"
    expect "lasting 429: one try and three retries" 4 "$(attempts registry.example.com/down:1)"
    expect "an answer that is not a digest is not retried" 1 "$(attempts registry.example.com/liar:2)"
    expect "untagged and unpinned references are not looked up" 0 \
        "$(grep -cE '^(localhost|adobe|postgres|docker\.io)' "$WORK/attempts" || true)"
    expect_line "two stages, same pin: one row" "$WORK/out" \
        "| \`$PY\` | \`$(short "$A")\` | \`$(short "$A")\` | up to date | \`sample/Dockerfile:2\`, \`sample/Dockerfile:4\` |"
    expect_line "same tag, other digest: update available" "$WORK/out" \
        "| \`$PY\` | \`$(short "$E")\` | \`$(short "$A")\` | update available |"
    expect_line "no tag row" "$WORK/out" "| \`adobe/s3mock\` | \`$(short "$C")\` | \`-\` | cannot check, no tag |"
    expect_line "not pinned row" "$WORK/out" "| \`postgres:16\` | \`-\` | \`-\` | not pinned |"
    expect_line "lookup failed row" "$WORK/out" "| \`registry.example.com/down:1\` | \`$(short "$G")\` | \`-\` | lookup failed |"
    expect_line "malformed digest row" "$WORK/out" "| \`(malformed pin)\` | \`-\` | \`-\` | malformed pin | \`sample/Dockerfile:11\` |"
    expect_line "no issue yet: would open one" "$WORK/out" \
        "$NODE: DRY RUN, would open issue \"${TITLE_PREFIX}$NODE\" with labels dependencies, docker:"
    expect_line "issue body lists the pinning line" "$WORK/out" "| - \`sample/Dockerfile:13\` pins \`$H\` (needs the update)"
    expect_line "issue reports an older digest: would comment" "$WORK/out" "$PY: DRY RUN, would comment on issue #8:"
    expect_line "issue already reports this digest: nothing" "$WORK/out" \
        "$TOOL: issue #7 already reports $(short "$F"), nothing to do"
    expect "registry text never reaches the output" 0 "$(grep -c 'script' "$WORK/out" || true)"
    expect "no issue for an up-to-date or failed image" 0 \
        "$(grep -cE 'down:1: DRY|liar:2: DRY' "$WORK/out" || true)"

    log ""
    if [[ $TESTS_FAILED -gt 0 ]]; then
        log "self-test FAILED: $TESTS_FAILED check(s)"
        return 1
    fi
    log "self-test passed"
}

main() {
    if [[ ${1:-} == --self-test ]]; then
        self_test
        return
    fi
    if [[ $# -gt 0 ]]; then
        log "usage: $0 [--self-test]"
        return 2
    fi
    pick_lookup_tool
    log "Lookup tool: $LOOKUP_TOOL. Mode: $([[ $DRY_RUN == false ]] && echo real run || echo dry run)."
    scan_repo
    check "${GITHUB_STEP_SUMMARY:-}"
}

main "$@"
