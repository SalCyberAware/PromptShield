#!/usr/bin/env bash
# Weekly base image digest check, run by .github/workflows/base-image-watch.yml.
#
# Finds every image pinned as image:tag@sha256:<digest> in the repo's
# Dockerfiles (any file named Dockerfile or Dockerfile.*) and in the image:
# lines of .github/workflows/*.yml. For each pinned image:tag it sends one
# HEAD request for the tag's manifest and reads the Docker-Content-Digest
# header, the digest the tag points at now. When that differs from
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
#   RETRY_DELAYS  seconds to wait before each retry of a failed lookup.
#                 Default "30 60 120": three retries.
#   GH_TOKEN, GH_REPO  for gh. Issues are read in a dry run and written only
#                 in a real run.
#   GITHUB_STEP_SUMMARY  the summary table is appended here when set.
#
# Exit status: 0 when every pin could be checked, 1 when a lookup still failed
# after the retries, a pin is malformed, or an issue could not be handled.
# Registry output is untrusted: a digest is used only after it matches
# ^sha256:[0-9a-f]{64}$, and no registry text is ever printed. Needs bash 4,
# curl and gh, nothing else.

# Backticks in the printf formats are Markdown code spans, not commands.
# shellcheck disable=SC2016

set -euo pipefail

DIGEST_RE='^sha256:[0-9a-f]{64}$'
# Docker reference grammar, simplified: lowercase path components, an optional
# registry port, and the tag character set.
NAME_RE='^[a-z0-9]+([._-]+[a-z0-9]+)*(:[0-9]+)?(/[a-z0-9]+([._-]+[a-z0-9]+)*)*$'
TAG_RE='^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$'
LOCATION_RE='^[A-Za-z0-9_.][A-Za-z0-9_./-]*:[0-9]+$'
# The registry answers with the digest of whatever the tag points at: the
# index for a multi-platform image, else the single manifest.
ACCEPT='application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json'
# A token realm must be https on the registry's own host or on its known token
# host here, so a registry cannot send the token request anywhere else.
declare -A TOKEN_HOSTS=([registry-1.docker.io]=auth.docker.io)
REALM_RE='^https://([A-Za-z0-9.-]+)(:[0-9]+)?(/[A-Za-z0-9._~/-]*)?$'
TOKEN_RE='"(access_token|token)"[[:space:]]*:[[:space:]]*"([^"]*)"'
# The token is written into a curl config line, so only these characters, and
# at most TOKEN_MAX of them, are accepted.
TOKEN_OK_RE='^[A-Za-z0-9._~+/=-]+$'
TOKEN_MAX=8192
MARKER='base-image-watch reported'
TITLE_PREFIX='Base image update: '

DRY_RUN=${DRY_RUN:-true}
RETRY_DELAYS=${RETRY_DELAYS:-30 60 120}
ISSUE_BACKEND=gh

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
RECORDS="$WORK/records"
: > "$RECORDS"

declare -A STAGES=()
declare -a KEYS=() ROWS=()
declare -A KEY_SEEN=() ROW_KIND=() ROW_REF=() ROW_KEY=() ROW_PIN=() ROW_LOCS=()
declare -A CURRENT=() LOOKUP_FAILED=()
# Anonymous pull token per registry host, reused while the registry accepts
# it. Kept in this variable only and never printed.
declare -A TOKENS=()
declare -A HEAD_REJECTED=()
FAILURES=0

log() { printf '%s\n' "$*"; }

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

# split_ref IMAGE:TAG sets REF_REGISTRY, REF_REPO and REF_TAG for the
# registry API. Docker Hub names (no registry, or docker.io) go to
# registry-1.docker.io, with library/ for official images.
split_ref() {
    local name=${1%:*} first
    REF_TAG=${1##*:}
    first=${name%%/*}
    if [[ $name == */* && ($first == *.* || $first == *:* || $first == localhost) ]]; then
        REF_REGISTRY=$first REF_REPO=${name#*/}
    else
        REF_REGISTRY=docker.io REF_REPO=$name
    fi
    if [[ $REF_REGISTRY == docker.io || $REF_REGISTRY == index.docker.io ]]; then
        REF_REGISTRY=registry-1.docker.io
        [[ $REF_REPO == */* ]] || REF_REPO=library/$REF_REPO
    fi
}

manifest_url() { # IMAGE:TAG
    split_ref "$1"
    printf 'https://%s/v2/%s/manifests/%s' "$REF_REGISTRY" "$REF_REPO" "$REF_TAG"
}

# header_value FILE NAME prints the value of the last NAME header in a saved
# response, matching the name in any case and ignoring CR line ends.
header_value() {
    local line name value=""
    while IFS= read -r line || [[ -n $line ]]; do
        line=${line%$'\r'}
        [[ $line == *:* ]] || continue
        name=${line%%:*}
        if [[ ${name,,} == "${2,,}" ]]; then
            value=${line#*:}
            value=${value#"${value%%[![:space:]]*}"}
            value=${value%"${value##*[![:space:]]}"}
        fi
    done < "$1"
    printf '%s' "$value"
}

# parse_challenge FILE REGISTRY REPO reads the "WWW-Authenticate: Bearer
# realm=...,service=...,scope=..." header of a saved 401 and sets CH_REALM,
# CH_SERVICE and CH_SCOPE. With no scope it asks for repository:REPO:pull.
# Fails with CH_ERROR set when the challenge is unusable or the realm is not
# https on the registry's host or its known token host.
parse_challenge() {
    local rest key value host
    CH_REALM="" CH_SERVICE="" CH_SCOPE="" CH_ERROR=""
    rest=$(header_value "$1" www-authenticate)
    if [[ ! $rest =~ ^[Bb][Ee][Aa][Rr][Ee][Rr][[:space:]]+(.*)$ ]]; then
        CH_ERROR="no Bearer challenge"
        return 1
    fi
    rest=${BASH_REMATCH[1]}
    while [[ $rest =~ ^[[:space:],]*([A-Za-z]+)=\"([^\"]*)\"(.*)$ ]]; do
        key=${BASH_REMATCH[1],,} value=${BASH_REMATCH[2]} rest=${BASH_REMATCH[3]}
        case $key in
            realm) CH_REALM=$value ;;
            service) CH_SERVICE=$value ;;
            scope) CH_SCOPE=$value ;;
        esac
    done
    if [[ ! $CH_REALM =~ $REALM_RE ]]; then
        CH_ERROR="token realm is not an https URL"
        return 1
    fi
    host=${BASH_REMATCH[1],,}
    if [[ $host != "${2%%:*}" && $host != "${TOKEN_HOSTS[${2%%:*}]:-}" ]]; then
        CH_ERROR="token realm is on another host"
        return 1
    fi
    [[ -n $CH_SCOPE ]] || CH_SCOPE="repository:$3:pull"
    if [[ ! $CH_SERVICE =~ ^[A-Za-z0-9._:-]*$ || ! $CH_SCOPE =~ ^[A-Za-z0-9._:/,*-]+$ ]]; then
        CH_ERROR="unexpected characters in the challenge"
        return 1
    fi
}

# http_request METHOD URL [TOKEN] sends one manifest request, saves the
# response headers to $WORK/headers and prints the status ("000" for no
# answer). The token reaches curl on stdin, never on the command line.
# No redirects are followed.
http_request() {
    local method=$1 url=$2 token=${3:-} code
    local -a args=(--silent --connect-timeout 10 --max-time 30 --proto "=https"
        --output /dev/null --dump-header "$WORK/headers" --write-out '%{http_code}'
        --header "Accept: $ACCEPT")
    if [[ $method == HEAD ]]; then args+=(--head); fi
    : > "$WORK/headers"
    code=$(if [[ -n $token ]]; then printf 'header = "Authorization: Bearer %s"\n' "$token"; fi |
        curl --config - "${args[@]}" "$url" 2> /dev/null) || true
    [[ $code =~ ^[0-9]{3}$ ]] || code=000
    printf '%s' "$code"
}

# token_request REALM SERVICE SCOPE asks the token endpoint for an anonymous
# pull token and prints the answer, a newline and the status. No credentials
# are sent.
token_request() {
    local -a args=(--silent --connect-timeout 10 --max-time 30 --proto "=https" --get
        --write-out '\n%{http_code}' --data-urlencode "scope=$3")
    if [[ -n $2 ]]; then args+=(--data-urlencode "service=$2"); fi
    curl "${args[@]}" "$1" 2> /dev/null || true
}

status_reason() { # STATUS
    case $1 in
        000) printf 'no answer, network error or timeout' ;;
        401) printf 'unauthorized' ;;
        403) printf 'forbidden' ;;
        404) printf 'not found' ;;
        405 | 501) printf 'method not allowed' ;;
        429) printf 'too many requests' ;;
        5??) printf 'server error' ;;
        *) printf 'unexpected status' ;;
    esac
}

retryable() { [[ $1 == 000 || $1 == 429 || $1 == 5?? ]]; }

token_ok() { [[ ${#1} -le $TOKEN_MAX && $1 =~ $TOKEN_OK_RE ]]; }

# get_token HOST sets TOKENS[HOST] from the challenge in CH_*. On failure it
# sets LK_STATUS and LK_REASON and returns 1 when a retry may help, else 2.
# A token that fails token_ok is never stored or printed and is not retried.
get_token() {
    local out code token
    out=$(token_request "$CH_REALM" "$CH_SERVICE" "$CH_SCOPE")
    code=${out##*$'\n'}
    [[ $code =~ ^[0-9]{3}$ ]] || code=000
    LK_STATUS=$code
    if [[ $code == 200 && $out =~ $TOKEN_RE ]]; then
        token=${BASH_REMATCH[2]}
        if token_ok "$token"; then
            TOKENS[$1]=$token
            return 0
        fi
        LK_REASON="token request failed: unexpected characters or too long"
        return 2
    fi
    if [[ $code == 200 ]]; then
        LK_REASON="token request: no token in the answer"
        return 2
    fi
    LK_REASON="token request: $(status_reason "$code")"
    if retryable "$code"; then return 1; fi
    return 2
}

# lookup_once IMAGE:TAG makes one manifest request. Only when the registry
# answers 401 does it fetch an anonymous token and send the request once more.
# A registry that rejects HEAD gets a GET instead. Sets LK_STATUS, LK_REASON
# and LK_DIGEST, and adds to LK_REQUESTS. Returns 0 with a digest, 1 when a
# retry may help, 2 when it will not.
lookup_once() {
    local key=$1 url host method=HEAD asked_token=0 rc
    url=$(manifest_url "$key")
    split_ref "$key"
    host=$REF_REGISTRY
    LK_DIGEST="" LK_REASON=""
    while :; do
        [[ -z ${HEAD_REJECTED[$host]+x} ]] || method=GET
        LK_STATUS=$(http_request "$method" "$url" "${TOKENS[$host]:-}")
        LK_REQUESTS=$((LK_REQUESTS + 1))
        case $LK_STATUS in
            200)
                LK_DIGEST=$(header_value "$WORK/headers" docker-content-digest)
                [[ ! $LK_DIGEST =~ $DIGEST_RE ]] || return 0
                if [[ -z $LK_DIGEST ]]; then
                    LK_REASON="no Docker-Content-Digest header"
                else
                    LK_REASON="the answer is not a sha256 digest"
                fi
                LK_DIGEST=""
                return 2
                ;;
            401)
                if ((asked_token)); then
                    LK_REASON="unauthorized, even with a new token"
                    return 2
                fi
                asked_token=1
                if ! parse_challenge "$WORK/headers" "$host" "$REF_REPO"; then
                    LK_REASON=$CH_ERROR
                    return 2
                fi
                rc=0
                get_token "$host" || rc=$?
                LK_REQUESTS=$((LK_REQUESTS + 1))
                ((rc == 0)) || return "$rc"
                ;;
            405 | 501)
                if [[ $method == GET ]]; then
                    LK_REASON=$(status_reason "$LK_STATUS")
                    return 2
                fi
                HEAD_REJECTED[$host]=1
                ;;
            *)
                LK_REASON=$(status_reason "$LK_STATUS")
                if retryable "$LK_STATUS"; then return 1; fi
                return 2
                ;;
        esac
    done
}

# lookup KEY sets CURRENT[KEY] or LOOKUP_FAILED[KEY]. A 429, 5xx or network
# error is retried once per entry in RETRY_DELAYS. A 404, any other status or
# an answer that is not a digest is not retried. Each failed attempt is logged
# with the HTTP status first.
lookup() {
    local key=$1 attempt=0 rc
    local -a delays=()
    read -r -a delays <<< "$RETRY_DELAYS" || true
    LK_REQUESTS=0
    while :; do
        attempt=$((attempt + 1))
        rc=0
        lookup_once "$key" || rc=$?
        if ((rc == 0)); then
            CURRENT[$key]=$LK_DIGEST
            log "  $key: $(short "$LK_DIGEST") (HTTP $LK_STATUS, attempt $attempt, $LK_REQUESTS request(s))"
            return 0
        fi
        log "  HTTP $LK_STATUS ($LK_REASON) on attempt $attempt: $key"
        ((rc == 1 && attempt <= ${#delays[@]})) || break
        log "  $key: retrying in ${delays[attempt - 1]} s"
        sleep "${delays[attempt - 1]}"
    done
    LOOKUP_FAILED[$key]=1
    FAILURES=$((FAILURES + 1))
    log "  $key: lookup failed after $LK_REQUESTS request(s)"
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

# Fake registry, standing in for http_request and token_request in the
# self-test. FAKE_HTTP[URL] lists one answer per request to that URL, the last
# one repeating: a status, optionally ":" and the Docker-Content-Digest value.
# A 401 carries FAKE_CHALLENGE. Each request is logged to $WORK/requests as
# URL, method and whether it carried a token.
declare -A FAKE_HTTP=()
FAKE_CHALLENGE=""
FAKE_TOKEN='FAKE-SECRET-TOKEN'
fake_http() { # METHOD URL [TOKEN]
    local n answer status digest=""
    local -a answers=()
    printf '%s\t%s\t%s\n' "$2" "$1" "${3:+token}" >> "$WORK/requests"
    n=$(cut -f1 "$WORK/requests" | grep -cxF -- "$2")
    read -r -a answers <<< "${FAKE_HTTP[$2]:-404}"
    answer=${answers[n - 1]:-${answers[${#answers[@]} - 1]}}
    status=${answer%%:*}
    [[ $answer != *:* ]] || digest=${answer#*:}
    {
        printf 'HTTP/1.1 %s Fake\r\n' "$status"
        if [[ $status == 401 ]]; then printf 'www-authenticate: %s\r\n' "$FAKE_CHALLENGE"; fi
        if [[ -n $digest ]]; then printf 'docker-content-digest: %s\r\n' "$digest"; fi
        printf '\r\n'
    } > "$WORK/headers"
    printf '%s' "$status"
}
fake_token() { # REALM SERVICE SCOPE
    printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$WORK/tokens"
    printf '{"token": "%s", "expires_in": 300}\n200' "$FAKE_TOKEN"
}
declare -A FAKE_ISSUES=() FAKE_REPORTED=()
fake_issue_find() { printf '%s' "${FAKE_ISSUES[$1]:-}"; }
fake_issue_reported() { printf '%s' "${FAKE_REPORTED[$1]:-}"; }

# requests URL counts the manifest requests sent to URL.
requests() { cut -f1 "$WORK/requests" | grep -cxF -- "$1" || true; }

# challenge HEADER_VALUE REGISTRY REPO prints what parse_challenge made of it.
challenge() {
    printf 'HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: %s\r\n\r\n' "$1" > "$WORK/challenge"
    if parse_challenge "$WORK/challenge" "$2" "$3"; then
        printf 'ok %s %s %s' "$CH_REALM" "$CH_SERVICE" "$CH_SCOPE"
    else
        printf 'refused: %s' "$CH_ERROR"
    fi
}

self_test() {
    local A B C D E F G H I PY TOOL NODE out status rc url T=$'\t'
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
        "FROM registry.example.com/old:3@$G"
        "FROM registry.example.com/gone:4@$G"
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
pinned|registry.example.com/old|3|$G|sample/Dockerfile:16
pinned|registry.example.com/gone|4|$G|sample/Dockerfile:17
unpinned|postgres|16||.github/workflows/sample.yml:1
notag|adobe/s3mock||$C|.github/workflows/sample.yml:2
pinned|ghcr.io/example/tool|1.2.3|$D|.github/workflows/sample.yml:3
unpinned||||.github/workflows/sample.yml:4
malformed||||.github/workflows/sample.yml:5
pinned|public.ecr.aws/docker/library/python|3.12-slim-trixie|$E|.github/workflows/sample.yml:6" "$out"

    log ""
    log "Registry names"
    expect "Docker Hub official image" "https://registry-1.docker.io/v2/library/postgres/manifests/16" \
        "$(manifest_url postgres:16)"
    expect "docker.io prefix" "https://registry-1.docker.io/v2/library/busybox/manifests/1.37" \
        "$(manifest_url docker.io/library/busybox:1.37)"
    expect "Docker Hub user image" "https://registry-1.docker.io/v2/adobe/s3mock/manifests/4" \
        "$(manifest_url adobe/s3mock:4)"
    expect "registry with a port" "https://localhost:5000/v2/team/base/manifests/2" \
        "$(manifest_url localhost:5000/team/base:2)"
    expect "public.ecr.aws" "https://public.ecr.aws/v2/docker/library/python/manifests/3.12-slim-trixie" \
        "$(manifest_url "$PY")"

    log ""
    log "Token challenge"
    expect "valid challenge" "ok https://public.ecr.aws/token/ public.ecr.aws aws" \
        "$(challenge 'Bearer realm="https://public.ecr.aws/token/",service="public.ecr.aws",scope="aws"' \
            public.ecr.aws docker/library/python)"
    expect "no scope: asks for pull on the repository, known token host" \
        "ok https://auth.docker.io/token registry.docker.io repository:library/postgres:pull" \
        "$(challenge 'Bearer realm="https://auth.docker.io/token",service="registry.docker.io"' \
            registry-1.docker.io library/postgres)"
    expect "non-https realm refused" "refused: token realm is not an https URL" \
        "$(challenge 'Bearer realm="http://public.ecr.aws/token/",service="public.ecr.aws",scope="aws"' \
            public.ecr.aws docker/library/python)"
    expect "realm on a foreign host refused" "refused: token realm is on another host" \
        "$(challenge 'Bearer realm="https://tokens.example.net/token",service="public.ecr.aws",scope="aws"' \
            public.ecr.aws docker/library/python)"
    expect "look-alike realm host refused" "refused: token realm is on another host" \
        "$(challenge 'Bearer realm="https://public.ecr.aws.example.net/token",scope="aws"' \
            public.ecr.aws docker/library/python)"
    expect "Docker Hub's token host is not accepted for another registry" "refused: token realm is on another host" \
        "$(challenge 'Bearer realm="https://auth.docker.io/token",service="registry.docker.io"' \
            ghcr.io example/tool)"
    expect "not a Bearer challenge" "refused: no Bearer challenge" \
        "$(challenge 'Basic realm="registry"' public.ecr.aws docker/library/python)"

    log ""
    log "Digest header"
    printf 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nDOCKER-CONTENT-DIGEST: %s\r\n\r\n' "$A" > "$WORK/h1"
    expect "header name in any case, CRLF line ends" "$A" "$(header_value "$WORK/h1" docker-content-digest)"
    printf 'HTTP/1.1 200 OK\nDocker-Content-Digest:   %s  \n\n' "$B" > "$WORK/h2"
    expect "LF line ends and padding" "$B" "$(header_value "$WORK/h2" docker-content-digest)"
    printf 'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n' > "$WORK/h3"
    expect "missing header gives nothing" "" "$(header_value "$WORK/h3" docker-content-digest)"

    http_request() { fake_http "$@"; }
    token_request() { fake_token "$@"; }
    : > "$WORK/requests"
    : > "$WORK/tokens"
    LK_REQUESTS=0
    url=$(manifest_url registry.example.com/nohdr:1)
    FAKE_HTTP[$url]=200
    rc=0
    lookup_once registry.example.com/nohdr:1 || rc=$?
    expect "200 without the header: not retried" "2 200 no Docker-Content-Digest header" "$rc $LK_STATUS $LK_REASON"
    url=$(manifest_url registry.example.com/upper:1)
    FAKE_HTTP[$url]="200:sha256:$(hex A)"
    rc=0
    lookup_once registry.example.com/upper:1 || rc=$?
    expect "malformed digest in the header: not retried, not used" "2 the answer is not a sha256 digest|" \
        "$rc $LK_REASON|$LK_DIGEST"

    log ""
    log "Token check"
    local saved_token=$FAKE_TOKEN bad_token=$'BAD-TOKEN\nheader = "X-Injected: 1"'
    out=""
    for rc in 'BAD"TOKEN' "$bad_token" "$(hex 0 $((TOKEN_MAX + 1)))" ""; do
        if token_ok "$rc"; then out+=pass,; else out+=refused,; fi
    done
    expect "a token with a quote or newline, too long or empty is refused" "refused,refused,refused,refused," "$out"
    out=""
    for rc in "$FAKE_TOKEN" "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln-_~+/=" "$(hex 0 "$TOKEN_MAX")"; do
        if token_ok "$rc"; then out+=pass,; else out+=refused,; fi
    done
    expect "a normal token passes, also at the length limit" "pass,pass,pass," "$out"
    : > "$WORK/requests"
    : > "$WORK/tokens"
    TOKENS=()
    FAKE_CHALLENGE='Bearer realm="https://registry.example.com/token",service="registry.example.com"'
    url=$(manifest_url registry.example.com/badtoken:1)
    FAKE_HTTP[$url]=401
    FAKE_TOKEN=$bad_token
    rc=0
    lookup_once registry.example.com/badtoken:1 || rc=$?
    expect "a token from the endpoint with a newline: failed token request, not retried, not kept" \
        "2 200 token request failed: unexpected characters or too long 1 1 0" \
        "$rc $LK_STATUS $LK_REASON $(requests "$url") $(wc -l < "$WORK/tokens") ${#TOKENS[@]}"
    (RETRY_DELAYS="0 0 0" lookup registry.example.com/badtoken:1) > "$WORK/badtoken" 2>&1 || true
    expect "a refused token is never printed" "0 1" \
        "$(grep -c 'BAD-TOKEN\|Injected' "$WORK/badtoken" || true) $(grep -c 'token request failed' "$WORK/badtoken" || true)"
    FAKE_TOKEN=$saved_token

    log ""
    log "Compare (fake registry, fake issues, dry run)"
    ISSUE_BACKEND=fake DRY_RUN=true RETRY_DELAYS="0 0 0"
    : > "$WORK/requests"
    : > "$WORK/tokens"
    TOKENS=()
    FAKE_CHALLENGE='Bearer realm="https://public.ecr.aws/token/",service="public.ecr.aws",scope="aws"'
    FAKE_HTTP[$(manifest_url "$PY")]="401 200:$A"
    FAKE_HTTP[$(manifest_url "$TOOL")]="429 000 200:$F"
    FAKE_HTTP[$(manifest_url "$NODE")]="200:$I"
    FAKE_HTTP[$(manifest_url registry.example.com/down:1)]=429
    FAKE_HTTP[$(manifest_url registry.example.com/liar:2)]='200:sha256:<script>alert(1)</script>'
    FAKE_HTTP[$(manifest_url registry.example.com/old:3)]="405 200:$G"
    FAKE_HTTP[$(manifest_url registry.example.com/gone:4)]=404
    FAKE_ISSUES["${TITLE_PREFIX}$PY"]=8
    FAKE_REPORTED[8]=$B
    FAKE_ISSUES["${TITLE_PREFIX}$TOOL"]=7
    FAKE_REPORTED[7]=$F

    status=0
    check "" > "$WORK/out" 2>&1 || status=$?
    sed 's/^/    > /' "$WORK/out"

    url=$(manifest_url "$PY")
    expect "the run fails (three lookups failed, three pins malformed)" 1 "$status"
    expect "python pinned in three places: one lookup, 401 then one retry with a token" \
        "$url${T}HEAD${T}|$url${T}HEAD${T}token" "$(grep -F "$url" "$WORK/requests" | paste -sd '|')"
    expect "one token request, with the challenge's service and scope" \
        "https://public.ecr.aws/token/${T}public.ecr.aws${T}aws" "$(cat "$WORK/tokens")"
    expect "the token is reused for the same registry: one request" \
        "$(manifest_url "$NODE")${T}HEAD${T}token" "$(grep -F "$(manifest_url "$NODE")" "$WORK/requests")"
    expect "429 then network error then success: three attempts" 3 "$(requests "$(manifest_url "$TOOL")")"
    expect "lasting 429: one try and three retries" 4 "$(requests "$(manifest_url registry.example.com/down:1)")"
    expect "an answer that is not a digest is not retried" 1 "$(requests "$(manifest_url registry.example.com/liar:2)")"
    expect "404 is not retried" 1 "$(requests "$(manifest_url registry.example.com/gone:4)")"
    expect "HEAD rejected: GET once instead" "HEAD|GET" \
        "$(grep -F "$(manifest_url registry.example.com/old:3)" "$WORK/requests" | cut -f2 | paste -sd '|')"
    expect "untagged and unpinned references are not looked up" 0 \
        "$(grep -cE 'localhost|s3mock|postgres|busybox' "$WORK/requests" || true)"
    expect "failed attempt logged with the HTTP status first" 1 \
        "$(grep -cxF '  HTTP 429 (too many requests) on attempt 1: registry.example.com/down:1' "$WORK/out" || true)"
    expect "network error logged as HTTP 000" 1 \
        "$(grep -cxF "  HTTP 000 (no answer, network error or timeout) on attempt 2: $TOOL" "$WORK/out" || true)"
    expect_line "404 logged" "$WORK/out" "  HTTP 404 (not found) on attempt 1: registry.example.com/gone:4"
    expect "the token never reaches the output" 0 "$(grep -c "$FAKE_TOKEN" "$WORK/out" || true)"
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
    log "Lookup: one manifest request per image:tag. Mode: $([[ $DRY_RUN == false ]] && echo real run || echo dry run)."
    scan_repo
    check "${GITHUB_STEP_SUMMARY:-}"
}

main "$@"
