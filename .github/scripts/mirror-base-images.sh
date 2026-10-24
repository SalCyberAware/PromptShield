#!/usr/bin/env bash
# Weekly mirror of pinned base images into GHCR, run by
# .github/workflows/mirror-base-images.yml.
#
# Finds every image pinned as image:tag@sha256:<digest> in the Dockerfiles and
# workflow image: lines of each repo it is given, with the same parsing as
# .github/scripts/base-image-watch.sh, and keeps a copy of each in the mirror
# (ghcr.io/salcyberaware/mirror unless MIRROR_PREFIX says otherwise):
#
#   <mirror>/<name>@<digest>  every pinned digest, pullable by digest
#   <mirror>/<name>:<tag>     the digest the upstream tag points at now
#
# <name> is the image path after the registry, without a leading
# docker/library/ (public.ecr.aws) or library/ (Docker Hub). crane copy keeps
# the manifest bytes, so a mirrored image has the same digest as upstream. The
# script proves it: it hashes the manifest it reads back from the mirror, and
# compares the digest of the mirror tag with the upstream tag. A digest that
# is already in the mirror is not copied again.
#
# Seed mode creates each mirror package before the first copy. GHCR creates a
# package as private, and it can only be made public once it exists. Private
# storage on a GitHub Free account is 500 MB, so copying gigabytes of base
# images into new private packages fails. Seed mode pushes one placeholder per
# package instead: an image with a single empty layer, built locally by crane
# with no upstream pull, tagged <mirror>/<name>:seed. A package whose seed tag
# exists is skipped. After Sal makes the packages public, the normal run copies
# into them. The normal run never reads, moves or deletes the seed tag, and
# refuses an upstream image whose tag is "seed".
#
# Usage, from the PromptShield repo root:
#   .github/scripts/mirror-base-images.sh LABEL=DIR...  mirror the pins of each
#                       repo checked out at DIR; LABEL names it in the output
#   .github/scripts/mirror-base-images.sh --seed LABEL=DIR...  push a seed
#                       placeholder to each mirror package the normal run uses
#   .github/scripts/mirror-base-images.sh --self-test   test parsing, dedupe and
#                       the copy and seed decisions with a fake crane, no network
#
# Environment:
#   DRY_RUN        "false" copies and tags (with --seed: pushes placeholders).
#                  Anything else (and the default) only reads, lists what
#                  would be copied or pushed and writes nothing.
#   MIRROR_PREFIX  default ghcr.io/salcyberaware/mirror
#   CRANE          the crane binary, default "crane"
#   RETRY_DELAYS   seconds to wait before each retry of a crane call that
#                  failed with 429, 5xx or a network error. Default
#                  "30 60 120": three retries.
#   GHCR_TOKEN     token for the mirror registry. A real run logs in with it
#                  before copying. A dry run reads anonymously and logs in only
#                  if the mirror refuses an anonymous read. It reaches crane on
#                  stdin, never on the command line, and is never printed.
#   GITHUB_ACTOR   user name for the login, default github-actions
#   GITHUB_STEP_SUMMARY  the summary table is appended here when set.
#
# Exit status: 0 when every pinned digest and tag is in the mirror (in a dry
# run: when every lookup worked), 1 when a lookup, copy, tag or check failed.
# Every image is tried before the script exits. Error text from a registry is
# reduced to a short reason and a filtered line in the log; the summary shows
# only the reason. Needs bash 4, git, sha256sum and crane.

# Backticks in the printf formats are Markdown code spans, not commands.
# shellcheck disable=SC2016

set -euo pipefail

# The next four patterns and the "Finding pins" section are copied unchanged
# from .github/scripts/base-image-watch.sh, so both scripts find the same pins.
# The self-test fails if the section drifts from that file.
DIGEST_RE='^sha256:[0-9a-f]{64}$'
# Docker reference grammar, simplified: lowercase path components, an optional
# registry port, and the tag character set.
NAME_RE='^[a-z0-9]+([._-]+[a-z0-9]+)*(:[0-9]+)?(/[a-z0-9]+([._-]+[a-z0-9]+)*)*$'
TAG_RE='^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$'
LOCATION_RE='^[A-Za-z0-9_.][A-Za-z0-9_./-]*:[0-9]+$'
LABEL_RE='^[A-Za-z0-9][A-Za-z0-9_.-]*$'

DRY_RUN=${DRY_RUN:-true}
MIRROR_PREFIX=${MIRROR_PREFIX:-ghcr.io/salcyberaware/mirror}
CRANE=${CRANE:-crane}
RETRY_DELAYS=${RETRY_DELAYS:-30 60 120}
SEED=0
SEED_TAG=seed

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
WORK=$(mktemp -d)
LOGGED_IN=0
cleanup() {
    # A real login writes the runner's docker config; remove it again.
    if [[ $LOGGED_IN -eq 1 && $CRANE != fake_crane ]]; then
        "$CRANE" auth logout "${MIRROR_PREFIX%%/*}" > /dev/null 2>&1 || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT
RECORDS="$WORK/records"
: > "$RECORDS"

declare -A STAGES=()
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

declare -a KEYS=() SKIPPED=()
declare -A KEY_SEEN=() KEY_PINS=() KEY_LOCS=()

# scan_into LABEL DIR scans the repo checked out at DIR and adds its records
# to RECORDS, each location prefixed with LABEL/.
scan_into() {
    local label=$1 dir=$2 all=$RECORDS kind name tag digest loc
    RECORDS="$WORK/records.$label"
    : > "$RECORDS"
    (cd "$dir" && scan_repo)
    while IFS='|' read -r kind name tag digest loc; do
        printf '%s|%s|%s|%s|%s\n' "$kind" "$name" "$tag" "$digest" "$label/$loc" >> "$all"
    done < "$RECORDS"
    RECORDS=$all
}

# group_records fills KEYS (each image:tag once, in the order found),
# KEY_PINS[KEY] (its distinct pinned digests, space separated) and
# KEY_LOCS[KEY@DIGEST] (where each pin is). References without a tag, without
# a digest or that are malformed cannot be mirrored and go to SKIPPED; the
# base image watch already reports them.
group_records() {
    local kind name tag digest loc key
    while IFS='|' read -r kind name tag digest loc; do
        if [[ $kind != pinned ]]; then
            SKIPPED+=("$loc ($kind)")
            continue
        fi
        key="$name:$tag"
        if [[ -z ${KEY_SEEN[$key]+x} ]]; then
            KEY_SEEN[$key]=1
            KEYS+=("$key")
            KEY_PINS[$key]=""
        fi
        if [[ " ${KEY_PINS[$key]} " != *" $digest "* ]]; then
            KEY_PINS[$key]+="${KEY_PINS[$key]:+ }$digest"
        fi
        KEY_LOCS[$key@$digest]+="${KEY_LOCS[$key@$digest]:+ }$loc"
    done < "$RECORDS"
}

# mirror_name NAME prints the mirror path for an image name: the path after
# the registry, without a leading docker/library/, and for Docker Hub without
# a leading library/.
mirror_name() {
    local name=$1 first=${1%%/*} hub=1
    if [[ $name == */* && ($first == *.* || $first == *:* || $first == localhost) ]]; then
        [[ $first == docker.io || $first == index.docker.io ]] || hub=0
        name=${name#*/}
    fi
    name=${name#docker/library/}
    if ((hub)); then name=${name#library/}; fi
    printf '%s' "$name"
}

# ── crane calls ─────────────────────────────────────────────────────────────

# classify_error FILE prints one short reason for a failed crane call, read
# from its error text. It matches registry error codes and HTTP status
# phrases, never a bare number, which a digest in the same text can contain.
classify_error() {
    if grep -qiE 'toomanyrequests|too many requests|status code 429' "$1"; then
        printf 'too many requests'
    elif grep -qE 'status code 5[0-9]{2}|Internal Server Error|Bad Gateway|Service Unavailable|Gateway Timeout|INTERNAL_ERROR|UNAVAILABLE' "$1"; then
        printf 'server error'
    elif grep -qE 'MANIFEST_UNKNOWN|NAME_UNKNOWN|status code 404|404 Not Found' "$1"; then
        printf 'not found'
    elif grep -qE 'DENIED|UNAUTHORIZED|status code 40[13]|401 Unauthorized|403 Forbidden' "$1"; then
        printf 'denied'
    elif grep -qiE 'i/o timeout|connection reset|connection refused|no such host|handshake timeout|unexpected EOF|deadline exceeded|: EOF$' "$1"; then
        printf 'network error'
    else
        printf 'other error'
    fi
}

retryable() { [[ $1 == 'too many requests' || $1 == 'server error' || $1 == 'network error' ]]; }

# error_line FILE prints the last line of crane's error text for the log,
# without the timestamp, cut to 200 characters of a plain character set.
error_line() {
    local line
    line=$({ grep -v '^[[:space:]]*$' "$1" || true; } | tail -n 1 | tr -d '\r')
    line=${line#[0-9][0-9][0-9][0-9]/[0-9][0-9]/[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9] }
    line=${line#Error: }
    printf '%s' "$line" | tr -cd 'A-Za-z0-9 ._:/@=%?&,()-' | cut -c1-200
}

# crane_call OUT ARGS... runs crane with its output in the file OUT. A failure
# classed as too many requests, server error or network error is retried once
# per entry in RETRY_DELAYS. On failure CR_REASON holds the reason. Failed
# attempts are logged with a filtered line of crane's error text.
crane_call() {
    local out=$1 attempt=0
    shift
    local -a delays=()
    read -r -a delays <<< "$RETRY_DELAYS" || true
    CR_REASON=""
    while :; do
        attempt=$((attempt + 1))
        if "$CRANE" "$@" > "$out" 2> "$WORK/err"; then return 0; fi
        CR_REASON=$(classify_error "$WORK/err")
        # "not found" is the normal answer for a digest the mirror lacks; the
        # caller reports it.
        [[ $CR_REASON != 'not found' ]] || return 1
        log "    crane $1, attempt $attempt: $CR_REASON ($(error_line "$WORK/err"))"
        retryable "$CR_REASON" || return 1
        ((attempt <= ${#delays[@]})) || return 1
        log "    retrying in ${delays[attempt - 1]} s"
        sleep "${delays[attempt - 1]}"
    done
}

# login logs in to the mirror registry once, with GHCR_TOKEN on stdin.
login() {
    local host=${MIRROR_PREFIX%%/*}
    [[ $LOGGED_IN -eq 0 ]] || return 0
    if [[ -z ${GHCR_TOKEN:-} ]]; then
        log "  cannot log in to $host: GHCR_TOKEN is not set"
        return 1
    fi
    if printf '%s' "$GHCR_TOKEN" | "$CRANE" auth login "$host" -u "${GITHUB_ACTOR:-github-actions}" \
        --password-stdin > /dev/null 2> "$WORK/err"; then
        LOGGED_IN=1
        log "  logged in to $host"
        return 0
    fi
    log "  login to $host failed: $(classify_error "$WORK/err")"
    return 1
}

# mirror_read ARGS... is crane_call for a read from the mirror. In a dry run
# an anonymous read that is refused logs in once and is tried again, because
# a package that is not public yet refuses anonymous reads.
mirror_read() {
    if crane_call "$@"; then return 0; fi
    if [[ $CR_REASON == denied && $LOGGED_IN -eq 0 && -n ${GHCR_TOKEN:-} ]]; then
        log "    the mirror refused an anonymous read, logging in to read"
        login || return 1
        crane_call "$@"
        return
    fi
    return 1
}

# upstream_digest IMAGE:TAG sets GOT to the digest the tag points at now.
upstream_digest() {
    GOT=""
    crane_call "$WORK/out" digest "$1" || return 1
    GOT=$(< "$WORK/out")
    if [[ ! $GOT =~ $DIGEST_RE ]]; then
        GOT="" CR_REASON="the answer is not a sha256 digest"
        return 1
    fi
}

# mirror_has REPO@DIGEST sets MH_STATE: present when the mirror serves a
# manifest whose bytes hash to DIGEST, mismatch when the bytes differ, absent
# when the mirror does not have it (or, read anonymously, does not show it),
# error otherwise.
mirror_has() {
    local want=${1##*@} got
    if mirror_read "$WORK/manifest" manifest "$1"; then
        got=sha256:$(sha256sum "$WORK/manifest" | cut -d' ' -f1)
        if [[ $got == "$want" ]]; then MH_STATE=present; else MH_STATE=mismatch; fi
        return 0
    fi
    case $CR_REASON in
        'not found') MH_STATE=absent ;;
        denied) if [[ $LOGGED_IN -eq 0 ]]; then MH_STATE=absent; else MH_STATE=error; fi ;;
        *) MH_STATE=error ;;
    esac
}

# mirror_tag_digest REPO:TAG sets GOT to the digest the mirror tag points at,
# or to "" when the tag does not exist. Returns 1 on any other failure.
mirror_tag_digest() {
    GOT=""
    if mirror_read "$WORK/out" digest "$1"; then
        GOT=$(< "$WORK/out")
        [[ $GOT =~ $DIGEST_RE ]] && return 0
        GOT="" CR_REASON="the answer is not a sha256 digest"
        return 1
    fi
    [[ $CR_REASON == 'not found' || ($CR_REASON == denied && $LOGGED_IN -eq 0) ]]
}

# ── Mirroring ───────────────────────────────────────────────────────────────

declare -a ROWS=()
declare -A DEST_OWNER=()

add_row() { # IMAGE MIRROR SOURCE_DIGEST MIRROR_DIGEST RESULT
    ROWS+=("$1|$2|$3|$4|$5")
}

fail() { # MESSAGE
    log "  FAILED: $1"
    FAILURES=$((FAILURES + 1))
}

# ensure_digest KEY DEST DIGEST ROLE makes DEST@DIGEST exist in the mirror.
# ED_OK is 1 when it is there afterwards (in a dry run: when it would be).
ensure_digest() {
    local key=$1 dest=$2 d=$3 role=$4 src=${1%:*}
    ED_OK=0
    log "  $dest@$d ($role)"
    mirror_has "$dest@$d"
    case $MH_STATE in
        present)
            log "    already present, manifest bytes match"
            add_row "$key" "$dest@" "$d" "$d" "already present"
            ED_OK=1
            return
            ;;
        mismatch)
            fail "$dest@$d serves a manifest that does not hash to $d"
            add_row "$key" "$dest@" "$d" "-" "failed: digest mismatch"
            return
            ;;
        error)
            fail "could not read $dest@$d: $CR_REASON"
            add_row "$key" "$dest@" "$d" "-" "failed: $CR_REASON"
            return
            ;;
    esac
    if [[ $DRY_RUN != false ]]; then
        log "    DRY RUN, would copy $src@$d"
        add_row "$key" "$dest@" "$d" "-" "dry run, would copy"
        ED_OK=1
        return
    fi
    if ! crane_call "$WORK/out" copy "$src@$d" "$dest@$d"; then
        fail "copy of $src@$d: $CR_REASON"
        add_row "$key" "$dest@" "$d" "-" "failed: $CR_REASON"
        return
    fi
    mirror_has "$dest@$d"
    if [[ $MH_STATE != present ]]; then
        fail "after the copy, $dest@$d is $MH_STATE${CR_REASON:+ ($CR_REASON)}"
        add_row "$key" "$dest@" "$d" "-" "failed: $MH_STATE after copy"
        return
    fi
    log "    copied, manifest bytes match"
    add_row "$key" "$dest@" "$d" "$d" copied
    ED_OK=1
}

# ensure_tag KEY DEST TAG CURRENT CURRENT_OK points DEST:TAG at CURRENT.
# CURRENT_OK says ensure_digest put CURRENT in the mirror. When the upstream
# lookup or that copy failed, the failure is already counted and the tag is
# left alone.
ensure_tag() {
    local key=$1 dest=$2 tag=$3 cur=$4 cur_ok=$5 had
    log "  $dest:$tag (tag)"
    if [[ -z $cur ]]; then
        log "    not checked, the upstream digest is unknown"
        add_row "$key" "$dest:$tag" "-" "-" "failed: upstream lookup"
        return
    fi
    if [[ $cur_ok -ne 1 ]]; then
        log "    left alone, the current digest is not in the mirror"
        add_row "$key" "$dest:$tag" "$cur" "-" "failed: current digest not mirrored"
        return
    fi
    if ! mirror_tag_digest "$dest:$tag"; then
        fail "could not read $dest:$tag: $CR_REASON"
        add_row "$key" "$dest:$tag" "$cur" "-" "failed: $CR_REASON"
        return
    fi
    had=$GOT
    if [[ $had == "$cur" ]]; then
        log "    already points at the upstream digest"
        add_row "$key" "$dest:$tag" "$cur" "$had" "already present"
        return
    fi
    if [[ $DRY_RUN != false ]]; then
        log "    DRY RUN, would point it at $cur (now: ${had:-no tag})"
        add_row "$key" "$dest:$tag" "$cur" "${had:--}" "dry run, would tag"
        return
    fi
    if ! crane_call "$WORK/out" tag "$dest@$cur" "$tag"; then
        fail "tag $dest:$tag: $CR_REASON"
        add_row "$key" "$dest:$tag" "$cur" "${had:--}" "failed: $CR_REASON"
        return
    fi
    if ! mirror_tag_digest "$dest:$tag" || [[ $GOT != "$cur" ]]; then
        fail "after tagging, $dest:$tag points at ${GOT:-nothing}, not $cur"
        add_row "$key" "$dest:$tag" "$cur" "${GOT:--}" "failed: tag check"
        return
    fi
    log "    tagged, digest matches upstream (was: ${had:-no tag})"
    add_row "$key" "$dest:$tag" "$cur" "$GOT" copied
}

# mirror_key IMAGE:TAG mirrors every pinned digest of IMAGE:TAG and the digest
# its tag points at now, then points the mirror tag at the current digest.
mirror_key() {
    local key=$1 name=${1%:*} tag=${1##*:} dest cur="" cur_ok=0 d loc
    local -a pins=() locs=()
    dest=$MIRROR_PREFIX/$(mirror_name "$name")
    read -r -a pins <<< "${KEY_PINS[$key]}"
    log ""
    log "$key -> $dest"
    for d in "${pins[@]}"; do
        read -r -a locs <<< "${KEY_LOCS[$key@$d]}"
        for loc in "${locs[@]}"; do log "  pinned at $(short "$d") in $loc"; done
    done

    if [[ $tag == "$SEED_TAG" ]]; then
        fail "$dest:$SEED_TAG is the seed placeholder; an upstream tag named $SEED_TAG cannot be mirrored"
        for d in "${pins[@]}"; do add_row "$key" "$dest@" "$d" "-" "failed: tag reserved for the seed"; done
        return
    fi
    if [[ -n ${DEST_OWNER[$dest:$tag]+x} ]]; then
        fail "$dest:$tag is already the mirror of ${DEST_OWNER[$dest:$tag]}; two sources cannot share it"
        for d in "${pins[@]}"; do add_row "$key" "$dest@" "$d" "-" "failed: mirror name taken"; done
        return
    fi
    DEST_OWNER[$dest:$tag]=$key

    if upstream_digest "$key"; then
        cur=$GOT
        log "  upstream $key now: $cur"
    else
        fail "could not read the upstream digest of $key: $CR_REASON"
    fi

    for d in "${pins[@]}"; do
        ensure_digest "$key" "$dest" "$d" pinned
        [[ $d != "$cur" ]] || cur_ok=$ED_OK
    done
    if [[ -n $cur && " ${KEY_PINS[$key]} " != *" $cur "* ]]; then
        ensure_digest "$key" "$dest" "$cur" "current upstream, not pinned"
        cur_ok=$ED_OK
    fi
    ensure_tag "$key" "$dest" "$tag" "$cur" "$cur_ok"
}

# ── Seeding ─────────────────────────────────────────────────────────────────

declare -a SEED_ROWS=()

# seed_size REPO@DIGEST sets SIZE to the bytes of the image: its manifest plus
# every config and layer size the manifest lists. Returns 1 when the manifest
# cannot be read.
seed_size() {
    local n total
    SIZE=""
    mirror_read "$WORK/manifest" manifest "$1" || return 1
    total=$(wc -c < "$WORK/manifest")
    while read -r n; do
        total=$((total + n))
    done < <(grep -oE '"size":[[:space:]]*[0-9]+' "$WORK/manifest" | grep -oE '[0-9]+$' || true)
    SIZE=$total
}

# seed_package DEST pushes the placeholder to DEST:seed unless that tag
# exists. Nothing is read from or copied out of an upstream registry.
seed_package() {
    local dest=$1 ref=$1:$SEED_TAG
    log ""
    log "$ref"
    if ! mirror_tag_digest "$ref"; then
        fail "could not read $ref: $CR_REASON"
        SEED_ROWS+=("$dest|-|-|failed: $CR_REASON")
        return
    fi
    if [[ -n $GOT ]]; then
        if seed_size "$dest@$GOT"; then
            log "  already seeded ($SIZE bytes), skipped"
        else
            log "  already seeded (size unknown: $CR_REASON), skipped"
        fi
        SEED_ROWS+=("$dest|$GOT|${SIZE:--}|already seeded")
        return
    fi
    if [[ $DRY_RUN != false ]]; then
        log "  DRY RUN, would push the placeholder (one empty layer, under 1 KB)"
        SEED_ROWS+=("$dest|-|-|dry run, would seed")
        return
    fi
    if ! crane_call "$WORK/out" append --oci-empty-base -f "$WORK/seed-layer.tar" -t "$ref"; then
        fail "push of $ref: $CR_REASON"
        SEED_ROWS+=("$dest|-|-|failed: $CR_REASON")
        return
    fi
    if ! mirror_tag_digest "$ref" || [[ -z $GOT ]]; then
        fail "after the push, $ref cannot be read${CR_REASON:+ ($CR_REASON)}"
        SEED_ROWS+=("$dest|-|-|failed: seed check")
        return
    fi
    seed_size "$dest@$GOT" || SIZE=""
    log "  seeded at $GOT (${SIZE:-unknown} bytes)"
    SEED_ROWS+=("$dest|$GOT|${SIZE:--}|seeded")
}

# seed_all pushes one placeholder per distinct mirror package of KEYS.
seed_all() {
    local key dest
    local -A seen=()
    # An empty tar archive: two 512-byte zero blocks.
    head -c 1024 /dev/zero > "$WORK/seed-layer.tar"
    for key in "${KEYS[@]}"; do
        dest=$MIRROR_PREFIX/$(mirror_name "${key%:*}")
        [[ -z ${seen[$dest]+x} ]] || continue
        seen[$dest]=1
        seed_package "$dest"
    done
}

write_seed_summary() { # FILE
    local row dest digest size result mode="real run"
    [[ $DRY_RUN == false ]] || mode="dry run, nothing pushed"
    {
        printf '## Base image mirror seed (%s)\n\n' "$mode"
        printf 'Placeholder tag `%s` in each package under `%s`. Upstream images are not copied.\n\n' \
            "$SEED_TAG" "$MIRROR_PREFIX"
        if [[ ${#SEED_ROWS[@]} -eq 0 ]]; then
            printf 'No pinned images found.\n'
        else
            printf '| Package | Seed digest | Size (bytes) | Result |\n'
            printf '|---|---|---|---|\n'
            for row in "${SEED_ROWS[@]}"; do
                IFS='|' read -r dest digest size result <<< "$row"
                printf '| `%s` | `%s` | %s | %s |\n' "${dest#"${MIRROR_PREFIX%/*}"/}" \
                    "$(short "${digest#-}")" "$size" "$result"
            done
        fi
    } >> "$1"
}

write_summary() { # FILE
    local row image mirror src dst result mode="real run"
    [[ $DRY_RUN == false ]] || mode="dry run, nothing copied"
    {
        printf '## Base image mirror (%s)\n\n' "$mode"
        printf 'Mirror: `%s`. A mirror row ending in `@` is the image at the digest in the source column.\n\n' "$MIRROR_PREFIX"
        if [[ ${#ROWS[@]} -eq 0 ]]; then
            printf 'No pinned images found.\n'
        else
            printf '| Image | Mirror | Source digest | Mirror digest | Result |\n'
            printf '|---|---|---|---|---|\n'
            for row in "${ROWS[@]}"; do
                IFS='|' read -r image mirror src dst result <<< "$row"
                printf '| `%s` | `%s` | `%s` | `%s` | %s |\n' "$image" "${mirror#"$MIRROR_PREFIX"/}" \
                    "$(short "${src#-}")" "$(short "${dst#-}")" "$result"
            done
        fi
        if [[ ${#SKIPPED[@]} -gt 0 ]]; then
            printf '\nNot mirrored (no tag, no digest, or malformed): %s reference(s), see the base image watch.\n' \
                "${#SKIPPED[@]}"
        fi
    } >> "$1"
}

# run_mirror LABEL=DIR... is the whole run.
run_mirror() {
    local spec label dir key
    if [[ ! $MIRROR_PREFIX =~ $NAME_RE || $MIRROR_PREFIX != */* ]]; then
        log "MIRROR_PREFIX is not a registry and path"
        return 2
    fi
    : > "$RECORDS"
    : > "$WORK/summary"
    for spec in "$@"; do
        label=${spec%%=*} dir=${spec#*=}
        if [[ $spec != *=* || ! $label =~ $LABEL_RE ]] || ! git -C "$dir" rev-parse --git-dir > /dev/null 2>&1; then
            log "not LABEL=DIR with DIR a git checkout: $spec"
            return 2
        fi
        scan_into "$label" "$dir"
    done
    group_records
    local mode
    if ((SEED)); then
        mode=$([[ $DRY_RUN == false ]] && echo seed, real run || echo seed, dry run, nothing pushed)
    else
        mode=$([[ $DRY_RUN == false ]] && echo real run || echo dry run, nothing copied)
    fi
    log "Mode: $mode. Mirror: $MIRROR_PREFIX"
    log "Pinned image:tags: ${#KEYS[@]}. Not mirrored (no tag, no digest, malformed): ${#SKIPPED[@]}"
    if [[ $DRY_RUN == false ]] && ! login; then
        log "FAILED: cannot log in to the mirror, nothing $([[ $SEED -eq 1 ]] && echo pushed || echo copied)."
        return 1
    fi
    if ((SEED)); then
        seed_all
        log ""
        write_seed_summary "$WORK/summary"
    else
        for key in "${KEYS[@]}"; do mirror_key "$key"; done
        log ""
        write_summary "$WORK/summary"
    fi
    cat "$WORK/summary"
    [[ -z ${GITHUB_STEP_SUMMARY:-} ]] || cat "$WORK/summary" >> "$GITHUB_STEP_SUMMARY"
    log ""
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

# dg TEXT prints the digest of a fake manifest whose bytes are TEXT.
dg() { printf 'sha256:%s' "$(printf '%s' "$1" | sha256sum | cut -d' ' -f1)"; }

# Fake crane for the self-test. FAKE_MANIFEST[REPO@DIGEST] holds manifest
# bytes, FAKE_TAG[REPO:TAG] a digest. FAKE_FAIL["COMMAND REF"] lists one answer
# per call (ok, 429, 503 or denied), the last one repeating. With
# FAKE_ANON_DENIED=1, mirror reads are refused until a login. Every call is
# logged to $WORK/calls; the login's stdin goes to $WORK/login-stdin.
declare -A FAKE_MANIFEST=() FAKE_TAG=() FAKE_FAIL=() FAKE_N=()
FAKE_ANON_DENIED=0
# The manifest a fake append pushes. It lists 233 + 32 more bytes.
FAKE_SEED='{"schemaVersion":2,"config":{"size":233},"layers":[{"size": 32}],"x":"fake-seed-manifest"}'
fake_crane() {
    local cmd=$1 ref=${2:-} n answer
    local -a answers=()
    printf '%s\n' "$*" >> "$WORK/calls"
    if [[ $cmd == auth ]]; then
        cat > "$WORK/login-stdin"
        return 0
    fi
    # append: the reference is the -t value; the layer file's size is logged.
    local layer="" i
    if [[ $cmd == append ]]; then
        local -a args=("$@")
        for ((i = 1; i + 1 < ${#args[@]}; i++)); do
            [[ ${args[i]} != -t ]] || ref=${args[i + 1]}
            [[ ${args[i]} != -f ]] || layer=${args[i + 1]}
        done
        printf 'layer bytes %s\n' "$(wc -c < "$layer")" >> "$WORK/calls"
    fi
    n=$((${FAKE_N["$cmd $ref"]:-0} + 1))
    FAKE_N["$cmd $ref"]=$n
    read -r -a answers <<< "${FAKE_FAIL["$cmd $ref"]:-ok}"
    answer=${answers[n - 1]:-${answers[${#answers[@]} - 1]}}
    if [[ $FAKE_ANON_DENIED -eq 1 && ! -f $WORK/login-stdin && $ref == "$MIRROR_PREFIX"/* ]]; then
        answer=denied
    fi
    case $answer in
        429) printf '2026/10/19 06:30:00 Error: GET https://%s: toomanyrequests: Data limit exceeded\n' "$ref" >&2; return 1 ;;
        503) printf 'Error: GET https://%s: unexpected status code 503 Service Unavailable\n' "$ref" >&2; return 1 ;;
        denied) printf 'Error: GET https://x/token?scope=y: DENIED: requested access to the resource is denied\n' >&2; return 1 ;;
    esac
    case $cmd in
        digest)
            if [[ $ref == *@* && -n ${FAKE_MANIFEST[$ref]+x} ]]; then printf '%s\n' "${ref##*@}"; return 0; fi
            if [[ $ref != *@* && -n ${FAKE_TAG[$ref]+x} ]]; then printf '%s\n' "${FAKE_TAG[$ref]}"; return 0; fi
            ;;
        manifest)
            if [[ -n ${FAKE_MANIFEST[$ref]+x} ]]; then printf '%s' "${FAKE_MANIFEST[$ref]}"; return 0; fi
            ;;
        copy)
            if [[ -n ${FAKE_MANIFEST[$2]+x} ]]; then FAKE_MANIFEST[$3]=${FAKE_MANIFEST[$2]}; return 0; fi
            ;;
        tag)
            if [[ -n ${FAKE_MANIFEST[$2]+x} ]]; then FAKE_TAG[${2%@*}:$3]=${2##*@}; return 0; fi
            ;;
        append)
            FAKE_MANIFEST[${ref%:*}@$(dg "$FAKE_SEED")]=$FAKE_SEED
            FAKE_TAG[$ref]=$(dg "$FAKE_SEED")
            dg "$FAKE_SEED"
            return 0
            ;;
    esac
    printf 'Error: GET https://%s: MANIFEST_UNKNOWN: manifest unknown sha256:4290\n' "$ref" >&2
    return 1
}

# fake_repo DIR FILE LINE... creates a git repo at DIR (once) with FILE
# holding LINEs, added to the index so git ls-files lists it.
fake_repo() {
    local dir=$1 file=$2
    shift 2
    [[ -d $dir/.git ]] || git -c init.defaultBranch=main init -q "$dir"
    git -C "$dir" config core.autocrlf false
    mkdir -p "$(dirname "$dir/$file")"
    printf '%s\n' "$@" > "$dir/$file"
    git -C "$dir" add -- "$file"
}

calls() { grep -cE "$1" "$WORK/calls" || true; }

self_test() {
    local PY=public.ecr.aws/docker/library/python:3.12-slim-trixie
    local PG=public.ecr.aws/docker/library/postgres:18
    local PGA=public.ecr.aws/docker/library/postgres:18-alpine
    local NODE=public.ecr.aws/docker/library/node:24-trixie-slim
    local S3=adobe/s3mock:5.2.3 FLAKY=registry.example.com/team/flaky:1 DOWN=registry.example.com/team/down:2
    local M=ghcr.io/salcyberaware/mirror A A2 C P Q N S F D out status key R="$WORK/repos"
    A=$(dg python-a) A2=$(dg python-old) C=$(dg python-new) P=$(dg postgres) Q=$(dg postgres-alpine)
    N=$(dg node) S=$(dg s3mock) F=$(dg flaky) D=$(dg down)
    CRANE=fake_crane RETRY_DELAYS="0 0 0" MIRROR_PREFIX=ghcr.io/salcyberaware/mirror
    : > "$WORK/calls"

    log "Copied parsing"
    if [[ -f $SCRIPT_DIR/base-image-watch.sh ]]; then
        expect "the Finding pins section is identical to base-image-watch.sh" "same" \
            "$(cmp -s <(pins_section "$SCRIPT_DIR/base-image-watch.sh") <(pins_section "${BASH_SOURCE[0]}") \
                && echo same || echo different)"
    else
        expect "base-image-watch.sh is next to this script" "present" "missing"
    fi

    log ""
    log "Mirror names"
    out=""
    for key in public.ecr.aws/docker/library/python public.ecr.aws/docker/library/postgres adobe/s3mock \
        postgres docker.io/library/busybox ghcr.io/example/tool localhost:5000/team/base; do
        out+="$(mirror_name "$key"),"
    done
    expect "registry and docker/library/ dropped, Docker Hub library/ dropped" \
        "python,postgres,adobe/s3mock,postgres,busybox,example/tool,team/base," "$out"

    log ""
    log "Error classes"
    out=""
    for key in 'Error: GET https://public.ecr.aws/v2/x/blobs/sha256:429abc: toomanyrequests: Data limit exceeded' \
        'unexpected status code 502 Bad Gateway' \
        'GET https://ghcr.io/v2/a/manifests/sha256:4290429: MANIFEST_UNKNOWN: manifest unknown' \
        'GET https://ghcr.io/token?scope=x: DENIED: requested access to the resource is denied' \
        'dial tcp: lookup ghcr.io: no such host' 'something else 429 5000'; do
        printf '%s\n' "$key" > "$WORK/e"
        out+="$(classify_error "$WORK/e"),"
    done
    expect "429, 5xx, not found, denied, network, other; a 429 inside a digest is not a 429" \
        "too many requests,server error,not found,denied,network error,other error," "$out"
    printf '2026/10/19 06:30:00 Error: GET https://x/y: DENIED: no <b>\n' > "$WORK/e"
    expect "log line: no timestamp, filtered characters" "GET https://x/y: DENIED: no b" "$(error_line "$WORK/e")"

    log ""
    log "Parsing and dedupe across three repos"
    fake_repo "$R/alpha" Dockerfile "FROM $DOWN@$D AS tools" "FROM $PY@$A AS build" "FROM $PY@$A" \
        "COPY --from=tools /x /x"
    fake_repo "$R/alpha" .github/workflows/ci.yml "    services:" "      db:" "        image: $PG@$P"
    fake_repo "$R/beta" backend/Dockerfile "FROM $NODE@$N" "FROM $PY@$A2"
    fake_repo "$R/beta" .github/workflows/ci.yml "        image: postgres:16"
    fake_repo "$R/gamma" ops/Dockerfile.restore "FROM $PGA@$Q"
    fake_repo "$R/gamma" tools/Dockerfile "FROM $FLAKY@$F"
    fake_repo "$R/gamma" .github/workflows/db.yml "        image: $PG@$P" "        image: $S3@$S" \
        "        image: adobe/s3mock@$S" "        image: docker.io/library/postgres:18@$P"
    printf 'FROM %s@%s\n' "$PY" "$C" > "$R/gamma/Dockerfile.untracked"

    (
        scan_into alpha "$R/alpha"
        scan_into beta "$R/beta"
        scan_into gamma "$R/gamma"
        group_records
        for key in "${KEYS[@]}"; do printf '%s = %s\n' "$key" "${KEY_PINS[$key]}"; done
        printf 'locations of python@A: %s\n' "${KEY_LOCS[$PY@$A]}"
        printf 'locations of postgres@P: %s\n' "${KEY_LOCS[$PG@$P]}"
        printf 'skipped: %s\n' "${SKIPPED[*]}"
    ) > "$WORK/parsed"
    expect "one entry per image:tag, distinct digests, untracked files ignored" \
        "$DOWN = $D
$PY = $A $A2
$PG = $P
$NODE = $N
$PGA = $Q
$FLAKY = $F
$S3 = $S
docker.io/library/postgres:18 = $P
locations of python@A: alpha/Dockerfile:2 alpha/Dockerfile:3
locations of postgres@P: alpha/.github/workflows/ci.yml:3 gamma/.github/workflows/db.yml:1
skipped: beta/.github/workflows/ci.yml:1 (unpinned) gamma/.github/workflows/db.yml:3 (notag)" "$(cat "$WORK/parsed")"

    # Upstream: python's tag has moved on to C. The mirror already has
    # python@A with its tag still at A, and postgres complete. Its copy of
    # postgres-alpine is damaged. Flaky answers 429, 503, then works; down
    # keeps answering 429.
    FAKE_MANIFEST["${PY%:*}@$A"]=python-a
    FAKE_MANIFEST["${PY%:*}@$A2"]=python-old
    FAKE_MANIFEST["${PY%:*}@$C"]=python-new
    FAKE_MANIFEST["${PG%:*}@$P"]=postgres
    FAKE_MANIFEST["${PGA%:*}@$Q"]=postgres-alpine
    FAKE_MANIFEST["${NODE%:*}@$N"]=node
    FAKE_MANIFEST["${S3%:*}@$S"]=s3mock
    FAKE_MANIFEST["${FLAKY%:*}@$F"]=flaky
    FAKE_MANIFEST["docker.io/library/postgres@$P"]=postgres
    FAKE_TAG[$PY]=$C FAKE_TAG[$PG]=$P FAKE_TAG[$PGA]=$Q FAKE_TAG[$NODE]=$N FAKE_TAG[$S3]=$S FAKE_TAG[$FLAKY]=$F
    FAKE_TAG[docker.io/library/postgres:18]=$P
    FAKE_MANIFEST["$M/python@$A"]=python-a
    FAKE_TAG["$M/python:3.12-slim-trixie"]=$A
    FAKE_MANIFEST["$M/postgres@$P"]=postgres
    FAKE_TAG["$M/postgres:18"]=$P
    FAKE_MANIFEST["$M/postgres@$Q"]=tampered
    FAKE_FAIL["digest $FLAKY"]="429 503 ok"
    FAKE_FAIL["copy ${FLAKY%:*}@$F"]="429 ok"
    FAKE_FAIL["digest $DOWN"]=429
    FAKE_FAIL["manifest $M/team/down@$D"]=429
    local -a repos=("alpha=$R/alpha" "beta=$R/beta" "gamma=$R/gamma")
    local T=FAKE-GHCR-TOKEN-5f3a

    log ""
    log "Dry run, packages public (fake crane)"
    : > "$WORK/calls"
    status=0
    (DRY_RUN=true GHCR_TOKEN=$T run_mirror "${repos[@]}") > "$WORK/dry" 2>&1 || status=$?
    sed 's/^/    > /' "$WORK/dry"
    expect "dry run fails: down unreachable, damaged copy, mirror name taken" 1 "$status"
    expect "dry run copies, tags and logs in to nothing" 0 "$(calls '^(copy|tag|auth) ')"
    expect_line "pin already in the mirror" "$WORK/dry" \
        "| \`$PY\` | \`python@\` | \`$(short "$A")\` | \`$(short "$A")\` | already present |"
    expect_line "pin not in the mirror: would copy" "$WORK/dry" \
        "| \`$PY\` | \`python@\` | \`$(short "$A2")\` | \`-\` | dry run, would copy |"
    expect_line "tag behind upstream: would tag" "$WORK/dry" \
        "| \`$PY\` | \`python:3.12-slim-trixie\` | \`$(short "$C")\` | \`$(short "$A")\` | dry run, would tag |"
    expect_line "pin and tag both present: nothing to do" "$WORK/dry" \
        "| \`$PG\` | \`postgres:18\` | \`$(short "$P")\` | \`$(short "$P")\` | already present |"
    expect_line "the same pin in two repos: one mirror row" "$WORK/dry" "Pinned image:tags: 8. Not mirrored"
    expect "postgres@P checked once" 1 "$(calls "^manifest $M/postgres@$P\$")"
    expect_line "a mirror copy whose bytes do not match fails" "$WORK/dry" \
        "| \`$PGA\` | \`postgres@\` | \`$(short "$Q")\` | \`-\` | failed: digest mismatch |"
    expect_line "two sources for one mirror tag fail" "$WORK/dry" \
        "| \`docker.io/library/postgres:18\` | \`postgres@\` | \`$(short "$P")\` | \`-\` | failed: mirror name taken |"
    expect "lasting 429 upstream: one try and three retries" 4 "$(calls "^digest $DOWN\$")"
    expect "a 429 on the mirror side is retried too" 4 "$(calls "^manifest $M/team/down@$D\$")"
    expect "429, 503, then success: three tries" 3 "$(calls "^digest $FLAKY\$")"
    expect_line "failed attempt logged with the reason" "$WORK/dry" \
        "    crane digest, attempt 1: too many requests (GET https://$DOWN: toomanyrequests: Data limit exceeded)"
    expect_line "images after a failure are still handled" "$WORK/dry" \
        "| \`$S3\` | \`adobe/s3mock:5.2.3\` | \`$(short "$S")\` | \`-\` | dry run, would tag |"
    expect_line "references without a tag or digest are counted, not mirrored" "$WORK/dry" \
        "Not mirrored (no tag, no digest, or malformed): 2 reference(s)"

    log ""
    log "Dry run, packages not public yet (fake crane)"
    : > "$WORK/calls"
    rm -f "$WORK/login-stdin"
    FAKE_N=()
    status=0
    (FAKE_ANON_DENIED=1 DRY_RUN=true GHCR_TOKEN=$T run_mirror "${repos[@]}") > "$WORK/dry2" 2>&1 || status=$?
    expect "refused anonymous read: one login, then reads" "1 1" "$(calls '^auth login ') $status"
    expect "still no copies or tags" 0 "$(calls '^(copy|tag) ')"
    expect_line "after the login the pin reads as present" "$WORK/dry2" \
        "| \`$PY\` | \`python@\` | \`$(short "$A")\` | \`$(short "$A")\` | already present |"
    rm -f "$WORK/login-stdin"
    FAKE_N=()
    (FAKE_ANON_DENIED=1 DRY_RUN=true GHCR_TOKEN="" run_mirror "${repos[@]}") > "$WORK/dry3" 2>&1 || true
    expect_line "refused and no token: listed as would copy" "$WORK/dry3" \
        "| \`$PY\` | \`python@\` | \`$(short "$A")\` | \`-\` | dry run, would copy |"

    log ""
    log "Real run (fake crane)"
    : > "$WORK/calls"
    rm -f "$WORK/login-stdin"
    FAKE_N=()
    status=0
    (DRY_RUN=false GHCR_TOKEN=$T GITHUB_ACTOR=octo GITHUB_STEP_SUMMARY="$WORK/step-summary" \
        run_mirror "${repos[@]}") > "$WORK/real" 2>&1 || status=$?
    sed 's/^/    > /' "$WORK/real"
    expect "real run fails at the end" "1" "$status"
    expect_line "four problems: down upstream and mirror read, damaged copy, name taken" "$WORK/real"         "FAILED: 4 problem(s), see above."
    expect "login first, token on stdin only" "auth login ghcr.io -u octo --password-stdin|$T" \
        "$(head -n 1 "$WORK/calls")|$(cat "$WORK/login-stdin")"
    expect "the token is never an argument or in the output" "0 0" \
        "$(grep -c -- "$T" "$WORK/calls" || true) $(grep -c -- "$T" "$WORK/real" || true)"
    grep -E '^(copy|tag) ' "$WORK/calls" > "$WORK/writes" || true
    expect "copies only what is missing, by digest, and moves only stale tags" \
        "copy ${PY%:*}@$A2 $M/python@$A2
copy ${PY%:*}@$C $M/python@$C
tag $M/python@$C 3.12-slim-trixie
copy ${NODE%:*}@$N $M/node@$N
tag $M/node@$N 24-trixie-slim
copy ${FLAKY%:*}@$F $M/team/flaky@$F
copy ${FLAKY%:*}@$F $M/team/flaky@$F
tag $M/team/flaky@$F 1
copy ${S3%:*}@$S $M/adobe/s3mock@$S
tag $M/adobe/s3mock@$S 5.2.3" "$(cat "$WORK/writes")"
    expect_line "copied row" "$WORK/real" \
        "| \`$PY\` | \`python@\` | \`$(short "$C")\` | \`$(short "$C")\` | copied |"
    expect_line "tag row: mirror digest equals the upstream digest" "$WORK/real" \
        "| \`$PY\` | \`python:3.12-slim-trixie\` | \`$(short "$C")\` | \`$(short "$C")\` | copied |"
    expect_line "the old pin stays pullable" "$WORK/real" \
        "| \`$PY\` | \`python@\` | \`$(short "$A")\` | \`$(short "$A")\` | already present |"
    expect_line "lasting 429: failed row" "$WORK/real" \
        "| \`$DOWN\` | \`team/down@\` | \`$(short "$D")\` | \`-\` | failed: too many requests |"
    expect_line "summary written to the step summary" "$WORK/step-summary" "## Base image mirror (real run)"

    log ""
    log "Real run, nothing left to copy"
    : > "$WORK/calls"
    rm -f "$WORK/login-stdin"
    FAKE_N=()
    FAKE_MANIFEST["$M/python@$A2"]=python-old FAKE_MANIFEST["$M/python@$C"]=python-new
    FAKE_TAG["$M/python:3.12-slim-trixie"]=$C
    (DRY_RUN=false GHCR_TOKEN=$T run_mirror "alpha=$R/alpha" "beta=$R/beta" 2>&1 |
        grep -v down || true) > /dev/null
    expect "python complete: no copy or tag for it" 0 "$(calls '^(copy|tag) .*/python[@:]')"

    # Five image:tags in four packages: python twice, postgres twice. The
    # postgres package already has its seed tag.
    local PY11=public.ecr.aws/docker/library/python:3.11-slim-trixie E seedrepos=("seed=$R/seed")
    fake_repo "$R/seed" Dockerfile "FROM $PY@$A AS build" "FROM $PY11@$A2" "FROM $NODE@$N"
    fake_repo "$R/seed" .github/workflows/ci.yml "        image: $PG@$P" "        image: $PGA@$Q" \
        "        image: $S3@$S"
    FAKE_TAG[$PY11]=$A2
    local EM='{"config":{"size":10},"layers":[{"size":5}]}'
    E=$(dg "$EM")
    FAKE_MANIFEST["$M/postgres@$E"]=$EM
    FAKE_TAG["$M/postgres:seed"]=$E

    log ""
    log "Seed, dry run (fake crane)"
    : > "$WORK/calls"
    rm -f "$WORK/login-stdin"
    FAKE_N=()
    status=0
    (SEED=1 DRY_RUN=true GHCR_TOKEN="" run_mirror "${seedrepos[@]}") > "$WORK/seed-dry" 2>&1 || status=$?
    sed 's/^/    > /' "$WORK/seed-dry"
    expect "seed dry run passes" 0 "$status"
    expect "seed dry run pushes, copies, tags and logs in to nothing" 0 "$(calls '^(append|copy|tag|auth) ')"
    expect "seed never reads upstream" 0 "$(grep -vcE "^[a-z]+ $M/" "$WORK/calls" || true)"
    expect "one seed tag read per package" \
        "$M/python:seed $M/node:seed $M/postgres:seed $M/adobe/s3mock:seed" \
        "$(grep -E '^digest ' "$WORK/calls" | cut -d' ' -f2 | paste -sd' ')"
    expect_line "missing seed: would seed" "$WORK/seed-dry" "| \`mirror/python\` | \`-\` | - | dry run, would seed |"
    expect_line "present seed: skipped, size shown" "$WORK/seed-dry" \
        "| \`mirror/postgres\` | \`$(short "$E")\` | $((${#EM} + 15)) | already seeded |"

    log ""
    log "Seed, real run (fake crane)"
    : > "$WORK/calls"
    rm -f "$WORK/login-stdin"
    FAKE_N=()
    FAKE_FAIL["append $M/node:seed"]="429 ok"
    status=0
    (SEED=1 DRY_RUN=false GHCR_TOKEN=$T GITHUB_ACTOR=octo GITHUB_STEP_SUMMARY="$WORK/seed-summary" \
        run_mirror "${seedrepos[@]}") > "$WORK/seed-real" 2>&1 || status=$?
    sed 's/^/    > /' "$WORK/seed-real"
    expect "seed real run passes" 0 "$status"
    expect "login first, token on stdin only" "auth login ghcr.io -u octo --password-stdin|$T" \
        "$(head -n 1 "$WORK/calls")|$(cat "$WORK/login-stdin")"
    expect "the token is never an argument or in the output" "0 0" \
        "$(grep -c -- "$T" "$WORK/calls" || true) $(grep -c -- "$T" "$WORK/seed-real" || true)"
    grep -E '^(append|copy|tag) ' "$WORK/calls" | sed "s|$WORK|WORK|" > "$WORK/writes" || true
    expect "pushes only missing seeds, the 429 retried, never copies or tags" \
        "append --oci-empty-base -f WORK/seed-layer.tar -t $M/python:seed
append --oci-empty-base -f WORK/seed-layer.tar -t $M/node:seed
append --oci-empty-base -f WORK/seed-layer.tar -t $M/node:seed
append --oci-empty-base -f WORK/seed-layer.tar -t $M/adobe/s3mock:seed" "$(cat "$WORK/writes")"
    expect "seed never reads upstream" 0 "$(grep -vcE "^([a-z]+ $M/|auth |append |layer bytes )" "$WORK/calls" || true)"
    expect "the placeholder layer is an empty tar, 1024 bytes" "layer bytes 1024" \
        "$(grep -m1 '^layer bytes ' "$WORK/calls")"
    expect_line "pushed seed: digest and size" "$WORK/seed-real" \
        "| \`mirror/adobe/s3mock\` | \`$(short "$(dg "$FAKE_SEED")")\` | $((${#FAKE_SEED} + 265)) | seeded |"
    expect_line "present seed left alone" "$WORK/seed-real" \
        "| \`mirror/postgres\` | \`$(short "$E")\` | $((${#EM} + 15)) | already seeded |"
    expect_line "package names and sizes in the log" "$WORK/seed-real" \
        "  seeded at $(dg "$FAKE_SEED") ($((${#FAKE_SEED} + 265)) bytes)"
    expect_line "seed summary written to the step summary" "$WORK/seed-summary" \
        "## Base image mirror seed (real run)"

    log ""
    log "Seed, second real run"
    # The runs above were subshells; record their pushes here.
    for key in python node adobe/s3mock; do
        FAKE_MANIFEST["$M/$key@$(dg "$FAKE_SEED")"]=$FAKE_SEED
        FAKE_TAG["$M/$key:seed"]=$(dg "$FAKE_SEED")
    done
    : > "$WORK/calls"
    rm -f "$WORK/login-stdin"
    FAKE_N=()
    (SEED=1 DRY_RUN=false GHCR_TOKEN=$T run_mirror "${seedrepos[@]}") > "$WORK/seed-again" 2>&1 || true
    expect "every seed present: nothing pushed" "0 4" \
        "$(calls '^append ') $(grep -c '| already seeded |' "$WORK/seed-again" || true)"

    log ""
    log "Real run after seeding leaves the seed tags alone"
    : > "$WORK/calls"
    rm -f "$WORK/login-stdin"
    FAKE_N=()
    out="${FAKE_TAG[$M/python:seed]} ${FAKE_TAG[$M/postgres:seed]}"
    FAKE_MANIFEST["$M/postgres@$Q"]=postgres-alpine
    status=0
    (DRY_RUN=false GHCR_TOKEN=$T run_mirror "${seedrepos[@]}") > "$WORK/after-seed" 2>&1 || status=$?
    expect "real run passes and never touches a seed tag" "0 0" "$status $(calls ':seed')"
    expect "seed tags unchanged" "$out" "${FAKE_TAG[$M/python:seed]} ${FAKE_TAG[$M/postgres:seed]}"
    expect_line "the real run completes" "$WORK/after-seed" "Done."
    fake_repo "$R/reserved" Dockerfile "FROM registry.example.com/team/odd:seed@$F"
    status=0
    (DRY_RUN=true run_mirror "reserved=$R/reserved") > "$WORK/reserved" 2>&1 || status=$?
    expect "an upstream tag named seed fails, nothing read for it" "1 0" \
        "$status $(calls 'team/odd')"
    expect_line "reserved tag reported" "$WORK/reserved" "failed: tag reserved for the seed"

    log ""
    if [[ $TESTS_FAILED -gt 0 ]]; then
        log "self-test FAILED: $TESTS_FAILED check(s)"
        return 1
    fi
    log "self-test passed"
}

# pins_section FILE prints the "Finding pins" section of a script.
pins_section() { sed -n '/^# ── Finding pins/,/^# ── Grouping/p' "$1" | sed '$d'; }

main() {
    if [[ ${1:-} == --self-test ]]; then
        self_test
        return
    fi
    if [[ ${1:-} == --seed ]]; then
        SEED=1
        shift
    fi
    if [[ $# -eq 0 || ${1:-} == -* ]]; then
        log "usage: $0 [--seed] LABEL=DIR... | --self-test"
        return 2
    fi
    run_mirror "$@"
}

main "$@"
