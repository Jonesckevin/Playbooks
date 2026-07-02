#!/bin/sh

log_event() {
    level="$1"
    event="$2"
    subject="$3"
    details="$4"
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    subject=$(printf '%s' "$subject" | sed 's/\\/\\\\/g; s/"/\\"/g')
    details=$(printf '%s' "$details" | sed 's/\\/\\\\/g; s/"/\\"/g')
    printf '{"ts":"%s","level":"%s","event":"%s","subject":"%s","details":"%s"}\n' \
        "$timestamp" "$level" "$event" "$subject" "$details" >&2
}