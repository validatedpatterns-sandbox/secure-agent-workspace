#!/usr/bin/env bash
# Validate repository prefixes before using them in image commands or Job data.
validate_image_repo() {
  local repo="$1"
  local pattern='^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?(/[a-z0-9]+(([._]|__|-+)[a-z0-9]+)*)+$'
  if [[ ! "$repo" =~ $pattern || "$repo" == *..* ]]; then
    echo 'Error: IMAGE_REPO must be a registry[:port]/namespace path without schemes, whitespace, or shell characters.' >&2
    return 1
  fi
}
