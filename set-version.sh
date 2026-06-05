#!/bin/bash -e

NEW_VERSION=$1
# Tags are v1.0.2; Maven versions must be 1.0.2
NEW_VERSION="${NEW_VERSION#v}"

if [ -z "${NEW_VERSION}" ] || [[ "${NEW_VERSION}" == v* ]] || [[ "${NEW_VERSION}" == V* ]]; then
  echo "Invalid Maven version derived from tag: $1" >&2
  exit 1
fi

./mvnw versions:set -DnewVersion="$NEW_VERSION" -DgenerateBackupPoms=false

echo "New version: $NEW_VERSION" >&2