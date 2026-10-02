#!/bin/sh
# Fetches microsoft/vega-prover at the pinned revision into third_party/ and applies
# local patches. Cargo.toml [patch] points the git dependency at this checkout.
# A no-op when the checkout already matches REV + patches: re-applying would bump mtimes
# and make cargo rebuild the prover (and everything downstream) on every call.
set -eu
cd "$(dirname "$0")/.."
REV=c0ee259053cd12eaf43ed71b5cde375452b3ee4d
DEST=third_party/vega-prover
STAMP=third_party/vega-prover.stamp
WANT="$REV $(cat patches/*.patch | cksum)"
if [ -d "$DEST/.git" ] && [ "$(cat "$STAMP" 2>/dev/null)" = "$WANT" ]; then
  exit 0
fi
if [ ! -d "$DEST/.git" ]; then
  mkdir -p third_party
  git clone --quiet https://github.com/microsoft/vega-prover.git "$DEST"
fi
git -C "$DEST" checkout --quiet --force "$REV"
git -C "$DEST" clean -fdq
for p in patches/*.patch; do
  git -C "$DEST" apply "../../$p"
done
echo "$WANT" > "$STAMP"
echo "vega-prover $REV ready in $DEST"
