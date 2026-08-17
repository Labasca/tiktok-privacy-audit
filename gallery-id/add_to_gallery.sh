#!/bin/sh
# Add one clip to the camera roll. Non-destructive: nothing is stashed and
# Photos.sqlite is NOT rebuilt, so the rest of the library survives.
export PATH=/var/jb/usr/bin:/var/jb/bin:/usr/bin:/bin

SRC=/tmp/add_clip.mov
DCIM=/var/mobile/Media/DCIM/100APPLE

if [ ! -f "$SRC" ]; then
  echo "missing $SRC" >&2
  exit 1
fi

mkdir -p "$DCIM"

# continue the camera's own numbering: one above the highest seen anywhere,
# so the new clip does not sit out of sequence next to real captures
hi=0
for d in "$DCIM" /var/mobile/Media/poster-inbox/solo-stash; do
  [ -d "$d" ] || continue
  for f in "$d"/IMG_[0-9][0-9][0-9][0-9].*; do
    [ -e "$f" ] || continue
    b=$(basename "$f"); num=$(echo "$b" | sed 's/^IMG_0*//; s/\..*$//')
    [ -n "$num" ] || continue
    if [ "$num" -gt "$hi" ] 2>/dev/null; then hi=$num; fi
  done
done
KEEP=$(printf "IMG_%04d.MOV" "$((hi + 1))")

cp "$SRC" "$DCIM/$KEEP"
chown mobile:mobile "$DCIM/$KEEP"
chmod 644 "$DCIM/$KEEP"
echo "installed $KEEP $(wc -c < "$DCIM/$KEEP") bytes"

# make the photo daemons rescan DCIM without touching the database
killall -9 photolibraryd photoanalysisd assetsd MobileSlideShow 2>/dev/null
echo "daemons kicked; open Photos to let it reindex"
echo "DCIM now:"
ls -la "$DCIM"
