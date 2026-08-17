# TikTok privacy audit artifact

## Project
- name: TikTok privacy audit
- slug: tiktok-metadata
- description: Frida observation of what TikTok reads from posted videos
- audience: operator running the iPhone X burner posts

## Artifact
- url: (not published — no claude.ai Artifact tool in this session)
- favicon: phone+magnifier
- title: TikTok privacy audit — metadata
- html: artifacts/tiktok-metadata.html

## Sources
- runs/unique-1-solo/tags.json (CLEAN)
- runs/unique-2-solo/tags.json (STAMPED)
- runs/unique-3-sintel/tags.json
- runs/unique-4-bunny/tags.json
- runs/unique-5-camera/tags.json (fresh Camera + GPS)
- runs/unique-6-canary-2/tags.json (canary reads)
- runs/unique-6-publish/tags.json + bodies (CDN /upload/v1)
- testfiles/unique-1-clean.mov / unique-2-stamped.mov / unique-6-canary.mov
- gallery-id/IMG_0026-camera.MOV and publish_video_local_canary.mp4
- earlier blended runs kept only as caveats

## Notes
- 2026-08-17 10:51 UTC canary strip + CDN upload; unique-8-ai-2 wrote aigc_label_type 2; aweme JSON not seen
