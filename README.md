# site

Password-protected static deliverable.

All substantive content is AES-GCM-encrypted client-side; this repo contains only the gate, the decrypt runtime, and the encrypted bundles. Access requires a password shared out-of-band. All user-facing labels live in a local-only `content-private.json` (gitignored) that is baked into the encrypted bundles at build time.

## Build

From inside this directory:

```sh
npm run build
```

That runs `node build.mjs` and regenerates the encrypted bundles from sources under `../` plus the local `content-private.json`.

## Deploy

```sh
npm run deploy
```

Build + commit + push.

## Password override

```sh
node build.mjs --password=newpassword
```
