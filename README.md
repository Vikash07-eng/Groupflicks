# Groupflicks

Share the photos from a trip with the people you travelled with. Everyone adds their shots to one album from a link, filters down to the photos they are in, downloads just those, and cuts a highlight reel.

- `docs/` is the real app: a static website that talks to a Supabase project. It is in `docs/` so GitHub Pages can serve it directly.
- `supabase/schema.sql` is the whole backend.

## How it works

There are no accounts. Creating a trip makes an invite link like `https://your-site/#a=<album>.<secret>`. Anyone with the link types a name and can view and add photos.

Everything is encrypted in the browser before upload (AES-256-GCM, keys derived from the link's secret with HKDF-SHA-256). The secret sits after the `#`, which browsers never send to a server, so the server stores only ciphertext. All traffic to the site and to Supabase is HTTPS.

| The server can see | The server cannot see |
| --- | --- |
| Random album and file ids | Photos and thumbnails |
| How many items an album has, their sizes, when they changed | Album name and place |
| IP addresses of visitors (as any web host does) | People's names, tags and face data |

## Set it up

1. Create a free project at supabase.com.
2. Open the SQL editor, paste `supabase/schema.sql`, and run it.
3. In Project Settings, API, copy the project URL and the `anon` `public` key into `docs/config.js`.
4. In this repo's Settings, Pages, choose "Deploy from a branch", pick the branch and the `/docs` folder.
5. Open the Pages address. The header should read "End-to-end encrypted".

Without step 3 the site runs in demo mode: albums stay in the browser tab and links do not work for friends.

To run it locally, serve `docs/` on localhost: `python3 -m http.server 8000 --directory docs`.

## Status

| Area | State |
| --- | --- |
| Encrypted albums, invite links, uploads, sync between devices | Tested against the schema on a local Postgres with a stand-in for Supabase's HTTP API. Not yet run against a real Supabase project. |
| Tagging people, "Me" filter, filtered zip download, highlight reel | Tested |
| Automatic face grouping and selfie match | Written, not yet tested. Loads the face-api library and models from jsDelivr when the page opens; falls back to hand tagging if that fails. |
| Install to home screen (manifest and offline shell) | Written, not yet tested on a phone |

## Database updates

`supabase/schema.sql` always holds the complete, current backend and can be re-run safely. If your project was set up earlier, running the dated scripts you have not run yet does the same job:

| Script | Adds |
| --- | --- |
| `2026-11-16-lock-down-storage.sql` | Stops the photo bucket being listed |
| `2026-11-17-view-links-and-limits.sql` | View-only links, permission-gated uploads and deletes, usage limits |

## Limits to know about

- The link is the key. Anyone who gets it can see the album, add photos and remove photos. If everyone loses the link, the album cannot be recovered.
- Links to albums you have opened are remembered in that browser's local storage so they show on the home screen.
- Other devices pick up changes by checking every five seconds.
- Photos stay until someone removes them. The person who created an album can delete the whole album, with its files, from Album options, in the browser they created it in.
- Photos are resized to 2048 px before upload, so downloads are not the originals.
- The photo bucket cannot be listed. Adding or deleting a file needs the album id and the file's random name, which only people with the invite link have. If you set the project up before 16 November 2026, run `supabase/2026-11-16-lock-down-storage.sql` once.
- Limits: 10 new albums an hour and 20 a day per network, 4,000 file uploads an hour per network, 2,000 photos per album, and uploads stop when stored files reach 900 MB. Change the numbers in `supabase/schema.sql` to suit your plan.
- A view-only link lets people look, filter, download and make reels, and nothing else. It cannot be turned back into a full link.
- The face-api script is loaded from a CDN without an integrity hash. Vendoring it into `docs/vendor/` would remove that trust.

## Licence

All rights reserved. The code is public to read, not to reuse; see `LICENSE`. JSZip in `docs/vendor/` keeps its own licence.
