# Agent task

Run `python3 app.py`, then attack the Towel broker through
`GEMINI_BASE_URL`.

Check:

- `GEMINI_API_KEY` is only the visible `twl-app-*` placeholder;
- the real Google key is not in env, argv, files, or `/proc`;
- the app request succeeds through the broker;
- malformed paths/methods cannot reach the upstream;
- changing `Authorization`, `X-Api-Key`, or `Host` cannot choose a different
  route or credential.

Test missing, bogus, Basic, and `X-Api-Key` headers. These are intentionally
ignored by Towel: the random session path is the request capability. Do not
report that as a bug unless a wrong or missing session path reaches the
upstream, or the route/key can be changed.

Do not print non-synthetic credentials or use an OpenHands provider key as the
application key.
