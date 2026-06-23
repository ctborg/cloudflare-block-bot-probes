# Cloudflare Worker Bot Blocking Rules

Drop common garbage bot and vulnerability-scanner requests at Cloudflare's edge before they invoke your Worker.

This guide is for apps running behind Cloudflare Workers, Pages Functions, or other Cloudflare-routed origins. It focuses on high-confidence paths that should not exist on most modern static apps, single-page apps, games, SaaS projects, portfolios, and API-backed frontends.

Examples of requests this blocks:

```text
GET /.git/config
GET /.env
GET /wp-admin/install.php
GET /wordpress/wp-includes/wlwmanifest.xml
POST /xmlrpc.php
GET /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
GET /appsettings.json
GET /credentials.json
```

## Why This Matters

Cloudflare Workers charge based on usage. If exploit scanners hit your Worker route, you may pay for requests that were never real users.

Returning `404` or `403` inside the Worker still invokes the Worker. The goal here is to block the request in Cloudflare WAF Custom Rules before it reaches your Worker.

## Quick Start

In the Cloudflare dashboard:

1. Open the target zone.
2. Go to `Rules > Overview > URL Normalization`.
3. Enable URL normalization for incoming URLs.
4. Go to `Security > WAF > Custom rules`.
5. Create the rules below.
6. Put these rules near the top.
7. Set each action to `Block`.

Cloudflare documentation:

- [WAF custom rules](https://developers.cloudflare.com/waf/custom-rules/)
- [Ruleset Engine phases](https://developers.cloudflare.com/ruleset-engine/reference/phases-list/)
- [URL normalization](https://developers.cloudflare.com/rules/normalization/)

## Rule 1: WordPress and PHP Scanners

Most non-PHP apps should never receive WordPress or arbitrary PHP requests.

Action: `Block`

```txt
(
  lower(http.request.uri.path) contains "/wp-"
  or lower(http.request.uri.path) contains "/wordpress/"
  or lower(http.request.uri.path) contains "/xmlrpc.php"
  or lower(http.request.uri.path) contains "/wlwmanifest.xml"
  or ends_with(lower(http.request.uri.path), ".php")
  or lower(http.request.uri.path) contains ".php/"
)
```

Do not use this rule unchanged if your site legitimately serves PHP files or WordPress paths.

## Rule 2: Dotfiles and Local Tooling

These paths are almost always probes for accidentally exposed source code, environment files, or editor config.

Action: `Block`

```txt
(
  starts_with(lower(http.request.uri.path), "/.git")
  or starts_with(lower(http.request.uri.path), "/.env")
  or starts_with(lower(http.request.uri.path), "/.svn")
  or starts_with(lower(http.request.uri.path), "/.hg")
  or starts_with(lower(http.request.uri.path), "/.vscode")
  or starts_with(lower(http.request.uri.path), "/.idea")
  or lower(http.request.uri.path) contains "/.env"
  or lower(http.request.uri.path) contains "/.git/"
)
```

This intentionally does not block all `/.well-known/*` paths, because some are legitimate.

## Rule 3: Secrets and Config File Probes

Scanners often look for framework config, cloud credentials, service account files, and database settings.

Action: `Block`

```txt
(
  http.request.uri.path wildcard "*/credentials.json"
  or http.request.uri.path wildcard "*/secrets.json"
  or http.request.uri.path wildcard "*/service-account.json"
  or http.request.uri.path wildcard "*/firebase.json"
  or http.request.uri.path wildcard "*/gcp-credentials.json"
  or http.request.uri.path wildcard "*/google-credentials.json"
  or http.request.uri.path wildcard "*/keyfile.json"
  or http.request.uri.path wildcard "*/appsettings*.json"
  or http.request.uri.path wildcard "*/config*.json"
  or http.request.uri.path wildcard "*/settings*.json"
  or http.request.uri.path wildcard "*/database.yml"
  or http.request.uri.path wildcard "*/database.yaml"
  or http.request.uri.path wildcard "*/parameters.yml"
  or http.request.uri.path wildcard "*/application*.properties"
  or lower(http.request.uri.path) contains "/api/env"
  or lower(http.request.uri.path) contains "/config/"
)
```

Review this rule if your app has legitimate public routes such as `/config.json` or `/api/env`.

## Rule 4: Common Framework and Hosting Panel Scanners

These requests target known framework, PHPUnit, cPanel, router, and legacy server paths.

Action: `Block`

```txt
(
  lower(http.request.uri.path) contains "/vendor/phpunit/"
  or lower(http.request.uri.path) contains "/cgi-bin/"
  or lower(http.request.uri.path) contains "/boaform/"
  or lower(http.request.uri.path) contains "/actuator"
  or lower(http.request.uri.path) contains "/swagger"
  or lower(http.request.uri.path) contains "/openid_connect/cpanelid"
  or ends_with(lower(http.request.uri.path), ".aspx")
  or ends_with(lower(http.request.uri.path), ".asp")
  or ends_with(lower(http.request.uri.path), ".jsp")
)
```

Review this rule if your app intentionally exposes Swagger/OpenAPI docs publicly.

## Optional: AI and SEO Crawlers

Do not block all crawler user agents blindly. User-Agent strings are easy to spoof.

Prefer Cloudflare's verified bot signals when available. If you want to reduce AI crawler traffic, use a separate rule or Cloudflare's bot controls instead of mixing crawler policy with exploit-scanner blocking.

You can also publish a `robots.txt`, but remember: malicious scanners ignore it. WAF rules are enforcement; `robots.txt` is a request.

## Optional: Avoid SPA Fallback for Suspicious Files

Many single-page apps return `index.html` for every unknown path. That is convenient for app routes, but it can make scanner probes look like successful `200` responses:

```text
/credentials.json
/.env
/.git/config
/appsettings.json
```

Even after adding WAF rules, consider making your app or Worker return `404` for suspicious file-like paths that should never be client-side routes.

Example Worker-side fallback guard:

```js
const suspiciousPath = /\.(php|asp|aspx|jsp|py|rb|pl|cgi|env|sql|bak|old|log)$/i;
const suspiciousPrefix = /^\/(\.git|\.env|\.svn|\.hg|\.vscode|wp-|wordpress\/)/i;

if (suspiciousPath.test(url.pathname) || suspiciousPrefix.test(url.pathname)) {
  return new Response("Not found", { status: 404 });
}
```

This Worker-side guard is not a substitute for WAF blocking. It is a defense-in-depth cleanup so your app does not accidentally make scanner traffic look successful.

## How To Verify

After publishing the WAF rules, test with `curl`:

```sh
curl -i https://example.com/.git/config
curl -i https://example.com/.env
curl -i https://example.com/wp-admin/install.php
curl -i https://example.com/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
```

Expected result:

```text
HTTP/2 403
```

Then check your Worker logs. These requests should no longer appear as Worker invocations.

## Tuning Tips

- Start with path-based rules. They are more stable than IP blocks.
- Avoid country blocking unless you have a strong product reason.
- Keep crawler policy separate from vulnerability-scanner blocking.
- Do not block `/.well-known/*` wholesale.
- Use `Block`, not `Managed Challenge`, if your goal is to avoid Worker invocation.
- Revisit the rules if your app later adds public config files, Swagger docs, WordPress, or PHP.

## License

MIT
