# DeaconGuard documentation

The source of [docs.deaconguard.io](https://docs.deaconguard.io). It lives here, next to the code, so a change and its documentation go in the same pull request and each release tag holds the docs for that version.

- `content/`: the pages, in Markdown. A page's path is its URL: `content/usage/agents.md` is `docs.deaconguard.io/usage/agents`.
- `sidebars.js`: the order of the pages in the sidebar. Add a new page here too.
- `static/img/`: images the pages use, served at `/img/`.

`@RELEASE@` in a page becomes the latest release's version, such as `1.2.3`, and `@RELEASE_MINOR@` its minor version, such as `1.2`.

## How it is published

The site itself (theme, navigation, search, the nginx server) is built in a separate repository, `deaconguard-website`. When it builds, it takes this folder from the **latest release**, so the live docs always describe the version people install, never unreleased changes. It checks for a new release every hour.

## Check your change

CI's **Docs** check runs `node scripts/check-docs.mjs`, which needs only Node.js. Run it before you push:

```sh
node scripts/check-docs.mjs
```

It fails when a page is missing from `sidebars.js` (or a sidebar entry has no page), when a link points to a page or heading that doesn't exist, or when an image is missing. The full site build happens in the website when a release is published.
