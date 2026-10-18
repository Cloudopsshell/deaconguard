// check-docs.mjs checks the documentation in docs/ before it is published on
// docs.deaconguard.io, without installing anything:
//
//   - every page is in docs/sidebars.js, and every sidebar entry has a page;
//   - every link to another page (./page.md, ../dir/page.md#heading) points to
//     a page that exists, and to a heading on it, if one is named;
//   - every image under /img/ exists in docs/static/img.
//
// Run it from the repository root: node scripts/check-docs.mjs
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join, normalize, relative, resolve } from 'node:path';

const root = resolve('docs');
const content = join(root, 'content');
const problems = [];

function pages(dir) {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return pages(path);
    return /\.mdx?$/.test(name) ? [path] : [];
  });
}

const id = (path) => relative(content, path).replace(/\.mdx?$/, '');

// Heading anchors as Docusaurus makes them: an explicit {#id}, or the text in
// lower case, without punctuation, with spaces as hyphens, numbered if repeated.
function anchors(text) {
  const seen = new Map();
  const found = new Set();
  let fenced = false;
  for (const line of text.split('\n')) {
    if (/^\s*(```|~~~)/.test(line)) fenced = !fenced;
    const heading = !fenced && line.match(/^#{1,6}\s+(.*?)\s*#*\s*$/);
    if (!heading) continue;
    const explicit = heading[1].match(/\{#([^}]+)\}\s*$/);
    if (explicit) {
      found.add(explicit[1]);
      continue;
    }
    const slug = heading[1]
      .replace(/<[^>]+>/g, '')
      .replace(/\[([^\]]*)\]\([^)]*\)/g, '$1')
      .replace(/[`*_~]/g, '')
      .toLowerCase()
      .replace(/[^\p{L}\p{N}\s-]/gu, '')
      .trim()
      .replace(/\s/g, '-');
    const count = seen.get(slug) ?? 0;
    seen.set(slug, count + 1);
    found.add(count ? `${slug}-${count}` : slug);
  }
  return found;
}

const all = pages(content);
const ids = new Set(all.map(id));

// Sidebar entries: strings, and { type: 'doc', id } items.
const sidebars = createRequire(import.meta.url)(join(root, 'sidebars.js'));
const listed = new Set();
(function walk(item) {
  if (typeof item === 'string') listed.add(item);
  else if (Array.isArray(item)) item.forEach(walk);
  else if (item && typeof item === 'object') {
    if (item.type === 'doc' && item.id) listed.add(item.id);
    if (item.items) walk(item.items);
    Object.values(item).forEach((value) => Array.isArray(value) && value.forEach(walk));
  }
})(sidebars);
for (const entry of listed) if (!ids.has(entry)) problems.push(`docs/sidebars.js lists "${entry}", but there is no docs/content/${entry}.md`);
for (const page of ids) if (!listed.has(page)) problems.push(`docs/content/${page}.md is not in docs/sidebars.js`);

const anchorCache = new Map();
const anchorsOf = (path) => {
  if (!anchorCache.has(path)) anchorCache.set(path, anchors(readFileSync(path, 'utf8')));
  return anchorCache.get(path);
};

for (const path of all) {
  const text = readFileSync(path, 'utf8').replace(/^(```|~~~)[\s\S]*?^\1/gm, '');
  const where = relative(process.cwd(), path);
  for (const [, target] of text.matchAll(/\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g)) {
    if (/^(https?:|mailto:)/.test(target)) continue;
    if (target.startsWith('/img/')) {
      if (!existsSync(join(root, 'static', target))) problems.push(`${where}: image ${target} is not in docs/static/img`);
      continue;
    }
    const [file, anchor] = target.split('#');
    const linked = file ? normalize(join(dirname(path), file)) : path;
    if (file && !/\.mdx?$/.test(file)) {
      problems.push(`${where}: link "${target}" should point to a .md page`);
      continue;
    }
    if (!existsSync(linked)) {
      problems.push(`${where}: link "${target}" points to a page that doesn't exist`);
      continue;
    }
    if (anchor && !anchorsOf(linked).has(anchor)) problems.push(`${where}: link "${target}": no heading #${anchor} on that page`);
  }
  for (const [, src] of text.matchAll(/(?:src|srcSet)="(\/img\/[^"\s]+)"/g)) {
    if (!existsSync(join(root, 'static', src))) problems.push(`${where}: image ${src} is not in docs/static/img`);
  }
}

if (problems.length) {
  for (const problem of problems) console.error(`::error::${problem}`);
  console.error(`${problems.length} problem(s) in docs/.`);
  process.exit(1);
}
console.log(`docs/: ${all.length} pages, all in the sidebar; links, headings and images resolve.`);
