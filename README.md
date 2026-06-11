# Stigward's Security Journal

Source for [stigward.github.io](https://stigward.github.io) — a blog focused on
vulnerability research, exploit development, and general security topics.

Built with the [Chalk](https://github.com/nielsenramon/chalk) theme for Jekyll
(MIT licensed), running in dark mode.

## Local development

Chalk depends on Jekyll 3.8 / `jekyll-assets`, which need Ruby 2.x and a
JavaScript runtime. The simplest way to build locally is with the same
`ruby:2.7` container CI uses:

```sh
# install JS deps (host needs yarn)
yarn install --modules-folder ./_assets/yarn

# build + serve inside the container
docker run --rm -it -p 4000:4000 -v "$PWD":/srv -w /srv ruby:2.7 bash -c '
  apt-get update -qq && apt-get install -y -qq nodejs
  gem install bundler -v 2.4.22 -N
  bundle install
  bundle exec jekyll serve --host 0.0.0.0
'
```

With a native Ruby 2.x toolchain you can instead use the bundled scripts:

```sh
npm run setup   # bundle install + yarn install
npm run local   # bundle exec jekyll serve --drafts
```

## Deployment

Pushes to `main` trigger `.github/workflows/pages-deploy.yml`, which builds the
site in a `ruby:2.7` container and publishes `_site` to the `gh-pages` branch.
GitHub Pages should be configured to serve from `gh-pages`.

## Writing posts

Posts live in `_posts/` as `YYYY-MM-DD-title.md` with front matter:

```yaml
---
title: "Post title"
date: 2024-01-01
description: "One-line summary shown in listings and SEO tags."
tags: [pwn, ctf]
---
```

Each tag used in a post must have a matching file in `_my_tags/` (e.g.
`_my_tags/pwn.md`) so the tag pages and footers resolve its display name.
Post images go under `assets/img/<dir>/` and are referenced with absolute
paths, e.g. `![alt](/assets/img/img_non/foo.png)`.
