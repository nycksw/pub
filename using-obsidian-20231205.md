---
tags: [think]
---
# Using Obsidian

Writing notes [is thinking](taking-notes-is-thinking-20230901.md), and having low-friction note-taking tools can be helpful. Obsidian is an elegant piece of software for taking notes. The mission of the product emphasizes user data and not the software that generates it. Having all your notes in a simple and versatile text format helps ensure that in the future your notes will still be useful even if the software isn't maintained, or if the company has gone defunct, or even if you just simply decide to use something else. This philosophy is unique in a world where most software companies seem to be explicitly aiming for user lock-in.

## Philosophy

The basic goal is to minimize complexity, particularly premature optimization. For example, I started with using some basic front-matter YAML, like tags, source links, etc., but then realized I was barely using the functionality, so I removed all the front-matter, which made me feel happy and free.

## Structure

The structure is I use is generally `/prj/` for active projects, `/pub/` for finished work (suitable for the public), `/prv/` for finished work that's not meant for the public, `/log/` for daily journals, and `/tp`/ for Templater templates.

I have a plugin that maintains consistent attachments in a directory named `_` in the same folder as the source notes, for a cleaner directory listing.

Beyond those folders mentioned above, I try to keep everything else as flat as possible. I try to avoid categorizing notes, preferring instead to allow link structure to emerge around concepts.

## Editing

I'm using [vim mode](https://publish.obsidian.md/hub/04+-+Guides%2C+Workflows%2C+%26+Courses/for+Vim+users) and the [Obsidian vimrc plugin](https://github.com/esm7/obsidian-vimrc-support). I'm still getting comfortable with the functionality gap between that and actual Vim. I still compulsively type `:w` all the time which is hilarious, but I mapped that to trigger the [Linter](https://github.com/platers/obsidian-linter), so that works for me now.

### Open Issues with `vim` Mode

Which lines in my `vimrc` file aren't supported by the `vimrc` plugin? How many of them do I want to live without, or can I replicate using another plugin? Need balance between complexity of configuration and utility.

Right now, it's just:

```text
" Navigate visual lines not logical lines.
nmap j gj
nmap k gk
```

## Filenames

I started with `Uppercase File Names With Spaces.md` but after a couple months I switched to `slugified-filenames.md`. The main rationale for that change is that it's a pain in the butt to work with filenames with spaces in Linux, but it's also just an aesthetic I like. This also translates directly to the URL names for published pages.

## Obsidian Linter

There's a [sophisticated Obsidian linter](https://platers.github.io/obsidian-linter/settings/spacing-rules/) available. It's amazing.
