---
tags:
  - linux
---
# Using `tmux`

## Set a New Working-directory for New Panes while inside a `tmux` Session

Set a new working-directory for new panes while inside a `tmux` session:

```text
:attach-session -c /path/to/new/directory
```

## Copying Text with `tmux`

I do a lot of copying and pasting text between applications, and a lot of it comes from my `tmux` scroll-buffer.

- When copying text from the `tmux` scroll buffer, I want to select text using "vi keys". This is especially handy for copying large amounts of text.
- I want my selections from the `tmux` buffer to go straight into my system clipboard, for pasting into other applications.
- I want to trim whitespace from the ends of lines.

Here's how I did it. Below are snippets from my `tmux.conf`. (A [more recent version is also available](https://gist.github.com/nycksw/6d8af2a24ece01f880683638e4a68554).)

Here I set `prefix-Escape` to enter the scroll buffer, and enable "vi keys".

```text
# vi-style buffer nav and copy/paste.
bind Escape copy-mode
set-window-option -g mode-keys vi
```

The rest of the magic happens inside the following conditional block, which checks for the existence of `xclip`. That is a command-line interface for the system clipboard.

```text
if-shell -b "command -v xclip >/dev/null 2>&1" {
```

`tmux` has its own internal paste buffer that's distinct from the system clipboard. It can be pasted with `prefix-]`. I still use that sometimes, mostly out of habit. The following binds that key to replace the `tmux` buffer with the contents of the clipboard.

```text
  # Use system clipboard instead of the tmux buffer.
  bind-key ] run-shell "xclip -o -selection clipboard | tmux load-buffer - ; tmux paste-buffer"
```

Now, the following keys are for use within copy-mode.

 The `v` key, for **v**isual, begins a visually-highlighted selection for copying, which is how it works in `vi` also.

```text
  bind -T copy-mode-vi v send-keys -X begin-selection
```

Like `vi`, I want the `y` key to be what **y**anks the selection into a copy buffer. The following also trims whitespace at the end of the line.

```text
  bind -T copy-mode-vi y send-keys -X copy-pipe-and-cancel "sed 's/[ \t]*$//' | xclip -sel clip"
```

Once you've made the selection using `v`, remember that `y` will **y**ank it into the copy buffer.

The remaining lines are all about remapping the defaults. Many default key-binding in the `copy-mode-vi` table will do `copy-pipe-and-cancel`, which I either unbind or remap because I want `y`, `Escape`, `q`, or `C-c` to be the only ways to exit copy mode.

```text
# Use "(y)ank" instead of these:
  unbind -T copy-mode-vi A
  unbind -T copy-mode-vi D
  unbind -T copy-mode-vi MouseDragEnd1Pane
  unbind -T root DoubleClick1Pane
  unbind -T root TripleClick1Pane

  bind -T copy-mode-vi Enter send -X cursor-down
  bind -T copy-mode-vi C-j send -X cursor-down

  bind -T copy-mode-vi Escape send-keys -X cancel
  bind -T copy-mode-vi q send-keys -X cancel
  bind -T copy-mode-vi C-c send-keys -X cancel
```

Finally, closing the conditional block, if `xclip` isn't installed then an error message should be displayed when `tmux` launches:

```text
} "display-message 'xclip not installed, clipboard functions disabled'"
```

Here's the whole section:

```text
...
bind Escape copy-mode

# vi-style buffer nav and copy/paste.
set-window-option -g mode-keys vi

# If `xclip` is installed, enable (y)anking a selection from the buffer into the clipboard.

if-shell -b "command -v xclip >/dev/null 2>&1" {

  set -g set-clipboard external

  # Use system clipboard instead of the tmux buffer.
  bind-key ] run-shell "xclip -o -selection clipboard | tmux load-buffer - ; tmux paste-buffer"

  # Text-selection happens either with the "v" key or by highlighting with the mouse.
  bind -T copy-mode-vi v send-keys -X begin-selection
  bind -T copy-mode-vi MouseDrag1Pane send-keys -X begin-selection

  # Selections are made only via "(y)ank".
  bind -T copy-mode-vi y send-keys -X copy-pipe-and-cancel "sed 's/[ \t]*$//' | xclip -sel clip"

  # Use "(y)ank" instead of these:
  unbind -T copy-mode-vi A
  unbind -T copy-mode-vi D
  unbind -T copy-mode-vi MouseDragEnd1Pane
  unbind -T root DoubleClick1Pane
  unbind -T root TripleClick1Pane

  bind -T copy-mode-vi Enter send -X cursor-down
  bind -T copy-mode-vi C-j send -X cursor-down

  bind -T copy-mode-vi Escape send-keys -X cancel
  bind -T copy-mode-vi q send-keys -X cancel
  bind -T copy-mode-vi C-c send-keys -X cancel

} "display-message 'xclip not installed, clipboard functions disabled'"
...
```
