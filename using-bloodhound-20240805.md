---
tags:
  - hack
---
# Using BloodHound

## Queries

Tip: after initial access, see who's in local "Administrators" group. Any domain groups? Mark as "high value". Ensure compromised users are marked as "owned".

Find users with `CanPSRemote` privileges:

```console
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2
```

Insert any privilege, e.g. `SQLAdmin`:

```text
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) RETURN p2
```
