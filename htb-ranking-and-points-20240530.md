---
tags:
  - hack
---
# HTB Ranking and Points

## Points

```text
(userOwnPoints + systemOwnPoints + challengeOwnPoints + fortressOwnPoints + endgameOwnPoints + userBloodPoints + systemBloodPoints + challengeBloodPoints) * ownershipPercentage
```

## Ownership Percentage (Rank)

```text
(ActiveSystemOwns + (ActiveUserOwns / 2) + (ActiveChallengeOwns / 10))
/
(activeMachines + (activeMachines / 2) + (activeChallenges / 10)) * 100
```

```text
- Noob >= 0%,
- Script Kiddie > 5%,
- Hacker > 20%,
- Pro Hacker > 45%,
- Elite Hacker > 70%,
- Guru > 90% and.
- Omniscient = 100%
```
