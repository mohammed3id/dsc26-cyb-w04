# AI usage: dsc26-cyb-w04

## Tools

<!-- Which AI tools you used (or "none"), and for which parts of the task. -->

Claude (claude.ai chat): Helped me understand the task and explained the concepts of Static Application Security Testing (SAST).

## What AI got wrong

<!-- At least one thing an AI tool got wrong that you changed, and how you noticed:
     a test, the docs, running it. -->

- The AI told me to expect "about 90 tests". When I ran pytest myself I got 68 (5 public tests plus 63 of my own), so its estimate was wrong.

- The AI's explanation said the security-severity score must be a number and that "9.0" as a string is not a number. In the real SARIF file the score is stored as a quoted string ("security-severity":"8.8"), and the task says "parses as a number", so the explanation was wrong. The code accepts both numbers and numeric strings, and my tests cover both.

## In my own words

<!-- One or two sentences each, written without AI. -->

1. I would fix the hardcoded database password first because an attacker could use it to access the database.

2. A suppression needs an expiry date because security issues should be reviewed regularly and should not be ignored forever.