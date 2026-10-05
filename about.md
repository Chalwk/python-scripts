---
layout: page
title: About
subtitle: "What this repo is, and what it isn't."
permalink: /about/
---

`python-scripts` is a personal collection of scripts I've written that turned
out to be useful more than once. They span different domains: networking,
security, automation, text processing, web, and there's no unifying theme
beyond "I needed this, so I wrote it".

## What you'll find here

- **Self-contained scripts.** Each file is a complete tool. No shared library,
  no package to install, no build step.
- **Standard library first.** If a script genuinely needs a third-party
  package, it says so at the top of the file and in the [README](https://github.com/{{ site.repository }}).
- **Readable code.** Nothing is obfuscated or clever for the sake of it. If a
  script makes a judgement call, it shows its work.
- **`--help` always works.** Every script has a real argument parser, not positional guesswork.

## What you won't find here

- Frameworks, abstractions, or "platforms".
- Anything that requires a config file to do the simplest possible thing.
- Code I wouldn't run on my own machine.

## Conventions

A few rules I try to stick to:

1. **Python 3.8+.** No version requirements more exotic than that unless
   there's a compelling reason.
2. **Secrets come from the environment first**, command line second, config
   file third, hardcoded last, and never hardcoded in a published script.
3. **Destructive actions are opt-in**, not default.
4. **`--self-test` where it makes sense.** Offline tests, no API key, no network.

## License

MIT. Take what's useful, ignore the rest.

Copyright &copy; {{ site.author.name }}.