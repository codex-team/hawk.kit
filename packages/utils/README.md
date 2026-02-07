# @hawk.so/utils

Shared utilities for Hawk packages.

## Contents

- **hasValue(v)** — returns `true` if the value is not `undefined`, not `null`, and not an empty string; otherwise `false`.
- **TimeMs** — enum of time intervals in milliseconds:
  - `Millisecond`, `Second`, `Minute`, `Hour`, `Day`, `Week`

## Installation

```bash
yarn add @hawk.so/utils
```

## Example

```typescript
import { hasValue, TimeMs } from '@hawk.so/utils';

if (hasValue(process.env.API_KEY)) {
  // ...
}

const fiveMinutes = 5 * TimeMs.Minute;
```

## License

AGPL-3.0

## About CodeX

<img align="right" width="120" height="120" src="https://codex.so/public/app/img/codex-logo.svg" hspace="50">

CodeX is a team of digital specialists around the world interested in building high-quality open source products on a global market. We are [open](https://codex.so/join) for young people who want to constantly improve their skills and grow professionally with experiments in cutting-edge technologies.

| 🌐 | Join  👋  | Twitter | Instagram |
| -- | -- | -- | -- |
| [codex.so](https://codex.so) | [codex.so/join](https://codex.so/join) |[@codex_team](http://twitter.com/codex_team) | [@codex_team](http://instagram.com/codex_team/) |

