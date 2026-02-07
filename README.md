# @hawk.so/kit

Set of packages for Hawk services development (monorepo).

## Packages

- **[@hawk.so/utils](./packages/utils)** — shared utilities for Hawk packages.
  - `hasValue` — check that a value is not `undefined`, `null`, or empty string.
  - `TimeMs` — enum of time intervals in milliseconds (Second, Minute, Hour, Day, Week).

- **[@hawk.so/github-sdk](./packages/github)** — GitHub API client for Hawk.
  - `GitHubService` — GitHub App (installation, installations, repositories).
  - Create and manage issues, assign Copilot to an issue.
  - OAuth: exchange code for token, refresh token, validate user token.
  - `normalizeGitHubPrivateKey` — normalize PEM key from env (base64, quotes, `\n`).
  - Types: `GitHubServiceConfig`, `OAuthTokens`, `GitHubUser`, `ValidateUserTokenResult`, `Repository`, `Installation`, `GitHubIssue`, `IssueData`.

## Requirements

- Node.js >= 22.0.0
- Yarn 4 (Corepack enabled in repo)

## Commands

```bash
yarn install   # install dependencies
yarn build     # build all packages
yarn lint      # lint (build + eslint across packages)
yarn test      # run tests
yarn clean     # remove dist and tsbuildinfo
```

## License

AGPL-3.0

## About CodeX

<img align="right" width="120" height="120" src="https://codex.so/public/app/img/codex-logo.svg" hspace="50">

CodeX is a team of digital specialists around the world interested in building high-quality open source products on a global market. We are [open](https://codex.so/join) for young people who want to constantly improve their skills and grow professionally with experiments in cutting-edge technologies.

| 🌐 | Join  👋  | Twitter | Instagram |
| -- | -- | -- | -- |
| [codex.so](https://codex.so) | [codex.so/join](https://codex.so/join) |[@codex_team](http://twitter.com/codex_team) | [@codex_team](http://instagram.com/codex_team/) |

