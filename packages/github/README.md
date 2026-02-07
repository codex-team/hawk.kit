# @hawk.so/github-sdk

GitHub API client for Hawk. Unified service for GitHub App, Issues, OAuth.
Shared by API and Workers.

## Build

```bash
cd packages/github && yarn build
```

Build before using in API or Workers (when using `file:` dependency).

## Usage

Pass configuration via constructor:

```typescript
import { GitHubService, type GitHubServiceConfig } from '@hawk.so/github-sdk';

const config: GitHubServiceConfig = {
  appId: process.env.GITHUB_APP_ID!,
  privateKey: process.env.GITHUB_PRIVATE_KEY!,
  appSlug: process.env.GITHUB_APP_SLUG,
  clientId: process.env.GITHUB_APP_CLIENT_ID,
  clientSecret: process.env.GITHUB_APP_CLIENT_SECRET,
  apiUrl: process.env.API_URL,  // required for getInstallationUrl, OAuth
};

const githubService = new GitHubService(config);
```

API and Workers read env vars and pass them to the constructor.

## Config fields

| Field         | Required for                                  |
|---------------|-----------------------------------------------|
| `appId`       | all                                           |
| `privateKey`  | all (PEM format, `\n` escape sequences)       |
| `appSlug`     | optional (default: `hawk-tracker`)            |
| `clientId`    | OAuth (token exchange, refresh)               |
| `clientSecret`| OAuth                                         |
| `apiUrl`      | `getInstallationUrl`, OAuth redirect URI. Hawk API host. |

## About CodeX

<img align="right" width="120" height="120" src="https://codex.so/public/app/img/codex-logo.svg" hspace="50">

CodeX is a team of digital specialists around the world interested in building high-quality open source products on a global market. We are [open](https://codex.so/join) for young people who want to constantly improve their skills and grow professionally with experiments in cutting-edge technologies.

| 🌐 | Join  👋  | Twitter | Instagram |
| -- | -- | -- | -- |
| [codex.so](https://codex.so) | [codex.so/join](https://codex.so/join) |[@codex_team](http://twitter.com/codex_team) | [@codex_team](http://instagram.com/codex_team/) |

