# @hawk.so/github-sdk

GitHub API client for Hawk. Unified service for GitHub App, Issues, OAuth.
Shared by API and Workers.

## Build

```bash
cd utils/packages/github && yarn build
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
| `apiUrl`      | `getInstallationUrl`, OAuth redirect URI. Hawk Api host. |
