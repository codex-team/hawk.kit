import jwt from 'jsonwebtoken';
import { Octokit } from '@octokit/rest';
import { exchangeWebFlowCode, refreshToken as refreshOAuthToken } from '@octokit/oauth-methods';
import { hasValue, TimeMs } from '@hawk.so/utils';
import { normalizeGitHubPrivateKey } from './normalizePrivateKey';
import type {
  GitHubServiceConfig,
  GitHubUser,
  Installation,
  Repository,
  IssueData,
  GitHubIssue,
  OAuthTokens,
  ValidateUserTokenResult
} from './types';

/**
 * Buffer time before token expiration to trigger refresh (5 minutes)
 */
// eslint-disable-next-line @typescript-eslint/no-magic-numbers
const TOKEN_REFRESH_BUFFER_MS = 5 * TimeMs.Minute;

/**
 * Error object with optional HTTP status (e.g. from Octokit request failure).
 */
/* eslint-disable-next-line jsdoc/require-jsdoc */
type ErrorWithStatus = { status?: number };

/**
 * Service for interacting with GitHub API
 */
export class GitHubService {
  // eslint-disable-next-line @typescript-eslint/naming-convention, @typescript-eslint/no-magic-numbers
  private static readonly DEFAULT_TIMEOUT = 10 * TimeMs.Second;
  // eslint-disable-next-line @typescript-eslint/naming-convention
  private static readonly JWT_EXPIRATION_MINUTES = 10;

  /**
   * GitHub App ID; used to sign JWTs and identify the app in API requests.
   */
  private readonly appId: string;

  /**
   * PEM private key for the GitHub App; used to sign JWTs for app and installation auth.
   */
  private readonly privateKey: string;

  /**
   * App slug (URL name); used in installation and OAuth URLs (e.g. github.com/apps/{appSlug}/installations/new).
   */
  private readonly appSlug: string;

  /**
   * OAuth App client ID; required for exchanging codes and refreshing user tokens.
   */
  private readonly clientId?: string;

  /**
   * OAuth App client secret; required for exchanging codes and refreshing user tokens.
   */
  private readonly clientSecret?: string;

  /**
   * Base URL of the API; used for OAuth redirect URLs and when not using public GitHub.
   */
  private readonly apiUrl?: string;

  /**
   * Whether to emit debug logs.
   */
  private readonly logs: boolean;

  /**
   * Creates a GitHubService instance.
   * @param config - App credentials and optional OAuth/API settings (e.g. from env).
   */
  constructor(config: GitHubServiceConfig) {
    if (!hasValue(config.appId)) {
      throw new Error('appId is required');
    }

    if (!hasValue(config.privateKey)) {
      throw new Error('privateKey is required');
    }

    this.appId = config.appId;
    this.privateKey = normalizeGitHubPrivateKey(config.privateKey);
    this.appSlug = hasValue(config.appSlug) ? config.appSlug : 'hawk-tracker';
    this.clientId = config.clientId;
    this.clientSecret = config.clientSecret;
    this.apiUrl = config.apiUrl;
    this.logs = config.logs !== false;
  }

  /**
   * Returns the GitHub App installation URL for the given state.
   * @param state - Opaque state string to pass through the OAuth flow.
   * @returns Full URL to start the app installation flow.
   */
  public getInstallationUrl(state: string): string {
    if (!hasValue(this.apiUrl)) {
      throw new Error('apiUrl is required for getInstallationUrl (pass it in constructor config)');
    }

    const redirectUrl = `${this.apiUrl}/integration/github/oauth`;

    return `https://github.com/apps/${this.appSlug}/installations/new?state=${encodeURIComponent(state)}&redirect_url=${encodeURIComponent(redirectUrl)}`;
  }

  /**
   * Uninstalls the GitHub App from the given installation.
   * @param installationId - GitHub App installation ID.
   */
  public async deleteInstallation(installationId: string): Promise<void> {
    const token = this.createJWT();
    const octokit = this.createOctokit(token);

    await octokit.rest.apps.deleteInstallation({
      // eslint-disable-next-line @typescript-eslint/naming-convention
      installation_id: parseInt(installationId, 10),
    });
  }

  /**
   * Fetches installation metadata for the given installation ID.
   * @param installationId - GitHub App installation ID.
   * @returns Installation details (id, account, target_type, permissions).
   */
  public async getInstallationForRepository(installationId: string): Promise<Installation> {
    const token = this.createJWT();
    const octokit = this.createOctokit(token);

    try {
      const { data } = await octokit.rest.apps.getInstallation({
        // eslint-disable-next-line @typescript-eslint/naming-convention
        installation_id: parseInt(installationId, 10),
      });

      let accountLogin = '';
      let accountType = '';

      if (data.account) {
        if ('login' in data.account) {
          accountLogin = data.account.login;
          accountType = 'login' in data.account && 'type' in data.account ? data.account.type : 'User';
        } else if ('slug' in data.account) {
          accountLogin = data.account.slug;
          accountType = 'Organization';
        }
      }

      return {
        id: data.id,
        account: {
          login: accountLogin,
          type: accountType,
        },
        // eslint-disable-next-line @typescript-eslint/naming-convention
        target_type: data.target_type,
        permissions: data.permissions ?? {},
      };
    } catch (error) {
      throw new Error(`Failed to get installation: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Lists repositories accessible to the given installation, sorted by last updated.
   * @param installationId - GitHub App installation ID.
   * @returns Array of repository summaries.
   */
  public async getRepositoriesForInstallation(installationId: string): Promise<Repository[]> {
    if (!hasValue(installationId)) {
      throw new Error('installationId is required for getting repositories');
    }

    const accessToken = await this.createInstallationToken(installationId);
    const octokit = this.createOctokit(accessToken);

    try {
      const jwtToken = this.createJWT();
      const jwtOctokit = this.createOctokit(jwtToken);

      const installationInfo = await jwtOctokit.rest.apps.getInstallation({
        // eslint-disable-next-line @typescript-eslint/naming-convention
        installation_id: parseInt(installationId, 10),
      });

      this.log('Installation info:', {
        id: installationInfo.data.id,
        account: installationInfo.data.account,
        // eslint-disable-next-line @typescript-eslint/naming-convention
        target_type: installationInfo.data.target_type,
        // eslint-disable-next-line @typescript-eslint/naming-convention
        repository_selection: installationInfo.data.repository_selection,
      });

      const repositoriesData = await octokit.paginate(
        octokit.rest.apps.listReposAccessibleToInstallation,
        {
          // eslint-disable-next-line @typescript-eslint/naming-convention
          installation_id: parseInt(installationId, 10),
          // eslint-disable-next-line @typescript-eslint/naming-convention
          per_page: 100,
        }
      );

      this.log(`Total repositories fetched: ${repositoriesData.length}`);

      const repositories = repositoriesData.map(repo => ({
        id: repo.id.toString(),
        name: repo.name,
        fullName: repo.full_name,
        private: repo.private || false,
        htmlUrl: repo.html_url,
        updatedAt: hasValue(repo.updated_at) ? new Date(repo.updated_at) : new Date(0),
        language: hasValue(repo.language) ? repo.language : null,
      }));

      return repositories.sort((a, b) => b.updatedAt.getTime() - a.updatedAt.getTime());
    } catch (error) {
      throw new Error(`Failed to get repositories: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Creates a GitHub issue in the given repository using installation access.
   * @param repoFullName - Repository in "owner/repo" format.
   * @param installationId - GitHub App installation ID (required).
   * @param issueData - Issue title, body, and optional labels.
   * @returns Created issue (number, html_url, title, state).
   */
  public async createIssue(
    repoFullName: string,
    installationId: string | null,
    issueData: IssueData
  ): Promise<GitHubIssue> {
    const [owner, repo] = repoFullName.split('/');

    if (!hasValue(owner) || !hasValue(repo)) {
      throw new Error(`Invalid repository name format: ${repoFullName}. Expected format: owner/repo`);
    }

    if (!hasValue(installationId)) {
      throw new Error('installationId is required for creating GitHub issues');
    }

    const accessToken = await this.createInstallationToken(installationId);
    const octokit = this.createOctokit(accessToken);

    try {
      const { data } = await octokit.rest.issues.create({
        owner,
        repo,
        title: issueData.title,
        body: issueData.body,
        labels: issueData.labels,
      });

      return {
        number: data.number,
        // eslint-disable-next-line @typescript-eslint/naming-convention
        html_url: data.html_url,
        title: data.title,
        state: data.state,
      };
    } catch (error) {
      throw new Error(`Failed to create issue: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Assigns the Copilot coding agent (copilot-swe-agent) to the given issue via GraphQL.
   * @param repoFullName - Repository in "owner/repo" format.
   * @param issueNumber - Number of the issue in the repository.
   * @param delegatedUserToken - User access token with repo scope (e.g. from OAuth).
   */
  public async assignCopilot(
    repoFullName: string,
    issueNumber: number,
    delegatedUserToken: string
  ): Promise<void> {
    const [owner, repo] = repoFullName.split('/');

    if (!owner || !repo) {
      throw new Error(`Invalid repository name format: ${repoFullName}. Expected format: owner/repo`);
    }

    const octokit = this.createOctokit(delegatedUserToken);

    try {
      const suggestedActorsLimit = 100;
      const repoInfoQuery = `
        query($owner: String!, $name: String!, $issueNumber: Int!) {
          repository(owner: $owner, name: $name) {
            id
            issue(number: $issueNumber) {
              id
            }
            suggestedActors(capabilities: [CAN_BE_ASSIGNED], first: ${suggestedActorsLimit}) {
              nodes {
                login
                __typename
                ... on Bot {
                  id
                }
                ... on User {
                  id
                }
              }
            }
          }
        }
      `;

      /** GraphQL response shape for repository + issue + suggestedActors query. */
      type RepoInfoGraphQLResponse = {
        /* eslint-disable jsdoc/require-jsdoc */
        repository?: {
          id: string;
          issue?: { id: string };
          suggestedActors: {
            nodes: Array<{
              login: string;
              // eslint-disable-next-line @typescript-eslint/naming-convention
              __typename?: string;
              id?: string;
            }>;
          };
        };
        /* eslint-enable jsdoc/require-jsdoc */
      };

      const repoInfo = await octokit.graphql<RepoInfoGraphQLResponse>(repoInfoQuery, {
        owner,
        name: repo,
        issueNumber,
      });

      this.log('[GitHub API] Repository info query response:', JSON.stringify(repoInfo, null, 2));

      const repositoryId = repoInfo?.repository?.id;
      const issueId = repoInfo?.repository?.issue?.id;

      if (!hasValue(repositoryId)) {
        throw new Error(`Failed to get repository ID for ${repoFullName}`);
      }

      if (!hasValue(issueId)) {
        throw new Error(`Failed to get issue ID for issue #${issueNumber}`);
      }

      /** Node in suggestedActors (login, optional __typename and id). */
      /* eslint-disable jsdoc/require-jsdoc */
      type SuggestedActorNode = {
        login: string;
        // eslint-disable-next-line @typescript-eslint/naming-convention
        __typename?: string;
        id?: string ;
      };
      /* eslint-enable jsdoc/require-jsdoc */

      let copilotBot = (repoInfo?.repository?.suggestedActors?.nodes ?? []).find(
        (node: SuggestedActorNode) => node.login === 'copilot-swe-agent'
      );

      this.log(
        '[GitHub API] Copilot bot found in suggestedActors:',
        copilotBot
          ? {
              login: copilotBot.login,
              id: copilotBot.id,
            }
          : 'not found'
      );

      if (!hasValue(copilotBot) || !hasValue(copilotBot?.id)) {
        this.log('[GitHub API] Trying to get Copilot bot directly by login...');

        try {
          const copilotBotQuery = `
            query($login: String!) {
              user(login: $login) {
                id
                login
                __typename
              }
            }
          `;

          /** GraphQL response shape for user(login) query. */
          /* eslint-disable jsdoc/require-jsdoc */
          type CopilotUserInfoGraphQLResponse = {
            user?: {
              id: string;
              login: string;
              // eslint-disable-next-line @typescript-eslint/naming-convention
              __typename?: string;
            };
          };
          /* eslint-enable jsdoc/require-jsdoc */

          const copilotUserInfo = await octokit.graphql<CopilotUserInfoGraphQLResponse>(copilotBotQuery, {
            login: 'copilot-swe-agent',
          });

          this.log('[GitHub API] Direct Copilot bot query response:', JSON.stringify(copilotUserInfo, null, 2));

          if (hasValue(copilotUserInfo?.user?.id)) {
            copilotBot = {
              login: copilotUserInfo.user.login,
              id: copilotUserInfo.user.id,
            };
          }
        } catch (directQueryError) {
          this.log('[GitHub API] Failed to get Copilot bot directly:', directQueryError);
        }
      }

      if (!hasValue(copilotBot) || !hasValue(copilotBot?.id)) {
        throw new Error('Copilot coding agent (copilot-swe-agent) is not available for this repository');
      }

      this.log('[GitHub API] Using Copilot bot:', {
        login: copilotBot.login,
        id: copilotBot.id,
      });

      const assignCopilotMutation = `
        mutation($issueId: ID!, $assigneeIds: [ID!]!) {
          addAssigneesToAssignable(input: {
            assignableId: $issueId
            assigneeIds: $assigneeIds
          }) {
            assignable {
              ... on Issue {
                id
                number
                assignees(first: 10) {
                  nodes {
                    login
                  }
                }
              }
              ... on PullRequest {
                id
                number
                assignees(first: 10) {
                  nodes {
                    login
                  }
                }
              }
            }
          }
        }
      `;

      /** GraphQL response shape for addAssigneesToAssignable mutation. */
      /* eslint-disable jsdoc/require-jsdoc */
      type AssignCopilotGraphQLResponse = {
        addAssigneesToAssignable?: {
          assignable?: {
            id: string;
            number: number;
            assignees?: { nodes?: Array<{ login: string }> };
          };
        };
      };
      /* eslint-enable jsdoc/require-jsdoc */

      const response = await octokit.graphql<AssignCopilotGraphQLResponse>(assignCopilotMutation, {
        issueId,
        assigneeIds: [copilotBot.id],
      });

      this.log('[GitHub API] Assign Copilot mutation response:', JSON.stringify(response, null, 2));

      const assignable = response?.addAssigneesToAssignable?.assignable;

      if (!assignable) {
        throw new Error('Failed to assign Copilot to issue');
      }

      /* eslint-disable-next-line jsdoc/require-jsdoc */
      const assignedLogins = assignable.assignees?.nodes?.map((n: { login: string }) => n.login) || [];

      this.log(`[GitHub API] Issue assignees after mutation:`, assignedLogins);

      const assignedNumber = assignable.number;

      if (assignedLogins.includes('copilot-swe-agent')) {
        this.log(`[GitHub API] Successfully assigned Copilot to issue #${assignedNumber}`);
      } else {
        this.log(`[GitHub API] Copilot assignment mutation completed for issue #${assignedNumber}, but assignees list not yet updated in response`);
      }
    } catch (error) {
      throw new Error(`Failed to assign Copilot: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Returns a valid access token, refreshing it if expired or near expiry.
   * Used by workers when assigning Copilot with delegated user token.
   * @param tokenInfo - Current access/refresh tokens and their expiry dates.
   * @param onRefresh - Optional callback invoked when tokens are refreshed (e.g. to persist).
   * @returns Valid access token string.
   */
  public async getValidAccessToken(
    /* eslint-disable jsdoc/require-jsdoc */
    tokenInfo: {
      accessToken: string;
      refreshToken: string;
      accessTokenExpiresAt: Date | null;
      refreshTokenExpiresAt: Date | null;
    },
    onRefresh?: (newTokens: OAuthTokens) => Promise<void>
    /* eslint-enable jsdoc/require-jsdoc */
  ): Promise<string> {
    const now = new Date();

    if (tokenInfo.accessTokenExpiresAt) {
      const timeUntilExpiration = tokenInfo.accessTokenExpiresAt.getTime() - now.getTime();

      if (timeUntilExpiration <= TOKEN_REFRESH_BUFFER_MS) {
        if (!hasValue(tokenInfo.refreshToken)) {
          throw new Error('Access token expired and no refresh token available');
        }

        if (tokenInfo.refreshTokenExpiresAt && tokenInfo.refreshTokenExpiresAt <= now) {
          throw new Error('Refresh token is expired');
        }

        if (!hasValue(this.clientId) || !hasValue(this.clientSecret)) {
          throw new Error('GITHUB_APP_CLIENT_ID and GITHUB_APP_CLIENT_SECRET are required for token refresh');
        }

        const newTokens = await this.refreshUserToken(tokenInfo.refreshToken);

        if (onRefresh) {
          await onRefresh(newTokens);
        }

        return newTokens.accessToken;
      }
    }

    return tokenInfo.accessToken;
  }

  /**
   * Exchanges an OAuth authorization code for access and refresh tokens.
   * @param code - Authorization code from GitHub OAuth callback.
   * @param redirectUri - Redirect URI used in the OAuth request (defaults to apiUrl + /integration/github/oauth).
   * @returns Access token, refresh token, expiry dates, and authenticated user.
   */
  /* eslint-disable jsdoc/require-jsdoc */
  public async exchangeOAuthCodeForToken(
    code: string,
    redirectUri?: string
  ): Promise<{
    accessToken: string;
    refreshToken: string;
    expiresAt: Date | null;
    refreshTokenExpiresAt: Date | null;
    user: GitHubUser;
  }> {
  /* eslint-enable jsdoc/require-jsdoc */
    if (!hasValue(this.clientId) || !hasValue(this.clientSecret)) {
      throw new Error('GITHUB_APP_CLIENT_ID and GITHUB_APP_CLIENT_SECRET are required for OAuth token exchange');
    }

    try {
      if (!hasValue(redirectUri)) {
        if (!hasValue(this.apiUrl)) {
          throw new Error('apiUrl is required for exchangeOAuthCodeForToken when redirectUri is not provided (pass it in constructor config)');
        }
        redirectUri = `${this.apiUrl}/integration/github/oauth`;
      }

      const { authentication } = await exchangeWebFlowCode({
        clientType: 'github-app',
        clientId: this.clientId,
        clientSecret: this.clientSecret,
        code,
        redirectUrl: redirectUri,
      });

      if (!authentication.token) {
        throw new Error('No access token in OAuth response');
      }

      const accessToken = authentication.token;
      const refreshToken = 'refreshToken' in authentication && authentication.refreshToken
        ? authentication.refreshToken
        : '';
      const expiresAt = 'expiresAt' in authentication && authentication.expiresAt
        ? new Date(authentication.expiresAt)
        : null;
      const refreshTokenExpiresAt = 'refreshTokenExpiresAt' in authentication && authentication.refreshTokenExpiresAt
        ? new Date(authentication.refreshTokenExpiresAt)
        : null;

      const octokit = this.createOctokit(accessToken);
      const { data: userData } = await octokit.rest.users.getAuthenticated();

      return {
        accessToken,
        refreshToken,
        expiresAt,
        refreshTokenExpiresAt,
        user: {
          id: userData.id,
          login: userData.login,
        },
      };
    } catch (error) {
      throw new Error(`Failed to exchange OAuth code for token: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Checks whether a user access token is valid and returns user info if so.
   * @param accessToken - GitHub user access token (e.g. from OAuth).
   * @returns valid, optional user (id, login), and status ('active' or 'revoked').
   */
  public async validateUserToken(accessToken: string): Promise<ValidateUserTokenResult> {
    try {
      const octokit = this.createOctokit(accessToken);
      const { data: userData } = await octokit.rest.users.getAuthenticated();

      return {
        valid: true,
        user: {
          id: userData.id,
          login: userData.login,
        },
        status: 'active',
      };
    } catch (error: unknown) {
      const err = error as ErrorWithStatus;

      /** HTTP 401 Unauthorized */
      const HTTP_UNAUTHORIZED = 401;
      /** HTTP 403 Forbidden */
      const HTTP_FORBIDDEN = 403;

      if (err?.status === HTTP_UNAUTHORIZED || err?.status === HTTP_FORBIDDEN) {
        return {
          valid: false,
          status: 'revoked',
        };
      }
      throw new Error(`Failed to validate user token: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Refreshes a user OAuth token using the refresh token.
   * @param refreshToken - Current refresh token.
   * @returns New access token, refresh token, and expiry dates.
   */
  public async refreshUserToken(refreshToken: string): Promise<OAuthTokens> {
    if (!hasValue(this.clientId) || !hasValue(this.clientSecret)) {
      throw new Error('GITHUB_APP_CLIENT_ID and GITHUB_APP_CLIENT_SECRET are required for token refresh');
    }

    try {
      const { authentication } = await refreshOAuthToken({
        clientType: 'github-app',
        clientId: this.clientId,
        clientSecret: this.clientSecret,
        refreshToken,
      });

      if (!authentication.token) {
        throw new Error('No access token in refresh response');
      }

      const newRefreshToken = 'refreshToken' in authentication
        ? authentication.refreshToken || refreshToken
        : refreshToken;

      return {
        accessToken: authentication.token,
        refreshToken: newRefreshToken,
        expiresAt: 'expiresAt' in authentication && authentication.expiresAt
          ? new Date(authentication.expiresAt)
          : null,
        refreshTokenExpiresAt: 'refreshTokenExpiresAt' in authentication && authentication.refreshTokenExpiresAt
          ? new Date(authentication.refreshTokenExpiresAt)
          : null,
      };
    } catch (error) {
      throw new Error(`Failed to refresh user token: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Logs a message when logs are enabled.
   * @param args - Arguments passed to console.log.
   */
  private log(...args: unknown[]): void {
    if (this.logs) {
      console.log('[GitHubService]', ...args);
    }
  }

  /**
   * Creates an Octokit client with the given auth token and default timeout/headers.
   * @param auth - GitHub token (JWT or user access token).
   * @returns Octokit instance.
   */
  private createOctokit(auth: string): Octokit {
    return new Octokit({
      auth,
      request: {
        timeout: GitHubService.DEFAULT_TIMEOUT,
        headers: {
          // eslint-disable-next-line @typescript-eslint/naming-convention
          'GraphQL-Features': 'issues_copilot_assignment_api_support',
        },
      },
    });
  }

  /**
   * Creates a JWT for GitHub App authentication (installation/auth as app).
   * @returns Signed JWT string.
   */
  private createJWT(): string {
    const privateKey = this.privateKey;
    const now = Math.floor(Date.now() / TimeMs.Second);

    const payload = {
      iat: now - TimeMs.Minute / TimeMs.Second,
      exp: now + GitHubService.JWT_EXPIRATION_MINUTES * (TimeMs.Minute / TimeMs.Second),
      iss: this.appId,
    };

    return jwt.sign(payload, privateKey, { algorithm: 'RS256' });
  }

  /**
   * Creates an installation access token for the given installation ID.
   * @param installationId - GitHub App installation ID.
   * @returns Installation access token string.
   */
  private async createInstallationToken(installationId: string): Promise<string> {
    const token = this.createJWT();
    const octokit = this.createOctokit(token);

    try {
      const { data } = await octokit.rest.apps.createInstallationAccessToken({
        // eslint-disable-next-line @typescript-eslint/naming-convention
        installation_id: parseInt(installationId, 10),
      });

      return data.token;
    } catch (error) {
      throw new Error(`Failed to create installation token: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
}
