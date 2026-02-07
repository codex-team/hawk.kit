import type { Endpoints } from '@octokit/types';

/**
 * Parameters for creating a GitHub Issue.
 * Extracted from Octokit types for POST /repos/{owner}/{repo}/issues.
 */
export type IssueData = Pick<
  Endpoints['POST /repos/{owner}/{repo}/issues']['parameters'],
  'title' | 'body' | 'labels'
>;

/**
 * GitHub Issue as returned by the API.
 * Extracted from Octokit types for POST /repos/{owner}/{repo}/issues response.
 */
export type GitHubIssue = Pick<
  Endpoints['POST /repos/{owner}/{repo}/issues']['response']['data'],
  'number' | 'html_url' | 'title' | 'state'
>;

/**
 * GitHub Repository data.
 * Ephemeral data, not stored in database.
 */
export type Repository = {
  /** Repository ID (node_id). */
  id: string;
  /** Repository name without owner. */
  name: string;
  /** Full name "owner/name". */
  fullName: string;
  /** Whether the repository is private. */
  private: boolean;
  /** URL of the repository on GitHub. */
  htmlUrl: string;
  /** Last update time. */
  updatedAt: Date;
  /** Primary language or null if unknown. */
  language: string | null;
};

/**
 * GitHub App Installation as returned by the API.
 */
export type Installation = {
  /** Installation ID. */
  id: number;
  /** Account where the app is installed. */
  account: {
    /** GitHub username or org login. */
    login: string;
    /** Account type (e.g. "User", "Organization"). */
    type: string;
  };
  /** Target type of the installation (e.g. "User", "Organization"). */
  // eslint-disable-next-line @typescript-eslint/naming-convention
  target_type: string;
  /** Permissions granted to the app (scope -> access level). */
  permissions: Record<string, string>;
};

/**
 * OAuth access and refresh tokens with expiry dates.
 * Returned by refreshUserToken and passed to onRefresh when getValidAccessToken refreshes tokens.
 */
export type OAuthTokens = {
  /** GitHub user access token for API calls. */
  accessToken: string;
  /** Refresh token used to obtain a new access token when it expires. */
  refreshToken: string;
  /** When the access token expires, or null if unknown. */
  expiresAt: Date | null;
  /** When the refresh token expires, or null if unknown. */
  refreshTokenExpiresAt: Date | null;
};

/**
 * Configuration for GitHubService.
 * Values should be read from env by the caller (API, Workers) and passed in.
 */
export interface GitHubServiceConfig {
  /** GitHub App ID. */
  appId: string;
  /** PEM private key for the GitHub App. */
  privateKey: string;
  /** App slug (URL name). Defaults to "hawk-tracker" if omitted. */
  appSlug?: string;
  /** OAuth App client ID for user login flow. */
  clientId?: string;
  /** OAuth App client secret for user login flow. */
  clientSecret?: string;
  /** Base URL of the API (e.g. for GitHub Enterprise). */
  apiUrl?: string;
  /** Whether to emit debug logs. Defaults to true. */
  logs?: boolean;
}

/**
 * Fields that we use from the GitHub user identity.
 */
export type GitHubUser = {
  /** GitHub user ID. */
  id: number;
  /** GitHub username (login). */
  login: string;
};

/**
 * Whether a user access token is still valid and the authenticated user (or revocation status).
 */
export type ValidateUserTokenResult = {
  /** True if the token is valid and accepted by GitHub. */
  valid: boolean;
  /** Authenticated user (id, login) when valid. */
  user?: GitHubUser;
  /** 'active' when valid, 'revoked' when token was rejected (e.g. 401/403). */
  status: 'active' | 'revoked';
};
