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
  target_type: string;
  /** Permissions granted to the app (scope -> access level). */
  permissions: Record<string, string>;
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
}
