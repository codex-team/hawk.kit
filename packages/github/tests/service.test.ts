import { describe, it, expect, beforeEach, vi } from 'vitest';
import jwt from 'jsonwebtoken';
import { GitHubService } from '../src/service';

const mockOctokitRef = vi.hoisted(() => ({ current: null as Record<string, unknown> | null }));
const mockExchangeWebFlowCode = vi.fn();
const mockRefreshOAuthToken = vi.fn();

vi.mock('@octokit/rest', () => ({
  Octokit: vi.fn().mockImplementation(() => mockOctokitRef.current),
}));

vi.mock('@octokit/oauth-methods', () => ({
  exchangeWebFlowCode: (...args: unknown[]) => mockExchangeWebFlowCode(...args),
  refreshToken: (...args: unknown[]) => mockRefreshOAuthToken(...args),
}));

vi.mock('jsonwebtoken');

describe('GitHubService', () => {
  let githubService: GitHubService;
  const testAppId = '123456';
  const testAppSlug = 'hawk-tracker';
  const testPrivateKey = '-----BEGIN RSA PRIVATE KEY-----\nTEST_KEY\n-----END RSA PRIVATE KEY-----';
  const testClientId = 'Iv1.client-id';
  const testClientSecret = 'client-secret';
  const testInstallationId = '789012';
  const testApiUrl = 'https://api.example.com';

  let mockOctokit: {
    rest: {
      apps: {
        createInstallationAccessToken: ReturnType<typeof vi.fn>;
        getInstallation: ReturnType<typeof vi.fn>;
        deleteInstallation: ReturnType<typeof vi.fn>;
        listReposAccessibleToInstallation: ReturnType<typeof vi.fn>;
      };
      issues: {
        create: ReturnType<typeof vi.fn>;
        addAssignees: ReturnType<typeof vi.fn>;
      };
      users: {
        getAuthenticated: ReturnType<typeof vi.fn>;
      };
    };
    graphql: ReturnType<typeof vi.fn>;
    paginate: ReturnType<typeof vi.fn>;
  };

  const createMockOctokit = () => ({
    rest: {
      apps: {
        createInstallationAccessToken: vi.fn(),
        getInstallation: vi.fn(),
        deleteInstallation: vi.fn(),
        listReposAccessibleToInstallation: vi.fn(),
      },
      issues: {
        create: vi.fn(),
        addAssignees: vi.fn(),
      },
      users: {
        getAuthenticated: vi.fn(),
      },
    },
    graphql: vi.fn(),
    paginate: vi.fn(),
  });

  const getConfig = () => ({
    appId: testAppId,
    privateKey: testPrivateKey,
    appSlug: testAppSlug,
    clientId: testClientId,
    clientSecret: testClientSecret,
    apiUrl: testApiUrl,
  });

  beforeEach(() => {
    vi.clearAllMocks();

    mockOctokit = createMockOctokit();
    mockOctokitRef.current = mockOctokit;

    githubService = new GitHubService(getConfig());
  });

  describe('constructor', () => {
    it('should throw if appId is missing', () => {
      expect(() => {
        new GitHubService({
          ...getConfig(),
          appId: '',
        });
      }).toThrow('appId is required');
    });

    it('should throw if privateKey is missing', () => {
      expect(() => {
        new GitHubService({
          ...getConfig(),
          privateKey: '',
        });
      }).toThrow('privateKey is required');
    });
  });

  describe('getInstallationUrl', () => {
    it('should generate installation URL with state and redirect_url parameters url encoded', () => {
      const state = 'test-state-123';

      const url = githubService.getInstallationUrl(state);

      expect(url).toBe(
        `https://github.com/apps/${testAppSlug}/installations/new?state=${encodeURIComponent(state)}&redirect_url=${encodeURIComponent(`${testApiUrl}/integration/github/oauth`)}`
      );
    });

    it('should throw error if apiUrl is not provided in config', () => {
      const serviceWithoutApiUrl = new GitHubService({
        appId: testAppId,
        privateKey: testPrivateKey,
        appSlug: testAppSlug,
      });

      expect(() => {
        serviceWithoutApiUrl.getInstallationUrl('test-state');
      }).toThrow('apiUrl is required for getInstallationUrl (pass it in constructor config)');
    });
  });

  describe('getInstallationForRepository', () => {
    const mockJwtToken = 'mock-jwt-token';

    it('should get installation information for User account', async () => {
      vi.mocked(jwt.sign).mockImplementation(() => mockJwtToken);

      /* eslint-disable @typescript-eslint/camelcase, camelcase, @typescript-eslint/no-explicit-any */
      mockOctokit.rest.apps.getInstallation.mockResolvedValue({
        data: {
          id: 12345,
          account: {
            login: 'octocat',
            type: 'User',
            id: 1,
            node_id: 'MDQ6VXNlcjE=',
            avatar_url: 'https://github.com/images/error/octocat_happy.gif',
          },
          target_type: 'User',
          permissions: {
            issues: 'write',
            metadata: 'read',
          },
        },
      } as any);
      /* eslint-enable @typescript-eslint/camelcase, camelcase, @typescript-eslint/no-explicit-any */

      const result = await githubService.getInstallationForRepository(testInstallationId);

      expect(result).toEqual({
        id: 12345,
        account: {
          login: 'octocat',
          type: 'User',
        },
        target_type: 'User',
        permissions: {
          issues: 'write',
          metadata: 'read',
        },
      });

      expect(mockOctokit.rest.apps.getInstallation).toHaveBeenCalledWith({
        installation_id: parseInt(testInstallationId, 10),
      });
    });

    it('should get installation information for Organization account', async () => {
      vi.mocked(jwt.sign).mockImplementation(() => mockJwtToken);

      /* eslint-disable @typescript-eslint/camelcase, camelcase, @typescript-eslint/no-explicit-any */
      mockOctokit.rest.apps.getInstallation.mockResolvedValue({
        data: {
          id: 12345,
          account: {
            slug: 'my-org',
            type: 'Organization',
            id: 1,
            node_id: 'MDEyOk9yZ2FuaXphdGlvbjE=',
            avatar_url: 'https://github.com/images/error/octocat_happy.gif',
          },
          target_type: 'Organization',
          permissions: {
            issues: 'write',
            metadata: 'read',
          },
        },
      } as any);
      /* eslint-enable @typescript-eslint/camelcase, camelcase, @typescript-eslint/no-explicit-any */

      const result = await githubService.getInstallationForRepository(testInstallationId);

      expect(result).toEqual({
        id: 12345,
        account: {
          login: 'my-org',
          type: 'Organization',
        },
        target_type: 'Organization',
        permissions: {
          issues: 'write',
          metadata: 'read',
        },
      });
    });

    it('should throw error if request fails', async () => {
      vi.mocked(jwt.sign).mockImplementation(() => mockJwtToken);

      mockOctokit.rest.apps.getInstallation.mockRejectedValue(new Error('Network error'));

      await expect(
        githubService.getInstallationForRepository(testInstallationId)
      ).rejects.toThrow('Failed to get installation');
    });
  });

  describe('createIssue', () => {
    const mockJwtToken = 'mock-jwt-token';
    const mockInstallationToken = 'mock-installation-token';

    beforeEach(() => {
      vi.mocked(jwt.sign).mockImplementation(() => mockJwtToken);

      /* eslint-disable @typescript-eslint/camelcase, camelcase, @typescript-eslint/no-explicit-any */
      mockOctokit.rest.apps.createInstallationAccessToken.mockResolvedValue({
        data: {
          token: mockInstallationToken,
          expires_at: '2025-01-01T00:00:00Z',
        },
      } as any);
      /* eslint-enable @typescript-eslint/camelcase, camelcase, @typescript-eslint/no-explicit-any */
    });

    it('should create issue successfully', async () => {
      const issueData = {
        title: 'Test Issue',
        body: 'Test body',
        labels: ['bug'],
      };

      /* eslint-disable @typescript-eslint/camelcase, camelcase, @typescript-eslint/no-explicit-any */
      mockOctokit.rest.issues.create.mockResolvedValue({
        data: {
          number: 123,
          html_url: 'https://github.com/owner/repo/issues/123',
          title: 'Test Issue',
          state: 'open',
        },
      } as any);
      /* eslint-enable @typescript-eslint/camelcase, camelcase, @typescript-eslint/no-explicit-any */

      const result = await githubService.createIssue('owner/repo', testInstallationId, issueData);

      expect(result).toEqual({
        number: 123,
        html_url: 'https://github.com/owner/repo/issues/123',
        title: 'Test Issue',
        state: 'open',
      });

      expect(mockOctokit.rest.issues.create).toHaveBeenCalledWith({
        owner: 'owner',
        repo: 'repo',
        title: 'Test Issue',
        body: 'Test body',
        labels: ['bug'],
      });
    });

    it('should create issue without labels', async () => {
      const issueData = {
        title: 'Test Issue',
        body: 'Test body',
      };

      /* eslint-disable @typescript-eslint/camelcase, camelcase, @typescript-eslint/no-explicit-any */
      mockOctokit.rest.issues.create.mockResolvedValue({
        data: {
          number: 124,
          html_url: 'https://github.com/owner/repo/issues/124',
          title: 'Test Issue',
          state: 'open',
        },
      } as any);
      /* eslint-enable @typescript-eslint/camelcase, camelcase, @typescript-eslint/no-explicit-any */

      const result = await githubService.createIssue('owner/repo', testInstallationId, issueData);

      expect(result.number).toBe(124);
      expect(mockOctokit.rest.issues.create).toHaveBeenCalledWith({
        owner: 'owner',
        repo: 'repo',
        title: 'Test Issue',
        body: 'Test body',
        labels: undefined,
      });
    });

    it('should throw error for invalid repository name format', async () => {
      const issueData = {
        title: 'Test Issue',
        body: 'Test body',
      };

      await expect(
        githubService.createIssue('invalid-repo-name', testInstallationId, issueData)
      ).rejects.toThrow('Invalid repository name format: invalid-repo-name. Expected format: owner/repo');
    });

    it('should throw error if issue creation fails', async () => {
      const issueData = {
        title: 'Test Issue',
        body: 'Test body',
      };

      mockOctokit.rest.issues.create.mockRejectedValue(new Error('Repository not found'));

      await expect(
        githubService.createIssue('owner/repo', testInstallationId, issueData)
      ).rejects.toThrow('Failed to create issue');
    });
  });

  describe('assignCopilot', () => {
    const mockDelegatedUserToken = 'mock-delegated-user-token';

    it('should assign Copilot to issue successfully', async () => {
      const issueNumber = 123;

      mockOctokit.graphql
        .mockResolvedValueOnce({
          repository: {
            id: 'repo-123',
            issue: { id: 'issue-456' },
            suggestedActors: {
              nodes: [
                {
                  login: 'copilot-swe-agent',
                  __typename: 'Bot',
                  id: 'bot-789',
                },
              ],
            },
          },
        })
        .mockResolvedValueOnce({
          addAssigneesToAssignable: {
            assignable: {
              id: 'issue-456',
              number: issueNumber,
              assignees: { nodes: [] },
            },
          },
        });

      await githubService.assignCopilot('owner/repo', issueNumber, mockDelegatedUserToken);

      expect(mockOctokit.graphql).toHaveBeenCalledTimes(2);
    });

    it('should throw error if assignment fails', async () => {
      const issueNumber = 123;

      mockOctokit.graphql
        .mockResolvedValueOnce({
          repository: {
            id: 'repo-123',
            issue: { id: 'issue-456' },
            suggestedActors: {
              nodes: [
                {
                  login: 'copilot-swe-agent',
                  id: 'bot-789',
                },
              ],
            },
          },
        })
        .mockRejectedValue(new Error('Issue not found'));

      await expect(
        githubService.assignCopilot('owner/repo', issueNumber, mockDelegatedUserToken)
      ).rejects.toThrow('Failed to assign Copilot');
    });
  });

  describe('deleteInstallation', () => {
    const mockJwtToken = 'mock-jwt-token';

    it('should delete installation successfully', async () => {
      vi.mocked(jwt.sign).mockImplementation(() => mockJwtToken);
      mockOctokit.rest.apps.deleteInstallation.mockResolvedValue(undefined);

      await githubService.deleteInstallation(testInstallationId);

      expect(mockOctokit.rest.apps.deleteInstallation).toHaveBeenCalledWith({
        installation_id: parseInt(testInstallationId, 10),
      });
    });

    it('should throw error if delete fails', async () => {
      vi.mocked(jwt.sign).mockImplementation(() => mockJwtToken);
      mockOctokit.rest.apps.deleteInstallation.mockRejectedValue(new Error('Not found'));

      await expect(githubService.deleteInstallation(testInstallationId)).rejects.toThrow('Not found');
    });
  });

  describe('getRepositoriesForInstallation', () => {
    const mockJwtToken = 'mock-jwt-token';
    const mockInstallationToken = 'mock-installation-token';

    beforeEach(() => {
      vi.mocked(jwt.sign).mockImplementation(() => mockJwtToken);

      mockOctokit.rest.apps.createInstallationAccessToken.mockResolvedValue({
        data: { token: mockInstallationToken, expires_at: '2025-01-01T00:00:00Z' },
      } as any);

      mockOctokit.rest.apps.getInstallation.mockResolvedValue({
        data: { id: 12345, account: { login: 'test' }, target_type: 'User', repository_selection: 'all' },
      } as any);
    });

    it('should return repositories sorted by updatedAt desc', async () => {
      const reposData = [
        {
          id: 1,
          name: 'repo1',
          full_name: 'owner/repo1',
          private: false,
          html_url: 'https://github.com/owner/repo1',
          updated_at: '2024-01-02T00:00:00Z',
          language: 'TypeScript',
        },
        {
          id: 2,
          name: 'repo2',
          full_name: 'owner/repo2',
          private: true,
          html_url: 'https://github.com/owner/repo2',
          updated_at: '2024-01-03T00:00:00Z',
          language: null,
        },
      ];

      mockOctokit.paginate.mockResolvedValue(reposData);

      const result = await githubService.getRepositoriesForInstallation(testInstallationId);

      expect(result).toHaveLength(2);
      expect(result[0].name).toBe('repo2');
      expect(result[0].fullName).toBe('owner/repo2');
      expect(result[0].language).toBeNull();
      expect(result[1].name).toBe('repo1');
      expect(result[1].language).toBe('TypeScript');
    });

    it('should throw error if installationId is empty', async () => {
      await expect(githubService.getRepositoriesForInstallation('')).rejects.toThrow(
        'installationId is required for getting repositories'
      );
    });

    it('should throw error if paginate fails', async () => {
      mockOctokit.paginate.mockRejectedValue(new Error('API error'));

      await expect(
        githubService.getRepositoriesForInstallation(testInstallationId)
      ).rejects.toThrow('Failed to get repositories');
    });
  });

  describe('getValidAccessToken', () => {
    it('should return access token when not expired', async () => {
      const tokenInfo = {
        accessToken: 'valid-token',
        refreshToken: 'refresh-123',
        accessTokenExpiresAt: new Date(Date.now() + 10 * 60 * 1000),
        refreshTokenExpiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
      };

      const result = await githubService.getValidAccessToken(tokenInfo);

      expect(result).toBe('valid-token');
      expect(mockRefreshOAuthToken).not.toHaveBeenCalled();
    });

    it('should return access token when accessTokenExpiresAt is null', async () => {
      const tokenInfo = {
        accessToken: 'valid-token',
        refreshToken: 'refresh-123',
        accessTokenExpiresAt: null,
        refreshTokenExpiresAt: null,
      };

      const result = await githubService.getValidAccessToken(tokenInfo);

      expect(result).toBe('valid-token');
      expect(mockRefreshOAuthToken).not.toHaveBeenCalled();
    });

    it('should refresh token when expired and call onRefresh', async () => {
      const tokenInfo = {
        accessToken: 'expired-token',
        refreshToken: 'refresh-123',
        accessTokenExpiresAt: new Date(Date.now() - 1000),
        refreshTokenExpiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
      };

      const expiresAt = new Date(Date.now() + 60 * 60 * 1000);
      const refreshTokenExpiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);

      mockRefreshOAuthToken.mockResolvedValue({
        authentication: {
          token: 'new-access-token',
          refreshToken: 'new-refresh-token',
          expiresAt,
          refreshTokenExpiresAt,
        },
      });

      const onRefresh = vi.fn().mockResolvedValue(undefined);

      const result = await githubService.getValidAccessToken(tokenInfo, onRefresh);

      expect(result).toBe('new-access-token');
      expect(mockRefreshOAuthToken).toHaveBeenCalledWith(
        expect.objectContaining({ refreshToken: 'refresh-123' })
      );
      expect(onRefresh).toHaveBeenCalledWith({
        accessToken: 'new-access-token',
        refreshToken: 'new-refresh-token',
        expiresAt,
        refreshTokenExpiresAt,
      });
    });

    it('should throw when expired and no refresh token', async () => {
      const tokenInfo = {
        accessToken: 'expired-token',
        refreshToken: '',
        accessTokenExpiresAt: new Date(Date.now() - 1000),
        refreshTokenExpiresAt: null,
      };

      await expect(githubService.getValidAccessToken(tokenInfo)).rejects.toThrow(
        'Access token expired and no refresh token available'
      );
    });

    it('should throw when refresh token is expired', async () => {
      const tokenInfo = {
        accessToken: 'expired-token',
        refreshToken: 'refresh-123',
        accessTokenExpiresAt: new Date(Date.now() - 1000),
        refreshTokenExpiresAt: new Date(Date.now() - 1000),
      };

      await expect(githubService.getValidAccessToken(tokenInfo)).rejects.toThrow('Refresh token is expired');
    });

    it('should throw when clientId/clientSecret not set and refresh needed', async () => {
      const serviceWithoutOAuth = new GitHubService({
        appId: testAppId,
        privateKey: testPrivateKey,
        apiUrl: testApiUrl,
      });

      const tokenInfo = {
        accessToken: 'expired-token',
        refreshToken: 'refresh-123',
        accessTokenExpiresAt: new Date(Date.now() - 1000),
        refreshTokenExpiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
      };

      await expect(serviceWithoutOAuth.getValidAccessToken(tokenInfo)).rejects.toThrow(
        'GITHUB_APP_CLIENT_ID and GITHUB_APP_CLIENT_SECRET are required for token refresh'
      );
    });
  });

  describe('exchangeOAuthCodeForToken', () => {
    it('should exchange code for token successfully', async () => {
      mockExchangeWebFlowCode.mockResolvedValue({
        authentication: {
          token: 'access-token-123',
          refreshToken: 'refresh-token-456',
          expiresAt: '2025-12-31T23:59:59Z',
          refreshTokenExpiresAt: '2026-12-31T23:59:59Z',
        },
      });

      mockOctokit.rest.users.getAuthenticated.mockResolvedValue({
        data: { id: 42, login: 'testuser' },
      });

      const result = await githubService.exchangeOAuthCodeForToken('auth-code-xyz');

      expect(result).toEqual({
        accessToken: 'access-token-123',
        refreshToken: 'refresh-token-456',
        expiresAt: expect.any(Date),
        refreshTokenExpiresAt: expect.any(Date),
        user: { id: 42, login: 'testuser' },
      });
      expect(mockExchangeWebFlowCode).toHaveBeenCalledWith(
        expect.objectContaining({
          code: 'auth-code-xyz',
          clientId: testClientId,
          clientSecret: testClientSecret,
          redirectUrl: `${testApiUrl}/integration/github/oauth`,
        })
      );
    });

    it('should use provided redirectUri', async () => {
      mockExchangeWebFlowCode.mockResolvedValue({
        authentication: { token: 'token' },
      });
      mockOctokit.rest.users.getAuthenticated.mockResolvedValue({
        data: { id: 1, login: 'user' },
      });

      await githubService.exchangeOAuthCodeForToken('code', 'https://custom.com/oauth');

      expect(mockExchangeWebFlowCode).toHaveBeenCalledWith(
        expect.objectContaining({ redirectUrl: 'https://custom.com/oauth' })
      );
    });

    it('should throw when clientId/clientSecret not set', async () => {
      const serviceWithoutOAuth = new GitHubService({
        appId: testAppId,
        privateKey: testPrivateKey,
        apiUrl: testApiUrl,
      });

      await expect(
        serviceWithoutOAuth.exchangeOAuthCodeForToken('code')
      ).rejects.toThrow('GITHUB_APP_CLIENT_ID and GITHUB_APP_CLIENT_SECRET are required for OAuth token exchange');
    });

    it('should throw when apiUrl not set and redirectUri not provided', async () => {
      const serviceWithoutApiUrl = new GitHubService({
        appId: testAppId,
        privateKey: testPrivateKey,
        clientId: testClientId,
        clientSecret: testClientSecret,
      });

      await expect(
        serviceWithoutApiUrl.exchangeOAuthCodeForToken('code')
      ).rejects.toThrow('apiUrl is required for exchangeOAuthCodeForToken when redirectUri is not provided');
    });
  });

  describe('validateUserToken', () => {
    it('should return valid for valid token', async () => {
      mockOctokit.rest.users.getAuthenticated.mockResolvedValue({
        data: { id: 100, login: 'validuser' },
      });

      const result = await githubService.validateUserToken('valid-token');

      expect(result).toEqual({
        valid: true,
        user: { id: 100, login: 'validuser' },
        status: 'active',
      });
    });

    it('should return revoked for 401', async () => {
      const err = new Error('Unauthorized') as Error & { status?: number };
      err.status = 401;
      mockOctokit.rest.users.getAuthenticated.mockRejectedValue(err);

      const result = await githubService.validateUserToken('invalid-token');

      expect(result).toEqual({ valid: false, status: 'revoked' });
    });

    it('should return revoked for 403', async () => {
      const err = new Error('Forbidden') as Error & { status?: number };
      err.status = 403;
      mockOctokit.rest.users.getAuthenticated.mockRejectedValue(err);

      const result = await githubService.validateUserToken('forbidden-token');

      expect(result).toEqual({ valid: false, status: 'revoked' });
    });

    it('should throw for other errors', async () => {
      mockOctokit.rest.users.getAuthenticated.mockRejectedValue(new Error('Network error'));

      await expect(githubService.validateUserToken('token')).rejects.toThrow('Failed to validate user token');
    });
  });

  describe('refreshUserToken', () => {
    it('should refresh token successfully', async () => {
      mockRefreshOAuthToken.mockResolvedValue({
        authentication: {
          token: 'new-access-token',
          refreshToken: 'new-refresh-token',
          expiresAt: '2025-12-31T23:59:59Z',
          refreshTokenExpiresAt: '2026-12-31T23:59:59Z',
        },
      });

      const result = await githubService.refreshUserToken('old-refresh-token');

      expect(result).toEqual({
        accessToken: 'new-access-token',
        refreshToken: 'new-refresh-token',
        expiresAt: expect.any(Date),
        refreshTokenExpiresAt: expect.any(Date),
      });
      expect(mockRefreshOAuthToken).toHaveBeenCalledWith(
        expect.objectContaining({
          refreshToken: 'old-refresh-token',
          clientId: testClientId,
          clientSecret: testClientSecret,
        })
      );
    });

    it('should throw when clientId/clientSecret not set', async () => {
      const serviceWithoutOAuth = new GitHubService({
        appId: testAppId,
        privateKey: testPrivateKey,
      });

      await expect(serviceWithoutOAuth.refreshUserToken('refresh')).rejects.toThrow(
        'GITHUB_APP_CLIENT_ID and GITHUB_APP_CLIENT_SECRET are required for token refresh'
      );
    });
  });
});
