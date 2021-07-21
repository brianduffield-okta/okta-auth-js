/* eslint-disable @typescript-eslint/no-explicit-any */
// import { OktaAuth } from '@okta/okta-auth-js';
import tokens from '@okta/test.support/tokens';
import { OktaAuth } from '../../../lib';
import { AuthApiError, AuthSdkError, OAuthError } from '../../../lib/errors';
import { TokenManager } from '../../../lib/TokenManager';

const Emitter = require('tiny-emitter');

describe('TokenManager renew', () => {
  let testContext;

  beforeEach(function() {
    const emitter = new Emitter();
    const tokenStorage = {
        getStorage: jest.fn().mockImplementation(() => testContext.storage),
        setStorage: jest.fn().mockImplementation(() => {})
    };
    const sdkMock = {
      options: {},
      token: {
        renew: () => Promise.resolve(testContext.freshToken)
      },
      storageManager: {
        getTokenStorage: jest.fn().mockReturnValue(tokenStorage),
      },
      emitter
    };

    const instance = new TokenManager(sdkMock as any);
    jest.spyOn(instance, 'remove').mockImplementation(() => {});
    jest.spyOn(instance, 'add').mockImplementation(() => {});
    jest.spyOn(instance, 'emitRenewed').mockImplementation(() => {});
    jest.spyOn(instance, 'emitError').mockImplementation(() => {});
    
    const foo = {};
    const bar = {};
    const storage = {
      foo,
      bar
    };

    testContext = {
      sdkMock,
      tokenStorage,
      storage,
      instance,
      oldToken: foo,
      freshToken: {
        idToken: true
      }
    };
    
  });

  it('returns the fresh token', async () => {
    const res = await testContext.instance.renew('foo');
    expect(res).toBe(testContext.freshToken);
  });

  it('removes the old token from storage', async () => {
    await testContext.instance.renew('foo');
    expect(testContext.instance.remove).toHaveBeenCalledWith('foo');
  });

  it('adds the new token to storage', async () => {
    await testContext.instance.renew('foo');
    expect(testContext.instance.add).toHaveBeenCalledWith('foo', testContext.freshToken);
  });

  it('emits a renewed event', async () => {
    await testContext.instance.renew('foo');
    expect(testContext.instance.emitRenewed).toHaveBeenCalledWith('foo', testContext.freshToken, testContext.oldToken);
  });

  it('multiple token renew operations should produce consistent results', async () => {
    const authClient = new OktaAuth({
      pkce: false,
      issuer: 'https://auth-js-test.okta.com',
      clientId: 'NPSfOkH5eZrTy8PMDlvx',
      redirectUri: 'https://example.com/redirect',
      tokenManager: {
        autoRenew: false,
        storage: 'memory' // use memory as mock storage
      }
    });
    const expiredTokens = {
      idToken: { 
        ...tokens.standardIdTokenParsed, 
        expired: true
      },
      accessToken: { 
        ...tokens.standardAccessTokenParsed, 
        expired: true
      }
    }
    const freshTokens = {
      idToken: { ...tokens.standardIdTokenParsed },
      accessToken: { ...tokens.standardAccessTokenParsed }
    };
    // preset expired tokens in storage
    const tokenStorage = authClient.storageManager.getTokenStorage();
    tokenStorage.setStorage(expiredTokens);
    jest.spyOn(authClient.token, 'renew').mockImplementation((token) => {
      const type = authClient.tokenManager.getTokenType(token);
      return Promise.resolve(freshTokens[type]);
    });
    jest.spyOn(authClient.tokenManager, 'hasExpired').mockImplementation(token => !!token.expired);
    const handler = jest.fn();
    authClient.authStateManager.subscribe(handler);

    await authClient.tokenManager.renew('idToken'),
    await authClient.tokenManager.renew('accessToken')

    expect(handler).toHaveBeenCalledTimes(2);
    expect(handler).toHaveBeenNthCalledWith(1, {
      accessToken: freshTokens.accessToken,
      idToken: freshTokens.idToken,
      isAuthenticated: true
    });
    expect(handler).toHaveBeenNthCalledWith(2, {
      accessToken: freshTokens.accessToken,
      idToken: freshTokens.idToken,
      isAuthenticated: true
    });
  });

  describe('error handling', () => {
    beforeEach(() => {
      jest.spyOn(testContext.sdkMock.token, 'renew').mockImplementation(() => Promise.reject(testContext.error));
    });

    it('OAuthError', async () => {
      testContext.error = new OAuthError('does not matter', 'also not important');
      try {
        await testContext.instance.renew('foo');
      } catch (e) {
        expect(e).toMatchObject({
          name: 'OAuthError'
        });
      }
      expect(testContext.instance.remove).toHaveBeenCalledWith('foo');
      expect(testContext.instance.emitError).toHaveBeenCalledWith(testContext.error);
      expect(testContext.error.tokenKey).toBe('foo');
    });

    it('AuthSdkError', async () => {
      testContext.error = new AuthSdkError('does not matter');
      try {
        await testContext.instance.renew('foo');
      } catch (e) {
        expect(e).toMatchObject({
          name: 'AuthSdkError'
        });
      }
      expect(testContext.instance.remove).toHaveBeenCalledWith('foo');
      expect(testContext.instance.emitError).toHaveBeenCalledWith(testContext.error);
      expect(testContext.error.tokenKey).toBe('foo');
    });

    it('Refresh token error', async () => {
      testContext.error = new AuthApiError({
        errorSummary: 'does not matter'
      }, {
        status: 400,
        responseText: 'does not matter',
        responseJSON: {
          error: 'invalid_grant'
        }
      });
      try {
        await testContext.instance.renew('foo');
      } catch (e) {
        expect(e).toMatchObject({
          name: 'AuthApiError'
        });
      }
      expect(testContext.instance.remove).toHaveBeenCalledWith('foo');
      expect(testContext.instance.emitError).toHaveBeenCalledWith(testContext.error);
      expect(testContext.error.tokenKey).toBe('foo');
    });

  });

});