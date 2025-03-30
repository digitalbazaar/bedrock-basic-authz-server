/*!
 * Copyright (c) 2024-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as helpers from './helpers.js';
import {CapabilityAgent} from '@digitalbazaar/webkms-client';
import {zcapClient} from '@bedrock/basic-authz-server';

describe('http API', () => {
  const target = '/test-authorize-request';
  describe('authz request middleware', () => {
    let capability;
    let unauthorizedZcapClient;
    let url;
    before(async () => {
      const secret = '53ad64ce-8e1d-11ec-bb12-10bf48838a41';
      const handle = 'test';
      const capabilityAgent = await CapabilityAgent.fromSecret({
        secret, handle
      });
      unauthorizedZcapClient = helpers.createZcapClient({capabilityAgent});
      const rootInvocationTarget = bedrock.config.server.baseUri;
      url = `${rootInvocationTarget}${target}`;
      capability = `urn:zcap:root:${encodeURIComponent(rootInvocationTarget)}`;
    });

    const fixtures = [{
      name: 'GET',
      expectedAction: 'read',
      async authorizedZcap() {
        const result = await zcapClient.read({url, capability});
        return result.data;
      },
      async unauthorizedZcap() {
        const result = await unauthorizedZcapClient.read({url, capability});
        return result.data;
      },
      async oauth2({accessToken}) {
        const result = await helpers.doOAuth2Request({url, accessToken});
        return result.data;
      }
    }, {
      name: 'POST',
      expectedAction: 'write',
      async authorizedZcap() {
        const result = await zcapClient.write({
          url, json: {foo: 'bar'}, capability
        });
        return result.data;
      },
      async unauthorizedZcap() {
        const result = await unauthorizedZcapClient.write({
          url, json: {foo: 'bar'}, capability
        });
        return result.data;
      },
      async oauth2({accessToken}) {
        const result = await helpers.doOAuth2Request({
          url, json: {foo: 'bar'}, accessToken
        });
        return result.data;
      }
    }];
    for(const fixture of fixtures) {
      describe(fixture.name, () => {
        it('succeeds using an authorized zcap', async () => {
          let err;
          let result;
          try {
            result = await fixture.authorizedZcap();
          } catch(e) {
            err = e;
          }
          assertNoError(err);
          should.exist(result);
          result.should.deep.equal({success: true});
        });
        it('fails using an unauthorized zcap', async () => {
          let err;
          let result;
          try {
            result = await fixture.unauthorizedZcap();
          } catch(e) {
            err = e;
          }
          should.exist(err);
          should.not.exist(result);
          err.status.should.equal(403);
          err.data.type.should.equal('NotAllowedError');
        });
        it('succeeds using authorized access token', async () => {
          const accessToken = await helpers.createOAuth2AccessToken({
            action: fixture.expectedAction, target
          });
          let err;
          let result;
          try {
            result = await fixture.oauth2({accessToken});
          } catch(e) {
            err = e;
          }
          assertNoError(err);
          should.exist(result);
          result.should.deep.equal({success: true});
        });
        it('fails using an expired access token', async () => {
          const accessToken = await helpers.createOAuth2AccessToken({
            action: fixture.expectedAction, target,
            // expired 10 minutes ago
            exp: Math.floor(Date.now() / 1000 - 600)
          });
          let err;
          let result;
          try {
            result = await fixture.oauth2({accessToken});
          } catch(e) {
            err = e;
          }
          should.exist(err);
          should.not.exist(result);
          err.status.should.equal(403);
          err.data.type.should.equal('NotAllowedError');
          should.exist(err.data.cause);
          should.exist(err.data.cause.details);
          should.exist(err.data.cause.details.code);
          err.data.cause.details.code.should.equal('ERR_JWT_EXPIRED');
          should.exist(err.data.cause.details.claim);
          err.data.cause.details.claim.should.equal('exp');
        });
        it('fails using an access token w/future "nbf" claim', async () => {
          const accessToken = await helpers.createOAuth2AccessToken({
            action: fixture.expectedAction, target,
            // 10 minutes from now
            nbf: Math.floor(Date.now() / 1000 + 600)
          });
          let err;
          let result;
          try {
            result = await fixture.oauth2({accessToken});
          } catch(e) {
            err = e;
          }
          should.exist(err);
          should.not.exist(result);
          err.status.should.equal(403);
          err.data.type.should.equal('NotAllowedError');
          should.exist(err.data.cause);
          should.exist(err.data.cause.details);
          should.exist(err.data.cause.details.code);
          err.data.cause.details.code.should.equal(
            'ERR_JWT_CLAIM_VALIDATION_FAILED');
          should.exist(err.data.cause.details.claim);
          err.data.cause.details.claim.should.equal('nbf');
        });
        it('fails using an access token w/bad "typ" claim', async () => {
          const accessToken = await helpers.createOAuth2AccessToken({
            action: fixture.expectedAction, target,
            typ: 'unexpected'
          });
          let err;
          let result;
          try {
            result = await fixture.oauth2({accessToken});
          } catch(e) {
            err = e;
          }
          should.exist(err);
          should.not.exist(result);
          err.status.should.equal(403);
          err.data.type.should.equal('NotAllowedError');
          should.exist(err.data.cause);
          should.exist(err.data.cause.details);
          should.exist(err.data.cause.details.code);
          err.data.cause.details.code.should.equal(
            'ERR_JWT_CLAIM_VALIDATION_FAILED');
          should.exist(err.data.cause.details.claim);
          err.data.cause.details.claim.should.equal('typ');
        });
        it('fails using an access token w/bad "iss" claim', async () => {
          const accessToken = await helpers.createOAuth2AccessToken({
            action: fixture.expectedAction, target,
            iss: 'urn:example:unexpected'
          });
          let err;
          let result;
          try {
            result = await fixture.oauth2({accessToken});
          } catch(e) {
            err = e;
          }
          should.exist(err);
          should.not.exist(result);
          err.status.should.equal(403);
          err.data.type.should.equal('NotAllowedError');
          should.exist(err.data.cause);
          should.exist(err.data.cause.details);
          should.exist(err.data.cause.details.code);
          err.data.cause.details.code.should.equal(
            'ERR_JWT_CLAIM_VALIDATION_FAILED');
          should.exist(err.data.cause.details.claim);
          err.data.cause.details.claim.should.equal('iss');
        });
        it('fails using an access token w/bad action', async () => {
          const accessToken = await helpers.createOAuth2AccessToken({
            action: 'incorrect', target
          });
          let err;
          let result;
          try {
            result = await fixture.oauth2({accessToken});
          } catch(e) {
            err = e;
          }
          should.exist(err);
          should.not.exist(result);
          err.status.should.equal(403);
          err.data.type.should.equal('NotAllowedError');
          should.exist(err.data.cause);
          should.exist(err.data.cause.details);
          should.exist(err.data.cause.details.code);
          err.data.cause.details.code.should.equal(
            'ERR_JWT_CLAIM_VALIDATION_FAILED');
          should.exist(err.data.cause.details.claim);
          err.data.cause.details.claim.should.equal('scope');
        });
        it('fails using an access token w/bad target', async () => {
          const accessToken = await helpers.createOAuth2AccessToken({
            action: fixture.expectedAction, target: '/foo'
          });
          let err;
          let result;
          try {
            result = await helpers.doOAuth2Request({url, accessToken});
          } catch(e) {
            err = e;
          }
          should.exist(err);
          should.not.exist(result);
          err.status.should.equal(403);
          err.data.type.should.equal('NotAllowedError');
          should.exist(err.data.cause);
          should.exist(err.data.cause.details);
          should.exist(err.data.cause.details.code);
          err.data.cause.details.code.should.equal(
            'ERR_JWT_CLAIM_VALIDATION_FAILED');
          should.exist(err.data.cause.details.claim);
          err.data.cause.details.claim.should.equal('scope');
        });
      });
    }
  });

  describe('request oauth2 access token', () => {
    let clients;
    let url;
    before(() => {
      ({clients} = bedrock.config['basic-authz-server'].authorization.oauth2);
      url = `${bedrock.config.server.baseUri}/openid/token`;
    });

    it('succeeds when requesting one authorized scope', async () => {
      let err;
      let result;
      try {
        result = await helpers.requestOAuth2AccessToken({
          url,
          clientId: clients.authorizedClient.id,
          secret: clients.authorizedClient.id,
          requestedScopes: [`read:${target}`]
        });
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      result.data.access_token.should.be.a('string');
    });
    it('succeeds when requesting all authorized scopes', async () => {
      let err;
      let result;
      try {
        result = await helpers.requestOAuth2AccessToken({
          url,
          clientId: clients.authorizedClient.id,
          secret: clients.authorizedClient.id,
          requestedScopes: [`read:${target}`, `write:${target}`]
        });
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      result.data.access_token.should.be.a('string');
    });
    it('fails when requesting an unauthorized scope', async () => {
      let err;
      let result;
      try {
        result = await helpers.requestOAuth2AccessToken({
          url,
          clientId: clients.authorizedClient.id,
          secret: clients.authorizedClient.id,
          requestedScopes: [`read:/`]
        });
      } catch(e) {
        err = e;
      }
      should.exist(err);
      should.not.exist(result);
      err.status.should.equal(403);
      err.data.error.should.equal('not_allowed_error');
    });
    it('fails when requesting and no scopes are authorized', async () => {
      let err;
      let result;
      try {
        result = await helpers.requestOAuth2AccessToken({
          url,
          clientId: clients.unauthorizedClient.id,
          secret: clients.unauthorizedClient.id,
          requestedScopes: [`read:${target}`]
        });
      } catch(e) {
        err = e;
      }
      should.exist(err);
      should.not.exist(result);
      err.status.should.equal(403);
      err.data.error.should.equal('not_allowed_error');
    });
    it('succeeds when using requested token', async () => {
      const {
        data: {access_token: accessToken}
      } = await helpers.requestOAuth2AccessToken({
        url,
        clientId: clients.authorizedClient.id,
        secret: clients.authorizedClient.id,
        requestedScopes: [`read:${target}`]
      });
      let err;
      let result;
      try {
        result = await helpers.doOAuth2Request({
          url: `${bedrock.config.server.baseUri}${target}`,
          accessToken
        });
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      result.data.should.deep.equal({success: true});
    });
    it('succeeds using custom client retrieval', async () => {
      const customClientId = '5f4e027b-efb1-4bf4-b741-69d16338e47e';
      const {
        data: {access_token: accessToken}
      } = await helpers.requestOAuth2AccessToken({
        url,
        clientId: customClientId,
        secret: customClientId,
        requestedScopes: [`read:${target}`]
      });
      let err;
      let result;
      try {
        result = await helpers.doOAuth2Request({
          url: `${bedrock.config.server.baseUri}${target}`,
          accessToken
        });
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      result.data.should.deep.equal({success: true});
    });
  });
});
