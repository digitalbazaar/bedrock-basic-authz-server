/*!
 * Copyright (c) 2024-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as helpers from './helpers.js';
import {CapabilityAgent} from '@digitalbazaar/webkms-client';
import {zcapClient} from '@bedrock/basic-authz-server';

describe('http API', () => {
  describe('authz request middleware', () => {
    let capability;
    const target = '/test-authorize-request';
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
      expectedAction: 'get',
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
    // FIXME: remove me
    fixtures.shift();
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
          const accessToken = await helpers.getOAuth2AccessToken({
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
          const accessToken = await helpers.getOAuth2AccessToken({
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
          const accessToken = await helpers.getOAuth2AccessToken({
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
          const accessToken = await helpers.getOAuth2AccessToken({
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
          const accessToken = await helpers.getOAuth2AccessToken({
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
          const accessToken = await helpers.getOAuth2AccessToken({
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
          const accessToken = await helpers.getOAuth2AccessToken({
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
});
