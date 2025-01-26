/*!
 * Copyright (c) 2021-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as Ed25519Multikey from '@digitalbazaar/ed25519-multikey';
import {
  authorizeZcapInvocation as _authorizeZcapInvocation,
  authorizeZcapRevocation as _authorizeZcapRevocation
} from '@digitalbazaar/ezcap-express';
import assert from 'assert-plus';
import {asyncHandler} from '@bedrock/express';
import {checkAccessToken} from './oauth2.js';
import {documentLoader} from '../documentLoader.js';
import {
  Ed25519Signature2020
} from '@digitalbazaar/ed25519-signature-2020';
import {getAppIdentity} from '@bedrock/app-identity';
import {NAMESPACE} from '../constants.js';

const {util: {BedrockError}} = bedrock;

// creates middleware for authorizing an HTTP request using the authz method
// detected in the request; presently supports both zcaps and oauth2 (but only
// may be used in a given request); each use the app identity as the root of
// security; zcap revocation is not supported by default, this can be
// overridden by passing `async isZcapRevoked({capabilities})`
export function authorizeRequest({
  expectedAction, isZcapRevoked = () => false
} = {}) {
  // app identity is always the root controller for this middleware
  const {id: rootController} = getAppIdentity();

  const getExpectedValues = () => ({
    // allow expected action override
    action: expectedAction,
    host: bedrock.config.server.host,
    rootInvocationTarget: bedrock.config.server.baseUri
  });

  const getRootController = () => rootController;

  const authzMiddleware = {
    zcap: authorizeZcapInvocation({
      getExpectedValues, getRootController, isRevoked: isZcapRevoked
    }),
    oauth2: authorizeOAuth2AccessToken({getExpectedValues})
  };

  return _useDetectedAuthzMethod({authzMiddleware});
}

// creates a middleware that checks OAuth2 JWT access token
export function authorizeOAuth2AccessToken({getExpectedValues}) {
  return asyncHandler(async function authzOAuth2AccessToken(req, res, next) {
    try {
      await checkAccessToken({req, getExpectedValues});
    } catch(error) {
      return onError({error});
    }
    next();
  });
}

// calls ezcap-express's authorizeZcapInvocation w/constant params, exposing
// only those params that change in this module; zcap revocation not supported
// by default; requires override to use that feature
export function authorizeZcapInvocation({
  getExpectedValues, getRootController, isRevoked = () => false
} = {}) {
  const {authorizeZcapInvocationOptions} = bedrock.config[NAMESPACE];
  return _authorizeZcapInvocation({
    documentLoader, getExpectedValues, getRootController,
    getVerifier,
    async inspectCapabilityChain({capabilityChain, capabilityChainMeta}) {
      return _inspectCapabilityChain({
        capabilityChain, capabilityChainMeta, isRevoked
      });
    },
    onError,
    suiteFactory,
    ...authorizeZcapInvocationOptions
  });
}

// creates middleware for revocation of zcaps;
// `async isRevoked({capabilities})` must be provided for checking revocation
// status of the capabilities used in a given request
export function authorizeZcapRevocation({isRevoked = () => false} = {}) {
  assert.func(isRevoked, 'isRevoked');
  const {id: rootController} = getAppIdentity();
  return _authorizeZcapRevocation({
    documentLoader,
    expectedHost: bedrock.config.server.host,
    getRootController() {
      return rootController;
    },
    getVerifier,
    async inspectCapabilityChain({capabilityChain, capabilityChainMeta}) {
      return _inspectCapabilityChain({
        capabilityChain, capabilityChainMeta, isRevoked
      });
    },
    onError,
    suiteFactory
  });
}

// hook used to verify zcap invocation HTTP signatures
async function getVerifier({keyId, documentLoader}) {
  const {document} = await documentLoader(keyId);
  const key = await Ed25519Multikey.from(document);
  const verificationMethod = await key.export(
    {publicKey: true, includeContext: true});
  const verifier = key.verifier();
  return {verifier, verificationMethod};
}

function onError({error}) {
  if(!(error instanceof BedrockError)) {
    // always expose cause message and name; expose cause details as
    // BedrockError if error is marked public
    let details = {};
    if(error.details && error.details.public) {
      details = error.details;
    }
    error = new BedrockError(
      error.message,
      error.name || 'NotAllowedError', {
        ...details,
        public: true,
      }, error);
  }
  throw new BedrockError(
    'Authorization error.', 'NotAllowedError', {
      httpStatusCode: 403,
      public: true,
    }, error);
}

// hook used to create suites for verifying zcap delegation chains
async function suiteFactory() {
  return new Ed25519Signature2020();
}

async function _inspectCapabilityChain({
  capabilityChain, capabilityChainMeta, isRevoked
}) {
  // if capability chain has only root, there's nothing to check as root
  // zcaps cannot be revoked
  if(capabilityChain.length === 1) {
    return {valid: true};
  }

  // collect capability IDs and delegators for all delegated capabilities in
  // chain (skip root) so they can be checked for revocation
  const capabilities = [];
  for(const [i, capability] of capabilityChain.entries()) {
    // skip root zcap, it cannot be revoked
    if(i === 0) {
      continue;
    }
    const [{purposeResult}] = capabilityChainMeta[i].verifyResult.results;
    if(purposeResult && purposeResult.delegator) {
      capabilities.push({
        capabilityId: capability.id,
        delegator: purposeResult.delegator.id,
      });
    }
  }

  const revoked = await isRevoked({capabilities});
  if(revoked) {
    return {
      valid: false,
      error: new Error(
        'One or more capabilities in the chain have been revoked.')
    };
  }

  return {valid: true};
}

function _invokeMiddlewares({req, res, next, middlewares}) {
  if(!Array.isArray(middlewares)) {
    return middlewares(req, res, next);
  }
  if(middlewares.length === 1) {
    return middlewares[0](req, res, next);
  }
  const middleware = middlewares.shift();
  const localNext = (...args) => {
    if(args.length === 0) {
      return _invokeMiddlewares({req, res, next, middlewares});
    }
    next(...args);
  };
  middleware(req, res, localNext);
}

// create middleware that uses detected authz middleware
function _useDetectedAuthzMethod({authzMiddleware}) {
  return function useDetectedAuthzMethod(req, res, next) {
    const zcap = !!req.get('capability-invocation');
    const oauth2 = !!(req.get('authorization')?.startsWith('Bearer '));
    if(zcap && oauth2) {
      return next(new BedrockError(
        'Only one authorization method is permitted per request.',
        'NotAllowedError', {
          httpStatusCode: 403,
          public: true,
        }));
    }

    // use middleware that matches authz method used in request
    let mw;
    if(zcap) {
      mw = authzMiddleware.zcap;
    } else if(oauth2) {
      mw = authzMiddleware.oauth2;
    }
    // ensure an authz middleware always executes, including in cases where
    // no authz method was used in request or where matching method is not
    // enabled
    mw = mw || authzMiddleware.zcap || authzMiddleware.oauth2;

    const middlewares = Array.isArray(mw) ? mw.slice() : mw;
    _invokeMiddlewares({req, res, next, middlewares});
  };
}
