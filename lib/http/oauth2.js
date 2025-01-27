/*!
 * Copyright (c) 2021-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as Ed25519Multikey from '@digitalbazaar/ed25519-multikey';
import {
  checkTargetScopedAccessToken,
  getBasicAuthorizationCredentials
} from '@bedrock/oauth2-verifier';
import {createHash, timingSafeEqual} from 'node:crypto';
import {importJWK, SignJWT} from 'jose';
import assert from 'assert-plus';
import {asyncHandler} from '@bedrock/express';
import bodyParser from 'body-parser';
import cors from 'cors';
import {getAppIdentity} from '@bedrock/app-identity';
import {logger} from '../logger.js';
import {NAMESPACE} from '../constants.js';
import {
  oauthAccessTokenBody
} from '../../schemas/bedrock-basic-authz-server.js';
import {createValidateMiddleware as validate} from '@bedrock/validation';

const {util: {BedrockError}} = bedrock;

// export for testing purposes only
export let OAUTH2_ISSUER;

const CLIENT_MAP = new Map();

// initialize oauth info
bedrock.events.on('bedrock.init', async () => {
  // use application identity zcap key for capabilities expressed as
  // oauth access tokens as well
  const {id, keys: {capabilityInvocationKey}} = getAppIdentity();
  const cfg = bedrock.config[NAMESPACE];
  const {clients, routes} = cfg.authorization.oauth2;

  const {baseUri} = bedrock.config.server;
  OAUTH2_ISSUER = {
    // has the issuer's DID
    id,
    // has the OAuth2 "issuer" metadata value
    issuer: baseUri,
    configUrl: `${baseUri}${routes.asMetadata}`,
    keyPair: null,
    jwks: null,
    config: {
      issuer: baseUri,
      jwks_uri: `${baseUri}${routes.jwks}`,
      token_endpoint: `${baseUri}${routes.token}`,
      grant_types_supported: ['client_credentials']
    }
  };

  // ensure key pair can be imported and public key exported
  try {
    const importedKey = await Ed25519Multikey.from(capabilityInvocationKey);
    const keyPair = await importedKey.export({
      secretKey: true, raw: true, canonicalize: true
    });
    const [privateKeyJwk, publicKeyJwk] = await Promise.all([
      Ed25519Multikey.toJwk({
        keyPair,
        secretKey: true
      }),
      Ed25519Multikey.toJwk({keyPair})
    ]);
    privateKeyJwk.kid = capabilityInvocationKey.id;
    privateKeyJwk.alg = 'EdDSA';
    publicKeyJwk.kid = capabilityInvocationKey.id;
    publicKeyJwk.alg = 'EdDSA';
    const privateKey = await importJWK(privateKeyJwk);
    OAUTH2_ISSUER.keyPair = {publicKeyJwk, privateKey};
    OAUTH2_ISSUER.jwks = {keys: [publicKeyJwk]};
  } catch(e) {
    throw new BedrockError(
      'Could not import OAuth2 key pair.', {
        name: 'DataError',
        details: {httpStatusCode: 400, public: true},
        cause: e
      });
  }

  // build map of client_id => client from named clients
  for(const clientName in clients) {
    const client = _importOAuth2Client({client: clients[clientName]});
    CLIENT_MAP.set(client.id, client);
  }
});

export function addOAuth2AuthzServer({app}) {
  const cfg = bedrock.config[NAMESPACE];
  const {routes} = cfg.authorization.oauth2;

  // urlencoded body parser
  const urlencodedSmall = bodyParser.urlencoded({
    // (extended=true for rich JSON-like representation)
    extended: true
  });

  app.get(
    routes.asMetadata,
    cors(),
    asyncHandler(async (req, res) => {
      res.json(OAUTH2_ISSUER.config);
    }));

  app.get(
    routes.jwks,
    cors(),
    asyncHandler(async (req, res) => {
      res.json(OAUTH2_ISSUER.jwks);
    }));

  app.options(routes.token, cors());
  app.post(
    routes.token,
    cors(),
    urlencodedSmall,
    validate({bodySchema: oauthAccessTokenBody}),
    asyncHandler(async (req, res) => {
      let result;
      try {
        result = await _processAccessTokenRequest({req, res});
      } catch(error) {
        return _sendOauth2Error({res, error});
      }
      res.json(result);
    }));
}

export async function checkAccessToken({req, getExpectedValues} = {}) {
  // pass optional system-wide supported algorithms as allow list ... note
  // that `none` algorithm is always prohibited
  const {
    authorization: {
      oauth2: {maxClockSkew, allowedAlgorithms}
    }
  } = bedrock.config[NAMESPACE];
  return checkTargetScopedAccessToken({
    req, issuerConfigUrl: OAUTH2_ISSUER.configUrl, getExpectedValues,
    allowedAlgorithms, maxClockSkew
  });
}

async function _assertOauth2ClientSecret({client, secret}) {
  // hash secret for comparison (fast hash is used here which presumes
  // secrets are large and random so no rainbow table can be built but
  // the secrets won't be stored directly)
  const secretHash = await _sha256(secret);

  // ensure given secret hash matches client record
  if(!timingSafeEqual(
    Buffer.from(client.secretHash, 'base64url'), secretHash)) {
    throw new BedrockError(
      'Invalid OAuth2 client secret.', {
        name: 'NotAllowedError',
        details: {
          httpStatusCode: 403,
          public: true
        }
      });
  }
}

function _camelToSnakeCase(s) {
  return s.replace(/[A-Z]/g, (c, i) => (i === 0 ? '' : '_') + c.toLowerCase());
}

async function _checkBasicAuthorization({req}) {
  try {
    // parse credentials
    // see: https://datatracker.ietf.org/doc/html/rfc7617#section-2
    const {
      credentials: {userId: clientId, password: secret}
    } = getBasicAuthorizationCredentials({req});

    // find matching client
    const client = await _getOAuth2Client({clientId});

    // assert secret
    await _assertOauth2ClientSecret({client, secret});

    return {client};
  } catch(cause) {
    throw new BedrockError(
      'Basic authorization validation failed.', {
        name: 'NotAllowedError',
        details: {
          httpStatusCode: 403,
          public: true
        },
        cause
      });
  }
}

// export for testing purposes only
export async function _createAccessToken({client, request}) {
  // get (and validate) requested scopes
  const scope = _getRequestedScopes({client, request}).join(' ');

  // set `exp` based on configured TTL
  const cfg = bedrock.config[NAMESPACE];
  const {accessTokens} = cfg.authorization.oauth2;
  const exp = Math.floor(Date.now() / 1000) + accessTokens.ttl;

  // create access token
  const {
    issuer: iss,
    keyPair: {privateKey, publicKeyJwk: {alg, kid}}
  } = OAUTH2_ISSUER;
  const audience = bedrock.config.server.baseUri;
  const {accessToken, ttl} = await _createOAuth2AccessToken({
    privateKey, alg, kid, audience, scope, exp, iss
  });
  return {accessToken, ttl};
}

// export for testing purposes only
export async function _createOAuth2AccessToken({
  privateKey, alg, kid, audience, scope, exp, iss, nbf, typ = 'at+jwt'
}) {
  const builder = new SignJWT({scope})
    .setProtectedHeader({alg, kid, typ})
    .setIssuer(iss)
    .setAudience(audience);
  let ttl;
  if(exp !== undefined) {
    builder.setExpirationTime(exp);
    ttl = Math.max(0, exp - Math.floor(Date.now() / 1000));
  } else {
    // default to 15 minute expiration time
    builder.setExpirationTime('15m');
    ttl = Math.floor(Date.now() / 1000) + 15 * 60;
  }
  if(nbf !== undefined) {
    builder.setNotBefore(nbf);
  }
  const accessToken = await builder.sign(privateKey);
  return {accessToken, ttl};
}

function _getOAuth2Client({clientId}) {
  const client = CLIENT_MAP.get(clientId);
  if(!client) {
    throw new BedrockError(
      `OAuth2 client "${clientId}" not found.`, {
        name: 'NotFoundError',
        details: {
          httpStatusCode: 404,
          public: true
        }
      });
  }
  return client;
}

function _getRequestedScopes({client, request}) {
  const scopes = [...new Set(request.scope.split(' '))];
  for(const scope of scopes) {
    if(!client.requestableScopes.includes(scope)) {
      throw new BedrockError(
        `Unauthorized scope "${scope}" requested.`, {
          name: 'NotAllowedError',
          details: {
            httpStatusCode: 403,
            public: true
          }
        });
    }
  }
  return scopes;
}

function _importOAuth2Client({client} = {}) {
  // do not use assert on whole object to avoid logging client secret
  if(!(client && typeof client === 'object')) {
    throw new TypeError(
      'Invalid oauth2 client configuration; client is not an object.');
  }
  const {id, requestableScopes} = client;
  assert.string(id, 'client.id');
  assert.arrayOfString(requestableScopes, 'client.requestableScopes');
  const secretHash = client.secretHash ?? client.passwordHash;
  if(!(typeof secretHash === 'string' &&
    Buffer.from(secretHash, 'base64url').length === 32)) {
    throw new TypeError(
      'Invalid oauth2 client configuration; ' +
      '"secretHash" (or deprecated "passwordHash") must be a ' +
      'base64url-encoded SHA-256 hash of the ' +
      `client's sufficiently large, random secret.`);
  }
  return {
    id,
    requestableScopes,
    secretHash
  };
}

async function _processAccessTokenRequest({req}) {
  // only "client_credentials" grant type is supported
  // see: https://datatracker.ietf.org/doc/html/rfc6749#section-4.4
  const {
    grant_type: grantType,
    scope
  } = req.body;

  if(grantType !== 'client_credentials') {
    // unsupported grant type
    throw new BedrockError(
      `Unsupported grant type "${grantType}".`, {
        name: 'NotSupportedError',
        details: {httpStatusCode: 400, public: true}
      });
  }

  // create access token
  const {client} = await _checkBasicAuthorization({req});
  const request = {scope};
  const {accessToken, ttl} = await _createAccessToken({client, request});
  return {
    access_token: accessToken,
    token_type: 'bearer',
    expires_in: ttl
  };
}

function _sendOauth2Error({res, error}) {
  logger.error(error.message, {error});
  const status = error.details?.httpStatusCode ?? 500;
  const oid4Error = {
    error: _camelToSnakeCase(error.name ?? 'OperationError'),
    error_description: error.message
  };
  if(error?.details?.public) {
    oid4Error.details = error.details;
    // expose first level cause only
    if(oid4Error.cause?.details?.public) {
      oid4Error.cause = {
        name: error.cause.name,
        message: error.cause.message
      };
    }
  }
  res.status(status).json(oid4Error);
}

function _sha256(bufferOrString) {
  return createHash('sha256').update(bufferOrString).digest();
}
