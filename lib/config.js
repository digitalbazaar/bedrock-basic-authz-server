/*!
 * Copyright (c) 2024-2025 Digital Bazaar, Inc. All rights reserved.
 */
import {config} from '@bedrock/core';
import {NAMESPACE} from './constants.js';

const cfg = config[NAMESPACE] = {};

cfg.authorization = {
  zcap: {
    authorizeZcapInvocationOptions: {
      maxChainLength: 10,
      // 300 second clock skew permitted by default
      maxClockSkew: 300,
      // 1 year max TTL by default
      maxDelegationTtl: 1 * 60 * 60 * 24 * 365 * 1000
    }
  },
  oauth2: {
    accessTokens: {
      // TTL in seconds (default 24 hours = 86400 seconds)
      ttl: 86400
    },
    routes: {
      asMetadata: `/.well-known/oauth-authorization-server`,
      token: `/openid/token`,
      jwks: `/openid/jwks`
    },
    clients: {
      /*
      <pet name of client>: {
        id: ...,
        // scopes that can be requested in the future; changing this DOES NOT
        // alter existing access (for already issued tokens)
        allowedScopes: ...,
        // base64url-encoding of a SHA-256 of the client ID's secret;
        // security depends on secrets being sufficiently large (16 bytes or
        // more) random strings; this field should be populated using an
        // appropriate cloud secret store in any deployment
        secretHash
      }
      */
    },
    // 300 second clock skew permitted by default
    maxClockSkew: 300,
    // note: using undefined `allowedAlgorithms` will use the defaults set
    // by the `jose` library that are appropriate for the key / secret type;
    // (i.e., only asymmetric crypto will be used here); the top-level/parent
    // app should choose to either use `undefined` as the default or specify
    // a more restrictive list
    /*allowedAlgorithms: [
      // RSASSA-PKCS1-v1_ w/sha-XXX
      'RS256',
      'RS384',
      'RS512',
      // RSASSA-PSS w/ SHA-XXX
      'PS256',
      'PS384',
      'PS512',
      // ECDSA w/ SHA-XXX
      'ES256',
      'ES256K',
      'ES384',
      'ES512',
      // ed25519 / ed448
      'EdDSA'
    ]*/
  }
};
