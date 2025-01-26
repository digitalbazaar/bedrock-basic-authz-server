/*
 * Copyright (c) 2019-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {
  _createOAuth2AccessToken, OAUTH2_ISSUER
} from '@bedrock/basic-authz-server/lib/http/oauth2.js';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {httpClient} from '@digitalbazaar/http-client';
import {httpsAgent} from '@bedrock/https-agent';
import {ZcapClient} from '@digitalbazaar/ezcap';

export async function createOAuth2AccessToken({
  action, target, audience, exp, iss, nbf, typ = 'at+jwt'
}) {
  const {
    issuer,
    keyPair: {privateKey, publicKeyJwk: {alg, kid}}
  } = OAUTH2_ISSUER;
  audience = audience ?? bedrock.config.server.baseUri;
  iss = iss ?? issuer;
  const scope = `${action}:${target}`;
  const {accessToken} = await _createOAuth2AccessToken({
    privateKey, alg, kid, audience, scope, exp, iss, nbf, typ
  });
  return accessToken;
}

export function createZcapClient({
  capabilityAgent, delegationSigner, invocationSigner
}) {
  const signer = capabilityAgent && capabilityAgent.getSigner();
  return new ZcapClient({
    agent: httpsAgent,
    invocationSigner: invocationSigner || signer,
    delegationSigner: delegationSigner || signer,
    SuiteClass: Ed25519Signature2020
  });
}

export async function delegate({
  capability, controller, invocationTarget, expires, allowedActions,
  delegator
}) {
  const zcapClient = createZcapClient({capabilityAgent: delegator});
  expires = expires || (capability && capability.expires) ||
    new Date(Date.now() + 5000).toISOString().slice(0, -5) + 'Z';
  return zcapClient.delegate({
    capability, controller, expires, invocationTarget, allowedActions
  });
}

export async function doOAuth2Request({url, json, accessToken}) {
  const method = json === undefined ? 'get' : 'post';
  return httpClient[method](url, {
    agent: httpsAgent,
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    json
  });
}

export async function requestOAuth2AccessToken({
  url, clientId, password, requestedScopes
}) {
  const body = new URLSearchParams({
    grant_type: 'client_credentials',
    scope: requestedScopes.join(' ')
  });
  const credentials = Buffer.from(`${clientId}:${password}`).toString('base64');
  const headers = {
    accept: 'application/json',
    authorization: `Basic ${credentials}`
  };
  return httpClient.post(url, {agent: httpsAgent, body, headers});
}
