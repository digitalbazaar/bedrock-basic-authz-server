/*!
 * Copyright (c) 2024-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {
  addOAuth2AuthzServer, getOAuth2ClientFromConfig, middleware
} from '@bedrock/basic-authz-server';
import '@bedrock/https-agent';
import '@bedrock/express';

// add OAuth2 authz server routes
bedrock.events.on('bedrock-express.configure.routes', app => {
  const {baseUri} = bedrock.config.server;

  const additionalClients = new Map([
    ['5f4e027b-efb1-4bf4-b741-69d16338e47e', {
      id: '5f4e027b-efb1-4bf4-b741-69d16338e47e',
      allowedScopes: ['read:/test-authorize-request'],
      secretHash: 'wkueZ4zwWnw6J1xV3jtEfSqnE7yJutgcWL-sQb7OnZ8'
    }],
    // namespaced client, i.e., special audience
    ['ee8f6e61-a6c7-4ada-846e-9cbca3b15661', {
      id: 'ee8f6e61-a6c7-4ada-846e-9cbca3b15661',
      allowedScopes: [
        'read:/test-authorize-request',
      ],
      audience: `${baseUri}/namespace`,
      secretHash: 'Fikr8BzsZB5f0mEGeRTcIVqLxpgSCpTwkYOtyaeHNTs'
    }]
  ]);

  addOAuth2AuthzServer({
    app,
    async getOAuth2Client({clientId} = {}) {
      // first try `getOAuth2ClientFromConfig`
      try {
        const client = await getOAuth2ClientFromConfig({clientId});
        return client;
      } catch(e) {}

      // now return client w/custom storage implementation
      const client = additionalClients.get(clientId);
      return client;
    }
  });

  // add middleware test routes
  app.post(
    '/test-authorize-request',
    middleware.authorizeRequest(), (req, res) => {
      res.json({success: true});
    });
  app.get(
    '/test-authorize-request',
    middleware.authorizeRequest(), (req, res) => {
      res.json({success: true});
    });
  app.get(
    '/namespace/test-authorize-request',
    middleware.authorizeRequest({
      rootInvocationTarget: `${baseUri}/namespace`
    }), (req, res) => {
      res.json({success: true});
    });
});

import '@bedrock/test';
bedrock.start();
