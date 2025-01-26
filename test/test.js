/*!
 * Copyright (c) 2024-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {addOAuth2AuthzServer, middleware} from '@bedrock/basic-authz-server';
import '@bedrock/https-agent';
import '@bedrock/express';

// add OAuth2 authz server routes
bedrock.events.on('bedrock-express.configure.routes', app => {
  addOAuth2AuthzServer({app});

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
});

import '@bedrock/test';
bedrock.start();
