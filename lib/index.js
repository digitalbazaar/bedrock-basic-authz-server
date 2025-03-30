/*!
 * Copyright (c) 2024-2025 Digital Bazaar, Inc. All rights reserved.
 */
import {
  addOAuth2AuthzServer, getOAuth2ClientFromConfig, middleware
} from './http/index.js';
import {zcapClient} from './zcapClient.js';

// load config defaults
import './config.js';

// export APIs
export {
  addOAuth2AuthzServer, getOAuth2ClientFromConfig, middleware, zcapClient
};
