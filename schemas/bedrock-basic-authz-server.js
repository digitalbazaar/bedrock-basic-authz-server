/*!
 * Copyright (c) 2024-2025 Digital Bazaar, Inc. All rights reserved.
 */
export const oauthAccessTokenBody = {
  title: 'OAuth Access Token Request',
  type: 'object',
  additionalProperties: false,
  required: ['grant_type'],
  properties: {
    // only "client_credentials" grant type supported
    // https://datatracker.ietf.org/doc/html/rfc6749#section-4.4
    grant_type: {
      const: 'client_credentials'
    },
    scope: {
      type: 'string'
    }
  }
};
