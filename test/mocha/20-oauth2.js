/*!
 * Copyright (c) 2025 Digital Bazaar, Inc. All rights reserved.
 */
import {_importOAuth2Client} from
  '@bedrock/basic-authz-server/lib/http/oauth2.js';

describe('oauth2', () => {
  describe('_importOAuth2Client', () => {
    it('accepts a client w/ an external audience', async () => {
      let err;
      let result;
      try {
        result = _importOAuth2Client({
          client: {
            id: 'test-external-audience',
            allowedScopes: ['read:/test'],
            audience: 'https://external.example.com',
            secretHash: 'wkueZ4zwWnw6J1xV3jtEfSqnE7yJutgcWL-sQb7OnZ8'
          }
        });
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      result.audience.should.equal('https://external.example.com');
    });
  });
});
