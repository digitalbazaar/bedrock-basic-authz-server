/*!
 * Copyright (c) 2020-2025 Digital Bazaar, Inc. All rights reserved.
 */
import {config} from '@bedrock/core';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import '@bedrock/app-identity';
import '@bedrock/did-io';
import '@bedrock/https-agent';
import '@bedrock/basic-authz-server';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
config.mocha.options.fullTrace = true;
config.mocha.tests.push(path.join(__dirname, 'mocha'));

// allow self-signed certs in test framework
config['https-agent'].rejectUnauthorized = false;

// disable veres one fetching
config['did-io'].methodOverrides.v1.disableFetch = true;

const clients = config['basic-authz-server'].authorization.oauth2.clients;
clients.authorizedClient = {
  id: 'cbd47e49-8450-43f6-a3ce-072d876e7f62',
  requestableScopes: [
    'read:/test-authorize-request',
    'write:/test-authorize-request'
  ],
  secretHash: 'qpMmqCHdQ0FkyVCF1Sfuprt4jKZ4p4Id1LhSLxmdmu8'
};
clients.unauthorizedClient = {
  id: '5165774d-fadc-484b-8a78-d2b049721b52',
  // no requestable scopes
  requestableScopes: [],
  // hash of `client_id`
  secretHash: 'JySRI3hb_DJ3rV4oUulOowEcLkRS4DCMdnfzJx57Z3g'
};
