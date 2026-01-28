# bedrock-basic-authz-server

A [Bedrock][] module that provides basic authorization server functionality
using [zcaps][] (Authorization Capabilities) and OAuth2 access tokens.

## Configuration

Configuration is available under `bedrock.config['basic-authz-server']`.

### Zcap Authorization

```js
config['basic-authz-server'].authorization.zcap = {
  authorizeZcapInvocationOptions: {
    // maximum permitted length of a capability delegation chain
    maxChainLength: 10,
    // maximum allowed clock skew in seconds
    maxClockSkew: 300,
    // maximum TTL for delegated capabilities in milliseconds (default: 1 year)
    maxDelegationTtl: 1 * 60 * 60 * 24 * 365 * 1000
  }
};
```

### OAuth2

```js
config['basic-authz-server'].authorization.oauth2 = {
  accessTokens: {
    // TTL in seconds (default: 24 hours)
    ttl: 86400
  },
  routes: {
    // OAuth2 Authorization Server metadata endpoint
    asMetadata: '/.well-known/oauth-authorization-server',
    // token endpoint
    token: '/openid/token',
    // JWKS endpoint
    jwks: '/openid/jwks'
  },
  clients: {
    // named client configurations (see below)
  },
  // maximum allowed clock skew in seconds for JWT validation
  maxClockSkew: 300,
  // allowed JWT algorithms; undefined uses jose library defaults
  // allowedAlgorithms: ['RS256', 'ES256', 'EdDSA', ...]
};
```

### OAuth2 Client Configuration

Each OAuth2 client is configured as a named entry under `clients`:

```js
config['basic-authz-server'].authorization.oauth2.clients.myClient = {
  // unique client identifier
  id: 'cbd47e49-8450-43f6-a3ce-072d876e7f62',
  // scopes this client is allowed to request
  allowedScopes: [
    'read:/my-resource',
    'write:/my-resource'
  ],
  // base64url-encoded SHA-256 hash of the client's secret;
  // the secret itself should be stored in a secure secret store
  secretHash: '...',
  // optional: override the token audience (defaults to server baseUri);
  // useful for multi-tenant or namespaced deployments
  audience: 'https://example.com/my-namespace'
};
```

### Generating a Secret Hash

The `secretHash` is a base64url-encoded SHA-256 hash of the client's secret.
The secret should be a sufficiently large (16+ bytes) random string.

```js
import {createHash} from 'node:crypto';

const secret = 'my-sufficiently-large-random-secret';
const secretHash = createHash('sha256').update(secret).digest('base64url');
// use `secretHash` in client config
```

## License

[Apache-2.0 License](LICENSE).

[Bedrock]: https://github.com/digitalbazaar/bedrock
[zcaps]: https://w3c-ccg.github.io/zcap-spec/
