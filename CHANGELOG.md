# bedrock-basic-authz-server ChangeLog

## 1.3.0 - 2025-03-dd

### Changed
- Deprecate `requestableScopes`; replaced with `allowedScopes`.

## 1.2.0 - 2025-03-30

### Added
- Add `getClient({clientId})` optional function to be passed to
  `addOAuth2AuthzServer({... getClient})` to provide an alternative client
  lookup mechanism. The returned client must have the same properties
  expressed in this module's config where oauth2 clients may be optionally
  specified. If desired, the provided `getClient()` function may optionally
  internally retrieve configured oauth2 clients (if present and in
  whichever order of precedence the application decides) by calling
  `getOAuth2ClientFromConfig()`.

## 1.1.0 - 2025-01-27

### Changed
- Use `secretHash` instead of `passwordHash` (now deprecated but still
  available for use) in oauth2 client configuration.

## 1.0.0 - 2025-01-26

- See git history for changes.
