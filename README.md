# api-key-auth

This plugin allows you to protect routes with an API key specified in a header, query string param or path segment. If the user does not provide a valid key the middleware will return a 403.

## Config

### Static file

Add to your Traefik static configuration

#### yaml

```yaml
experimental:
  plugins:
    traefik-api-key-middleware:
      moduleName: "github.com/Septima/traefik-api-key-auth"
      version: "v0.1.0"
```

#### toml

```toml
[experimental.plugins.traefik-api-key-auth]
  moduleName = "github.com/Septima/traefik-api-key-auth"
  version = "v0.1.0"
```

### CLI

Add to your startup args:

```sh
--experimental.plugins.traefik-api-key-middleware.modulename=github.com/Septima/traefik-api-key-auth
--experimental.plugins.traefik-api-key-middleware.version=v0.1.0
```

### K8s CRD

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: verify-api-key
spec:
  plugin:
    traefik-api-key-middleware:
      authenticationHeader: true
      authenticationHeaderName: X-API-KEY
      bearerHeader: true
      bearerHeaderName: Authorization
      queryParam: true
      queryParamName: token
      pathSegment: true
      removeHeadersOnSuccess: true
      internalForwardHeaderName: ''
      internalErrorRoute: ''
      keys:
        - some-api-key
```

## Plugin options

| option                     | default           | type     | description                                                    | optional |
| :------------------------- | :---------------- | :------- | :---------------------------------------------------------     | :------- |
| `authenticationHeader`     | `true`            | bool     | Use an authentication header to pass a valid key.              | ⚠️       |
| `authenticationHeaderName` | `"X-API-KEY"`     | string   | The name of the authentication header.                         | ✅       |
| `bearerHeader`             | `true`            | bool     | Use an authorization header to pass a bearer token (key).      | ⚠️       |
| `bearerHeaderName`         | `"Authorization"` | string   | The name of the authorization bearer header.                   | ✅       |
| `queryParam`               | `true`            | bool     | Use a query string param to pass a valid key.                  | ⚠️       |
| `queryParamName`           | `"token"`         | string   | The name of the query string param.                            | ✅       |
| `pathSegment`              | `true`            | bool     | Use match on path segment to pass a valid key.                 | ⚠️       |
| `removeHeadersOnSuccess`   | `true`            | bool     | If true will remove the header on success.                     | ✅       |
| `internalForwardHeaderName`| `""`              | string   | Optionally forward validated key as header to next middleware. | ✅       |
| `internalErrorRoute`       | `""`              | string   | Optionally route to backend at specified path on invalid key   | ✅       |
| `keys`                     | `[]`              | []string | A list of valid keys that can be passed using the headers.     | ❌       |

⚠️ - Is optional but at least one of `authenticationHeader` or `bearerHeader` must be set to `true`.

❌ - Required.

✅ - Is optional and will use the default values if not set.
