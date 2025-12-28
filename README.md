# HTTP Message Signature Plugin for Yaak

A Yaak authentication plugin that implements RFC 9421 HTTP Message Signatures, allowing you to sign HTTP requests with a PEM private key.

## Features

- Sign HTTP requests using RSA-PSS-SHA512 or RSA-PKCS1-v1.5-SHA256 algorithms
- Automatic signature header generation
- Configurable private key and algorithm
- Adds `Signature-Input` and `Signature` headers to requests

## Installation

1. Open Yaak
2. Go to **Settings** → **Plugins**
3. Search for **HTTP Message Signature** or install from the plugin file

## Usage

### Setting up Authentication

1. In your Yaak workspace, select a request
2. Go to the **Auth** tab
3. Choose **HTTP Message Signature** from the authentication methods
4. Configure the following:
   - **PEM Private Key**: Your PEM-encoded private key
   - **Key ID**: (Optional) Unique identifier for your key
   - **Algorithm**: Signature algorithm (RSA-PSS-SHA512 or RSA-PKCS1-v1.5-SHA256)

### Automatic Signing

Once configured, the plugin will automatically add `Signature-Input` and `Signature` headers to your requests when you send them.

### Generating a Test Private Key

For testing purposes, you can generate a private key using OpenSSL:

```bash
# Generate a 2048-bit RSA private key
openssl genrsa -out private_key.pem 2048

# Convert to PKCS#8 format (recommended)
openssl pkcs8 -topk8 -inform PEM -outform PEM -in private_key.pem -out private_key_pkcs8.pem -nocrypt
```

The content of `private_key_pkcs8.pem` can be used as the `HTTPMessageSignature.privateKey` variable.

## Covered Components

The plugin currently signs the following request components:

- `@method`: HTTP method
- `@authority`: Host header value
- `@path`: Request path
- `content-digest`: Content digest header (if present)

## Example

### Setting up Variables

In Yaak Variables, set:

```
httpsig_privateKey = -----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC...\n-----END PRIVATE KEY-----
httpsig_keyId = my-key
httpsig_algorithm = rsa-pss-sha512
```

### Using in a Request

Add these headers to your HTTP request:

```
Signature-Input: {{httpsig(signature-input)}}
Signature: {{httpsig(signature)}}
```

Right-click the request → **"Generate HTTP Signature"**

The headers will be replaced with actual signatures:

```
Signature-Input: sig1=("@method" "@authority" "@path");created=1640995200;keyid="my-key"
Signature: sig1=:base64-encoded-signature:
```

## Security Notes

- Keep your private key secure and never commit it to version control
- Use strong, unique keys for each environment
- The signature includes a timestamp to prevent replay attacks
- Consider the security implications of the components you're signing

## Development

To build the plugin:

```bash
npm run build
```

To run tests:

```bash
npm test
```

## License

MIT