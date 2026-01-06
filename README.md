# HTTP Message Signature Plugin for Yaak

A Yaak authentication plugin that implements RFC 9421 HTTP Message Signatures, allowing you to sign HTTP requests with a PEM private key.

## Features

- Sign HTTP requests using the following algorithms:
  - ECDSA-SHA256
  - ECDSA-SHA512
  - Ed25519
  - RSA-PSS-SHA512
  - RSA-PKCS1-v1.5-SHA256
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
openssl pkcs8 -topk8 -inform PEM \
  -outform PEM -in private_key.pem \
  -out private_key_pkcs8.pem -nocrypt
```

The content of `private_key_pkcs8.pem` can be used as the `HTTPMessageSignature.privateKey` variable.

## Covered Components

The plugin currently signs a combination of the following request components:

- `@method`: HTTP method
- `@authority`: Host header value
- `@path`: Request path
- `@target-uri`: The absolute URI of the resource
- `@request-target`: Depending on the request method; Absolute URI, Relative Path or *
- `host`: Host header value
- `date`: Date header value
- `content-digest`: Content digest header (if present)
- `content-type`: Content type header (if present)


## Security Notes

- Keep your private key secure and never commit it to version control
- Use strong, unique keys for each environment
- The signature includes a timestamp to prevent replay attacks
- Consider the security implications of the components you're signing


## License

MIT