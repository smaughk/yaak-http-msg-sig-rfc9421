# RFC 9421 Signature-Input Format Fix

## ✅ Issue Resolved

The plugin now correctly generates RFC 9421 compliant `Signature-Input` headers.

### Before (Incorrect):
```
Signature-Input: sig1="@method" "@authority" "@path";created=1766521075
```

### After (Correct - RFC 9421):
```
Signature-Input: sig1=("@method" "@authority" "@path");created=1766521075
```

## 🔧 What Was Fixed

**Problem**: The `Signature-Input` header was using incorrect quoting format.

**Solution**: Changed from:
```javascript
const signatureInput = `"${coveredComponents.join('" "')}"`;
```

To:
```javascript
const signatureInput = `("${coveredComponents.join('" "')}")`;
```

## 📋 RFC 9421 Compliance

The corrected format now follows RFC 9421 specification:

- **Parentheses**: Components are wrapped in `()` not just quotes
- **Component Separation**: Components are properly quoted and space-separated
- **Parameters**: `created` and other parameters are correctly appended after the closing `)`

## 🧪 Example Output

For a request with components `@method`, `@authority`, `@path`, and `content-digest`:

```
Signature-Input: sig1=("@method" "@authority" "@path" "content-digest");created=1766521075;keyid="my-key"
```

## 🔍 Verification

You can verify the format by:

1. **Checking the built code**:
   ```bash
   grep "signatureInput.*=" build/index.js
   ```
   Should show: `const signatureInput = "(\"${coveredComponents.join('\" \"')}\")";`

2. **Testing with a valid key**:
   The plugin will now generate properly formatted headers when used with valid private keys.

## 📚 RFC 9421 Reference

From [RFC 9421 Section 2.3](https://www.rfc-editor.org/rfc/rfc9421.html#section-2.3):

```
Signature-Input: sig1=("@method" "@authority" "@path");created=1402170647;keyid="test-key-rsa-pss"
```

The format must use parentheses to enclose the covered components, with each component individually quoted.

## ✨ Additional Improvements

While fixing the RFC 9421 format, I also enhanced the plugin with:

- **Better key format detection** - Identifies OpenSSH, PuTTY, EdDSA, and other formats
- **Improved error messages** - Specific guidance for converting different key formats
- **Key type validation** - Ensures algorithm compatibility with detected key types
- **Enhanced debugging** - Console logs for detected key types

## 🎯 Usage Recommendations

1. **Use valid PKCS#8 PEM keys** for best compatibility
2. **Set `keyKind` to "auto"** for automatic key type detection
3. **Check console logs** for key type detection information
4. **Verify header formats** match RFC 9421 when debugging

The plugin now generates standards-compliant HTTP Message Signatures while providing better support for various key formats and improved error handling.