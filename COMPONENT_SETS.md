# HTTP Signature Plugin - Component Sets Guide

## 🎯 Component Sets Feature

The plugin now supports different sets of signature components to match various server requirements.

## 🔧 Available Component Sets

### 1. RFC 9421 Default (recommended for standards compliance)
**Components**: `@method`, `@authority`, `@path` (+ `content-digest` if present)
**Use Case**: Standards-compliant HTTP Message Signatures
**Example Output**:
```
Signature-Input: sig1=("@method" "@authority" "@path");created=1766521744;keyid="aa-bb-cc"
```

### 2. Common Set 1 (what you need!)
**Components**: `host`, `date`, `content-type`
**Use Case**: Many REST APIs and legacy systems
**Example Output**:
```
Signature-Input: sig1=("host" "date" "content-type");created=1766521744;keyid="aa-bb-cc"
```

### 3. Common Set 2
**Components**: `@request-target`, `host`, `date`
**Use Case**: Some OAuth implementations and older APIs
**Example Output**:
```
Signature-Input: sig1=("@request-target" "host" "date");created=1766521744;keyid="aa-bb-cc"
```

### 4. AWS Style
**Components**: `host`, `date`, `content-type` (+ `content-digest` if present)
**Use Case**: AWS API Gateway and similar services
**Example Output**:
```
Signature-Input: sig1=("host" "date" "content-type" "content-digest");created=1766521744;keyid="aa-bb-cc"
```

## 🎯 How to Use

### In the Plugin Configuration:

```javascript
// For the server that expects "host", "date", "content-type"
const config = {
    privateKey: "-----BEGIN PRIVATE KEY-----...",
    keyId: "aa-bb-cc",
    algorithm: "ecdsa-sha256",  // or whatever algorithm matches your key
    componentSet: "common-set1"   // This is what you need!
}
```

### Component Set Options:
- `"rfc9421-default"` - RFC 9421 standard components
- `"common-set1"` - `host`, `date`, `content-type` (✅ **This is likely what you need!**)
- `"common-set2"` - `@request-target`, `host`, `date`
- `"aws-style"` - `host`, `date`, `content-type`, `content-digest`

## 🔍 Troubleshooting

### If it still doesn't work:

1. **Check server documentation** for exact component requirements
2. **Ensure required headers are present**:
   - For `common-set1`: Make sure your request has `Host`, `Date`, and `Content-Type` headers
   - For `common-set2`: Make sure your request has `Host` and `Date` headers
3. **Verify header names are correct**: Some servers expect specific header names
4. **Check timestamp format**: Some servers are picky about timestamp precision

### Common Issues:

**Missing Headers**: If you select `common-set1` but your request doesn't have `Date` or `Content-Type` headers, the signature will fail.

**Header Name Mismatch**: Some servers expect `Content-type` (lowercase) vs `Content-Type` (standard).

**Timestamp Requirements**: Some servers require timestamps in specific formats or with certain precision.

## 📋 Component Reference

### Pseudo-components (start with @):
- `@method` - HTTP method (GET, POST, etc.)
- `@authority` - Host header value
- `@path` - URL path
- `@request-target` - Method + path + query (e.g., `get /api/test?param=value`)

### Regular Header Components:
- `host` - Host header
- `date` - Date header
- `content-type` - Content-Type header
- `content-digest` - Content-Digest header
- `content-length` - Content-Length header

## 🎓 Best Practices

1. **Start with RFC 9421 Default** for standards compliance
2. **Check server documentation** for specific requirements
3. **Use the component set** that matches what the server expects
4. **Ensure all required headers** are present in your request
5. **Test with different sets** if you're unsure what the server expects

## 🚀 Quick Fix for Your Issue

Based on your logs showing the server expects:
```
Signature-Input: sig1=("host" "date" "content-type")
```

**Use these settings:**
- **componentSet**: `"common-set1"`
- **Make sure your request has**: `Host`, `Date`, and `Content-Type` headers
- **Algorithm**: Match to your key type (e.g., `ecdsa-sha256` for EC keys)

This should generate the exact format the server is expecting!