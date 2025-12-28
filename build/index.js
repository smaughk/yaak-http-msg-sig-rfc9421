"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var index_exports = {};
__export(index_exports, {
  plugin: () => plugin
});
module.exports = __toCommonJS(index_exports);
var import_crypto = __toESM(require("crypto"));
var httpSigPlugin = {
  name: "http-sig",
  label: "HTTP Message Signatures (RFC 9421)",
  shortLabel: "HTTP Msg Sig",
  args: [
    {
      type: "text",
      name: "privateKey",
      label: "PEM Private Key",
      placeholder: "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
      description: "Your PEM-encoded private key for signing requests",
      optional: false,
      password: true
    },
    {
      type: "text",
      name: "keyId",
      label: "Key ID",
      placeholder: "my-key-id",
      description: "Optional unique identifier for your key",
      optional: true
    },
    {
      type: "select",
      name: "keyKind",
      label: "Key Type",
      description: "Key type to use (Auto will detect from the key)",
      options: [
        { label: "Auto-Detect", value: "auto" },
        { label: "EC", value: "ec" },
        { label: "Ed25519", value: "ed25519" },
        { label: "RSA", value: "rsa" }
      ],
      defaultValue: "auto",
      optional: true
    },
    {
      type: "select",
      name: "algorithm",
      label: "Algorithm",
      description: "Signature algorithm to use",
      options: [
        { label: "Auto-Detect (from key)", value: "auto" },
        { label: "ECDSA-SHA256", value: "ecdsa-sha256" },
        { label: "ECDSA-SHA512", value: "ecdsa-sha512" },
        { label: "Ed25519", value: "ed25519" },
        { label: "RSA-PSS-SHA512", value: "rsa-pss-sha512" },
        { label: "RSA-PKCS1-v1.5-SHA256", value: "rsa-v1_5-sha256" }
      ],
      defaultValue: "auto",
      optional: true
    },
    {
      type: "select",
      name: "componentSet",
      label: "Signature Components",
      description: "Components to include in the signature (choose based on server requirements)",
      options: [
        { label: "RFC 9421 (@method, @authority, @path)", value: "rfc9421-default" },
        { label: "Common Set 1 (host, date, content-type)", value: "common-set1" },
        { label: "Common Set 2 (@request-target, host, date)", value: "common-set2" },
        { label: "Common Set 3 (@method, @authority, @target-uri)", value: "common-set3" },
        { label: "AWS Style (host, date, content-type, content-digest)", value: "aws-style" }
      ],
      defaultValue: "rfc9421-default",
      optional: true
    }
  ],
  async onApply(ctx, args) {
    const { privateKey, keyId, algorithm = "rsa-pss-sha512" } = args.values;
    if (!privateKey) {
      throw new Error("Private key is required for HTTP signature generation");
    }
    let parsedKey = privateKey;
    if (typeof parsedKey === "string") {
      parsedKey = parsedKey.replace(/\\n/g, "\n");
      parsedKey = parsedKey.trim();
      const keyFormatDetection = detectKeyFormat(parsedKey);
      parsedKey = parsedKey.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
      if (!parsedKey.includes("\n")) {
        const headerMatch = parsedKey.match(/-----BEGIN [^-]+-----/);
        const footerMatch = parsedKey.match(/-----END [^-]+-----/);
        const contentMatch = parsedKey.match(/-----BEGIN [^-]+-----(.+)-----END [^-]+-----/);
        if (headerMatch && footerMatch && contentMatch) {
          const header = headerMatch[0];
          const footer = footerMatch[0];
          const content = contentMatch[1].trim();
          const formattedContent = content.match(/.{1,64}/g)?.join("\n") || content;
          parsedKey = `${header}
${formattedContent}
${footer}`;
        }
      }
    }
    const method = args.method;
    const url = new URL(args.url);
    const headers = args.headers || [];
    const componentSet = args.values.componentSet || "rfc9421-default";
    let coveredComponents = getComponentsForSet(componentSet, headers, method, url);
    const signatureBase = createSignatureBase(method, url, headers, coveredComponents);
    const created = Math.floor(Date.now() / 1e3);
    const signatureInput = `("${coveredComponents.join('" "')}")`;
    let signatureParams = `;tag="sig1";created=${created}`;
    if (keyId && keyId.trim()) {
      signatureParams += `;keyid="${keyId}"`;
    }
    const nonce = generateNonce();
    signatureParams += `;nonce="${nonce}"`;
    const sigParamsLine = `"@signature-params": ${signatureInput}${signatureParams}`;
    const finalSignatureBase = signatureBase + "\n" + sigParamsLine;
    const keyKindSelected = args.values.keyKind || "auto";
    const keyObj = (() => {
      try {
        return import_crypto.default.createPrivateKey({ key: parsedKey, format: "pem" });
      } catch (err) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        const formatInfo = detectKeyFormat(privateKey);
        if (/unsupported|not supported|unknown format/i.test(errorMsg)) {
          let specificGuidance = "";
          switch (formatInfo.format) {
            case "PEM_EC":
            case "PEM_RSA":
              specificGuidance = `
This key is in legacy ${formatInfo.format === "PEM_EC" ? "EC" : "RSA"} format. Convert it using:
openssl pkcs8 -topk8 -inform PEM -outform PEM -in key.pem -out converted.pem -nocrypt`;
              break;
            case "PEM_EdDSA":
              specificGuidance = `
This EdDSA/Ed25519 key may need conversion. Try:
ssh-keygen -p -m PEM -f key_file
Or use: ssh-keygen -e -m PEM -f key_file > converted.pem`;
              break;
            case "OPENSSH":
              specificGuidance = `
This is an OpenSSH format key. Convert it using:
ssh-keygen -p -m PEM -f key_file
Then use the converted key with this plugin.`;
              break;
            case "PUTTY":
              specificGuidance = `
This is a PuTTY format key. Use PuTTYgen to:
1. Load the key
2. Export as OpenSSH format
3. Convert to PEM using: ssh-keygen -p -m PEM -f openssh_key`;
              break;
            default:
              specificGuidance = `
${formatInfo.guidance}
Try converting to standard PKCS#8 PEM format.`;
          }
          throw new Error(`Failed to parse private key: ${errorMsg}.${specificGuidance}`);
        } else if (/encrypted|passphrase|password/i.test(errorMsg)) {
          throw new Error(`Failed to parse private key: ${errorMsg}. The key appears to be encrypted. Please provide an unencrypted PEM key.`);
        } else if (/invalid|malformed|bad/i.test(errorMsg)) {
          throw new Error(`Failed to parse private key: ${errorMsg}. ${formatInfo.guidance}`);
        } else {
          throw new Error(`Failed to parse private key: ${errorMsg}. ${formatInfo.guidance}`);
        }
      }
    })();
    const detectedKeyType = keyObj.asymmetricKeyType || "";
    const map = { rsa: "rsa", ec: "ec", ed25519: "ed25519" };
    const detectedSimple = map[detectedKeyType] || detectedKeyType;
    console.log(`Detected key type: ${detectedSimple}`);
    let finalAlgorithm = algorithm;
    if (algorithm === "auto") {
      console.log(`Auto-detecting algorithm for key type: ${detectedSimple}`);
      const algorithmMap = {
        "rsa": "rsa-pss-sha512",
        "ec": "ecdsa-sha256",
        "ed25519": "ed25519"
      };
      finalAlgorithm = algorithmMap[detectedSimple] || "rsa-pss-sha512";
      console.log(`Auto-selected algorithm: ${finalAlgorithm}`);
    }
    if (keyKindSelected !== "auto" && keyKindSelected && detectedKeyType) {
      if (detectedSimple !== keyKindSelected) {
        throw new Error(`Configured key type (${keyKindSelected}) does not match detected key type (${detectedSimple}). Please either:
- Set keyKind to "auto" for automatic detection, or
- Ensure the keyKind matches your actual key type`);
      }
    }
    const supportedAlgorithms = {
      "rsa": ["rsa-pss-sha512", "rsa-v1_5-sha256"],
      "ec": ["ecdsa-sha256", "ecdsa-sha512"],
      "ed25519": ["ed25519"]
    };
    const supportedAlgos = supportedAlgorithms[detectedSimple] || [];
    if (!supportedAlgos.includes(finalAlgorithm)) {
      throw new Error(`Selected algorithm (${finalAlgorithm}) is not compatible with detected key type (${detectedSimple}). Supported algorithms for ${detectedSimple} keys: ${supportedAlgos.join(", ")}`);
    }
    const signatureValue = signMessageWithKey(finalSignatureBase, keyObj, finalAlgorithm);
    let signatureInputValue = `sig1=${signatureInput};tag="sig1";created=${created}`;
    if (keyId && keyId.trim()) {
      signatureInputValue += `;keyid="${keyId}"`;
    }
    signatureInputValue += `;nonce="${nonce}"`;
    const signatureValueFinal = `sig1=:${signatureValue}:`;
    return {
      setHeaders: [
        {
          name: "Signature-Input",
          value: signatureInputValue
        },
        {
          name: "Signature",
          value: signatureValueFinal
        }
      ]
    };
  }
};
function generateNonce() {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let result = "";
  for (let i = 0; i < 16; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}
function getComponentsForSet(setName, headers, method, url) {
  switch (setName) {
    case "rfc9421-default":
      const components = ["@method", "@authority", "@path"];
      const contentDigestHeader = headers.find((h) => h.name.toLowerCase() === "content-digest");
      if (contentDigestHeader) {
        components.push("content-digest");
      }
      return components;
    case "common-set3":
      const targetUriComponents = ["@method", "@authority", "@target-uri"];
      const contentDigestHeader2 = headers.find((h) => h.name.toLowerCase() === "content-digest");
      if (contentDigestHeader2) {
        targetUriComponents.push("content-digest");
      }
      return targetUriComponents;
    case "common-set1":
      return ["host", "date", "content-type"];
    case "common-set2":
      return ["@request-target", "host", "date"];
    case "aws-style":
      const awsComponents = ["host", "date", "content-type"];
      const contentDigest = headers.find((h) => h.name.toLowerCase() === "content-digest");
      if (contentDigest) {
        awsComponents.push("content-digest");
      }
      return awsComponents;
    default:
      return ["@method", "@authority", "@path"];
  }
}
function detectKeyFormat(keyContent) {
  if (keyContent.startsWith("-----BEGIN PRIVATE KEY-----") && keyContent.includes("-----END PRIVATE KEY-----")) {
    return {
      format: "PEM_PKCS8",
      guidance: "Standard PKCS#8 PEM format - should work directly"
    };
  } else if (keyContent.startsWith("-----BEGIN EC PRIVATE KEY-----")) {
    return {
      format: "PEM_EC",
      guidance: "Legacy EC PEM format - convert with: openssl pkcs8 -topk8 -inform PEM -outform PEM -in key.pem -out converted.pem -nocrypt"
    };
  } else if (keyContent.startsWith("-----BEGIN RSA PRIVATE KEY-----")) {
    return {
      format: "PEM_RSA",
      guidance: "Legacy RSA PEM format - convert with: openssl pkcs8 -topk8 -inform PEM -outform PEM -in key.pem -out converted.pem -nocrypt"
    };
  } else if (keyContent.startsWith("-----BEGIN EdDSA PRIVATE KEY-----") || keyContent.startsWith("-----BEGIN ED25519 PRIVATE KEY-----")) {
    return {
      format: "PEM_EdDSA",
      guidance: "EdDSA/Ed25519 format - may need conversion. Try: ssh-keygen -p -m PEM -f key_file"
    };
  } else if (keyContent.startsWith("-----BEGIN OPENSSH PRIVATE KEY-----")) {
    return {
      format: "OPENSSH",
      guidance: "OpenSSH format - convert with: ssh-keygen -p -m PEM -f key_file"
    };
  } else if (keyContent.startsWith("PuTTY-User-Key-File")) {
    return {
      format: "PUTTY",
      guidance: "PuTTY format - convert with PuTTYgen: Load key, then export as OpenSSH format, then convert to PEM"
    };
  } else if (keyContent.includes("ssh-") && keyContent.includes("AAAAB3NzaC1")) {
    return {
      format: "OPENSSH_PUBLIC",
      guidance: "This appears to be a public key, not a private key"
    };
  } else {
    return {
      format: "UNKNOWN",
      guidance: "Unknown format - ensure this is a valid PEM-encoded private key"
    };
  }
}
function createSignatureBase(method, url, headers, coveredComponents) {
  const lines = [];
  for (const component of coveredComponents) {
    if (component === "@method") {
      lines.push(`"@method": ${method}`);
    } else if (component === "@authority") {
      const hostHeader = headers.find((h) => h.name.toLowerCase() === "host");
      if (hostHeader) {
        lines.push(`"@authority": ${hostHeader.value}`);
      } else {
        lines.push(`"@authority": ${url.host}`);
      }
    } else if (component === "@path") {
      lines.push(`"@path": ${url.pathname}`);
    } else if (component === "@request-target") {
      lines.push(`"@request-target": ${method.toLowerCase()} ${url.pathname}${url.search}`);
    } else if (component === "@target-uri") {
      lines.push(`"@target-uri": ${url.protocol}//${url.host}${url.pathname}${url.search}`);
    } else if (component === "host") {
      const hostHeader = headers.find((h) => h.name.toLowerCase() === "host");
      if (hostHeader) {
        lines.push(`"host": ${hostHeader.value}`);
      }
    } else if (component === "date") {
      const dateHeader = headers.find((h) => h.name.toLowerCase() === "date");
      if (dateHeader) {
        lines.push(`"date": ${dateHeader.value}`);
      }
    } else if (component === "content-type") {
      const contentTypeHeader = headers.find((h) => h.name.toLowerCase() === "content-type");
      if (contentTypeHeader) {
        lines.push(`"content-type": ${contentTypeHeader.value}`);
      }
    } else if (component === "content-digest") {
      const contentDigestHeader = headers.find((h) => h.name.toLowerCase() === "content-digest");
      if (contentDigestHeader) {
        lines.push(`"content-digest": ${contentDigestHeader.value}`);
      }
    }
  }
  return lines.join("\n");
}
function signMessageWithKey(signatureBase, keyObj, algorithm) {
  try {
    const keyType = keyObj.asymmetricKeyType || "";
    if (algorithm === "rsa-pss-sha512") {
      if (keyType !== "rsa") throw new Error(`Algorithm ${algorithm} requires an RSA key (detected ${keyType || "unknown"}).`);
      const sign = import_crypto.default.createSign("RSA-SHA512");
      sign.update(signatureBase, "utf8");
      return sign.sign({ key: keyObj, padding: import_crypto.default.constants.RSA_PKCS1_PSS_PADDING, saltLength: 64 }, "base64");
    } else if (algorithm === "rsa-v1_5-sha256") {
      if (keyType !== "rsa") throw new Error(`Algorithm ${algorithm} requires an RSA key (detected ${keyType || "unknown"}).`);
      const sign = import_crypto.default.createSign("RSA-SHA256");
      sign.update(signatureBase, "utf8");
      return sign.sign(keyObj, "base64");
    } else if (algorithm === "ecdsa-sha256") {
      if (keyType !== "ec") throw new Error(`Algorithm ${algorithm} requires an EC key (detected ${keyType || "unknown"}).`);
      const sign = import_crypto.default.createSign("SHA256");
      sign.update(signatureBase, "utf8");
      return sign.sign(keyObj, "base64");
    } else if (algorithm === "ecdsa-sha512") {
      if (keyType !== "ec") throw new Error(`Algorithm ${algorithm} requires an EC key (detected ${keyType || "unknown"}).`);
      const sign = import_crypto.default.createSign("SHA512");
      sign.update(signatureBase, "utf8");
      return sign.sign(keyObj, "base64");
    } else if (algorithm === "ed25519") {
      if (keyType !== "ed25519") throw new Error(`Algorithm ${algorithm} requires an Ed25519 key (detected ${keyType || "unknown"}).`);
      const sig = import_crypto.default.sign(null, Buffer.from(signatureBase, "utf8"), keyObj);
      return sig.toString("base64");
    } else {
      throw new Error(`Unsupported algorithm: ${algorithm}`);
    }
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    if (/encrypted|bad decrypt/i.test(msg)) {
      throw new Error(`Failed to sign message: private key appears to be encrypted (passphrase-protected). Provide an unencrypted PEM/PKCS#8 key. (${msg})`);
    }
    throw new Error(`Failed to sign message: ${msg}`);
  }
}
var plugin = {
  authentication: httpSigPlugin
};
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  plugin
});
