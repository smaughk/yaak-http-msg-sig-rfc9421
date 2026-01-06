import type { AuthenticationPlugin, PluginDefinition } from "@yaakapp/api";
import crypto from 'crypto';

const httpSigPlugin: AuthenticationPlugin = {
    name: "http-sig",
    label: "HTTP Message Signatures (RFC 9421)",
    shortLabel: "HTTP Msg Sig",

    args: [
        {
            type: "text",
            name: "privateKey",
            label: "PEM Private Key",
            placeholder: "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
            description: "The PEM-encoded private key used to cryptographically sign the request. This remains client-side.",
            optional: false,
            password: true,
        },
        {
            type: "text",
            name: "keyId",
            label: "Key ID",
            placeholder: "my-key-id",
            description: "The identifier that tells the server which public key to use for verification. Often required by APIs to look up your account.",
            optional: true,
        },
        {
            type: "select",
            name: "keyKind",
            label: "Key Type",
            description: "The cryptographic family of your key. Choose 'Auto-Detect' to derive the family from your PEM Private Key.",
            options: [
                { label: "Auto-Detect", value: "auto" },
                { label: "EC", value: "ec" },
                { label: "Ed25519", value: "ed25519" },
                { label: "RSA", value: "rsa" },
            ],
            defaultValue: "auto",
            optional: true,
        },
        {
            type: "select",
            name: "algorithm",
            label: "Algorithm",
            description: "The specific signing algorithm. Choose 'Auto-Detect' for the most secure algorithm automatically compatible with your key.",
            options: [
                { label: "Auto-Detect (from key)", value: "auto" },
                { label: "ECDSA-SHA256", value: "ecdsa-sha256" },
                { label: "ECDSA-SHA512", value: "ecdsa-sha512" },
                { label: "Ed25519", value: "ed25519" },
                { label: "RSA-PSS-SHA512", value: "rsa-pss-sha512" },
                { label: "RSA-PKCS1-v1.5-SHA256", value: "rsa-v1_5-sha256" },
            ],
            defaultValue: "auto",
            optional: true,
        },
        {
            type: "select",
            name: "componentSet",
            label: "Signature Components",
            description: "Specifies which HTTP headers and derived components are bundled into the signature.",
            options: [
                { label: "RFC 9421 (@method, @authority, @path)", value: "rfc9421-default" },
                { label: "Common Set 1 (host, date, content-type)", value: "common-set1" },
                { label: "Common Set 2 (@request-target, host, date)", value: "common-set2" },
                { label: "Common Set 3 (@method, @authority, @target-uri)", value: "common-set3" },
                { label: "AWS Style (host, date, content-type, content-digest)", value: "aws-style" },
            ],
            defaultValue: "rfc9421-default",
            optional: true,
        },
        {
            type: "accordion",
            label: "Additional Options",
            inputs: [
                {
                    type: "text",
                    name: "additionalSignatureInput",
                    label: "Append to the Signature-Input header",
                    placeholder: "header1, header2",
                    description: "Comma-separated values to be appended to the generated Signature-Input header.",
                    optional: true,
                },
                {
                    type: "text",
                    name: "signatureField",
                    label: "Append to the Signature header",
                    placeholder: "header1, header2",
                    description: "Comma-separated parameters to be appended to the generated Signature header.",
                    optional: true,
                },
            ],
        },
    ],

    async onApply(ctx, args) {
        const { privateKey, keyId, algorithm = "rsa-pss-sha512" } = args.values;

        if (!privateKey) {
            throw new Error("Private key is required for HTTP signature generation");
        }

        // Parse the private key - handle escaped newlines and validate format
        let parsedKey = privateKey;
        if (typeof parsedKey === 'string') {
            // Replace literal \n with actual newlines
            parsedKey = parsedKey.replace(/\\n/g, '\n');
            
            // Trim whitespace and validate basic PEM format
            parsedKey = parsedKey.trim();
            
            // Detect key format and provide specific guidance
            const keyFormatDetection = detectKeyFormat(parsedKey);
            
            // Ensure proper line endings and formatting
            parsedKey = parsedKey.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
            
            // Add missing newlines if needed
            if (!parsedKey.includes('\n')) {
                // Key is on a single line, try to format it properly
                const headerMatch = parsedKey.match(/-----BEGIN [^-]+-----/);
                const footerMatch = parsedKey.match(/-----END [^-]+-----/);
                const contentMatch = parsedKey.match(/-----BEGIN [^-]+-----(.+)-----END [^-]+-----/);
                
                if (headerMatch && footerMatch && contentMatch) {
                    const header = headerMatch[0];
                    const footer = footerMatch[0];
                    const content = contentMatch[1].trim();
                    
                    // Reformat with proper line breaks (64 characters per line for content)
                    const formattedContent = content.match(/.{1,64}/g)?.join('\n') || content;
                    parsedKey = `${header}\n${formattedContent}\n${footer}`;
                }
            }
        }

        // Get request details
        const method = args.method;
        const url = new URL(args.url);
        const headers = args.headers || [];

        // Determine covered components based on selected set
        const componentSet = (args.values.componentSet || 'rfc9421-default') as string;
        let coveredComponents = getComponentsForSet(componentSet, headers, method, url);

        const signatureBase = createSignatureBase(method, url, headers, coveredComponents);
        const created = Math.floor(Date.now() / 1000);
        const signatureInput = `("${coveredComponents.join('" "')}")`;
        let signatureParams = `;tag="sig1";created=${created}`;
        if (keyId && keyId.trim()) {
            signatureParams += `;keyid="${keyId}"`;
        }
        
        // Add nonce parameter with random string
        const nonce = generateNonce();
        signatureParams += `;nonce="${nonce}"`;

        // Create the signature params line for the signature base
        const sigParamsLine = `"@signature-params": ${signatureInput}${signatureParams}`;

        // Final signature base with params
        const finalSignatureBase = signatureBase + '\n' + sigParamsLine;

        // Validate/detect key type and ensure it matches selected keyKind if provided
        const keyKindSelected = (args.values.keyKind || 'auto') as string;
        const keyObj = (() => {
            try {
                return crypto.createPrivateKey({ key: parsedKey, format: 'pem' });
            } catch (err) {
                const errorMsg = err instanceof Error ? err.message : String(err);
                const formatInfo = detectKeyFormat(privateKey);
                
                // Provide more specific guidance based on the error and detected format
                if (/unsupported|not supported|unknown format/i.test(errorMsg)) {
                    let specificGuidance = '';
                    
                    switch (formatInfo.format) {
                        case 'PEM_EC':
                        case 'PEM_RSA':
                            specificGuidance = `\nThis key is in legacy ${formatInfo.format === 'PEM_EC' ? 'EC' : 'RSA'} format. Convert it using:\n` +
                                             `openssl pkcs8 -topk8 -inform PEM -outform PEM -in key.pem -out converted.pem -nocrypt`;
                            break;
                        case 'PEM_EdDSA':
                            specificGuidance = `\nThis EdDSA/Ed25519 key may need conversion. Try:\n` +
                                             `ssh-keygen -p -m PEM -f key_file\n` +
                                             `Or use: ssh-keygen -e -m PEM -f key_file > converted.pem`;
                            break;
                        case 'OPENSSH':
                            specificGuidance = `\nThis is an OpenSSH format key. Convert it using:\n` +
                                             `ssh-keygen -p -m PEM -f key_file\n` +
                                             `Then use the converted key with this plugin.`;
                            break;
                        case 'PUTTY':
                            specificGuidance = `\nThis is a PuTTY format key. Use PuTTYgen to:\n` +
                                             `1. Load the key\n` +
                                             `2. Export as OpenSSH format\n` +
                                             `3. Convert to PEM using: ssh-keygen -p -m PEM -f openssh_key`;
                            break;
                        default:
                            specificGuidance = `\n${formatInfo.guidance}\n` +
                                             `Try converting to standard PKCS#8 PEM format.`;
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

        const detectedKeyType = (keyObj as any).asymmetricKeyType || '';
        
        // Map node key types to our simple names
        const map: Record<string, string> = { rsa: 'rsa', ec: 'ec', ed25519: 'ed25519' };
        const detectedSimple = map[detectedKeyType] || detectedKeyType;
        
        console.log(`Detected key type: ${detectedSimple}`); // Debug log
        
        // Auto-detect algorithm if set to "auto"
        let finalAlgorithm = algorithm;
        if (algorithm === 'auto') {
            console.log(`Auto-detecting algorithm for key type: ${detectedSimple}`);
            
            // Map key types to recommended algorithms
            const algorithmMap: Record<string, string> = {
                'rsa': 'rsa-pss-sha512',
                'ec': 'ecdsa-sha256',
                'ed25519': 'ed25519'
            };
            
            finalAlgorithm = algorithmMap[detectedSimple] || 'rsa-pss-sha512';
            console.log(`Auto-selected algorithm: ${finalAlgorithm}`);
        }
        
        if (keyKindSelected !== 'auto' && keyKindSelected && detectedKeyType) {
            if (detectedSimple !== keyKindSelected) {
                throw new Error(`Configured key type (${keyKindSelected}) does not match detected key type (${detectedSimple}). Please either:\n` +
                               `- Set keyKind to "auto" for automatic detection, or\n` +
                               `- Ensure the keyKind matches your actual key type`);
            }
        }
        
        // Validate that the detected key type is supported by the selected algorithm
        const supportedAlgorithms: Record<string, string[]> = {
            'rsa': ['rsa-pss-sha512', 'rsa-v1_5-sha256'],
            'ec': ['ecdsa-sha256', 'ecdsa-sha512'],
            'ed25519': ['ed25519']
        };
        
        const supportedAlgos = supportedAlgorithms[detectedSimple] || [];
        if (!supportedAlgos.includes(finalAlgorithm)) {
            throw new Error(`Selected algorithm (${finalAlgorithm}) is not compatible with detected key type (${detectedSimple}). ` +
                           `Supported algorithms for ${detectedSimple} keys: ${supportedAlgos.join(', ')}`);
        }

        const signatureValue = signMessageWithKey(finalSignatureBase, keyObj, finalAlgorithm);

        // Build the Signature-Input header to match server format
        let signatureInputValue = `sig1=${signatureInput};tag="sig1";created=${created}`;
        if (keyId && keyId.trim()) {
            signatureInputValue += `;keyid="${keyId}"`;
        }
        signatureInputValue += `;nonce="${nonce}"`;
        
        // Append additional signature input if provided
        const additionalSignatureInput = args.values.additionalSignatureInput;
        if (additionalSignatureInput && additionalSignatureInput.trim()) {
            signatureInputValue += `, ${additionalSignatureInput.trim()}`;
        }
        
        let signatureValueFinal = `sig1=:${signatureValue}:`;
        
        // Append signature field if provided
        const signatureField = args.values.signatureField;
        if (signatureField && signatureField.trim()) {
            signatureValueFinal += `, ${signatureField.trim()}`;
        }

        return {
            setHeaders: [
                {
                    name: 'Signature-Input',
                    value: signatureInputValue,
                },
                {
                    name: 'Signature',
                    value: signatureValueFinal,
                },
            ],
        };
    },
};

function generateNonce(): string {
    // Generate a random nonce string (16 characters)
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < 16; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

function getComponentsForSet(setName: string, headers: any[], method: string, url: URL): string[] {
    switch (setName) {
        case 'rfc9421-default':
            // RFC 9421 default components (using @path)
            const components = ['@method', '@authority', '@path'];
            
            // Add content-digest if present
            const contentDigestHeader = headers.find(h => h.name.toLowerCase() === 'content-digest');
            if (contentDigestHeader) {
                components.push('content-digest');
            }
            return components;
            
        case 'common-set3':
            // RFC 9421 with @target-uri instead of @path
            const targetUriComponents = ['@method', '@authority', '@target-uri'];
            
            // Add content-digest if present
            const contentDigestHeader2 = headers.find(h => h.name.toLowerCase() === 'content-digest');
            if (contentDigestHeader2) {
                targetUriComponents.push('content-digest');
            }
            return targetUriComponents;
            
        case 'common-set1':
            // Common set: host, date, content-type
            return ['host', 'date', 'content-type'];
            
        case 'common-set2':
            // Another common set: @request-target, host, date
            return ['@request-target', 'host', 'date'];
            
        case 'aws-style':
            // AWS-style: host, date, content-type, content-digest
            const awsComponents = ['host', 'date', 'content-type'];
            const contentDigest = headers.find(h => h.name.toLowerCase() === 'content-digest');
            if (contentDigest) {
                awsComponents.push('content-digest');
            }
            return awsComponents;
            
        default:
            // Fallback to RFC 9421 default
            return ['@method', '@authority', '@path'];
    }
}

function detectKeyFormat(keyContent: string): { format: string, guidance: string } {
    // Detect the key format based on headers
    if (keyContent.startsWith('-----BEGIN PRIVATE KEY-----') && keyContent.includes('-----END PRIVATE KEY-----')) {
        return {
            format: 'PEM_PKCS8',
            guidance: 'Standard PKCS#8 PEM format - should work directly'
        };
    } else if (keyContent.startsWith('-----BEGIN EC PRIVATE KEY-----')) {
        return {
            format: 'PEM_EC',
            guidance: 'Legacy EC PEM format - convert with: openssl pkcs8 -topk8 -inform PEM -outform PEM -in key.pem -out converted.pem -nocrypt'
        };
    } else if (keyContent.startsWith('-----BEGIN RSA PRIVATE KEY-----')) {
        return {
            format: 'PEM_RSA',
            guidance: 'Legacy RSA PEM format - convert with: openssl pkcs8 -topk8 -inform PEM -outform PEM -in key.pem -out converted.pem -nocrypt'
        };
    } else if (keyContent.startsWith('-----BEGIN EdDSA PRIVATE KEY-----') || keyContent.startsWith('-----BEGIN ED25519 PRIVATE KEY-----')) {
        return {
            format: 'PEM_EdDSA',
            guidance: 'EdDSA/Ed25519 format - may need conversion. Try: ssh-keygen -p -m PEM -f key_file'
        };
    } else if (keyContent.startsWith('-----BEGIN OPENSSH PRIVATE KEY-----')) {
        return {
            format: 'OPENSSH',
            guidance: 'OpenSSH format - convert with: ssh-keygen -p -m PEM -f key_file'
        };
    } else if (keyContent.startsWith('PuTTY-User-Key-File')) {
        return {
            format: 'PUTTY',
            guidance: 'PuTTY format - convert with PuTTYgen: Load key, then export as OpenSSH format, then convert to PEM'
        };
    } else if (keyContent.includes('ssh-') && keyContent.includes('AAAAB3NzaC1')) {
        return {
            format: 'OPENSSH_PUBLIC',
            guidance: 'This appears to be a public key, not a private key'
        };
    } else {
        return {
            format: 'UNKNOWN',
            guidance: 'Unknown format - ensure this is a valid PEM-encoded private key'
        };
    }
}

function createSignatureBase(method: string, url: URL, headers: any[], coveredComponents: string[]): string {
    const lines: string[] = [];

    for (const component of coveredComponents) {
        if (component === '@method') {
            lines.push(`"@method": ${method}`);
        } else if (component === '@authority') {
            // Try to get @authority from Host header first, then fall back to URL host
            const hostHeader = headers.find((h: any) => h.name.toLowerCase() === 'host');
            if (hostHeader) {
                lines.push(`"@authority": ${hostHeader.value}`);
            } else {
                // Fall back to URL host if no Host header is present
                lines.push(`"@authority": ${url.host}`);
            }
        } else if (component === '@path') {
            lines.push(`"@path": ${url.pathname}`);
        } else if (component === '@request-target') {
            // @request-target is method + path + query
            lines.push(`"@request-target": ${method.toLowerCase()} ${url.pathname}${url.search}`);
        } else if (component === '@target-uri') {
            // @target-uri is the full URL including protocol and host
            lines.push(`"@target-uri": ${url.protocol}//${url.host}${url.pathname}${url.search}`);
        } else if (component === 'host') {
            // Regular host header
            const hostHeader = headers.find((h: any) => h.name.toLowerCase() === 'host');
            if (hostHeader) {
                lines.push(`"host": ${hostHeader.value}`);
            }
        } else if (component === 'date') {
            // Date header
            const dateHeader = headers.find((h: any) => h.name.toLowerCase() === 'date');
            if (dateHeader) {
                lines.push(`"date": ${dateHeader.value}`);
            }
        } else if (component === 'content-type') {
            // Content-Type header
            const contentTypeHeader = headers.find((h: any) => h.name.toLowerCase() === 'content-type');
            if (contentTypeHeader) {
                lines.push(`"content-type": ${contentTypeHeader.value}`);
            }
        } else if (component === 'content-digest') {
            const contentDigestHeader = headers.find((h: any) => h.name.toLowerCase() === 'content-digest');
            if (contentDigestHeader) {
                lines.push(`"content-digest": ${contentDigestHeader.value}`);
            }
        }
    }

    return lines.join('\n');
}

function signMessageWithKey(signatureBase: string, keyObj: crypto.KeyObject, algorithm: string): string {
    try {
        const keyType = (keyObj as any).asymmetricKeyType || '';

        if (algorithm === 'rsa-pss-sha512') {
            if (keyType !== 'rsa') throw new Error(`Algorithm ${algorithm} requires an RSA key (detected ${keyType || 'unknown'}).`);
            const sign = crypto.createSign('RSA-SHA512');
            sign.update(signatureBase, 'utf8');
            return sign.sign({ key: keyObj, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 64 }, 'base64');
        } else if (algorithm === 'rsa-v1_5-sha256') {
            if (keyType !== 'rsa') throw new Error(`Algorithm ${algorithm} requires an RSA key (detected ${keyType || 'unknown'}).`);
            const sign = crypto.createSign('RSA-SHA256');
            sign.update(signatureBase, 'utf8');
            return sign.sign(keyObj, 'base64');
        } else if (algorithm === 'ecdsa-sha256') {
            if (keyType !== 'ec') throw new Error(`Algorithm ${algorithm} requires an EC key (detected ${keyType || 'unknown'}).`);
            const sign = crypto.createSign('SHA256');
            sign.update(signatureBase, 'utf8');
            return sign.sign(keyObj, 'base64');
        } else if (algorithm === 'ecdsa-sha512') {
            if (keyType !== 'ec') throw new Error(`Algorithm ${algorithm} requires an EC key (detected ${keyType || 'unknown'}).`);
            const sign = crypto.createSign('SHA512');
            sign.update(signatureBase, 'utf8');
            return sign.sign(keyObj, 'base64');
        } else if (algorithm === 'ed25519') {
            if (keyType !== 'ed25519') throw new Error(`Algorithm ${algorithm} requires an Ed25519 key (detected ${keyType || 'unknown'}).`);
            const sig = crypto.sign(null, Buffer.from(signatureBase, 'utf8'), keyObj);
            return sig.toString('base64');
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

export const plugin: PluginDefinition = {
    authentication: httpSigPlugin,
};
