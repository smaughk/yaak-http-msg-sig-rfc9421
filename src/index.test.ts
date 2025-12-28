import { describe, expect, test } from 'vitest';
import {plugin} from "./index";

describe('HTTP Signature Plugin', () => {
    test('Exports plugin object', () => {
        expect(plugin).toBeTypeOf('object');
        expect(plugin.authentication).toBeDefined();
    });

    test('Has authentication plugin properties', () => {
        const authPlugin = plugin.authentication;
        expect(authPlugin.name).toBe('http-sig');
        expect(authPlugin.label).toBe('HTTP Message Signatures (RFC 9421)');
        expect(authPlugin.onApply).toBeTypeOf('function');
        expect(authPlugin.args).toBeDefined();
        expect(authPlugin.args.length).toBe(7);
    });

    test('Has new additional fields', () => {
        const authPlugin = plugin.authentication;
        const additionalFields = authPlugin.args.filter(arg => 
            arg.name === 'additionalSignatureInput' || arg.name === 'signatureField'
        );
        expect(additionalFields.length).toBe(2);
        expect(additionalFields[0].name).toBe('additionalSignatureInput');
        expect(additionalFields[1].name).toBe('signatureField');
    });
});
