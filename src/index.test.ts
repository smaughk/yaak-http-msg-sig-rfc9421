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
        expect(authPlugin.args.length).toBe(6); // Now 6 because the last 2 fields are wrapped in an accordion
    });

    test('Has new additional fields in accordion', () => {
        const authPlugin = plugin.authentication;
        // Find the accordion
        const accordion = authPlugin.args.find(arg => arg.type === 'accordion');
        expect(accordion).toBeDefined();
        expect(accordion?.label).toBe('Additional Options');
        expect(accordion?.inputs).toBeDefined();
        expect(accordion?.inputs?.length).toBe(2);
        
        // Check the fields inside the accordion
        const additionalFields = accordion?.inputs || [];
        expect(additionalFields[0].name).toBe('additionalSignatureInput');
        expect(additionalFields[1].name).toBe('signatureField');
    });
});
