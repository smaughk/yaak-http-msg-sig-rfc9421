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
        expect(authPlugin.args.length).toBe(5);
    });
});
