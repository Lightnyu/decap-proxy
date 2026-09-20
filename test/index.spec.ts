// test/index.spec.ts
import { SELF } from 'cloudflare:test';
import { describe, it, expect, vi, afterEach } from 'vitest';

afterEach(() => {
	vi.unstubAllGlobals();
});

describe('GET /', () => {
	it('responds with no-op (Hello)', async () => {
		const response = await SELF.fetch('https://example.com');
		expect(await response.text()).toMatchInlineSnapshot(`"Hello 👋"`);
	});
});

describe('GET /auth', () => {
	it('fails clearly instead of redirecting with an undefined OAuth client ID', async () => {
		const response = await SELF.fetch('https://example.com/auth?provider=github');
		expect(response.status).toBe(500);
		const responseBody = await response.text();
		expect(responseBody).toContain('CMS sign-in is temporarily unavailable');
		expect(responseBody).toContain('GITHUB_OAUTH_ID');
		expect(responseBody).toContain('GITHUB_OAUTH_SECRET');
	});
});

describe('GET /callback', () => {
	it('fails clearly when OAuth runtime configuration is unavailable', async () => {
		const response = await SELF.fetch('https://example.com/callback?provider=github&code=some-authorization-code');
		expect(response.status).toBe(500);
		const responseBody = await response.text();
		expect(responseBody).toContain('CMS sign-in is temporarily unavailable');
	});
});
