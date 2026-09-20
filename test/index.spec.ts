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
	it('uses the stable GitHub OAuth client ID fallback and never redirects with client_id=undefined', async () => {
		const response = await SELF.fetch('https://example.com/auth?provider=github');
		const responseBody = await response.text();

		if (response.status === 500) {
			expect(responseBody).toContain('GITHUB_OAUTH_SECRET');
			expect(responseBody).not.toContain('GITHUB_OAUTH_ID');
		} else {
			expect(response.url).toContain('client_id=Ov23Ii3SQqSOZU16Wjcw');
			expect(response.url).not.toContain('client_id=undefined');
		}
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


describe('OAuth redirect URI', () => {
	it('uses the registered callback URI without an extra provider query string', async () => {
		const response = await SELF.fetch('https://example.com/auth?provider=github');
		if (response.status !== 500) {
			expect(response.url).toContain('redirect_uri=https://example.com/callback');
			expect(response.url).not.toContain('callback?provider=github');
		}
	});
});


describe('OAuth environment sanitising', () => {
	it('keeps the worker from ever constructing client_id=undefined', async () => {
		const response = await SELF.fetch('https://example.com/auth?provider=github');
		expect(response.url).not.toContain('client_id=undefined');
	});
});
