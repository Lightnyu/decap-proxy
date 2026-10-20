import { OAuthClient } from './oauth';

interface Env {
  GITHUB_OAUTH_ID?: string;
  GITHUB_OAUTH_CLIENT_ID?: string;
  GITHUB_CLIENT_ID?: string;
  GITHUB_OAUTH_SECRET?: string;
  GITHUB_CLIENT_SECRET?: string;
  GITHUB_REPO_PRIVATE?: string;
}

function randomHex(bytes: number): string {
	const buf = new Uint8Array(bytes);
	crypto.getRandomValues(buf);
	return Array.from(buf)
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
}

const GITHUB_OAUTH_CLIENT_ID_FALLBACK = 'Ov23li3SQqSOZU16Wjcw';

const TRUSTED_EDITOR_ORIGIN = 'https://www.bertoniconstruction.co.uk';
const OAUTH_STATE_COOKIE = 'bertoni_oauth_state';
const stateCookie = (state: string) =>
  OAUTH_STATE_COOKIE + '=' + state + '; Max-Age=600; Path=/callback; Secure; HttpOnly; SameSite=Lax';
const clearStateCookie =
  OAUTH_STATE_COOKIE + '=; Max-Age=0; Path=/callback; Secure; HttpOnly; SameSite=Lax';

const readStateCookie = (request: Request): string => {
  const cookies = request.headers.get('Cookie') || '';
  const item = cookies.split(';').map(part => part.trim())
    .find(part => part.startsWith(OAUTH_STATE_COOKIE + '='));
  return item ? item.slice(OAUTH_STATE_COOKIE.length + 1) : '';
};


const cleanEnvValue = (value?: string) => {
  const cleaned = (value || '').trim();
  if (!cleaned) return '';
  if (['undefined', 'null', 'none'].includes(cleaned.toLowerCase())) return '';
  return cleaned;
};

const getOAuthConfig = (env: Env) => {
  const id =
    cleanEnvValue(env.GITHUB_OAUTH_ID) ||
    cleanEnvValue(env.GITHUB_OAUTH_CLIENT_ID) ||
    cleanEnvValue(env.GITHUB_CLIENT_ID) ||
    GITHUB_OAUTH_CLIENT_ID_FALLBACK;

  const secret =
    cleanEnvValue(env.GITHUB_OAUTH_SECRET) ||
    cleanEnvValue(env.GITHUB_CLIENT_SECRET);

  return { id, secret };
};

const configErrorResponse = (missing: string[]) => {
  const items = missing.map(name => `<li><code>${name}</code></li>`).join('');
  return new Response(
    `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Bertoni CMS authentication configuration</title>
  <style>
    body{font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f7f4ef;color:#252842;margin:0;padding:32px}
    main{max-width:720px;margin:8vh auto;background:white;border:1px solid #ddd8d0;border-radius:18px;padding:28px;box-shadow:0 18px 60px rgba(30,33,58,.08)}
    h1{font-size:26px;margin:0 0 12px}
    p,li{line-height:1.55}
    code{background:#f1eee9;padding:2px 6px;border-radius:6px}
  </style>
</head>
<body>
  <main>
    <h1>CMS sign-in is temporarily unavailable</h1>
    <p>The authentication worker is running, but a required Cloudflare runtime setting is missing.</p>
    <p>Missing configuration:</p>
    <ul>${items}</ul>
    <p>No GitHub login was started, so you will not be sent to a broken 404 page.</p>
  </main>
</body>
</html>`,
    { status: 500, headers: { 'Content-Type': 'text/html; charset=UTF-8', 'Cache-Control': 'no-store' } }
  );
};

const createOAuth = (env: Env) => {
  const { id, secret } = getOAuthConfig(env);
	return new OAuthClient({
		id,
		secret,
		target: {
			tokenHost: 'https://github.com',
			tokenPath: '/login/oauth/access_token',
			authorizePath: '/login/oauth/authorize',
		},
	});
};

const handleAuth = async (url: URL, env: Env) => {
  const { id, secret } = getOAuthConfig(env);
  const missing = [];
  if (!id) missing.push('GITHUB_OAUTH_ID');
  if (!secret) missing.push('GITHUB_OAUTH_SECRET');
  if (missing.length) return configErrorResponse(missing);

	const provider = url.searchParams.get('provider');
	if (provider !== 'github') {
		return new Response('Invalid provider', { status: 400 });
	}

  const repoIsPrivate = env.GITHUB_REPO_PRIVATE != undefined && env.GITHUB_REPO_PRIVATE !== '0';
  const repoScope = repoIsPrivate ? 'repo,user' : 'public_repo,user';

	const oauth2 = createOAuth(env);
	const state = randomHex(32); // 256-bit CSRF nonce, checked on callback
	const authorizationUri = oauth2.authorizeURL({
		redirect_uri: `https://${url.hostname}/callback?provider=github`,
		scope: repoScope,
		state,
	});

	return new Response(null, {
		status: 302,
		headers: {
			location: authorizationUri,
			'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
			Pragma: 'no-cache',
			Expires: '0',
			'X-Bertoni-OAuth-Version': '3',
			'Set-Cookie': stateCookie(state),
			'X-Content-Type-Options': 'nosniff',
			'Referrer-Policy': 'no-referrer',
		},
	});
};


const callbackScriptResponse = (status: string, token: string) => {
  // Only the trusted editor origin may receive the GitHub access token.
  // JSON serialization escapes token data before it enters the script.
  const message = 'authorization:github:' + status + ':' + JSON.stringify({ token });
  const encodedMessage = JSON.stringify(message).replace(/</g, '\\u003c');
  const html = [
    '<!doctype html>',
    '<html lang="en"><head><meta charset="utf-8"><title>Signing in to Bertoni editor</title></head>',
    '<body><p>Completing secure sign-in...</p><script>',
    '(function () {',
    '  var editorOrigin = ' + JSON.stringify(TRUSTED_EDITOR_ORIGIN) + ';',
    '  if (!window.opener || window.opener.closed) return;',
    '  function receiveMessage(event) {',
    '    if (event.origin !== editorOrigin || event.source !== window.opener) return;',
    '    window.removeEventListener("message", receiveMessage, false);',
    '    window.opener.postMessage(' + encodedMessage + ', editorOrigin);',
    '  }',
    '  window.addEventListener("message", receiveMessage, false);',
    '  window.opener.postMessage("authorizing:github", editorOrigin);',
    '}());',
    '</script></body></html>'
  ].join('\\n');
  return new Response(html, {
    headers: {
      'Content-Type': 'text/html; charset=UTF-8',
      'Cache-Control': 'no-store, no-cache, must-revalidate',
      'Set-Cookie': clearStateCookie,
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'no-referrer',
      'Content-Security-Policy': "default-src 'none'; script-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'"
    }
  });
};


const handleCallback = async (url: URL, env: Env, request: Request) => {
  const { id, secret } = getOAuthConfig(env);
  const missing: string[] = [];
  if (!id) missing.push('GITHUB_OAUTH_ID');
  if (!secret) missing.push('GITHUB_OAUTH_SECRET');
  if (missing.length) return configErrorResponse(missing);

  const provider = url.searchParams.get('provider');
  if (provider && provider !== 'github') return new Response('Invalid provider', { status: 400 });

  // Require the nonce issued at /auth; never exchange a code without validating state.
  const state = url.searchParams.get('state') || '';
  const storedState = readStateCookie(request);
  if (!/^[a-f0-9]{64}$/.test(state) || state !== storedState) {
    return new Response('Invalid or expired OAuth state. Please sign in again.', {
      status: 403,
      headers: {
        'Cache-Control': 'no-store',
        'Set-Cookie': clearStateCookie,
        'X-Content-Type-Options': 'nosniff'
      }
    });
  }

  const code = url.searchParams.get('code');
  if (!code) return new Response('Missing code', {
    status: 400,
    headers: { 'Cache-Control': 'no-store', 'Set-Cookie': clearStateCookie }
  });

  const oauth2 = createOAuth(env);
  const accessToken = await oauth2.getToken({
    code,
    redirect_uri: 'https://' + url.hostname + '/callback?provider=github'
  });
  return callbackScriptResponse('success', accessToken);
};

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		const url = new URL(request.url);
    console.log(`url.pathname is ${url.pathname}`);
		if (url.pathname === '/auth' || url.pathname === '/auth-v2') {
			return handleAuth(url, env);
		}
		if (url.pathname === '/health') {
			const oauth = getOAuthConfig(env);
			return Response.json({
				status: 'ok',
				version: 'oauth-v3',
				clientId: oauth.id,
				clientIdConfigured: Boolean(oauth.id),
				clientIdIsUndefined: oauth.id.toLowerCase() === 'undefined',
				redirectUri: `https://${url.hostname}/callback?provider=github`,
				secretConfigured: Boolean(oauth.secret),
				repoPrivate: env.GITHUB_REPO_PRIVATE != undefined && env.GITHUB_REPO_PRIVATE !== '0',
			}, {
				headers: { 'Cache-Control': 'no-store' }
			});
		}
		if (url.pathname === '/callback') {
			return handleCallback(url, env, request);
		}
		return new Response('Hello 👋');
	},
};
