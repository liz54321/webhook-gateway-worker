import { jwtVerify, createRemoteJWKSet } from 'jose';

// Service configuration
interface ServiceConfig {
  path: string;
  backend: string;
  authType: 'telegram-secret' | 'whatsapp-signature' | 'jwt';
  secretToken?: string;
  verifyToken?: string;
  appSecret?: string;
}

interface Environment {
  // Secrets (encrypted)
  TELEGRAM_SECRET_TOKEN: string;
  WHATSAPP_VERIFY_TOKEN: string;
  WHATSAPP_APP_SECRET: string;
  
  // Environment variables (plain text)
  AUTHENTIK_ISSUER: string;
  AUTHENTIK_CLIENT_ID: string;
  
  // Backend URLs
  TELEGRAM_BACKEND: string;
  WHATSAPP_BACKEND: string;
  N8N_BACKEND: string;
}

export default {
  async fetch(request: Request, env: Environment): Promise<Response> {
    // CORS preflight handling
    if (request.method === 'OPTIONS') {
      return handleCORS();
    }

    try {
      const url = new URL(request.url);
      const path = url.pathname;

      // Route determination
      const service = determineService(path);
      if (!service) {
        return createErrorResponse('Unknown endpoint', 404);
      }

      // Get service configuration
      const serviceConfig = getServiceConfig(service, env);
      
      // Handle different HTTP methods
      if (request.method === 'GET') {
        return handleGETRequest(request, service, serviceConfig);
      } else if (request.method === 'POST') {
        return handlePOSTRequest(request, service, serviceConfig, env);
      } else {
        return createErrorResponse('Method not allowed', 405);
      }

    } catch (error) {
      console.error('Worker error:', error);
      return createErrorResponse('Internal server error', 500);
    }
  },
};

function determineService(path: string): string | null {
  if (path.startsWith('/telegram')) return 'telegram';
  if (path.startsWith('/whatsapp')) return 'whatsapp';
  if (path.startsWith('/webhook/')) return 'n8n';
  return null;
}

function getServiceConfig(service: string, env: Environment): ServiceConfig {
  const configs = {
    telegram: {
      path: '/telegram',
      backend: env.TELEGRAM_BACKEND || 'https://telegram-bot.yourdomain.com',
      authType: 'telegram-secret' as const,
      secretToken: env.TELEGRAM_SECRET_TOKEN,
    },
    whatsapp: {
      path: '/whatsapp',
      backend: env.WHATSAPP_BACKEND || 'https://whatsapp-bot.yourdomain.com',
      authType: 'whatsapp-signature' as const,
      verifyToken: env.WHATSAPP_VERIFY_TOKEN,
      appSecret: env.WHATSAPP_APP_SECRET,
    },
    n8n: {
      path: '/webhook',
      backend: env.N8N_BACKEND || 'https://n8n.yourdomain.com',
      authType: 'jwt' as const,
    },
  };

  return configs[service as keyof typeof configs];
}

async function handleGETRequest(
  request: Request,
  service: string,
  config: ServiceConfig
): Promise<Response> {
  // Only WhatsApp uses GET for webhook verification
  if (service === 'whatsapp') {
    return handleWhatsAppVerification(request, config);
  }
  
  return createErrorResponse('GET not supported for this endpoint', 405);
}

async function handleWhatsAppVerification(
  request: Request,
  config: ServiceConfig
): Promise<Response> {
  const url = new URL(request.url);
  const mode = url.searchParams.get('hub.mode');
  const token = url.searchParams.get('hub.verify_token');
  const challenge = url.searchParams.get('hub.challenge');

  if (mode === 'subscribe' && token === config.verifyToken) {
    console.log('WhatsApp webhook verified successfully');
    return new Response(challenge, { status: 200 });
  }

  console.log('WhatsApp webhook verification failed');
  return createErrorResponse('Verification failed', 403);
}

async function handlePOSTRequest(
  request: Request,
  service: string,
  config: ServiceConfig,
  env: Environment
): Promise<Response> {
  // Authenticate request
  const authResult = await authenticateRequest(request, config, env);
  if (!authResult.success) {
    return createErrorResponse(authResult.error || 'Authentication failed', 401);
  }

  // Forward request to backend
  return forwardToBackend(request, config, authResult.transformedPath);
}

async function authenticateRequest(
  request: Request,
  config: ServiceConfig,
  env: Environment
): Promise<{ success: boolean; error?: string; transformedPath?: string }> {
  try {
    switch (config.authType) {
      case 'telegram-secret':
        return authenticateTelegram(request, config);
      
      case 'whatsapp-signature':
        return await authenticateWhatsApp(request, config);
      
      case 'jwt':
        return await authenticateJWT(request, env);
      
      default:
        return { success: false, error: 'Unknown auth type' };
    }
  } catch (error) {
    console.error('Authentication error:', error);
    return { success: false, error: 'Authentication failed' };
  }
}

function authenticateTelegram(
  request: Request,
  config: ServiceConfig
): { success: boolean; error?: string } {
  const token = request.headers.get('x-telegram-bot-api-secret-token');
  
  if (!token || token !== config.secretToken) {
    console.log('Telegram authentication failed: invalid secret token');
    return { success: false, error: 'Invalid secret token' };
  }

  return { success: true };
}

async function authenticateWhatsApp(
  request: Request,
  config: ServiceConfig
): Promise<{ success: boolean; error?: string }> {
  const signature = request.headers.get('x-hub-signature-256');
  
  if (!signature) {
    return { success: false, error: 'Missing signature' };
  }

  // Get request body
  const body = await request.text();
  
  // Calculate expected signature
  const expectedSignature = await generateHMACSHA256(body, config.appSecret!);
  
  if (signature !== expectedSignature) {
    console.log('WhatsApp signature verification failed');
    return { success: false, error: 'Invalid signature' };
  }

  return { success: true };
}

async function authenticateJWT(
  request: Request,
  env: Environment
): Promise<{ success: boolean; error?: string; transformedPath?: string }> {
  const authHeader = request.headers.get('authorization');
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return { success: false, error: 'Missing or invalid authorization header' };
  }

  const token = authHeader.substring(7);
  
  try {
    // Create JWKS client
    const JWKS = createRemoteJWKSet(new URL(`${env.AUTHENTIK_ISSUER}/application/o/authorize/jwks/`));
    
    // Verify JWT
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: env.AUTHENTIK_ISSUER,
      audience: env.AUTHENTIK_CLIENT_ID,
    });

    console.log('JWT verified successfully for user:', payload.sub);
    
    // Transform path to remove /webhook prefix for n8n
    const url = new URL(request.url);
    const transformedPath = url.pathname.replace('/webhook', '');
    
    return { success: true, transformedPath };
  } catch (error) {
    console.error('JWT verification failed:', error);
    return { success: false, error: 'Invalid token' };
  }
}

async function generateHMACSHA256(data: string, secret: string): Promise<string> {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(secret);
  const messageData = encoder.encode(data);

  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign('HMAC', cryptoKey, messageData);
  const hashArray = Array.from(new Uint8Array(signature));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  
  return `sha256=${hashHex}`;
}

async function forwardToBackend(
  request: Request,
  config: ServiceConfig,
  transformedPath?: string
): Promise<Response> {
  try {
    const url = new URL(request.url);
    const targetPath = transformedPath || url.pathname;
    const targetURL = `${config.backend}${targetPath}${url.search}`;

    // Clone the request but modify the URL
    const forwardRequest = new Request(targetURL, {
      method: request.method,
      headers: request.headers,
      body: request.body,
    });

    // Add timeout and better error handling
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30000); // 30s timeout

    try {
      const response = await fetch(forwardRequest, {
        signal: controller.signal,
      });
      
      clearTimeout(timeoutId);
      
      // Create response with security headers
      const responseHeaders = new Headers(response.headers);
      addSecurityHeaders(responseHeaders);
      
      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders,
      });
    } catch (fetchError) {
      clearTimeout(timeoutId);
      throw fetchError;
    }
  } catch (error) {
    console.error('Backend forwarding error:', error);
    
    if (error.name === 'AbortError') {
      return createErrorResponse('Backend timeout', 504);
    }
    
    return createErrorResponse('Backend unavailable', 502);
  }
}

function addSecurityHeaders(headers: Headers): void {
  headers.set('content-security-policy', "default-src 'none'; script-src 'none'; object-src 'none';");
  headers.set('x-content-type-options', 'nosniff');
  headers.set('x-frame-options', 'DENY');
  headers.set('x-xss-protection', '1; mode=block');
  headers.set('referrer-policy', 'no-referrer');
  
  // CORS headers
  headers.set('access-control-allow-origin', '*'); // Adjust as needed
  headers.set('access-control-allow-methods', 'POST, GET, OPTIONS');
  headers.set('access-control-allow-headers', 'Content-Type, Authorization, X-Telegram-Bot-Api-Secret-Token, X-Hub-Signature-256');
}

function handleCORS(): Response {
  return new Response(null, {
    status: 204,
    headers: {
      'access-control-allow-origin': '*',
      'access-control-allow-methods': 'POST, GET, OPTIONS',
      'access-control-allow-headers': 'Content-Type, Authorization, X-Telegram-Bot-Api-Secret-Token, X-Hub-Signature-256',
      'access-control-max-age': '86400',
    },
  });
}

function createErrorResponse(message: string, status: number): Response {
  const errorResponse = {
    error: message,
    timestamp: new Date().toISOString(),
    status,
  };

  return new Response(JSON.stringify(errorResponse), {
    status,
    headers: {
      'content-type': 'application/json',
      'access-control-allow-origin': '*',
    },
  });
}