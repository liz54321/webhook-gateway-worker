// Simplified worker that routes everything to n8n
interface Env {
  AUTHENTIK_ISSUER: string;
  AUTHENTIK_CLIENT_ID: string;
  TELEGRAM_SECRET_TOKEN: string;
  WHATSAPP_VERIFY_TOKEN: string;
  WHATSAPP_APP_SECRET: string;
  N8N_BACKEND: string;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    console.log(`Processing ${request.method} ${path}`);

    try {
      // Route based on path
      if (path.startsWith('/telegram')) {
        return await handleTelegram(request, env);
      } else if (path.startsWith('/whatsapp')) {
        return await handleWhatsApp(request, env);
      } else if (path.startsWith('/webhook/')) {
        return await handleN8nWebhook(request, env);
      } else {
        return new Response('Webhook Gateway Active', { 
          status: 200,
          headers: { 'Content-Type': 'text/plain' }
        });
      }
    } catch (error) {
      console.error('Error processing request:', error);
      return new Response('Internal Server Error', { status: 500 });
    }
  },
};

async function handleTelegram(request: Request, env: Env): Promise<Response> {
  // Verify Telegram webhook secret
  const secretToken = request.headers.get('x-telegram-bot-api-secret-token');
  if (secretToken !== env.TELEGRAM_SECRET_TOKEN) {
    return new Response('Unauthorized', { status: 401 });
  }

  // Forward directly to n8n telegram webhook
  const n8nUrl = `${env.N8N_BACKEND}/webhook/telegram`;
  
  return await forwardRequest(request, n8nUrl);
}

async function handleWhatsApp(request: Request, env: Env): Promise<Response> {
  if (request.method === 'GET') {
    // Handle WhatsApp webhook verification
    const url = new URL(request.url);
    const mode = url.searchParams.get('hub.mode');
    const token = url.searchParams.get('hub.verify_token');
    const challenge = url.searchParams.get('hub.challenge');

    if (mode === 'subscribe' && token === env.WHATSAPP_VERIFY_TOKEN) {
      return new Response(challenge, { status: 200 });
    } else {
      return new Response('Forbidden', { status: 403 });
    }
  }

  // Verify WhatsApp webhook signature for POST requests
  if (request.method === 'POST') {
    const signature = request.headers.get('x-hub-signature-256');
    if (signature && env.WHATSAPP_APP_SECRET) {
      const body = await request.clone().text();
      if (!await verifyWhatsAppSignature(body, signature, env.WHATSAPP_APP_SECRET)) {
        return new Response('Unauthorized', { status: 401 });
      }
    }

    // Forward to n8n WhatsApp webhook
    const n8nUrl = `${env.N8N_BACKEND}/webhook/whatsapp`;
    return await forwardRequest(request, n8nUrl);
  }

  return new Response('Method not allowed', { status: 405 });
}

async function handleN8nWebhook(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const webhookPath = url.pathname.substring('/webhook/'.length);
  
  // Forward to n8n with the webhook path
  const n8nUrl = `${env.N8N_BACKEND}/webhook/${webhookPath}${url.search}`;
  
  return await forwardRequest(request, n8nUrl);
}

async function forwardRequest(request: Request, targetUrl: string): Promise<Response> {
  const headers = new Headers(request.headers);
  
  // Remove hop-by-hop headers
  headers.delete('connection');
  headers.delete('upgrade');
  
  const response = await fetch(targetUrl, {
    method: request.method,
    headers: headers,
    body: request.method !== 'GET' ? await request.clone().arrayBuffer() : null,
  });

  // Return the response from n8n
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers,
  });
}

async function verifyWhatsAppSignature(body: string, signature: string, secret: string): Promise<boolean> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const hmac = await crypto.subtle.sign('HMAC', key, encoder.encode(body));
  const expectedSignature = 'sha256=' + Array.from(new Uint8Array(hmac))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');

  return expectedSignature === signature;
}