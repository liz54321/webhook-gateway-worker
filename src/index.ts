// Truly simplified worker - no security checks, just forwards everything
interface Env {
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
        return new Response('Webhook Gateway Active - Simplified Version', {
          status: 200,
          headers: { 'Content-Type': 'text/plain' }
        });
      }
    } catch (error) {
      console.error('Error processing request:', error);
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      return new Response(`Internal Server Error: ${errorMessage}`, { status: 500 });
    }
  },
};

async function handleTelegram(request: Request, env: Env): Promise<Response> {
  // No security check - directly forward to n8n
  console.log('Forwarding Telegram request to n8n');
  const n8nUrl = `${env.N8N_BACKEND}/webhook/telegram`;
  return await forwardRequest(request, n8nUrl);
}

async function handleWhatsApp(request: Request, env: Env): Promise<Response> {
  if (request.method === 'GET') {
    // Simple WhatsApp verification - accept any challenge
    const url = new URL(request.url);
    const challenge = url.searchParams.get('hub.challenge');
    
    if (challenge) {
      console.log('WhatsApp verification - returning challenge');
      return new Response(challenge, { status: 200 });
    } else {
      return new Response('Missing challenge parameter', { status: 400 });
    }
  }

  // For POST requests, forward to n8n
  console.log('Forwarding WhatsApp request to n8n');
  const n8nUrl = `${env.N8N_BACKEND}/webhook/whatsapp`;
  return await forwardRequest(request, n8nUrl);
}

async function handleN8nWebhook(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const webhookPath = url.pathname.substring('/webhook/'.length);

  console.log(`Forwarding webhook /${webhookPath} to n8n`);

  // Forward to n8n with the webhook path
  const n8nUrl = `${env.N8N_BACKEND}/webhook/${webhookPath}${url.search}`;

  return await forwardRequest(request, n8nUrl);
}

async function forwardRequest(request: Request, targetUrl: string): Promise<Response> {
  console.log(`Forwarding ${request.method} to ${targetUrl}`);

  const headers = new Headers(request.headers);

  // Remove hop-by-hop headers
  headers.delete('connection');
  headers.delete('upgrade');
  headers.delete('host'); // Let fetch set the correct host

  try {
    const response = await fetch(targetUrl, {
      method: request.method,
      headers: headers,
      body: request.method !== 'GET' ? await request.clone().arrayBuffer() : null,
    });

    console.log(`n8n responded with status: ${response.status}`);

    // Return the response from n8n
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
    });
  } catch (error) {
    console.error('Error forwarding to n8n:', error);
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return new Response(`Error forwarding to n8n: ${errorMessage}`, {
      status: 502,
      headers: { 'Content-Type': 'text/plain' }
    });
  }
}