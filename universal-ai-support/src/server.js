import http from 'node:http';
const port = Number(process.env.PORT || 3000);
const server = http.createServer((req, res) => {
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  if (req.url === '/health' && req.method === 'GET') { res.writeHead(200); res.end(JSON.stringify({status:'ok', service:'universal-ai-support'})); return; }
  if (req.url === '/' && req.method === 'GET') { res.writeHead(200); res.end(JSON.stringify({service:'universal-ai-support', status:'running', message:'Universal AI Support API is ready.'})); return; }
  res.writeHead(404); res.end(JSON.stringify({error:'Not found'}));
});
server.listen(port, '0.0.0.0', () => console.log(`Universal AI Support listening on port ${port}`));
