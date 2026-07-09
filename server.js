// 매출관리 AI 직원 - 쿠팡 Open API 로컬 프록시 서버
// 실행: node server.js  (Node.js 18+ 필요, 외부 패키지 설치 불필요)
// 역할: 브라우저(index.html)가 아니라 이 서버가 Coupang Open API에
//       서명(HMAC)된 요청을 보내고, secretKey는 서버 밖으로 절대 나가지 않습니다.

const http = require('http');
const https = require('https');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ---------- .env 읽기 (외부 라이브러리 없이 직접 파싱) ----------
function loadEnv(){
  const envPath = path.join(__dirname, '.env');
  const env = {};
  if(fs.existsSync(envPath)){
    fs.readFileSync(envPath, 'utf8').split(/\r?\n/).forEach(line=>{
      const m = line.match(/^\s*([A-Z_]+)\s*=\s*(.*)\s*$/);
      if(m) env[m[1]] = m[2];
    });
  }
  return env;
}
const env = loadEnv();
const VENDOR_ID = env.VENDOR_ID || '';
const ACCESS_KEY = env.ACCESS_KEY || '';
const SECRET_KEY = env.SECRET_KEY || '';
const PORT = env.PORT || 5500;

if(!VENDOR_ID || !ACCESS_KEY || !SECRET_KEY){
  console.warn('[경고] .env 파일에 VENDOR_ID / ACCESS_KEY / SECRET_KEY 가 설정되지 않았습니다. .env.example을 복사해 입력하세요.');
}

// ---------- 쿠팡 Open API HMAC 서명 ----------
// 문서: https://developers.coupangcorp.com/hc/en-us/articles/360033461914-Creating-HMAC-Signature
function signCoupang(method, pathWithoutQuery, query){
  const now = new Date();
  const pad = n => String(n).padStart(2,'0');
  const signedDate = `${pad(now.getUTCFullYear()%100)}${pad(now.getUTCMonth()+1)}${pad(now.getUTCDate())}` +
                      `T${pad(now.getUTCHours())}${pad(now.getUTCMinutes())}${pad(now.getUTCSeconds())}Z`;
  const message = signedDate + method + pathWithoutQuery + query;
  const signature = crypto.createHmac('sha256', SECRET_KEY).update(message).digest('hex');
  const authorization = `CEA algorithm=HmacSHA256, access-key=${ACCESS_KEY}, signed-date=${signedDate}, signature=${signature}`;
  return authorization;
}

// ---------- 매출내역(revenue-history) 조회 ----------
// 문서: https://developers.coupangcorp.com/hc/en-us/articles/360033922413-Sales-Detail-Query
// 응답 필드명은 쿠팡 정책에 따라 바뀔 수 있으니, normalizeItem()만 상황에 맞게 고치면 됩니다.
function fetchRevenuePage(recognitionDateFrom, recognitionDateTo, token){
  return new Promise((resolve, reject)=>{
    const apiPath = `/v2/providers/openapi/apis/api/v1/revenue-history`;
    const params = new URLSearchParams({ vendorId: VENDOR_ID, recognitionDateFrom, recognitionDateTo, maxPerPage: '50' });
    if(token) params.set('token', token);
    const query = `?${params.toString()}`;
    const authorization = signCoupang('GET', apiPath, query);

    const options = {
      hostname: 'api-gateway.coupang.com',
      path: apiPath + query,
      method: 'GET',
      headers: {
        'Authorization': authorization,
        'X-Requested-By': VENDOR_ID,
        'Content-Type': 'application/json'
      }
    };
    const req = https.request(options, (res)=>{
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', ()=>{
        try{ resolve({ status: res.statusCode, json: JSON.parse(body) }); }
        catch(e){ reject(new Error('쿠팡 응답 파싱 실패: ' + body.slice(0,300))); }
      });
    });
    req.on('error', reject);
    req.end();
  });
}

function normalizeItem(item){
  // 쿠팡 응답 필드명이 다르면 아래 매핑만 수정하세요.
  return {
    date: item.recognitionDate || item.saleDate || '',
    product: item.productName || item.itemName || '(상품명없음)',
    amount: Number(item.saleAmount ?? item.settlementAmount ?? 0),
    qty: Number(item.saleQty ?? item.quantity ?? 1)
  };
}

async function fetchAllRevenue(from, to){
  let token = undefined;
  const all = [];
  for(let page=0; page<50; page++){ // 최대 50페이지 안전장치
    const { status, json } = await fetchRevenuePage(from, to, token);
    if(status !== 200){
      throw new Error(`쿠팡 API 오류 (status ${status}): ${JSON.stringify(json).slice(0,300)}`);
    }
    const items = json.data || json.content || [];
    items.forEach(it => all.push(normalizeItem(it)));
    token = json.nextToken || json.token;
    if(!token || !items.length) break;
  }
  return all.filter(r => r.date && r.amount);
}

// ---------- HTTP 서버 ----------
const server = http.createServer(async (req, res)=>{
  const url = new URL(req.url, `http://localhost:${PORT}`);

  // CORS (index.html을 파일로 직접 열어도 호출 가능하도록 허용)
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  if(req.method === 'OPTIONS'){ res.writeHead(204); res.end(); return; }

  if(url.pathname === '/api/revenue' && req.method === 'GET'){
    const from = url.searchParams.get('from');
    const to = url.searchParams.get('to');
    if(!from || !to){
      res.writeHead(400, {'Content-Type':'application/json'});
      res.end(JSON.stringify({ error: 'from, to 쿼리 파라미터가 필요합니다 (예: ?from=2026-06-01&to=2026-07-06)' }));
      return;
    }
    try{
      const data = await fetchAllRevenue(from, to);
      res.writeHead(200, {'Content-Type':'application/json'});
      res.end(JSON.stringify(data));
    }catch(e){
      res.writeHead(502, {'Content-Type':'application/json'});
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  // 같은 폴더의 index.html도 함께 서빙 (http://localhost:5500 로 접속 가능)
  if(url.pathname === '/' || url.pathname === '/index.html'){
    const file = path.join(__dirname, 'index.html');
    fs.readFile(file, (err, content)=>{
      if(err){ res.writeHead(500); res.end('index.html을 읽을 수 없습니다.'); return; }
      res.writeHead(200, {'Content-Type':'text/html; charset=utf-8'});
      res.end(content);
    });
    return;
  }

  res.writeHead(404, {'Content-Type':'application/json'});
  res.end(JSON.stringify({ error: 'not found' }));
});

server.listen(PORT, ()=>{
  console.log(`매출관리 AI 직원 로컬 서버 실행 중: http://localhost:${PORT}`);
  console.log(`대시보드에서 "로컬 서버에서 가져오기" 버튼으로 실제 쿠팡 매출 데이터를 불러올 수 있습니다.`);
});
