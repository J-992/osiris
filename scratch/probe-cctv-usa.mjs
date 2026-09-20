/**
 * Probe the candidate camera endpoints for the three US states OSIRIS does not
 * cover yet, and report what each one actually answers.
 *
 * Written because the session that added New York had no egress: its cloud
 * environment was on Trusted network access, so every DOT host came back as a
 * 403 on CONNECT and not one shape could be confirmed. New York went in anyway
 * — 511ny.org is the same IBI 511 deployment as six sources already in the
 * tree, so it reuses loadIbi511Cameras unchanged. Pennsylvania and Texas run
 * something else, and guessing at their payloads would have shipped two
 * modules that quietly return nothing.
 *
 *   node scratch/probe-cctv-usa.mjs            # locally, or on Full/Custom egress
 *   NODE_USE_ENV_PROXY=1 node scratch/...      # Node >= 22.21 behind a proxy
 *
 * Node's built-in fetch ignores HTTPS_PROXY unless that variable is set, which
 * reads as a hang rather than a refusal.
 */

const IBI_QUERY = encodeURIComponent(JSON.stringify({
  columns: [{ data: null, name: '' }, { name: 'sortOrder', s: true }, { name: 'roadway', s: true }, { data: 3, name: '' }],
  order: [{ column: 1, dir: 'asc' }],
  start: 0,
  length: 2,
  search: { value: '' },
}));

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36';

const TARGETS = [
  // ── New York: confirm the assumption newyork.ts is built on ──
  { state: 'NY', label: '511NY DataTables', url: `https://511ny.org/List/GetData/Cameras?query=${IBI_QUERY}&lang=en`, xhr: true },

  // ── Pennsylvania ──
  // Is 511PA the same IBI stack? No prod-pa.ibi511.com host and no
  // /help/endpoint/cameras page turned up for it, unlike every other state in
  // the tree, so this is the question to settle first.
  { state: 'PA', label: '511PA DataTables', url: `https://www.511pa.com/List/GetData/Cameras?query=${IBI_QUERY}&lang=en`, xhr: true },
  // PennDOT's keyless ArcGIS layer. Read the field list before the rows: what
  // matters is whether it carries an image or stream URL per camera, or only
  // a location — a layer of bare points is no use to the map.
  { state: 'PA', label: 'PennDOT ArcGIS layer 14 (fields)', url: 'https://gis.penndot.gov/arcgis/rest/services/paprojects/paprojects/MapServer/14?f=json' },
  { state: 'PA', label: 'PennDOT ArcGIS layer 14 (rows)', url: 'https://gis.penndot.gov/arcgis/rest/services/paprojects/paprojects/MapServer/14/query?where=1%3D1&outFields=*&resultRecordCount=2&f=json' },

  // ── Texas ──
  // TxDOT runs ~4,200 cameras across 25 district sites. The district pages are
  // HTML; the probe scrapes them for whatever address the page itself calls.
  { state: 'TX', label: 'TxDOT ITS Austin district', url: 'https://its.txdot.gov/its/District/AUS/cameras', scrape: true },
  { state: 'TX', label: 'TxDOT ITS district index', url: 'https://its.txdot.gov/its/District/cameras', scrape: true },
  { state: 'TX', label: 'DriveTexas', url: 'https://drivetexas.org/', scrape: true },
  { state: 'TX', label: 'Houston TranStar API docs', url: 'https://traffic.houstontranstar.org/api/api_doc.aspx', scrape: true },
  { state: 'TX', label: 'Austin open data (Socrata)', url: 'https://data.austintexas.gov/resource/b4k4-adkb.json?$limit=2' },
];

/** Addresses a page fetches its own data from — the thing worth probing next. */
function candidateUrls(html) {
  const found = new Set();
  const patterns = [
    /["'`]([^"'`\s]*\/(?:api|json|data|rest|services)\/[^"'`\s]*)["'`]/gi,
    /["'`]([^"'`\s]*\.(?:json|geojson)(?:\?[^"'`\s]*)?)["'`]/gi,
    /["'`]([^"'`\s]*(?:[Cc]amera|CCTV|cctv)[^"'`\s]*\.(?:aspx|json|ashx)[^"'`\s]*)["'`]/g,
  ];
  for (const re of patterns) {
    for (const m of html.matchAll(re)) {
      const u = m[1];
      if (u.length > 4 && u.length < 200 && !/\.(png|jpe?g|gif|svg|css|woff2?)$/i.test(u)) found.add(u);
    }
  }
  return [...found].slice(0, 15);
}

function summarize(json) {
  if (Array.isArray(json)) {
    return `array of ${json.length}; first row keys: ${Object.keys(json[0] ?? {}).join(', ') || '(empty)'}`;
  }
  const keys = Object.keys(json);
  const lines = [`object keys: ${keys.join(', ')}`];
  if (Array.isArray(json.data)) lines.push(`  data[]: ${json.data.length} rows, keys: ${Object.keys(json.data[0] ?? {}).join(', ')}`);
  if (typeof json.recordsTotal === 'number') lines.push(`  recordsTotal: ${json.recordsTotal}  <- IBI 511 stack, loadIbi511Cameras works as is`);
  if (Array.isArray(json.features)) lines.push(`  features[]: ${json.features.length}, attribute keys: ${Object.keys(json.features[0]?.attributes ?? {}).join(', ')}`);
  if (Array.isArray(json.fields)) lines.push(`  fields: ${json.fields.map(f => f.name).join(', ')}`);
  return lines.join('\n');
}

async function probe(t) {
  process.stdout.write(`\n── [${t.state}] ${t.label}\n   ${t.url}\n`);
  try {
    const res = await fetch(t.url, {
      redirect: 'follow',
      signal: AbortSignal.timeout(25_000),
      headers: {
        'User-Agent': UA,
        Accept: t.scrape ? 'text/html,*/*' : 'application/json, text/plain, */*',
        ...(t.xhr ? { 'X-Requested-With': 'XMLHttpRequest' } : {}),
      },
    });
    const body = await res.text();
    console.log(`   HTTP ${res.status} ${res.headers.get('content-type') ?? ''} — ${body.length} bytes`);
    if (!res.ok) return console.log(`   ${body.slice(0, 200).replace(/\s+/g, ' ')}`);

    try {
      console.log('   ' + summarize(JSON.parse(body)).replace(/\n/g, '\n   '));
    } catch {
      if (t.scrape) {
        const urls = candidateUrls(body);
        console.log(urls.length ? `   data addresses in the page:\n     ${urls.join('\n     ')}` : '   HTML, no data address found — open it in a browser and watch the network tab');
      } else {
        console.log(`   not JSON: ${body.slice(0, 200).replace(/\s+/g, ' ')}`);
      }
    }
  } catch (e) {
    console.log(`   FAILED: ${e instanceof Error ? e.message : e}`);
  }
}

for (const t of TARGETS) await probe(t);
console.log('\nDone. A recordsTotal in the NY or PA response means that state needs nothing but an Ibi511Source config.\n');
