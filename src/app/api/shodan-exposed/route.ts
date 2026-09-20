import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

/**
 * OSIRIS — Exposed Infrastructure (Shodan Search)
 * Source: https://www.shodan.io/  (API docs: developer.shodan.io)
 *
 * Unlike /api/osint/shodan — which hits the free, keyless internetdb.shodan.io
 * for a single IP in the RECON panel — this route uses the authenticated Shodan
 * REST *search* API to pull back many geolocated, internet-exposed hosts at once
 * and render them as a map layer.
 *
 * Requires SHODAN_API_KEY. Fails closed: with no key the route reports itself
 * unconfigured and the map layer stays hidden, mirroring /api/cloudflare-radar
 * and /api/scanner. The key is read server-side only and never returned.
 *
 * Note on Shodan plans: search *filters* (tag:, vuln:, has_screenshot:, …) and
 * paging require a paid membership. A free key can still reach this endpoint but
 * upstream may answer 403 for a filtered query; that is surfaced to the client
 * rather than crashing the layer.
 */

const SEARCH_BASE = 'https://api.shodan.io/shodan/host/search';

/** Curated preset queries. Each is one Shodan search (≤ 1 query credit). */
export const CATEGORIES: Record<string, { query: string; label: string }> = {
  ics:      { query: 'tag:ics',                    label: 'Industrial Control Systems' },
  scada:    { query: 'tag:scada',                  label: 'SCADA Devices' },
  webcam:   { query: 'has_screenshot:true webcam', label: 'Exposed Webcams' },
  database: { query: 'product:MongoDB port:27017', label: 'Exposed Databases' },
  rdp:      { query: 'port:3389',                  label: 'Exposed RDP' },
};

const DEFAULT_CATEGORY = 'ics';
const MAX_DEVICES = 500;

export interface ExposedDevice {
  ip: string;
  lat: number;
  lng: number;
  port: number | null;
  ports: number[];
  transport: string | null;
  org: string | null;
  isp: string | null;
  os: string | null;
  product: string | null;
  country: string | null;
  city: string | null;
  hostnames: string[];
  tags: string[];
  vulns: string[];
  category: string;
  /** Precomputed for the map paint: red when vulnerable, else category colour. */
  color: string;
}

const CATEGORY_COLOR: Record<string, string> = {
  ics: '#FFA726',
  scada: '#FFA726',
  webcam: '#00E5FF',
  database: '#B388FF',
  rdp: '#FF80AB',
};
const VULN_COLOR = '#FF3D3D';
const FALLBACK_COLOR = '#B388FF';

function isConfigured(): boolean {
  return !!process.env.SHODAN_API_KEY;
}

/** Shodan match → normalised device. Returns null when it has no coordinates. */
function normalizeMatch(m: any, category: string): ExposedDevice | null {
  const loc = m?.location ?? {};
  const lat = typeof loc.latitude === 'number' ? loc.latitude : null;
  const lng = typeof loc.longitude === 'number' ? loc.longitude : null;
  if (lat === null || lng === null) return null;

  const vulns = Array.isArray(m?.vulns)
    ? m.vulns
    : m?.vulns && typeof m.vulns === 'object'
      ? Object.keys(m.vulns)
      : [];

  return {
    ip: String(m?.ip_str ?? ''),
    lat,
    lng,
    port: typeof m?.port === 'number' ? m.port : null,
    ports: Array.isArray(m?.ports) ? m.ports.filter((p: any) => typeof p === 'number') : [],
    transport: m?.transport ?? null,
    org: m?.org ?? null,
    isp: m?.isp ?? null,
    os: m?.os ?? null,
    product: m?.product ?? null,
    country: loc.country_name ?? null,
    city: loc.city ?? null,
    hostnames: Array.isArray(m?.hostnames) ? m.hostnames : [],
    tags: Array.isArray(m?.tags) ? m.tags : [],
    vulns,
    category,
    color: vulns.length > 0 ? VULN_COLOR : (CATEGORY_COLOR[category] ?? FALLBACK_COLOR),
  };
}

/** Normalise and de-duplicate a Shodan search payload's matches (by IP). */
export function normalizeMatches(matches: any[], category: string): ExposedDevice[] {
  const seen = new Set<string>();
  const out: ExposedDevice[] = [];
  for (const m of matches ?? []) {
    const d = normalizeMatch(m, category);
    if (!d || !d.ip || seen.has(d.ip)) continue;
    seen.add(d.ip);
    out.push(d);
    if (out.length >= MAX_DEVICES) break;
  }
  return out;
}

export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);

  // Capability probe — lets the UI decide whether to show the layer without
  // provoking an upstream call (and without spending a query credit).
  if (searchParams.get('probe') === '1') {
    return NextResponse.json({
      configured: isConfigured(),
      source: 'Shodan',
      categories: Object.entries(CATEGORIES).map(([id, c]) => ({ id, label: c.label })),
    });
  }

  if (!isConfigured()) {
    return NextResponse.json(
      {
        configured: false,
        devices: [],
        error: 'Shodan not configured',
        hint: 'Set SHODAN_API_KEY (account.shodan.io → API key) in .env',
      },
      { status: 503 },
    );
  }

  // A caller may pass either a known preset category or a raw query. A raw
  // query is trusted to the same degree as the operator running this instance;
  // it is only ever sent to Shodan, never executed locally.
  const categoryParam = searchParams.get('category') ?? DEFAULT_CATEGORY;
  const rawQuery = searchParams.get('q')?.trim();
  const preset = CATEGORIES[categoryParam];
  const category = preset ? categoryParam : 'custom';
  const query = rawQuery || preset?.query || CATEGORIES[DEFAULT_CATEGORY].query;

  const url = new URL(SEARCH_BASE);
  url.searchParams.set('key', process.env.SHODAN_API_KEY as string);
  url.searchParams.set('query', query);
  url.searchParams.set('minify', 'true'); // drop banner bodies — cheaper payload

  try {
    const res = await fetch(url.toString(), {
      signal: AbortSignal.timeout(12000),
      cache: 'no-store',
    });

    if (!res.ok) {
      // 401 bad key · 403 plan does not permit this query · 429 rate limited.
      let detail = `Shodan HTTP ${res.status}`;
      try {
        const body = await res.json();
        if (body?.error) detail = String(body.error);
      } catch { /* non-JSON error body */ }
      return NextResponse.json(
        { configured: true, devices: [], error: 'Shodan search failed', detail, status: res.status },
        { status: res.status === 429 ? 429 : 502 },
      );
    }

    const data = await res.json();
    const devices = normalizeMatches(data?.matches ?? [], category);

    return NextResponse.json(
      {
        configured: true,
        query,
        category,
        total: typeof data?.total === 'number' ? data.total : devices.length,
        returned: devices.length,
        devices,
        timestamp: new Date().toISOString(),
      },
      { headers: { 'Cache-Control': 'public, max-age=300' } },
    );
  } catch (error: any) {
    return NextResponse.json(
      { configured: true, devices: [], error: 'Shodan search failed', detail: error?.message ?? String(error) },
      { status: 502 },
    );
  }
}
