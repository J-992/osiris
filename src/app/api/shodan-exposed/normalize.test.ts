import { describe, it, expect } from 'vitest';
import { normalizeMatches, CATEGORIES } from './route';

/* The map layer only ever renders what normalizeMatches returns, so these pin
   the contract it depends on: coordinates required, IPs de-duplicated, vulns
   accepted in either shape Shodan emits, and vulnerable hosts flagged red. */

const match = (over: Record<string, any> = {}) => ({
  ip_str: '198.51.100.7',
  port: 502,
  location: { latitude: 52.37, longitude: 4.89, country_name: 'Netherlands', city: 'Amsterdam' },
  org: 'Example ISP',
  ...over,
});

describe('normalizeMatches', () => {
  it('maps a Shodan match to a device with coordinates', () => {
    const [d] = normalizeMatches([match()], 'ics');
    expect(d.ip).toBe('198.51.100.7');
    expect(d.lat).toBe(52.37);
    expect(d.lng).toBe(4.89);
    expect(d.port).toBe(502);
    expect(d.country).toBe('Netherlands');
    expect(d.category).toBe('ics');
  });

  it('drops matches with no coordinates', () => {
    expect(normalizeMatches([match({ location: {} })], 'ics')).toHaveLength(0);
    expect(normalizeMatches([match({ location: { latitude: 1 } })], 'ics')).toHaveLength(0);
  });

  it('de-duplicates by IP, keeping the first', () => {
    const out = normalizeMatches([match({ port: 502 }), match({ port: 102 })], 'ics');
    expect(out).toHaveLength(1);
    expect(out[0].port).toBe(502);
  });

  it('accepts vulns as an array or an object map', () => {
    expect(normalizeMatches([match({ vulns: ['CVE-2021-1'] })], 'ics')[0].vulns).toEqual(['CVE-2021-1']);
    expect(normalizeMatches([match({ vulns: { 'CVE-2021-2': {} } })], 'ics')[0].vulns).toEqual(['CVE-2021-2']);
  });

  it('paints vulnerable hosts red and clean hosts by category', () => {
    expect(normalizeMatches([match({ vulns: ['CVE-2021-1'] })], 'webcam')[0].color).toBe('#FF3D3D');
    expect(normalizeMatches([match()], 'webcam')[0].color).toBe('#00E5FF');
  });

  it('defines a query for every advertised category', () => {
    for (const [id, c] of Object.entries(CATEGORIES)) {
      expect(c.query, id).toBeTruthy();
      expect(c.label, id).toBeTruthy();
    }
  });
});
