import { cachedSource } from '@/lib/sourceCache';
import { loadIbi511Cameras, type Ibi511Source } from './ibi511';

/**
 * OSIRIS — New York CCTV Cameras (511NY / 511ny.org)
 * Source: https://511ny.org — the same IBI 511 stack Arizona and Georgia run
 * ~1,800 cameras statewide — NO API KEY NEEDED.
 *
 * NYSDOT and the Thruway Authority pool their cameras into one index here, so
 * the card credits 511NY rather than either agency: a single row does not say
 * which of the two owns it, and roughly a third of the state's cameras are
 * Thruway. New York City alone is some seven hundred of the total, with the
 * rest along the Thruway, the Southern Tier and the Buffalo and Albany metros.
 *
 * 511NY also publishes a documented REST API at /api/getcameras, but it wants
 * a registered developer key and throttles to 10 calls a minute — no use to a
 * map that refreshes a whole state. The DataTables index every one of these
 * deployments exposes needs neither, which is what the other six read.
 *
 * Unverified: 511NY renders neighbouring-state pages (its New Jersey region
 * view), and no sample row was reachable from the sandbox this was written in
 * to say whether foreign rows also reach the camera index. The bounds below
 * are the state's own, so anything past Albany or out on Long Island is safe,
 * but northern New Jersey sits inside the same box and would survive the
 * filter. The live test asserts on the captions, which is where such a row
 * would show itself.
 */
const NY511: Ibi511Source = {
  base: 'https://511ny.org',
  idPrefix: 'nysdot',
  source: '511NY',
  state: 'New York',
  bounds: { minLat: 40.4, maxLat: 45.1, minLng: -79.9, maxLng: -71.8 },
};

export const fetchNewYorkCameras = cachedSource('newyork', () => loadIbi511Cameras(NY511));
