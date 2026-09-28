/**
 * OWASP Top 10:2025 — the ten categories, and the CWEs OWASP maps to each.
 *
 * ---- Source ------------------------------------------------------------
 *
 * Official, and only official: https://owasp.org/Top10/2025/ (which
 * redirects to OWASP's own https://top10.owasp.org/2025/), retrieved
 * 2026-09-28. The category list is the index page's "Top 10:2025 List"; the
 * CWEs are each category page's "List of Mapped CWEs" section, extracted from
 * the HTML rather than typed, and checked against the same page's "CWEs
 * Mapped" figure — 40, 16, 6, 32, 37, 39, 36, 14, 5, 24, which is 249 CWEs,
 * none of them listed under two categories (`owaspTop10_2025.test.ts` holds
 * all of that).
 *
 * Not from memory and not from a summary: 2025 renumbered the list, and
 * summaries circulate with the 2021 order under the 2025 year. The Semgrep
 * registry itself ships one such label — "A03:2025 - Injection" on an
 * injection rule (p/default, measured 2026-09-28), where A03:2025 is
 * Software Supply Chain Failures. {@link parseOwasp2025Label} refuses a
 * label whose title names another category for exactly that reason.
 *
 * ---- What the mapping is, and is not ----------------------------------
 *
 * Exact CWE ids only. OWASP maps the ids listed; a child of a listed CWE is
 * not listed (CWE-367, TOCTOU, is a child of CWE-362 and is in no 2025
 * category), and walking the CWE hierarchy to find one would be this
 * module's opinion presented as OWASP's. A CWE outside every list maps to
 * nothing, and the finding simply carries no category.
 */

export const OWASP_2025_IDS = [
  'A01:2025',
  'A02:2025',
  'A03:2025',
  'A04:2025',
  'A05:2025',
  'A06:2025',
  'A07:2025',
  'A08:2025',
  'A09:2025',
  'A10:2025',
] as const;
export type Owasp2025Id = (typeof OWASP_2025_IDS)[number];

export interface Owasp2025Category {
  id: Owasp2025Id;
  title: string;
  /** The category's page on owasp.org. */
  url: string;
  /** The CWE numbers OWASP maps to this category, ascending. */
  cwes: readonly number[];
}

const PAGE = 'https://owasp.org/Top10/2025';

export const OWASP_TOP10_2025: readonly Owasp2025Category[] = [
  {
    id: 'A01:2025',
    title: 'Broken Access Control',
    url: `${PAGE}/A01_2025-Broken_Access_Control/`,
    cwes: [
      22, 23, 36, 59, 61, 65, 200, 201, 219, 276, 281, 282,
      283, 284, 285, 352, 359, 377, 379, 402, 424, 425, 441, 497,
      538, 540, 548, 552, 566, 601, 615, 639, 668, 732, 749, 862,
      863, 918, 922, 1275,
    ],
  },
  {
    id: 'A02:2025',
    title: 'Security Misconfiguration',
    url: `${PAGE}/A02_2025-Security_Misconfiguration/`,
    cwes: [
      5, 11, 13, 15, 16, 260, 315, 489, 526, 547, 611, 614,
      776, 942, 1004, 1174,
    ],
  },
  {
    id: 'A03:2025',
    title: 'Software Supply Chain Failures',
    url: `${PAGE}/A03_2025-Software_Supply_Chain_Failures/`,
    cwes: [447, 1035, 1104, 1329, 1357, 1395],
  },
  {
    id: 'A04:2025',
    title: 'Cryptographic Failures',
    url: `${PAGE}/A04_2025-Cryptographic_Failures/`,
    cwes: [
      261, 296, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328,
      329, 330, 331, 332, 334, 335, 336, 337, 338, 340, 342, 347,
      523, 757, 759, 760, 780, 916, 1240, 1241,
    ],
  },
  {
    id: 'A05:2025',
    title: 'Injection',
    url: `${PAGE}/A05_2025-Injection/`,
    cwes: [
      20, 74, 76, 77, 78, 79, 80, 83, 86, 88, 89, 90,
      91, 93, 94, 95, 96, 97, 98, 99, 103, 104, 112, 113,
      114, 115, 116, 129, 159, 470, 493, 500, 564, 610, 643, 644,
      917,
    ],
  },
  {
    id: 'A06:2025',
    title: 'Insecure Design',
    url: `${PAGE}/A06_2025-Insecure_Design/`,
    cwes: [
      73, 183, 256, 266, 269, 286, 311, 312, 313, 316, 362, 382,
      419, 434, 436, 444, 451, 454, 472, 501, 522, 525, 539, 598,
      602, 628, 642, 646, 653, 656, 657, 676, 693, 799, 807, 841,
      1021, 1022, 1125,
    ],
  },
  {
    id: 'A07:2025',
    title: 'Authentication Failures',
    url: `${PAGE}/A07_2025-Authentication_Failures/`,
    cwes: [
      258, 259, 287, 288, 289, 290, 291, 293, 294, 295, 297, 298,
      299, 300, 302, 303, 304, 305, 306, 307, 308, 309, 346, 350,
      384, 521, 613, 620, 640, 798, 940, 941, 1390, 1391, 1392, 1393,
    ],
  },
  {
    id: 'A08:2025',
    title: 'Software or Data Integrity Failures',
    url: `${PAGE}/A08_2025-Software_or_Data_Integrity_Failures/`,
    cwes: [
      345, 353, 426, 427, 494, 502, 506, 509, 565, 784, 829, 830,
      915, 926,
    ],
  },
  {
    id: 'A09:2025',
    // The index page's spelling; the category page's heading writes "&".
    title: 'Security Logging and Alerting Failures',
    url: `${PAGE}/A09_2025-Security_Logging_and_Alerting_Failures/`,
    cwes: [117, 221, 223, 532, 778],
  },
  {
    id: 'A10:2025',
    title: 'Mishandling of Exceptional Conditions',
    url: `${PAGE}/A10_2025-Mishandling_of_Exceptional_Conditions/`,
    cwes: [
      209, 215, 234, 235, 248, 252, 274, 280, 369, 390, 391, 394,
      396, 397, 460, 476, 478, 484, 550, 636, 703, 754, 755, 756,
    ],
  },
];

const BY_ID: ReadonlyMap<string, Owasp2025Category> = new Map(OWASP_TOP10_2025.map((c) => [c.id, c]));

const CATEGORY_OF_CWE: ReadonlyMap<number, Owasp2025Id> = new Map(
  OWASP_TOP10_2025.flatMap((c) => c.cwes.map((n) => [n, c.id] as const)),
);

export function isOwasp2025Id(value: unknown): value is Owasp2025Id {
  return typeof value === 'string' && BY_ID.has(value);
}

export function owasp2025Category(id: Owasp2025Id): Owasp2025Category {
  const found = BY_ID.get(id);
  // Unreachable for a typed id; the fallback keeps the signature total.
  return found ?? { id, title: id, url: `${PAGE}/`, cwes: [] };
}

/** The 2025 category OWASP maps a `CWE-<n>` id to, or null when none lists it. */
export function owaspCategoryOfCwe(cwe: string): Owasp2025Id | null {
  const m = /^CWE-(\d+)$/.exec(cwe);
  if (m === null || m[1] === undefined) return null;
  return CATEGORY_OF_CWE.get(Number.parseInt(m[1], 10)) ?? null;
}

/** Words that do not tell two category titles apart ("and"/"or"/"&" included). */
const TITLE_NOISE = new Set(['and', 'or', 'of', 'the']);

function titleWords(title: string): string {
  return title
    .toLowerCase()
    .replace(/&/g, ' ')
    .split(/[^a-z]+/)
    .filter((w) => w.length > 0 && !TITLE_NOISE.has(w))
    .join(' ');
}

/**
 * A scanner's OWASP label as a 2025 category id, or null.
 *
 * Only the 2025 edition: `A03:2021 - Injection` is refused, never renumbered
 * — 2021's A03 and 2025's A03 are different categories. A label that also
 * carries a title must name the SAME category its id does (compared word
 * by word, ignoring case, punctuation and "and"/"or"/"&", so the registry's
 * "Software and Data Integrity Failures" is 2025's "Software or Data
 * Integrity Failures"); one that names another category is a mislabel and is
 * refused, so the finding falls back to what its CWEs say.
 */
export function parseOwasp2025Label(raw: unknown): Owasp2025Id | null {
  if (typeof raw !== 'string') return null;
  const m = /^\s*A(\d{2})\s*:\s*2025\b\s*(?:[-–—:]\s*)?(.*)$/i.exec(raw);
  if (m === null || m[1] === undefined) return null;
  const id = `A${m[1]}:2025`;
  if (!isOwasp2025Id(id)) return null;
  const title = (m[2] ?? '').trim();
  if (title.length > 0 && titleWords(title) !== titleWords(owasp2025Category(id).title)) return null;
  return id;
}
