// MITRE ATT&CK technique mapping.
//
// Signals carry technique IDs; this resolves them to names and links. The point
// is to put the finding in language a SOC already uses — "this is T1566.002"
// travels between tools and teams in a way "suspicious link" does not, and it
// gives whoever reads the report a route into ATT&CK's own mitigation and
// detection guidance rather than stopping at our description.

import type { MitreTechnique, Signal } from './types';

const TECHNIQUES: Record<string, string> = {
  T1566: 'Phishing',
  'T1566.001': 'Phishing: Spearphishing Attachment',
  'T1566.002': 'Phishing: Spearphishing Link',
  'T1598.003': 'Phishing for Information: Spearphishing Link',
  T1204: 'User Execution',
  'T1204.001': 'User Execution: Malicious Link',
  'T1204.002': 'User Execution: Malicious File',
  'T1036.007': 'Masquerading: Double File Extension',
  'T1036.008': 'Masquerading: Masquerade File Type',
  T1534: 'Internal Spearphishing',
  T1656: 'Impersonation',
};

function techniqueUrl(id: string): string {
  // Sub-techniques live at /techniques/TXXXX/YYY/ rather than /TXXXX.YYY/.
  const [parent, sub] = id.split('.');
  return sub
    ? `https://attack.mitre.org/techniques/${parent}/${sub}/`
    : `https://attack.mitre.org/techniques/${parent}/`;
}

/** Distinct techniques across every signal that fired, in catalog order. */
function mapTechniques(signals: Signal[]): MitreTechnique[] {
  const ids = new Set<string>();
  for (const signal of signals) {
    for (const id of signal.mitre || []) {
      if (TECHNIQUES[id]) ids.add(id);
    }
  }

  return [...ids]
    .sort()
    .map((id) => ({ id, name: TECHNIQUES[id], url: techniqueUrl(id) }));
}

export { mapTechniques, TECHNIQUES, techniqueUrl };
