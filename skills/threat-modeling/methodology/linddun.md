# LINDDUN (Privacy Threat Modeling)

LINDDUN is STRIDE's privacy-focused cousin. Use it when privacy, GDPR/CCPA compliance, or handling of personal data is a primary concern.

## Categories

| Letter | Threat | Privacy Property Violated |
|--------|--------|----------------------------|
| L | Linkability | Anonymity / pseudonymity |
| I | Identifiability | Anonymity |
| N | Non-repudiation | Plausible deniability |
| D | Detectability | Undetectability |
| D | Disclosure of information | Confidentiality |
| U | Unawareness | User awareness |
| N | Non-compliance | Policy/regulation compliance |

### L - Linkability
Two items of interest (users, sessions, records) can be related despite the attacker not knowing their identity.
**Examples**: Tracking across sites via fingerprinting; correlating anonymous reviews to a user by writing style; cross-device linking via IP.
**Controls**: Pseudonymization with rotating identifiers, k-anonymity, differential privacy, isolated identifiers per context.

### I - Identifiability
An item of interest can be identified to a specific subject.
**Examples**: De-anonymization from quasi-identifiers (ZIP + DOB + gender); license plate in published photo; re-identification from aggregate data.
**Controls**: Data minimization, generalization/suppression, anonymization with provable guarantees (differential privacy).

### N - Non-repudiation (privacy sense)
A user cannot deny having performed an action — violates plausible deniability (e.g. whistleblower, dissident).
**Examples**: Signed logs tying a user to a query; ISP records tying IP to subscriber.
**Controls**: Anonymous credentials, off-the-record messaging protocols, deniable authentication, Tor-style onion routing.

### D - Detectability
Whether an item of interest exists can be observed, even if its content is protected.
**Examples**: Traffic analysis revealing the existence of an encrypted conversation; presence in a database revealable via response-time side channel.
**Controls**: Cover traffic, steganography, constant-time/constant-size responses, oblivious RAM.

### D - Disclosure of Information
Equivalent to STRIDE's Information Disclosure but scoped to personal data.
**Controls**: See STRIDE I controls; add data classification, DLP, purpose-limitation enforcement.

### U - Unawareness
User lacks awareness of how their data is collected, processed, or shared.
**Examples**: Dark patterns in consent UIs; third-party trackers not disclosed; default opt-in to data sharing.
**Controls**: Clear privacy notices, just-in-time consent, privacy dashboards, data subject access portals.

### N - Non-compliance
System does not comply with legal, regulatory, or corporate policy.
**Examples**: Retaining EU PII beyond lawful basis; processing without legal basis; violating purpose limitation.
**Controls**: Records of processing activities (ROPA), data protection impact assessments (DPIA), privacy-by-design reviews, automated retention enforcement.

## Analysis Process

1. Build a DFD with data-subject data flows clearly marked.
2. For each data flow, store, and process handling personal data: apply LINDDUN categories.
3. Map identified threats to applicable regulatory articles (GDPR Art. 5, 25, 32, 35; CCPA §1798.100; etc.).
4. Design privacy-enhancing technologies (PETs) as mitigations.
5. Document residual privacy risk.

## When to Use LINDDUN

- Any system processing personal data subject to GDPR, CCPA, PIPEDA, LGPD, POPIA.
- Health, education, children's data platforms.
- Anonymization/pseudonymization pipelines.
- AI/ML systems that train on personal data (add model-inversion and membership-inference to the threat set).

## Relation to STRIDE

LINDDUN's `Disclosure` overlaps STRIDE's `Information Disclosure`. In practice, run STRIDE first, then layer LINDDUN on top for the personal-data subset — most of STRIDE's mitigations help but LINDDUN surfaces privacy-specific properties (especially L, I, D-detectability, U).
