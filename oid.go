package pki

import "encoding/asn1"

var (
	// ── AIC OIDs ──
	OIDAIC              = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 1, 1}
	OIDAICAgentIdentity = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 1, 1, 1}
	// DelegationAuthorization is AIC tree .1.1.2 (principal signature evidence, former name UserAuth before v1.5).
	OIDAICDelegationAuthorization = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 1, 1, 2}
	// DelegationDepthControl (.1.1.4, spec v1.7.2 §3.7, FUTURE delegation depth control):
	// chainDepth = .1.1.4.1, maxDepth = .1.1.4.2. Parsed with P1-11 delegation chain implementation.
	OIDDelegationDepthControl = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 1, 1, 4}
	OIDDDCChainDepth          = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 1, 1, 4, 1}
	OIDDDCMaxDepth            = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 1, 1, 4, 2}

	// ── Signature algorithm OIDs ──
	OIDSigECDSAWithSHA256  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	OIDSigECDSAWithSHA384  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	OIDSigECDSAWithSHA512  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	OIDSigRSAWithSHA256    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	OIDSigRSAWithSHA384    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	OIDSigRSAWithSHA512    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	OIDSigRSAPSSWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	OIDSigEd25519          = asn1.ObjectIdentifier{1, 3, 101, 112}

	// ── PrincipalAuthorization ──
	OIDPrincipalAuthorization = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 1, 2}

	// ── Gateway Session ──
	OIDGatewaySession = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 1, 5}

	// ── Capability Scheme Registry (reserved) ──
	OIDCapabilitySchemeRegistry = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 1, 3}

	// ── Vendor Extension Registry (reserved) ──
	OIDVendorExtensionRegistry = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 1, 4}

	// ── RenewalToken ──
	OIDRenewalToken = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 1, 6}

	// ── 3.x Certification Extensions ──
	OIDIdentityExt      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 1}
	OIDCertificationExt = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 3}
	OIDMarketAccessId   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 3, 1}
	OIDTrustLevel       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 3, 2}
	OIDCrossBorder      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 3, 3}

	// ── 5.x GM Algorithms ──
	OIDGM        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 5}
	OIDSM2Sig    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 5, 1}
	OIDSM3Hash   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 5, 2}
	OIDSM4Enc    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 5, 3}
	OIDSM2SM3Sig = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 5, 4}

	// ── 6.x Certificate Transparency ──
	OIDCT    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 6}
	OIDCTSCT = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 6, 1}
	OIDCTLog = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 6, 2}

	// ── Hash algorithm OIDs ──
	OIDSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	OIDSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)
