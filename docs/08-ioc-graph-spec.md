# 08 — IOC Graph Specification

**Status:** implementation-backed

## Nodes

The graph includes the observed email, sender, optional Reply-To/Return-Path, extracted IP/domain/URL/email indicators, mail servers from the routing timeline, and GeoIP/ASN enrichment nodes.

## Edges

- `SENT_BY`
- `REPLIES_TO`
- `BOUNCES_TO`
- `CONTAINS`
- `ROUTED_VIA`
- `USES`
- `RESOLVES_TO`
- `GEOLOCATED_AS`
- `BELONGS_TO`

Each observed IOC node retains its evidence ID and provenance. External nodes are marked `EXTERNAL_INTELLIGENCE`.

## UI behavior

The investigator graph is a selectable SVG view. Selecting a node shows type, label, provenance, and bounded metadata. It is an investigation aid, not an automated attribution graph.
