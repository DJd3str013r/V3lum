# icij_offshore fixtures (batch p3-G10-1, P221)

Trimmed samples of the ICIJ Offshore Leaks bulk CSV (`full-oldb.LATEST.zip`, generated 2026-09-09), captured
2026-11-26 with HTTP range requests (the officers and addresses members were never fetched):

* `bulk_entities_sample.csv` - the real header and five real company rows (address column blanked); node
  `99000001` is synthetic (documentation values, ISO dates, a Pandora-style sourceID).
* `bulk_intermediaries_sample.csv` - real header, three real corporate intermediaries (address blanked) and the
  synthetic `99100001`.
* `bulk_officers_sample.csv` - the ICIJ data-dictionary header with synthetic rows only (no real person).
* `bulk_relationships_sample.csv` - real header and three real id-only rows; the officer_of / intermediary_of /
  address / similar rows are synthetic and touch only the synthetic `99xxxxxx` nodes (no claim about a real entity).
* `bulk_zip_members.json` - the archive's central directory (member names and sizes).

Contains information from the ICIJ Offshore Leaks Database (International Consortium of Investigative
Journalists), made available under the Open Database License (ODbL); database contents under Creative Commons
Attribution-ShareAlike (CC BY-SA). Test data only: never bundled in the package (A6).
