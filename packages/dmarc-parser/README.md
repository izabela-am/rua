# @rua/dmarc-parser

Parses DMARC aggregate (RUA) reports as defined in RFC 7489 appendix C. No I/O, no dependencies on the rest of Rua.

```ts
import { decompress, parseAggregateReport, ReportError } from "@rua/dmarc-parser";

const xml = decompress(attachmentBytes);       // gzip, zip (one .xml member) or plain XML
const report = parseAggregateReport(xml);      // throws ReportError on bad input
```

Reports are hostile input. The limits below are enforced and each one has a fixture in `fixtures/` or a test that generates one.

| Limit | Default | Error code |
| --- | --- | --- |
| Attachment size | 5 MB | `too_large` |
| Decompressed size | 50 MB, counted while streaming | `too_large` |
| Zip members | exactly one `.xml`, no directories | `nested_archive` |
| Archive inside archive | rejected | `nested_archive` |
| DTD and entity declarations | rejected before parsing | `not_xml` |
| XML depth | 16 | `not_xml` |
| Records | 100,000 | `too_large` |

Pass a partial `Limits` object as the second argument to override any of them.
