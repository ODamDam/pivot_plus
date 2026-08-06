# Data Directory

This directory is used for local dataset preparation and benchmark generation.

## Directory Layout

| directory | purpose | committed |
| --- | --- | --- |
| `raw/` | Local raw source datasets | no |
| `data_legacy/` | Local backup of previous data artifacts | no |
| `normalized/` | Intermediate normalized candidate pools | no |
| `review/` | Manual review CSV files | no |
| `final/` | Final benchmark artifacts or locked release candidates | selective |
| `inputs/` | Scanner-ready benchmark inputs | selective |
| `seeds/` | Reviewed parent seed archives | selective |

## Policy

Raw datasets and large intermediate files should not be committed.

Final benchmark files may be committed only after manual review, deduplication, license/source checks, and schema validation.
