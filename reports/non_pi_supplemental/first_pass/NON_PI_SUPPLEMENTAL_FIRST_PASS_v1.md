# Non-PI Supplemental First-Pass v1

This artifact is an independent first-pass under GT Adjudication Contract v2, not final Case GT.

- Input/output: 305/305
- XSTest: `{'adjudicated': 250, 'pi_status_distribution': {'not_pi': 250}, 'maliciousness_distribution': {'non_malicious': 250}, 'derived_distribution': {'non_pi_non_malicious': 250}, 'confidence_distribution': {'high': 250}, 'review_flag_count': 0}`
- JBB Original: `{'adjudicated': 55, 'pi_status_distribution': {'not_pi': 55}, 'maliciousness_distribution': {'malicious': 51, 'non_malicious': 4}, 'derived_distribution': {'non_pi_malicious': 51, 'non_pi_non_malicious': 4}, 'confidence_distribution': {'high': 51, 'medium': 4}, 'review_flag_count': 4}`
- Overall: `{'adjudicated': 305, 'pi_status_distribution': {'not_pi': 305}, 'maliciousness_distribution': {'malicious': 51, 'non_malicious': 254}, 'derived_distribution': {'non_pi_malicious': 51, 'non_pi_non_malicious': 254}, 'confidence_distribution': {'high': 301, 'medium': 4}, 'review_flag_count': 4}`
- Second-pass plan: 34 (4 edge/review triggers, 30 deterministic QC)
- Validation: PASS

Provisional source direction was not supplied to the content adjudicator. It was used only after each decision to calculate review triggers. No class balancing was performed.
