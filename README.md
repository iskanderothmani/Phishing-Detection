# Phishing Detection

A safe, explainable phishing-message triage prototype that scores suspicious text and URLs without opening links or contacting domains.

## Problem and solution
Security teams need repeatable triage that is explainable, auditable, and safe to test. This repository provides a small local-first prototype with transparent rules and synthetic examples.

## Features
- Inspect message text and visible URLs as strings only
- Flag urgency, credential requests, mismatched link cues, and URL shorteners
- Explain every signal contributing to the score
- No email access, link opening, or live reputation lookup

## Requirements
- Python 3.10+
- Standard library only

## Quick start
```bash
python app.py
```
Some tools accept a file or directory path; run `python app.py` without arguments to see usage where applicable.

## Safety and scope
This is an educational proof of concept, not a production security control. Test only with systems, files, and data you own or are authorized to assess. Do not commit credentials, personal information, real incident logs, or confidential company data. Findings are heuristic and require human validation.

## Roadmap
- Add automated unit tests and CI
- Add structured logging and configuration
- Add signed sample datasets and richer reporting
- Validate against documented test cases before production use

## License
MIT
