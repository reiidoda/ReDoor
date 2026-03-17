# Foundation from Shared PDF Manuals

This enterprise documentation aligns with engineering themes from a curated set of architecture, security, and software-engineering reference PDFs.

## 1. Architecture and System Design Foundations

| Reference | Applied in Redoor Docs |
|---|---|
| `Building.Microservices.pdf` | bounded contexts, service interfaces, independent scaling |
| `Designing Data-Intensive Applications ...pdf` | event-driven integration, reliability tradeoffs, data ownership |
| `OReilly.Fundamentals.of.Software.Architecture.2020.1.pdf` | architecture characteristics and design tradeoff framing |
| `Site Reliability Engineering.pdf` | SLO/error budget model, reliability-driven operations |
| `SEv3.pdf` / software engineering references | requirements traceability, quality and maintenance governance |

## 2. Security and Cryptography Foundations

| Reference | Applied in Redoor Docs |
|---|---|
| `cryptography_engineering_design_principles_and_practical_applications.pdf` | key management, safe crypto usage boundaries |
| `seriouscrytography.pdf` | modern cryptographic hygiene and implementation caution |
| `Understanding cryptography ...pdf` | protocol primitive choices and threat considerations |
| `[Jonathan_Katz.pdf` | formal cryptographic security mindset and adversary models |
| `API Security in Action.pdf` / `ecure-apis-design-build-and-implement-1.pdf` | API authn/authz, replay protection, schema hardening |

## 3. Quality and Testing Foundations

| Reference | Applied in Redoor Docs |
|---|---|
| `Art of Unit Testing.pdf` | test strategy layering and deterministic testing philosophy |
| `Clean Code.pdf` | maintainability and modular boundaries |
| `Computer Systems A Programmers Perspective ...pdf` | performance reasoning and systems-level constraints |
| `practical packet analysis 3rd edition.pdf` | protocol telemetry and network troubleshooting practices |

## 4. How These References Are Used

- as **design guidance**, not strict implementation mandates;
- combined with repository-specific constraints (RAM-first client behavior, privacy-centric transport);
- translated into actionable architecture, testing, security, and operational controls in `docs/enterprise/`.

