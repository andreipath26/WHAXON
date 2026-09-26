# WHAXON

<p align="center">
  <strong>One platform. Every layer of security.</strong>
</p>

<p align="center">
  A modular, portable cybersecurity testing platform built to unify security tools, workflows, and assessment capabilities.
</p>

<p align="center">
  <a href="https://github.com/andreipath26/WHAXON">Repository</a> ·
  <a href="https://github.com/andreipath26/WHAXON/issues">Issues</a> ·
  <a href="https://github.com/andreipath26/WHAXON/discussions">Discussions</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Status-In%20Development-orange?style=for-the-badge" alt="Project Status: In Development" />
  <img src="https://img.shields.io/badge/Language-Python-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/License-AGPL--3.0--or--later-green?style=for-the-badge" alt="License: AGPL-3.0-or-later" />
</p>

---

## Overview

**WHAXON** is an extensible cybersecurity platform inspired by the legacy of BackTrack and Kali Linux.

Designed for security professionals, penetration testers, researchers, and cybersecurity enthusiasts, WHAXON aims to bring a wide range of security tools and assessment workflows into one unified environment.

Built around Python, the project is designed to support a modular architecture with a centralized tool catalog, a flexible plugin system, and a shared backend powering both graphical and terminal-based interfaces.

WHAXON follows a **hybrid open-source and commercial model**, combining a free Community Edition with commercial licensing options and proprietary enterprise add-ons.

> **Project status:** Under active development. Features, architecture, and commercial offerings are subject to change.

---

## ✨ Core Features

| Feature                      | Description                                                           |
| ---------------------------- | --------------------------------------------------------------------- |
| 🧩 Modular Architecture      | Extend functionality through plugins and adapters.                    |
| 🛠️ Centralized Tool Catalog | Organize security tools and manage their availability.                |
| 🖥️ Desktop Interface        | Planned graphical application using PySide6.                          |
| ⌨️ Terminal Interface        | Planned terminal-based workflow using Textual.                        |
| 🔌 Plugin System             | Integrate external tools without tightly coupling them to the core.   |
| ⚙️ Shared Backend            | Reuse services, configuration, and execution logic across interfaces. |
| 📂 Evidence Management       | Organize assessment results and supporting evidence.                  |
| 📊 Reporting                 | Support structured findings and assessment reports.                   |
| 🌐 Future API Support        | Architecture designed with potential remote integrations in mind.     |

*Features are planned and may not yet be implemented.*

---

## 🔍 Security Domains

WHAXON is designed to support security assessment workflows across multiple domains.

| Domain             | Planned Capabilities                              |
| ------------------ | ------------------------------------------------- |
| Reconnaissance     | Asset discovery and information gathering         |
| Web & API Security | Web application and API testing                   |
| Network Security   | Network discovery and vulnerability assessment    |
| Identity Security  | Active Directory and identity assessments         |
| Cloud Security     | Cloud configuration and security reviews          |
| Mobile Security    | Mobile application testing                        |
| Firmware & IoT     | Embedded systems and connected device assessments |
| Digital Forensics  | Evidence collection and investigation             |
| Malware Analysis   | Malware research and analysis workflows           |
| Reporting          | Findings, evidence, and report generation         |

---

## 🏗️ Architecture

WHAXON is planned around a shared core with multiple interfaces and a modular tool integration layer.

```text
                         WHAXON
                            │
              ┌─────────────┴─────────────┐
              │                           │
         Desktop UI                  Terminal UI
          (PySide6)                   (Textual)
              │                           │
              └─────────────┬─────────────┘
                            │
                      Core Services
                            │
           ┌────────────────┼────────────────┐
           │                │                │
       Tool Catalog    Plugin Registry   Job & Scope
                                         Management
           │                │                │
           └────────────────┼────────────────┘
                            │
                      Tool Adapters
                            │
              ┌─────────────┼─────────────┐
              │             │             │
           Local CLI     Containers      APIs
              │             │             │
              └─────────────┼─────────────┘
                            │
                      Security Tools
                            │
                   Findings & Evidence
                            │
                        Reporting
```

The architecture aims to keep the core independent from individual tools and interfaces, making WHAXON easier to maintain, extend, and adapt.

---

## 💻 Technology Stack

| Component          | Technology                                                            |
| ------------------ | --------------------------------------------------------------------- |
| Core Backend       | Python                                                                |
| Desktop Interface  | PySide6                                                               |
| Terminal Interface | Textual (planned)                                                     |
| Tool Integration   | Plugins and adapters                                                  |
| External Tools     | System packages, upstream utilities, and containers where appropriate |
| Future API         | Planned                                                               |

---

## 💼 Editions & Licensing

WHAXON is designed around a hybrid licensing model that supports open-source development while providing commercial options for organizations.

### 🟢 WHAXON Community

**Free and open source**

The Community Edition is intended to provide a useful, self-hosted cybersecurity testing platform.

* Core platform and plugin framework
* Tool catalog and supported local execution workflows
* Community-supported integrations
* Basic assessment and reporting capabilities
* Public development and community contributions

**Planned license:** GNU Affero General Public License v3.0 or later (`AGPL-3.0-or-later`).

Users may use, modify, and redistribute the Community Edition in accordance with the license terms.

### 🔵 WHAXON Commercial Core

**Commercial licensing available**

Organizations may obtain a separate commercial license for the core platform under alternative licensing terms.

Potential offerings include:

* Alternative licensing terms for qualifying deployments
* Commercial integration and redistribution rights as defined in the agreement
* Optional support and maintenance
* Custom licensing arrangements

Commercial licensing does not mean that commercial use is prohibited under the AGPL.

### 🟣 WHAXON Enterprise

**Paid proprietary add-ons**

The Enterprise offering is planned to extend the platform with capabilities for teams and organizations.

Potential features include:

* Team and multi-user management
* Centralized assessment coordination
* Advanced reporting and compliance workflows
* Enterprise integrations and automation
* Priority support and deployment assistance

Enterprise components will be distributed under separate commercial terms.

*Commercial licensing and Enterprise features are planned offerings and may not yet be available.*

---

## 🗺️ Roadmap

### Core Platform

* [ ] Establish the core Python architecture
* [ ] Implement the centralized tool catalog
* [ ] Build the plugin and adapter framework
* [ ] Add tool installation and update workflows
* [ ] Develop the PySide6 desktop interface
* [ ] Develop the terminal interface
* [ ] Implement scope and job management
* [ ] Add findings and evidence management
* [ ] Introduce report generation

### Enterprise & Commercial

* [ ] Define the commercial licensing framework
* [ ] Establish contributor licensing procedures
* [ ] Define Community and Enterprise feature boundaries
* [ ] Develop enterprise add-ons
* [ ] Evaluate team and multi-user management
* [ ] Introduce advanced reporting and integrations
* [ ] Establish commercial support and maintenance options

### Ecosystem

* [ ] Expand integrations across security domains
* [ ] Improve third-party license tracking
* [ ] Evaluate future remote API support
* [ ] Publish plugin development documentation

---

## 🚀 Getting Started

WHAXON is currently under development. Installation instructions will be published once a stable, tested setup is available.

### Clone the repository

```bash
git clone https://github.com/andreipath26/WHAXON.git
cd WHAXON
```

Additional setup instructions, dependencies, and launch commands will be documented as development progresses.

---

## 🤝 Contributing

Contributions, ideas, bug reports, and feature suggestions are welcome.

Before contributing:

1. Check the existing [Issues](https://github.com/andreipath26/WHAXON/issues).
2. Open an issue to discuss substantial changes or new integrations.
3. Review the contribution guidelines once available.

Contributions may be subject to a Contributor License Agreement (CLA) to support the project's dual-licensing model.

When contributing, prioritize:

* Maintainability and clear documentation
* Safe and authorized execution
* Compatibility with the WHAXON architecture
* Respect for third-party licenses

---

## 📦 Third-Party Components

WHAXON is designed to integrate external security tools and libraries.

Third-party components may be governed by their own licenses, which remain applicable to those components.

Their inclusion does not imply ownership by WHAXON.

A third-party license inventory will be maintained as integrations are added.

---

## 🛡️ Responsible Use

WHAXON is intended for authorized security testing, defensive security operations, research, and education.

Only use WHAXON and its integrated tools on systems you own or have explicit permission to assess.

Users are responsible for complying with applicable laws, regulations, and engagement rules.

---

## 📜 License

The planned license for the WHAXON Community Edition is **GNU Affero General Public License v3.0 or later (`AGPL-3.0-or-later`)**.

The project intends to offer separate commercial licensing for the core and proprietary licensing for qualifying Enterprise add-ons.

Third-party components remain subject to their respective licenses.

See the repository's licensing documentation for details. Commercial licensing terms and Enterprise offerings are subject to formal agreements and availability.

---

## 📬 Contact & Commercial Inquiries

For commercial licensing, enterprise partnerships, support, or other business inquiries, please visit the repository:

**[github.com/andreipath26/WHAXON](https://github.com/andreipath26/WHAXON)**

---

<p align="center">
  <strong>WHAXON</strong><br/>
  <em>One platform. Every layer of security.</em>
</p>

<p align="center">
  <a href="https://github.com/andreipath26/WHAXON">GitHub Repository</a>
</p>
