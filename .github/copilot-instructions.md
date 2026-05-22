<!-- CMMC Artifact Gathering Tool - Project Setup Instructions -->

## Project Overview
Enterprise CMMC artifact gathering tool for Microsoft Windows environments designed for MSPs and organizations. Collects compliance data from Windows endpoints, Active Directory, security events, and policy configurations. Supports multiple output formats (JSON, CSV, XML, HTML reports) with MSP-specific features for third-party compliance presentation.

## Key Features

### Data Collection
- Windows endpoint data (OS, updates, security products)
- Active Directory objects and configurations
- Windows Security Event Logs
- Group Policy and security policy configurations

### MSP Capabilities
- Multi-tenant support for managing multiple customers
- Professional compliance reporting for third parties
- Executive summary generation with compliance scoring
- Automatic findings and recommendations
- Data filtering for sensitive information

### Export Formats
- JSON (data interchange)
- CSV (spreadsheet analysis)
- XML (enterprise integration)
- HTML (professional reports)
- MSP Report (compliance presentation)

## Architecture

### Core Components
- `CMMCGatherer`: Main orchestrator for artifact collection
- `Collectors`: Endpoint, AD, EventLog, and Policy collectors
- `Exporters`: Multi-format export with MSP-specific reporting
- `Models`: Data models for artifacts and collections
- `Utils`: Compliance scoring, data filtering, tenant management

### Project Structure
```
cmmc/
├── src/
│   └── cmmc_gatherer/
│       ├── collectors/     # Data collection modules
│       ├── exporters/      # Export format implementations
│       ├── models/         # Data models
│       ├── utils/          # Utility functions
│       ├── gatherer.py     # Main orchestrator
│       └── cli.py          # Command-line interface
├── tests/                  # Test suite
├── setup.py               # Package configuration
├── requirements.txt       # Dependencies
├── README.md              # Full documentation
└── .github/               # GitHub configuration
```

## Setup Checklist

- [x] Create copilot-instructions.md file
- [x] Get project setup info for Python
- [x] Scaffold the project structure
- [x] Customize for CMMC requirements with MSP features
- [x] Create core collectors (Endpoint, AD, EventLog, Policy)
- [x] Create exporters (JSON, CSV, XML, HTML, MSP Report)
- [x] Create utility modules (ComplianceScorer, DataFilter, TenantManager, ReportBuilder)
- [x] Create CLI interface
- [x] Create comprehensive test suite
- [x] Create setup.py and requirements.txt
- [x] Create detailed README documentation
- [x] Ensure project structure is complete

## Installation & Usage

### Install
```bash
pip install -r requirements.txt
pip install -e .
```

### Basic Collection
```python
from cmmc_gatherer import CMMCGatherer

gatherer = CMMCGatherer()
artifacts = gatherer.collect_all()
gatherer.export('msp_report', 'compliance_report.html')
```

### Multi-Tenant Reporting
```python
from cmmc_gatherer.utils import TenantManager

manager = TenantManager()
for customer_id, artifacts in collected_data.items():
    manager.add_tenant(customer_id, artifacts)

scores = manager.calculate_tenant_scores()
```

### CLI Usage
```bash
cmmc-gatherer collect --output artifacts.json --format msp_report
cmmc-gatherer report --customer "Acme Corp" --output report.html
```

## Next Steps
- Implement remote collection via WinRM/RPC for distributed environments
- Add database backend for historical data
- Create web dashboard for real-time monitoring
- Implement scheduled collection and reporting

