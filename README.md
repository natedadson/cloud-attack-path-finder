# Cloud Attack Path Finder

**AWS IAM Privilege Escalation Detection & Visualization**

*Research project by Nathaniel Dadson* | *Independent Security Research*

---

## Overview

**The Problem:** Individual IAM policies often look harmless, but combinations can create privilege escalation paths. A developer with Policy A + Policy B might be able to assume an admin role. Security teams cannot manually review millions of possible permission combinations.

**The Solution:** Cloud Attack Path Finder builds a directed graph of all IAM relationships and discovers attack paths from any user to admin-equivalent privileges.

---

## Architecture

```mermaid
flowchart TD
    subgraph AWS["AWS Account"]
        Users[IAM Users]
        Roles[IAM Roles]
        Policies[IAM Policies]
    end

    subgraph Tool["Attack Path Finder"]
        Builder["Graph Builder\n- Discover identities\n- Extract trust policies\n- Build relationship graph"]
        Analyzer["Path Analyzer\n- Find shortest paths\n- Detect escalation\n- Risk scoring"]
        Viz["Visualization\n- Graph layout\n- Color by risk\n- Export images"]
        
        Builder --> Analyzer --> Viz
    end

    Users --> Builder
    Roles --> Builder
    Policies --> Builder
    Viz --> Output["attack_paths.png"]
How It Works
Attack Path Example
text
User: developer@example.com
  → can_assume → lambda-execution-role
  → can_pass_role → ec2-instance
  → has_instance_profile → admin-role

RESULT: 3-step privilege escalation to admin
Graph Theory Application
Nodes: IAM users, roles, groups, resources

Edges: Permissions (can_assume, can_pass, can_access)

Path Finding: Shortest path algorithms identify fastest escalation routes

Prerequisites
Requirement	Version
Python	3.9+
AWS Account	Free tier
AWS CLI	2.x+
Installation
bash
git clone https://github.com/natedadson/cloud-attack-path-finder.git
cd cloud-attack-path-finder

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

aws configure --profile cloud-attack-path-finder
Usage
Build the Privilege Graph
bash
python src/graph/iam_graph.py
Visualize Attack Paths
bash
python src/visualization/graph_viz.py
Expected Output
text
============================================================
Building IAM Privilege Graph
============================================================
🔍 Discovering IAM users...
  ✓ Found 1 IAM users
🔍 Discovering IAM roles...
  ✓ Found 2 IAM roles

============================================================
Graph Statistics
============================================================
  Total Nodes: 4
  Total Edges: 2

============================================================
🔴 PRIVILEGE ESCALATION PATHS
============================================================

✅ No privilege escalation paths found

💾 Graph saved to iam_graph.gpickle
📊 Graph saved to iam_graph.png
Project Structure
text
cloud-attack-path-finder/
├── README.md
├── requirements.txt
├── .gitignore
├── src/
│   ├── graph/
│   │   └── iam_graph.py          # Graph builder
│   ├── analysis/
│   │   └── path_finder.py        # Coming soon
│   └── visualization/
│       └── graph_viz.py          # Graph visualization
├── tests/
├── data/
└── outputs/
Risk Detection
Risk Level	Edge Type	Example
HIGH	can_assume	User → Admin Role
MEDIUM	service_can_assume	Lambda → Role
LOW	can_access	Role → S3 Bucket
Development Roadmap
Phase	Status
Graph Builder	✅ Complete
Trust Relationship Detection	✅ Complete
Visualization	✅ Complete
Multi-Step Path Analysis	📅 Planned
Remediation Recommendations	📅 Planned
Toxic Combination Detection	📅 Planned
Research Publications
This tool supports the following research:

"Graph-Based Privilege Escalation Detection in AWS IAM" (Q4 2026)

License
MIT License

Author
Nathaniel Dadson

Independent Security Researcher

GitHub: github.com/natedadson

Independent research - not affiliated with any employer.

Last Updated
June 2026
