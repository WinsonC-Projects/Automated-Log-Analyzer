# Demonstration dataset

`demo_auth.log` is a **synthetic** training fixture, not real incident evidence.
Use assumed year **2026** when importing.
Expected: **6** recognized events (**4 failures**, **2 successes**), **66.7%** failure rate, **2** source IPs, most active source **192.168.1.50** with **4** events.
One unsupported sshd line and one repeat summary should be flagged for review, not silently expanded.
