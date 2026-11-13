# org-fleet-gate

Reusable pull-request check for the FleetHacker public repositories. It scans a pull request for sensitive content, binaries, workflow safety, house rules, and static contrast, and it flags security-relevant changes for a Researcher verdict. A browser accessibility scan stays off unless an admin sets the Actions variable `FLEET_GATE_BROWSER` to `on`. The scripts are Windows PowerShell 5.1 and the jobs run on the org's self-hosted runners.

Imported from the private comms repo `fleethacker-data-crucible/fleethacker-comms-data-crucible` at `04cb65e` (`04cb65e4612ac249772fd0c88019f05609d3e436`).

## Call it

Add `.github/workflows/fleet-gate.yml` in the caller repository:

```yaml
name: fleet-gate
on:
  pull_request:
    branches: [main]
  merge_group:
permissions:
  contents: read
jobs:
  fleet-gate:
    uses: fleethacker-data-crucible/org-fleet-gate/.github/workflows/fleet-gate.yml@<sha>
```

Replace `<sha>` with the full 40-character commit SHA of the `org-fleet-gate` revision you want. `permissions` is `contents: read`. The composite actions inside the called workflow use `$/`, so they come from this repository at that same commit. Repositories whose default branch is `master` should use `branches: [master]`.
