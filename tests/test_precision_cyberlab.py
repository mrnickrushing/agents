"""Precision regressions from the first real dashboard scans of a Drizzle +
pnpm monorepo (cyberlab): 17 false "no foreign key" findings and lockfile
contents mistaken for a manifest."""

from agents.database_architect import DatabaseArchitectAgent
from agents.supply_chain_audit import SupplyChainAuditAgent

DRIZZLE = """
export const findingsTable = pgTable("findings", {
  id: uuid("id").primaryKey().defaultRandom(),
  userId: uuid("user_id")
    .notNull()
    .references(() => usersTable.id, { onDelete: "cascade" }),
  targetId: uuid("target_id").references(() => targetsTable.id, {
    onDelete: "set null",
  }),
  cveId: text("cve_id"),
  workerJobId: text("worker_job_id"),
  ownerId: uuid("owner_id").notNull(),
});
"""


def _constraint_columns(code):
    result = DatabaseArchitectAgent()._review_constraints(code)
    return {f["column"] for f in result["findings"] if "column" in f}


def test_multiline_references_count_as_foreign_keys():
    columns = _constraint_columns(DRIZZLE)
    assert "userId" not in columns
    assert "targetId" not in columns
    # External identifiers are not relations either.
    assert "cveId" not in columns and "workerJobId" not in columns
    # A genuinely unreferenced relational column is still reported.
    assert "ownerId" in columns


def test_lockfiles_are_not_judged_as_manifests():
    agent = SupplyChainAuditAgent()
    lock = (
        "lockfileVersion: '9.0'\n"
        "packages:\n"
        "  '@types/react-dom@19.2.0':\n"
        "    peerDependencies:\n"
        "      '@types/react': '*'\n"
        "  react@19.1.0:\n"
        "    resolution: {integrity: sha512-x}\n"
        "    dependencies:\n"
        "      loose-envify: ^1.1.0\n"
    )
    issues = {
        f["issue"]
        for f in agent._audit_supply_chain(lock, path="pnpm-lock.yaml")["findings"]
    }
    assert not any("Wildcard" in i for i in issues)
    assert "Manifest uses broad version ranges" not in issues

    manifest = '{"dependencies": {"left-pad": "*", "react": "^19.1.0"}}'
    issues = {
        f["issue"]
        for f in agent._audit_supply_chain(manifest, path="package.json")["findings"]
    }
    assert any("Wildcard" in i for i in issues)
    # Caret ranges with a lockfile are the norm, not a finding…
    assert not any("open-ended" in i for i in issues)
    # …a library's peer range is meant to be wide…
    peer = '{"peerDependencies": {"react": ">=18"}, "dependencies": {"clsx": "^2.1.1"}}'
    issues = {
        f["issue"]
        for f in agent._audit_supply_chain(peer, path="package.json")["findings"]
    }
    assert not any("open-ended" in i for i in issues)
    # …open-ended ones still are.
    loose = '{"dependencies": {"express": ">=4", "lodash": "4.x"}}'
    issues = {
        f["issue"]
        for f in agent._audit_supply_chain(loose, path="package.json")["findings"]
    }
    assert any("open-ended" in i for i in issues)


def test_dockerfile_install_checks_know_pnpm_and_global_tools():
    from agents.railway_deploy import RailwayDeployAgent

    review = RailwayDeployAgent()._review_deployment_config
    ok = (
        "FROM node:22-slim\nRUN npm install -g pnpm@10\n"
        "COPY package.json pnpm-lock.yaml ./\nRUN pnpm install --frozen-lockfile\n"
    )
    assert not any(
        "lockfile-strict" in f["issue"] for f in review(ok, "Dockerfile")["findings"]
    )
    loose = "FROM node:22-slim\nRUN pnpm install --no-frozen-lockfile\n"
    assert any(
        "pnpm install --frozen-lockfile" in f["issue"]
        for f in review(loose, "Dockerfile")["findings"]
    )


def test_commented_env_example_entries_count_as_documented():
    from agents.config_audit import ConfigAuditAgent

    agent = ConfigAuditAgent()
    example = "DATABASE_URL=postgres://x\n# Optional\n# SHODAN_API_KEY=\n"
    documented = agent._audit_env_example(example, ".env.example")
    assert documented is not None
    # The parser is exercised through the scanner's cross-file check; here we
    # only assert the commented key is not itself reported as a problem.
    assert not any(
        "SHODAN_API_KEY" in f.get("issue", "") for f in documented.get("findings", [])
    )
