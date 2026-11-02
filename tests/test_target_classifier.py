"""Tests for target classifier and contract grouper.

Covers: classify_target, expand_targets (subdomain merge), group_contracts.
"""

from __future__ import annotations

from pathlib import Path

from hunter.workflow.target_classifier import (
    classify_target,
    expand_targets,
    group_contracts,
)


# ---------------------------------------------------------------------------
# classify_target
# ---------------------------------------------------------------------------


def test_classify_api_subdomain():
    """https://api.* → api"""
    assert classify_target("https://api.relay.link") == "api"
    assert classify_target("https://api.example.com/v1/status") == "api"
    assert classify_target("https://api-relay.link") == "api"


def test_classify_web_docs():
    """https://docs.* or *.link → web"""
    assert classify_target("https://docs.relay.link") == "web"
    assert classify_target("https://doc.relay.link") == "web"
    assert classify_target("https://relay.link") == "web"


def test_classify_github_repo():
    """github.com/<owner>/<repo> → repo"""
    assert classify_target("https://github.com/relaychain/relay-hub") == "repo"
    assert classify_target("https://github.com/user/repo/tree/main") == "repo"


def test_classify_github_repo_shorthand():
    """owner/repo shorthand → repo"""
    assert classify_target("relaychain/relay-hub") == "repo"


def test_classify_contract_dir(tmp_path):
    """Local directory with .sol files → contract"""
    (tmp_path / "Hub.sol").write_text("// dummy")
    assert classify_target(str(tmp_path)) == "contract"


def test_classify_bridge_path():
    """Deposit/mint/bridge paths → bridge_path"""
    assert classify_target("https://relay.link/bridge") == "bridge_path"
    assert classify_target("https://relay.link/deposit") == "bridge_path"
    assert classify_target("https://relay.link/mint") == "bridge_path"


def test_classify_regular_url():
    """Regular HTTP URL without special patterns → api"""
    assert classify_target("https://rpc.chain.relay.link") == "api"
    assert classify_target("https://example.com/some/path") == "api"


def test_classify_empty():
    """Empty/whitespace target → unknown"""
    assert classify_target("") == "unknown"
    assert classify_target("   ") == "unknown"


def test_classify_unknown():
    """Unrecognized strings → unknown"""
    assert classify_target("just-some-text") == "unknown"
    assert classify_target("not:a:url") == "unknown"


# ---------------------------------------------------------------------------
# expand_targets — subdomain merge
# ---------------------------------------------------------------------------


def test_expand_no_subdomain_merge():
    """Without allow_subdomains, each target stays separate."""
    targets = [
        "https://api.relay.link/v1",
        "https://docs.relay.link",
    ]
    result = expand_targets(targets, allow_subdomains=False)
    assert len(result) == 2
    kinds = {t["kind"] for t in result}
    assert kinds == {"api", "web"}


def test_expand_subdomain_merge():
    """With allow_subdomains=True, api.relay.link + docs.relay.link → *.relay.link."""
    targets = [
        "https://api.relay.link/v1",
        "https://docs.relay.link",
    ]
    result = expand_targets(targets, allow_subdomains=True)
    assert len(result) == 1
    assert result[0]["target"] == "*.relay.link"
    assert result[0]["merged"] is True
    assert "api.relay.link" in result[0]["hosts"]
    assert "docs.relay.link" in result[0]["hosts"]
    # Most specific kind wins (api > web)
    assert result[0]["kind"] == "api"


def test_expand_single_target_no_merge_needed():
    """A single target with allow_subdomains is not merged."""
    targets = ["https://api.relay.link"]
    result = expand_targets(targets, allow_subdomains=True)
    assert len(result) == 1
    assert result[0]["target"] == "https://api.relay.link"
    assert result[0].get("merged") is None


def test_expand_different_domains_no_merge():
    """Different root domains stay separate even with allow_subdomains=True."""
    targets = [
        "https://api.relay.link",
        "https://api.example.com",
    ]
    result = expand_targets(targets, allow_subdomains=True)
    assert len(result) == 2


def test_expand_empty_list():
    """Empty input → empty output."""
    assert expand_targets([]) == []
    assert expand_targets([], allow_subdomains=True) == []


def test_expand_mixed_targets():
    """Mix of URL and non-URL targets."""
    targets = [
        "https://api.relay.link",
        "https://github.com/org/repo",
        "just-text",
    ]
    result = expand_targets(targets, allow_subdomains=False)
    assert len(result) == 3
    kinds = {t["kind"] for t in result}
    assert kinds == {"api", "repo", "unknown"}


# ---------------------------------------------------------------------------
# group_contracts
# ---------------------------------------------------------------------------


def test_group_contracts_empty_dir(tmp_path):
    """Empty directory → empty result."""
    assert group_contracts(str(tmp_path)) == []


def test_group_contracts_missing_dir():
    """Non-existent directory → empty result."""
    assert group_contracts("/nonexistent/path/12345") == []


def test_group_contracts_classifies_50_plus_contracts(tmp_path):
    """Create 50+ .sol files across all 9 families and verify grouping."""
    contracts_dir = tmp_path / "contracts"
    contracts_dir.mkdir()

    # Hub family
    (contracts_dir / "RelayHub.sol").write_text("//")
    (contracts_dir / "HubBase.sol").write_text("//")
    (contracts_dir / "ERC20View.sol").write_text("//")
    (contracts_dir / "ERC20Permit.sol").write_text("//")

    # Oracle family
    (contracts_dir / "RelayOracleV2.sol").write_text("//")
    (contracts_dir / "RelayOracleMultisig.sol").write_text("//")
    (contracts_dir / "RelayOracleIdempotencyStore.sol").write_text("//")

    # Depository family
    (contracts_dir / "RelayDepository.sol").write_text("//")
    (contracts_dir / "RelayExecutor.sol").write_text("//")
    (contracts_dir / "RelayGatewayDepository.sol").write_text("//")

    # Allocator family
    (contracts_dir / "RelayAllocator.sol").write_text("//")
    (contracts_dir / "WithdrawGasPayer.sol").write_text("//")

    # Payload family
    (contracts_dir / "PayloadBuilder.sol").write_text("//")
    (contracts_dir / "GatewayVm.sol").write_text("//")
    (contracts_dir / "GasPaid.sol").write_text("//")
    (contracts_dir / "EmptyPayload.sol").write_text("//")

    # Pricing family
    (contracts_dir / "RelayPriceOracle.sol").write_text("//")
    (contracts_dir / "RelayBpsFeeCalculator.sol").write_text("//")
    (contracts_dir / "SignedPricingOracle.sol").write_text("//")

    # Rate limit family
    (contracts_dir / "RelayUsdRateLimiter.sol").write_text("//")
    (contracts_dir / "RelayAmountRateLimiter.sol").write_text("//")

    # Mapping family
    (contracts_dir / "RelayGenericMapping.sol").write_text("//")
    (contracts_dir / "GenericMappingBase.sol").write_text("//")

    # Funding family
    (contracts_dir / "RelayFundingPool.sol").write_text("//")
    (contracts_dir / "RelayFundingPoolFactory.sol").write_text("//")

    # Additional contracts to reach 50+ (variants with suffixes)
    extra_names = [
        "RelayHubV2", "RelayHubV3", "RelayHubProxy",
        "RelayOracleV3", "RelayOracleProxy",
        "RelayDepositoryV2",
        "RelayAllocatorV2", "RelayAllocatorV3",
        "PayloadBuilderV2", "PayloadBuilderV3", "GatewayVmV2",
        "RelayPriceOracleV2",
        "RelayUsdRateLimiterV2", "RelayUsdRateLimiterV3",
        "RelayGenericMappingV2",
        "RelayFundingPoolV2", "RelayFundingPoolV3",
        "RelayExecutorV2",
        "HubBaseV2", "ERC20ViewV2",
        "RelayGatewayDepositoryV2",
        "SignedPricingOracleV2",
        "RelayAmountRateLimiterV2",
        "GenericMappingBaseV2",
        "RelayGatewayDepositoryV3",
    ]
    for name in extra_names:
        (contracts_dir / f"{name}.sol").write_text("//")

    total = len(list(contracts_dir.glob("*.sol")))
    assert total >= 50, f"Expected 50+ contracts, got {total}"

    result = group_contracts(str(contracts_dir))

    # All 9 families should be present
    families_found = {g["family"] for g in result}
    expected = {"hub", "oracle", "depository", "allocator", "payload",
                "pricing", "rate_limit", "mapping", "funding"}
    assert expected.issubset(families_found)

    # Verify each family has its core contracts
    for group in result:
        names = [Path(c).stem for c in group["contracts"]]
        if group["family"] == "hub":
            assert "RelayHub" in names
        elif group["family"] == "oracle":
            assert "RelayOracleV2" in names
        elif group["family"] == "depository":
            assert "RelayDepository" in names
        elif group["family"] == "allocator":
            assert "RelayAllocator" in names
        elif group["family"] == "payload":
            assert "PayloadBuilder" in names
        elif group["family"] == "pricing":
            assert "RelayPriceOracle" in names
        elif group["family"] == "rate_limit":
            assert "RelayUsdRateLimiter" in names
        elif group["family"] == "mapping":
            assert "RelayGenericMapping" in names
        elif group["family"] == "funding":
            assert "RelayFundingPool" in names

    # Total count across all families
    total_grouped = sum(g["count"] for g in result)
    assert total_grouped == total


def test_group_contracts_unclassified(tmp_path):
    """Contracts that don't match any family go to unclassified."""
    d = tmp_path / "unknowns"
    d.mkdir()
    (d / "RandomContract.sol").write_text("//")
    (d / "AnotherWeirdOne.sol").write_text("//")

    result = group_contracts(str(d))
    assert len(result) == 1
    assert result[0]["family"] == "unclassified"
    assert result[0]["count"] == 2


def test_group_contracts_nested_directories(tmp_path):
    """Contracts in subdirectories are found recursively."""
    d = tmp_path / "nested"
    d.mkdir()
    sub = d / "hub"
    sub.mkdir()
    (sub / "RelayHub.sol").write_text("//")

    result = group_contracts(str(d))
    assert len(result) >= 1
    hub_group = next(g for g in result if g["family"] == "hub")
    assert "hub/RelayHub.sol" in hub_group["contracts"]


def test_group_contracts_with_path(tmp_path):
    """From parent directory, group_contracts handles a path argument."""
    d = tmp_path / "sol"
    d.mkdir()
    (d / "RelayHub.sol").write_text("//")
    (d / "PayloadBuilder.sol").write_text("//")

    result = group_contracts(str(d))
    families = {g["family"] for g in result}
    assert "hub" in families
    assert "payload" in families


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_classify_bridge_path_lock():
    """URLs with 'lock' in path → bridge_path."""
    assert classify_target("https://bridge.relay.link/lock") == "bridge_path"


def test_classify_bridge_path_send():
    """URLs with 'send' in path → bridge_path."""
    assert classify_target("https://relay.link/send") == "bridge_path"


def test_classify_bridge_path_relay_path():
    """URLs with 'relay' in path → bridge_path."""
    assert classify_target("https://gateway.example.com/relay/tokens") == "bridge_path"


def test_classify_transfer_path():
    """URLs with 'transfer' in path → bridge_path."""
    assert classify_target("https://relay.link/transfer/eth") == "bridge_path"


def test_classify_github_not_a_repo():
    """A domain that looks like github but isn't → not repo."""
    # "github.io" is not github.com — falls through to default api
    assert classify_target("https://myproject.github.io") == "api"


def test_expand_three_way_merge():
    """Three subdomains of the same root merge into one."""
    targets = [
        "https://api.relay.link",
        "https://docs.relay.link",
        "https://rpc.relay.link",
    ]
    result = expand_targets(targets, allow_subdomains=True)
    assert len(result) == 1
    assert result[0]["target"] == "*.relay.link"
    assert result[0]["merged"] is True


def test_expand_bridge_path_merge():
    """bridge.relay.link is classified as bridge_path and merges correctly."""
    targets = [
        "https://bridge.relay.link",
        "https://api.relay.link",
    ]
    result = expand_targets(targets, allow_subdomains=True)
    assert len(result) == 1
    # bridge_path has higher priority than api
    assert result[0]["kind"] == "bridge_path"