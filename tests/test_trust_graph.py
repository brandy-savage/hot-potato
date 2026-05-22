"""
Tests for TrustGraph — DAG tracing sources to tool calls.
No Docker, no network.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from hot_potato.trust_graph import TrustGraph, TrustNode, TrustEdge, NodeType, EdgeType


class TestTrustGraphBuilding:
    def test_add_and_retrieve_node(self):
        g = TrustGraph()
        node = TrustNode(id="n1", node_type=NodeType.ARTIFACT, label="https://evil.com")
        g.add_node(node)
        nodes = list(g.nodes())
        assert len(nodes) == 1
        assert nodes[0].id == "n1"

    def test_add_artifact(self):
        g = TrustGraph()
        n = g.add_artifact("a1", "https://example.com", "UNTRUSTED")
        assert n.node_type == NodeType.ARTIFACT
        assert n.metadata["trust_level"] == "UNTRUSTED"

    def test_add_tool_call(self):
        g = TrustGraph()
        n = g.add_tool_call("t1", "send_http", "deny")
        assert n.node_type == NodeType.TOOL
        assert n.metadata["outcome"] == "deny"

    def test_add_tool_call_with_triggered_by(self):
        g = TrustGraph()
        g.add_artifact("a1", "https://evil.com", "UNTRUSTED")
        g.add_tool_call("t1", "send_http", "deny", triggered_by=["a1"])
        edges = list(g.edges())
        assert len(edges) == 1
        assert edges[0].source_id == "a1"
        assert edges[0].target_id == "t1"
        assert edges[0].edge_type == EdgeType.INFLUENCED_BY

    def test_link_creates_edge(self):
        g = TrustGraph()
        g.add_artifact("a1", "src", "UNTRUSTED")
        g.add_tool_call("t1", "exec", "allow")
        g.link("a1", "t1", EdgeType.PROMPTED_BY)
        edges = list(g.edges())
        assert any(e.source_id == "a1" and e.target_id == "t1" for e in edges)


class TestTrustGraphQuerying:
    def test_ancestors_direct(self):
        g = TrustGraph()
        g.add_artifact("a1", "src", "UNTRUSTED")
        g.add_tool_call("t1", "exec", "allow", triggered_by=["a1"])
        assert "a1" in g.ancestors("t1")

    def test_ancestors_transitive(self):
        g = TrustGraph()
        g.add_artifact("a1", "src", "UNTRUSTED")
        g.add_artifact("a2", "derived", "UNTRUSTED")
        g.link("a1", "a2", EdgeType.DERIVED_FROM)
        g.add_tool_call("t1", "exec", "allow", triggered_by=["a2"])
        ancs = g.ancestors("t1")
        assert "a1" in ancs
        assert "a2" in ancs

    def test_ancestors_empty_for_root(self):
        g = TrustGraph()
        g.add_artifact("a1", "src", "UNTRUSTED")
        assert g.ancestors("a1") == set()

    def test_descendants_direct(self):
        g = TrustGraph()
        g.add_artifact("a1", "src", "UNTRUSTED")
        g.add_tool_call("t1", "exec", "allow", triggered_by=["a1"])
        assert "t1" in g.descendants("a1")

    def test_descendants_transitive(self):
        g = TrustGraph()
        g.add_artifact("a1", "src", "UNTRUSTED")
        g.add_artifact("a2", "derived", "UNTRUSTED")
        g.link("a1", "a2", EdgeType.DERIVED_FROM)
        g.add_tool_call("t1", "exec", "allow", triggered_by=["a2"])
        descs = g.descendants("a1")
        assert "a2" in descs
        assert "t1" in descs

    def test_descendants_empty_for_leaf(self):
        g = TrustGraph()
        g.add_tool_call("t1", "exec", "allow")
        assert g.descendants("t1") == set()

    def test_untrusted_tool_calls_found(self):
        g = TrustGraph()
        g.add_artifact("untrusted_src", "https://evil.com", "UNTRUSTED")
        g.add_artifact("trusted_src", "file:///app/config.yaml", "TRUSTED")
        g.add_tool_call("t1", "send_http", "deny", triggered_by=["untrusted_src"])
        g.add_tool_call("t2", "read_file", "allow", triggered_by=["trusted_src"])
        unsafe = g.untrusted_tool_calls()
        ids = [n.id for n in unsafe]
        assert "t1" in ids
        assert "t2" not in ids

    def test_untrusted_tool_calls_via_transitive_path(self):
        g = TrustGraph()
        g.add_artifact("a1", "https://evil.com", "UNTRUSTED")
        g.add_artifact("a2", "summary", "UNTRUSTED")
        g.link("a1", "a2", EdgeType.DERIVED_FROM)
        g.add_tool_call("t1", "write_file", "sandbox_only", triggered_by=["a2"])
        unsafe = g.untrusted_tool_calls()
        assert any(n.id == "t1" for n in unsafe)


class TestTrustGraphSerialization:
    def test_to_dict_structure(self):
        g = TrustGraph()
        g.add_artifact("a1", "https://example.com", "UNTRUSTED")
        g.add_tool_call("t1", "send_http", "deny", triggered_by=["a1"])
        d = g.to_dict()
        assert "nodes" in d
        assert "edges" in d
        assert len(d["nodes"]) == 2
        assert len(d["edges"]) == 1

    def test_to_json_valid(self):
        import json
        g = TrustGraph()
        g.add_artifact("a1", "src", "UNTRUSTED")
        j = g.to_json()
        parsed = json.loads(j)
        assert "nodes" in parsed
