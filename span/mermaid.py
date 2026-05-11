# Copyright 2026 Lupus Maximus Security, LLC
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of the copyright holder nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""Mermaid diagram output for SPAN.

See ``specs/mermaid.md`` for the design.
"""

import re

from IPython.display import display, Markdown, HTML


DIRECTIONS = ("LR", "RL", "TB", "BT")

# shape -> (open, close) Mermaid wrappers around the label.
NODE_SHAPES = {
    "rect":       ("[",   "]"),
    "round":      ("(",   ")"),
    "stadium":    ("([",  "])"),
    "cylinder":   ("[(",  ")]"),
    "subroutine": ("[[",  "]]"),
    "hex":        ("{{",  "}}"),
}

EDGE_STYLES = {
    # style -> (plain_arrow, labeled_left, labeled_right)
    "solid":  ("-->",  "--",   "-->"),
    "dotted": ("-.->", "-.",   ".->"),
    "thick":  ("==>",  "==",   "==>"),
}

# Higher number wins when the same node is added under multiple classes.
_CLASS_PRECEDENCE = {
    "focus":      6,
    "entrypoint": 5,
    "domain":     4,
    "file_w":     3,
    "file_r":     2,
    "overflow":   1,
}

# Shared classDef palette. Each diagram only emits the classes it uses.
_CLASS_DEFS = {
    "focus":      "fill:#ffe9b3,stroke:#b07a00,stroke-width:2px",
    "domain":     "fill:#dfe9ff,stroke:#3658b3",
    "entrypoint": "fill:#e5d4ff,stroke:#6a3fb5",
    "file_r":     "fill:#d6f5d6,stroke:#2f7a2f",
    "file_w":     "fill:#fcd9d9,stroke:#b03030",
    "overflow":   "fill:#eeeeee,stroke:#888,stroke-dasharray:3 3",
}

_LABEL_NEEDS_QUOTING = re.compile(r'[^A-Za-z0-9_]')
_ID_BAD_CHAR = re.compile(r'[^A-Za-z0-9_]')


def _sanitize_id(node_id):
    s = _ID_BAD_CHAR.sub("_", str(node_id))
    if not s:
        s = "n"
    if s[0].isdigit():
        s = "n_" + s
    return s


def _format_label(label):
    if label is None:
        return None
    escaped = label.replace('"', '&quot;')
    if _LABEL_NEEDS_QUOTING.search(label):
        return '"' + escaped + '"'
    return escaped


class MermaidDiagram:
    """Builder for a single Mermaid ``flowchart`` graph."""

    def __init__(self, direction="LR", title=None):
        if direction not in DIRECTIONS:
            raise ValueError("unknown direction: %r" % (direction,))
        self.direction = direction
        self.title = title
        # sanitized_id -> {"label": str|None, "shape": str, "css_class": str|None}
        self._nodes = {}
        # orig_id -> sanitized_id (so repeat lookups resolve consistently)
        self._id_map = {}
        # list of (src_sanitized, dst_sanitized, label, style)
        self._edges = []
        # name -> css string. Seeded with the standard palette so callers
        # only need to reference class names.
        self._class_defs = dict(_CLASS_DEFS)
        # css class names actually referenced by a node in this diagram.
        self._used_classes = set()

    # --- graph construction ----------------------------------------------

    def add_node(self, node_id, label=None, shape="rect", css_class=None):
        if shape not in NODE_SHAPES:
            raise ValueError("unknown shape: %r" % (shape,))

        sid = self._id_map.get(node_id)
        if sid is None:
            sid = _sanitize_id(node_id)
            self._id_map[node_id] = sid

        existing = self._nodes.get(sid)
        if existing is None:
            self._nodes[sid] = {
                "label": label if label is not None else str(node_id),
                "shape": shape,
                "css_class": css_class,
            }
        else:
            # Keep the first label; promote the strongest css_class.
            if css_class is not None:
                cur = existing["css_class"]
                if cur is None or _CLASS_PRECEDENCE.get(css_class, 0) > _CLASS_PRECEDENCE.get(cur, 0):
                    existing["css_class"] = css_class
                    existing["shape"] = shape

        if css_class is not None:
            self._used_classes.add(css_class)

        return sid

    def add_edge(self, src, dst, label=None, style="solid"):
        if style not in EDGE_STYLES:
            raise ValueError("unknown edge style: %r" % (style,))

        src_sid = self._id_map.get(src)
        if src_sid is None or src_sid not in self._nodes:
            src_sid = self.add_node(src)

        dst_sid = self._id_map.get(dst)
        if dst_sid is None or dst_sid not in self._nodes:
            dst_sid = self.add_node(dst)

        self._edges.append((src_sid, dst_sid, label, style))

    def add_class_def(self, name, css):
        self._class_defs[name] = css

    def is_empty(self):
        return len(self._edges) == 0

    # --- output ----------------------------------------------------------

    def render(self):
        lines = []
        if self.title:
            lines.append("---")
            lines.append("title: %s" % self.title)
            lines.append("---")
        lines.append("flowchart %s" % self.direction)

        for sid, node in self._nodes.items():
            lines.append("    " + self._render_node(sid, node))

        for src, dst, label, style in self._edges:
            lines.append("    " + self._render_edge(src, dst, label, style))

        if self._used_classes:
            lines.append("")
            for name in sorted(self._used_classes):
                css = self._class_defs.get(name)
                if css is None:
                    continue
                lines.append("    classDef %s %s;" % (name, css))

        return "\n".join(lines)

    def to_markdown(self):
        return "```mermaid\n" + self.render() + "\n```"

    def to_html(self):
        return (
            '<div class="mermaid">\n'
            + self.render()
            + "\n</div>\n"
            + '<script type="module">\n'
            + 'import mermaid from "https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs";\n'
            + "mermaid.initialize({ startOnLoad: true });\n"
            + "mermaid.run();\n"
            + "</script>"
        )

    def display(self):
        display(Markdown(self.to_markdown()))

    # --- internals -------------------------------------------------------

    def _render_node(self, sid, node):
        open_, close = NODE_SHAPES[node["shape"]]
        label = _format_label(node["label"]) if node["label"] is not None else sid
        out = "%s%s%s%s" % (sid, open_, label, close)
        if node["css_class"]:
            out += ":::" + node["css_class"]
        return out

    def _render_edge(self, src, dst, label, style):
        plain, left, right = EDGE_STYLES[style]
        if label is None:
            return "%s %s %s" % (src, plain, dst)
        return "%s %s%s%s %s" % (src, left, label, right, dst)


# ----- Per-section diagram builders -----------------------------------------
#
# These mirror the queries in span.domain_summary_raw so the diagram and
# the surrounding Markdown lists always agree on what they include.

_FILE_DIR_CLASSES = ["file", "blk_file", "chr_file", "lnk_file", "dir"]


def _focus_node(diagram, domain):
    diagram.add_node(domain, shape="stadium", css_class="focus")


def _peers_in(policy, domain, tclass, perms):
    rules = policy.terules_query_raw(
        target=domain, tclass=tclass, perms=perms
    )
    return sorted({str(r.source) for r in rules})


def _peers_out(policy, domain, tclass, perms, source_indirect=True):
    kwargs = dict(source=domain, tclass=tclass, perms=perms)
    if not source_indirect:
        kwargs["source_indirect"] = False
    rules = policy.terules_query_raw(**kwargs)
    return sorted({str(r.target) for r in rules})


def _apply_cap(peers, max_peers):
    if max_peers is None or len(peers) <= max_peers:
        return peers, 0
    return peers[:max_peers], len(peers) - max_peers


def _build_section(
    policy, domain, *, direction, max_peers,
    section_key, peer_shape, peer_class, edge_label, edge_style,
    edge_from_focus, peers,
):
    diagram = MermaidDiagram(direction=direction)
    _focus_node(diagram, domain)

    shown, overflow_count = _apply_cap(peers, max_peers)
    for peer in shown:
        diagram.add_node(peer, shape=peer_shape, css_class=peer_class)
        if edge_from_focus:
            diagram.add_edge(domain, peer, label=edge_label, style=edge_style)
        else:
            diagram.add_edge(peer, domain, label=edge_label, style=edge_style)

    if overflow_count > 0:
        overflow_id = "overflow_" + section_key
        diagram.add_node(
            overflow_id,
            label="... (+%d more)" % overflow_count,
            shape="hex",
            css_class="overflow",
        )
        if edge_from_focus:
            diagram.add_edge(domain, overflow_id, label=edge_label, style=edge_style)
        else:
            diagram.add_edge(overflow_id, domain, label=edge_label, style=edge_style)

    return diagram


def dta_in_diagram(policy, domain, *, direction="LR", max_peers=40):
    peers = _peers_in(policy, domain, tclass=["process"], perms=["transition"])
    return _build_section(
        policy, domain,
        direction=direction, max_peers=max_peers,
        section_key="dta_in",
        peer_shape="round", peer_class="domain",
        edge_label="transition", edge_style="solid",
        edge_from_focus=False,
        peers=peers,
    )


def dta_out_diagram(policy, domain, *, direction="LR", max_peers=40):
    peers = _peers_out(policy, domain, tclass=["process"], perms=["transition"])
    return _build_section(
        policy, domain,
        direction=direction, max_peers=max_peers,
        section_key="dta_out",
        peer_shape="round", peer_class="domain",
        edge_label="transition", edge_style="solid",
        edge_from_focus=True,
        peers=peers,
    )


def entrypoints_diagram(policy, domain, *, direction="LR", max_peers=40):
    peers = _peers_out(policy, domain, tclass=["file"], perms=["entrypoint"])
    return _build_section(
        policy, domain,
        direction=direction, max_peers=max_peers,
        section_key="entrypoints",
        peer_shape="subroutine", peer_class="entrypoint",
        edge_label="entrypoint", edge_style="dotted",
        edge_from_focus=False,
        peers=peers,
    )


def file_reads_diagram(policy, domain, *, direction="LR", max_peers=40):
    peers = _peers_out(
        policy, domain,
        tclass=_FILE_DIR_CLASSES, perms=["read"], source_indirect=False,
    )
    return _build_section(
        policy, domain,
        direction=direction, max_peers=max_peers,
        section_key="fread",
        peer_shape="cylinder", peer_class="file_r",
        edge_label="read", edge_style="solid",
        edge_from_focus=True,
        peers=peers,
    )


def file_writes_diagram(policy, domain, *, direction="LR", max_peers=40):
    peers = _peers_out(
        policy, domain,
        tclass=_FILE_DIR_CLASSES, perms=["write", "append"], source_indirect=False,
    )
    return _build_section(
        policy, domain,
        direction=direction, max_peers=max_peers,
        section_key="fwrite",
        peer_shape="cylinder", peer_class="file_w",
        edge_label="write", edge_style="solid",
        edge_from_focus=True,
        peers=peers,
    )


SECTION_BUILDERS = {
    "dta_in":      dta_in_diagram,
    "dta_out":     dta_out_diagram,
    "entrypoints": entrypoints_diagram,
    "fread":       file_reads_diagram,
    "fwrite":      file_writes_diagram,
}
