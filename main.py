"""
FW Watcher — FortiGate network topology viewer
"""
import sys
from pathlib import Path

from PyQt6.QtCore import Qt, QPointF
from PyQt6.QtGui  import QFont, QColor
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QSplitter, QVBoxLayout,
    QHBoxLayout, QPushButton, QLabel, QFileDialog, QTableWidget,
    QTableWidgetItem, QGroupBox, QStackedWidget,
    QTextEdit, QFrame, QStatusBar, QToolBar, QMessageBox,
    QLineEdit, QMenu,
)

from models  import NetworkTopology
from parsers import parse_addresses, parse_policies
from graph_view import NetworkGraphView


# ── helpers ───────────────────────────────────────────────────────────────────
def _label(text: str, bold=False, size=9) -> QLabel:
    lbl = QLabel(text)
    f   = QFont("Segoe UI", size)
    if bold:
        f.setBold(True)
    lbl.setFont(f)
    return lbl


def _separator() -> QFrame:
    line = QFrame()
    line.setFrameShape(QFrame.Shape.HLine)
    line.setFrameShadow(QFrame.Shadow.Sunken)
    return line


# ── Detail Panel (right side) ─────────────────────────────────────────────────
class DetailPanel(QWidget):
    """
    Three pages:
      0 – welcome/instructions
      1 – subnet info + members
      2 – edge / policy list
    """
    def __init__(self):
        super().__init__()
        self.setMinimumWidth(260)
        self.setMaximumWidth(380)
        self._topology = None

        self._stack = QStackedWidget()

        # page 0: welcome
        p0 = QWidget()
        v0 = QVBoxLayout(p0)
        v0.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ico = _label("🔍", size=32)
        ico.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hint = _label("Click a subnet node\nor a policy edge\nto see details.", size=9)
        hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hint.setStyleSheet("color: #666;")
        v0.addWidget(ico)
        v0.addSpacing(8)
        v0.addWidget(hint)
        self._stack.addWidget(p0)

        # page 1: subnet details
        p1 = QWidget()
        v1 = QVBoxLayout(p1)
        v1.setContentsMargins(8, 8, 8, 8)
        self._subnet_title   = _label("", bold=True, size=10)
        self._subnet_cidr    = _label("")
        self._subnet_comment = _label("")
        self._subnet_comment.setWordWrap(True)
        self._subnet_comment.setStyleSheet("color: #666;")
        v1.addWidget(self._subnet_title)
        v1.addWidget(self._subnet_cidr)
        v1.addWidget(self._subnet_comment)
        v1.addWidget(_separator())
        v1.addWidget(_label("Members", bold=True))
        self._members_table = self._make_table(["Name", "Type", "Address", "Comment"])
        v1.addWidget(self._members_table)
        v1.addWidget(_separator())
        v1.addWidget(_label("Related Policies", bold=True))
        self._subnet_policies_table = self._make_table(["#", "Name", "Src", "Dst", "Action"])
        v1.addWidget(self._subnet_policies_table)
        self._stack.addWidget(p1)

        # page 2: edge/policy details
        p2 = QWidget()
        v2 = QVBoxLayout(p2)
        v2.setContentsMargins(8, 8, 8, 8)
        self._edge_title = _label("", bold=True, size=10)
        v2.addWidget(self._edge_title)
        v2.addWidget(_separator())
        self._policy_table = self._make_table(["#", "Name", "Service", "Action", "Status"])
        self._policy_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows)
        self._policy_table.itemSelectionChanged.connect(self._on_policy_selected)
        v2.addWidget(self._policy_table)
        v2.addWidget(_separator())
        self._policy_detail = QTextEdit()
        self._policy_detail.setReadOnly(True)
        self._policy_detail.setMaximumHeight(160)
        self._policy_detail.setFont(QFont("Consolas", 8))
        v2.addWidget(self._policy_detail)
        self._stack.addWidget(p2)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self._stack)
        self._current_edge_conn = None

    # ── factory ────────────────────────────────────────────────────────────────
    def _make_table(self, headers: list[str]) -> QTableWidget:
        t = QTableWidget(0, len(headers))
        t.setHorizontalHeaderLabels(headers)
        t.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        t.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        t.horizontalHeader().setStretchLastSection(True)
        t.verticalHeader().setVisible(False)
        t.setFont(QFont("Segoe UI", 8))
        t.setAlternatingRowColors(True)
        t.setMinimumHeight(100)
        return t

    def _fill_table(self, table: QTableWidget, rows: list[list[str]]):
        table.setRowCount(0)
        for row_data in rows:
            r = table.rowCount()
            table.insertRow(r)
            for c, val in enumerate(row_data):
                item = QTableWidgetItem(str(val))
                if c == 4 and val == "ACCEPT":
                    item.setForeground(QColor("#107c10"))
                elif c == 4 and val == "DENY":
                    item.setForeground(QColor("#c50f1f"))
                table.setItem(r, c, item)
        table.resizeColumnsToContents()

    # ── public API ─────────────────────────────────────────────────────────────
    def set_topology(self, topo: NetworkTopology):
        self._topology = topo

    def show_welcome(self):
        self._stack.setCurrentIndex(0)

    def show_subnet(self, name: str):
        if not self._topology:
            return
        addr = self._topology.addresses.get(name)

        self._subnet_title.setText(name)
        self._subnet_cidr.setText(addr.display_addr if addr else "")
        self._subnet_comment.setText(addr.comment if addr and addr.comment else "")

        # members table
        members = self._topology.get_subnet_members(name)
        self._fill_table(self._members_table,
            [[m.name, m.obj_type, m.display_addr, m.comment] for m in members]
        )

        rel_pols = self._topology.get_policies_for_address(name)
        self._fill_table(self._subnet_policies_table, [
            [p.policy_id, p.name,
             ", ".join(p.src_addrs[:2]) + ("…" if len(p.src_addrs) > 2 else ""),
             ", ".join(p.dst_addrs[:2]) + ("…" if len(p.dst_addrs) > 2 else ""),
             p.action_label]
            for p in rel_pols
        ])
        self._stack.setCurrentIndex(1)

    def show_edge(self, conn: dict):
        self._current_edge_conn = conn
        src, dst = conn["src"], conn["dst"]
        self._edge_title.setText(f"{src}  →  {dst}")
        pols = conn["policies"]
        self._fill_table(self._policy_table, [
            [p.policy_id, p.name,
             ", ".join(p.services[:3]) or "any",
             p.action_label,
             "ON" if p.is_enabled else "OFF"]
            for p in pols
        ])
        self._policy_detail.clear()
        self._stack.setCurrentIndex(2)

    def _on_policy_selected(self):
        sel = self._policy_table.selectedItems()
        if not sel or not self._current_edge_conn:
            return
        row = sel[0].row()
        pols = self._current_edge_conn["policies"]
        if row >= len(pols):
            return
        p = pols[row]
        lines = [
            f"Policy ID  : {p.policy_id}",
            f"Name       : {p.name}",
            f"Src Intf   : {p.src_intf or '—'}",
            f"Dst Intf   : {p.dst_intf or '—'}",
            f"Source     : {', '.join(p.src_addrs)}",
            f"Destination: {', '.join(p.dst_addrs)}",
            f"Service    : {', '.join(p.services) or 'any'}",
            f"Action     : {p.action_label}",
            f"Status     : {'Enabled' if p.is_enabled else 'Disabled'}",
            f"NAT        : {p.nat or '—'}",
            f"Comment    : {p.comment or '—'}",
        ]
        self._policy_detail.setPlainText("\n".join(lines))


# ── Drill-Down View ────────────────────────────────────────────────────────────
class SubnetDrillView(QWidget):
    """Shows members of a subnet plus related policies in full detail."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._topology = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)

        # breadcrumb bar
        nav = QHBoxLayout()
        self._back_btn = QPushButton("← Back to Network")
        self._back_btn.setFont(QFont("Segoe UI", 9))
        self._back_btn.setStyleSheet(
            "QPushButton{border:none;color:#0078d4;text-decoration:underline;}"
            "QPushButton:hover{color:#005a9e;}")
        self._crumb    = _label("", bold=True, size=10)
        nav.addWidget(self._back_btn)
        nav.addSpacing(12)
        nav.addWidget(self._crumb)
        nav.addStretch()
        layout.addLayout(nav)
        layout.addWidget(_separator())

        # info row
        info = QHBoxLayout()
        self._cidr_lbl    = _label("", size=9)
        self._count_lbl   = _label("", size=9)
        self._comment_lbl = _label("", size=9)
        self._comment_lbl.setStyleSheet("color:#666;")
        self._comment_lbl.setWordWrap(True)
        info.addWidget(self._cidr_lbl)
        info.addSpacing(16)
        info.addWidget(self._count_lbl)
        info.addSpacing(16)
        info.addWidget(self._comment_lbl)
        info.addStretch()
        layout.addLayout(info)
        layout.addSpacing(8)

        # splitter: members top, policies bottom
        split = QSplitter(Qt.Orientation.Vertical)

        grp_m = QGroupBox("Address Objects in this Subnet")
        grp_m.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        vm = QVBoxLayout(grp_m)
        self._members_tbl = self._make_table(
            ["Name", "Type", "Address / Range", "Interface", "Comment"])
        vm.addWidget(self._members_tbl)
        split.addWidget(grp_m)

        grp_p = QGroupBox("Policies involving this Subnet")
        grp_p.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        vp = QVBoxLayout(grp_p)
        self._policy_tbl = self._make_table(
            ["#", "Name", "From", "To", "Source", "Destination",
             "Service", "Action", "Status"])
        vp.addWidget(self._policy_tbl)
        split.addWidget(grp_p)

        split.setSizes([300, 300])
        layout.addWidget(split)

    def _make_table(self, headers):
        t = QTableWidget(0, len(headers))
        t.setHorizontalHeaderLabels(headers)
        t.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        t.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        t.horizontalHeader().setStretchLastSection(True)
        t.verticalHeader().setVisible(False)
        t.setFont(QFont("Segoe UI", 8))
        t.setAlternatingRowColors(True)
        return t

    def _fill(self, table, rows, action_col=-1):
        table.setRowCount(0)
        for row_data in rows:
            r = table.rowCount()
            table.insertRow(r)
            for c, val in enumerate(row_data):
                item = QTableWidgetItem(str(val))
                if c == action_col:
                    item.setForeground(
                        QColor("#107c10") if val == "ACCEPT"
                        else QColor("#c50f1f") if val == "DENY"
                        else QColor("#888888"))
                table.setItem(r, c, item)
        table.resizeColumnsToContents()

    def load(self, name: str, topology: NetworkTopology):
        self._topology = topology
        addr = topology.addresses.get(name)
        self._crumb.setText(name)
        self._cidr_lbl.setText(f"CIDR: {addr.display_addr}" if addr else "")
        members = topology.get_subnet_members(name)
        self._count_lbl.setText(f"{len(members)} object(s)")
        self._comment_lbl.setText(addr.comment if addr and addr.comment else "")

        # members
        self._fill(self._members_tbl,
            [[m.name, m.obj_type, m.display_addr,
              m.interface, m.comment] for m in members])

        # related policies
        rel_pols = []
        seen = set()
        for c in topology.get_connections():
            if c["src"] == name or c["dst"] == name:
                for p in c["policies"]:
                    if p.policy_id not in seen:
                        seen.add(p.policy_id)
                        rel_pols.append(p)

        self._fill(self._policy_tbl, [
            [p.policy_id, p.name, p.src_intf, p.dst_intf,
             ", ".join(p.src_addrs[:2]),
             ", ".join(p.dst_addrs[:2]),
             ", ".join(p.services[:2]) or "any",
             p.action_label,
             "ON" if p.is_enabled else "OFF"]
            for p in rel_pols
        ], action_col=7)


# ── Legend Widget ─────────────────────────────────────────────────────────────
class LegendWidget(QWidget):
    def __init__(self):
        super().__init__()
        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 2, 8, 2)
        layout.setSpacing(16)

        items = [
            ("#107c10", "Accept"),
            ("#c50f1f", "Deny"),
            ("#e87722", "Mixed"),
            ("#888888", "Disabled"),
        ]
        layout.addWidget(_label("Legend:", bold=True, size=8))
        for color, text in items:
            dot = QLabel("●")
            dot.setStyleSheet(f"color:{color}; font-size:14px;")
            layout.addWidget(dot)
            layout.addWidget(_label(text, size=8))
        layout.addStretch()
        self.setStyleSheet("background:#f0f0f0;border-top:1px solid #ddd;")


# ── Main Window ───────────────────────────────────────────────────────────────
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("FW Watcher — FortiGate Network Topology")
        self.resize(1280, 760)
        self._topology = NetworkTopology()
        self._addr_file = ""
        self._pol_file  = ""

        self._build_ui()
        self._wire_signals()
        self._update_status()

    # ── UI construction ────────────────────────────────────────────────────────
    def _build_ui(self):
        # toolbar
        tb = QToolBar("Main")
        tb.setMovable(False)
        tb.setStyleSheet("QToolBar{background:#0078d4;padding:4px;spacing:4px;}")
        self.addToolBar(tb)

        btn_style = (
            "QPushButton{background:white;color:#0078d4;border:none;"
            "border-radius:4px;padding:4px 12px;font:bold 9pt 'Segoe UI';}"
            "QPushButton:hover{background:#e6f2fb;}"
            "QPushButton:disabled{background:#b0b0b0;color:#666;}"
        )

        self._btn_addr = QPushButton("📂 Load Addresses CSV")
        self._btn_pol  = QPushButton("📂 Load Policies CSV")
        self._btn_fit  = QPushButton("⊞ Fit View")
        self._btn_clr  = QPushButton("✖ Clear")
        for b in (self._btn_addr, self._btn_pol, self._btn_fit, self._btn_clr):
            b.setStyleSheet(btn_style)
            tb.addWidget(b)

        # ANY-node toggle
        any_style = (
            "QPushButton{background:white;color:#5c2d91;border:none;"
            "border-radius:4px;padding:4px 10px;font:bold 9pt 'Segoe UI';}"
            "QPushButton:hover{background:#e6f2fb;}"
            "QPushButton:checked{background:#5c2d91;color:white;}"
        )
        self._btn_any = QPushButton("⬡ Show ANY")
        self._btn_any.setCheckable(True)
        self._btn_any.setChecked(True)
        self._btn_any.setStyleSheet(any_style)
        tb.addWidget(self._btn_any)

        tb.addSeparator()

        # search box
        self._search = QLineEdit()
        self._search.setPlaceholderText("🔍  Search subnet…")
        self._search.setMaximumWidth(200)
        self._search.setClearButtonEnabled(True)
        self._search.setStyleSheet(
            "QLineEdit{border-radius:4px;padding:3px 8px;"
            "font:9pt 'Segoe UI';background:white;color:#333;}"
        )
        tb.addWidget(self._search)

        tb.addSeparator()
        self._lbl_addr = _label("  Addresses: —", size=8)
        self._lbl_pol  = _label("  Policies: —",  size=8)
        self._lbl_addr.setStyleSheet("color:white;")
        self._lbl_pol.setStyleSheet("color:white;")
        tb.addWidget(self._lbl_addr)
        tb.addWidget(self._lbl_pol)

        # central area: stacked (graph vs drill-down)
        self._stack = QStackedWidget()

        # page 0 — main graph + detail panel
        p0 = QWidget()
        h0 = QHBoxLayout(p0)
        h0.setContentsMargins(0, 0, 0, 0)
        h0.setSpacing(0)

        self._graph_view   = NetworkGraphView()
        self._detail_panel = DetailPanel()

        split = QSplitter(Qt.Orientation.Horizontal)
        split.addWidget(self._graph_view)
        split.addWidget(self._detail_panel)
        split.setSizes([900, 320])
        h0.addWidget(split)

        self._stack.addWidget(p0)

        # page 1 — drill-down
        self._drill_view = SubnetDrillView()
        self._stack.addWidget(self._drill_view)

        # legend bar
        legend = LegendWidget()

        central = QWidget()
        vc = QVBoxLayout(central)
        vc.setContentsMargins(0, 0, 0, 0)
        vc.setSpacing(0)
        vc.addWidget(self._stack)
        vc.addWidget(legend)
        self.setCentralWidget(central)

        # status bar
        self._status = QStatusBar()
        self.setStatusBar(self._status)

    def _wire_signals(self):
        self._btn_addr.clicked.connect(self._load_addresses)
        self._btn_pol.clicked.connect(self._load_policies)
        self._btn_fit.clicked.connect(self._graph_view.fit_all)
        self._btn_clr.clicked.connect(self._clear)
        self._btn_any.toggled.connect(self._toggle_any)
        self._search.textChanged.connect(self._on_search)

        scene = self._graph_view.scene()
        scene.node_selected.connect(self._on_node_selected)
        scene.edge_selected.connect(self._on_edge_selected)
        scene.subnet_drilled.connect(self._drill_into)
        scene.node_right_clicked.connect(self._on_node_right_clicked)

        self._drill_view._back_btn.clicked.connect(self._back_to_graph)

    # ── slots ──────────────────────────────────────────────────────────────────
    def _load_addresses(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Open FortiGate Addresses CSV", "", "CSV Files (*.csv);;All Files (*)")
        if not path:
            return
        try:
            content = Path(path).read_text(encoding="utf-8-sig", errors="replace")
            addrs, warns = parse_addresses(content)
            if warns:
                self._status.showMessage("  ⚠ " + " | ".join(warns), 6000)
            for a in addrs.values():
                self._topology.add_address(a)
            self._addr_file = Path(path).name
            self._update_status()
            self._rebuild_graph()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to parse addresses:\n{e}")

    def _load_policies(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Open FortiGate Policies CSV", "", "CSV Files (*.csv);;All Files (*)")
        if not path:
            return
        try:
            content = Path(path).read_text(encoding="utf-8-sig", errors="replace")
            pols, warns = parse_policies(content)
            if warns:
                self._status.showMessage("  ⚠ " + " | ".join(warns), 6000)
            for p in pols:
                self._topology.add_policy(p)
            self._pol_file = Path(path).name
            self._update_status()
            self._rebuild_graph()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to parse policies:\n{e}")

    def _rebuild_graph(self):
        self._graph_view.scene().build(self._topology)
        self._detail_panel.set_topology(self._topology)
        self._detail_panel.show_welcome()
        self._graph_view.fit_all()
        n_sub  = len(self._topology.get_subnets())
        n_pol  = len(self._topology.policies)
        n_conn = len(self._topology.get_connections())
        self._status.showMessage(
            f"  {n_sub} subnet(s) · {n_pol} polic(y/ies) · {n_conn} connection(s)"
            "  |  Double-click a subnet to drill in · Scroll to zoom · Middle-drag to pan",
            0
        )

    def _clear(self):
        self._topology.clear()
        self._addr_file = ""
        self._pol_file  = ""
        self._graph_view.scene().clear()
        self._detail_panel.show_welcome()
        self._stack.setCurrentIndex(0)
        self._update_status()
        self._status.showMessage("Cleared.", 3000)

    def _on_node_selected(self, name: str):
        self._detail_panel.show_subnet(name)

    def _on_edge_selected(self, conn: dict):
        self._detail_panel.show_edge(conn)

    def _drill_into(self, name: str):
        if name.startswith("__") or name.startswith("["):
            return  # virtual nodes have no members
        self._drill_view.load(name, self._topology)
        self._stack.setCurrentIndex(1)

    def _back_to_graph(self):
        self._stack.setCurrentIndex(0)

    def _toggle_any(self, checked: bool):
        self._graph_view.scene().set_show_any(checked)
        self._graph_view.fit_all()

    def _on_search(self, text: str):
        self._graph_view.scene().search(text)

    def _on_node_right_clicked(self, name: str, scene_pos: QPointF):
        view_pos   = self._graph_view.mapFromScene(scene_pos)
        screen_pos = self._graph_view.viewport().mapToGlobal(view_pos.toPoint())

        menu = QMenu(self)
        act_drill = menu.addAction("Drill into subnet")
        act_copy  = menu.addAction("Copy name")
        menu.addSeparator()
        act_hide  = menu.addAction("Hide node")

        chosen = menu.exec(screen_pos)
        if chosen == act_drill:
            self._drill_into(name)
        elif chosen == act_copy:
            QApplication.clipboard().setText(name)
        elif chosen == act_hide:
            node = self._graph_view.scene().node_items.get(name)
            if node:
                node.setVisible(False)

    def _update_status(self):
        n_a = len(self._topology.addresses)
        n_p = len(self._topology.policies)
        af  = self._addr_file or "not loaded"
        pf  = self._pol_file  or "not loaded"
        self._lbl_addr.setText(f"  Addresses: {af} ({n_a})")
        self._lbl_pol.setText(f"  Policies: {pf} ({n_p})")


# ── entry point ───────────────────────────────────────────────────────────────
def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setFont(QFont("Segoe UI", 9))

    # Azure-like palette tweak
    from PyQt6.QtGui import QPalette
    pal = app.palette()
    pal.setColor(QPalette.ColorRole.Highlight,        QColor("#0078d4"))
    pal.setColor(QPalette.ColorRole.HighlightedText,  QColor("white"))
    pal.setColor(QPalette.ColorRole.Link,             QColor("#0078d4"))
    app.setPalette(pal)

    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
