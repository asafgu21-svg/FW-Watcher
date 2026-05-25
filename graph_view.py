"""
Network topology graph — subnet nodes, policy edges, zoom/pan, drill-down signal.
"""
import math

import networkx as nx
from PyQt6.QtCore import Qt, QRectF, QPointF, QLineF, pyqtSignal
from PyQt6.QtGui import (QPainter, QPen, QBrush, QColor, QFont,
                         QPainterPath, QPolygonF, QFontMetrics,
                         QWheelEvent, QPainterPathStroker)
from PyQt6.QtWidgets import (QGraphicsItem, QGraphicsScene, QGraphicsView,
                              QGraphicsObject)

# ── colours ───────────────────────────────────────────────────────────────────
C_NODE_HDR    = QColor("#0078d4")
C_NODE_BG     = QColor("#ffffff")
C_NODE_HOVER  = QColor("#e6f2fb")
C_NODE_SEL    = QColor("#005a9e")
C_ANY_HDR     = QColor("#5c2d91")
C_HIGHLIGHT   = QColor("#ffd700")

C_ACCEPT   = QColor("#107c10")
C_DENY     = QColor("#c50f1f")
C_MIXED    = QColor("#e87722")
C_DISABLED = QColor("#888888")

C_MEMBER_HDR   = QColor("#4a9dd4")
C_MEMBER_BG    = QColor("#f0f7ff")
C_MEMBER_HOVER = QColor("#dce9f5")

NODE_W, NODE_H     = 180, 68
MEMBER_W, MEMBER_H = 150, 46
CURVE_OFFSET       = 55
EXPAND_RING_R      = 190


# ── SubnetNode ────────────────────────────────────────────────────────────────
class SubnetNode(QGraphicsObject):
    double_clicked = pyqtSignal(str)
    right_clicked  = pyqtSignal(str, QPointF)
    clicked        = pyqtSignal(str)

    def __init__(self, name: str, cidr: str, member_count: int, virtual=False):
        super().__init__()
        self.node_name    = name
        self.cidr         = cidr
        self.member_count = member_count
        self.virtual      = virtual
        self._hovered     = False
        self._highlighted = False
        self._dimmed      = False
        self._expanded    = False
        self._press_pos   = QPointF()
        self._is_dbl      = False

        self.setFlags(
            QGraphicsItem.GraphicsItemFlag.ItemIsMovable |
            QGraphicsItem.GraphicsItemFlag.ItemIsSelectable |
            QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges
        )
        self.setAcceptHoverEvents(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setZValue(1)
        self.setToolTip(name)

    def set_search_state(self, highlighted: bool, dimmed: bool):
        self._highlighted = highlighted
        self._dimmed      = dimmed
        self.setOpacity(0.25 if dimmed else 1.0)
        self.update()

    def set_expanded(self, expanded: bool):
        self._expanded = expanded
        self.update()

    def boundingRect(self) -> QRectF:
        pad = 10 if self._highlighted else 4
        return QRectF(-NODE_W/2 - pad, -NODE_H/2 - pad,
                      NODE_W + pad*2, NODE_H + pad*2)

    def shape(self) -> QPainterPath:
        p = QPainterPath()
        p.addRoundedRect(QRectF(-NODE_W/2, -NODE_H/2, NODE_W, NODE_H), 8, 8)
        return p

    def paint(self, painter: QPainter, option, widget=None):
        r = QRectF(-NODE_W/2, -NODE_H/2, NODE_W, NODE_H)
        hdr_color = C_ANY_HDR if self.virtual else C_NODE_HDR
        bg_color  = C_NODE_HOVER if self._hovered else C_NODE_BG
        border    = C_NODE_SEL if self.isSelected() else hdr_color
        bw        = 3 if self.isSelected() else 2

        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        if self._highlighted:
            painter.setPen(QPen(C_HIGHLIGHT, 4))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawRoundedRect(r.adjusted(-5, -5, 5, 5), 11, 11)

        # drop shadow
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(0, 0, 0, 35))
        painter.drawRoundedRect(r.adjusted(3, 3, 3, 3), 8, 8)

        # body
        painter.setPen(QPen(border, bw))
        painter.setBrush(QBrush(bg_color))
        painter.drawRoundedRect(r, 8, 8)

        # header band (top 26 px)
        hdr = QRectF(r.x(), r.y(), r.width(), 26)
        hp  = QPainterPath()
        hp.addRoundedRect(hdr, 8, 8)
        hp.addRect(QRectF(r.x(), r.y() + 14, r.width(), 12))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(hdr_color))
        painter.drawPath(hp)

        # expand/collapse button (+/−) in top-right of header
        has_expand = self.member_count > 0
        btn_w = 22 if has_expand else 0
        if has_expand:
            btn_r = QRectF(r.right() - btn_w - 2, r.y() + 2, btn_w, 22)
            painter.setBrush(QBrush(QColor(255, 255, 255, 55)))
            painter.setPen(QPen(QColor(255, 255, 255, 120), 1))
            painter.drawRoundedRect(btn_r, 4, 4)
            fe = QFont("Segoe UI", 11, QFont.Weight.Bold)
            painter.setFont(fe)
            painter.setPen(QColor("white"))
            painter.drawText(btn_r, Qt.AlignmentFlag.AlignCenter,
                             "−" if self._expanded else "+")

        # name
        name_w = r.width() - 16 - btn_w
        fn = QFont("Segoe UI", 9, QFont.Weight.Bold)
        painter.setFont(fn)
        painter.setPen(QColor("white"))
        fm = QFontMetrics(fn)
        display = fm.elidedText(self.node_name, Qt.TextElideMode.ElideRight, name_w)
        painter.drawText(QRectF(r.x() + 8, r.y(), name_w, 26),
                         Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, display)

        # cidr
        fc = QFont("Segoe UI", 8)
        painter.setFont(fc)
        painter.setPen(QColor("#333333"))
        cidr_text = self.cidr if self.cidr else ("Any / External" if self.virtual else "—")
        painter.drawText(QRectF(r.x() + 8, r.y() + 28, r.width() - 40, 18),
                         Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, cidr_text)

        # member count badge
        if self.member_count > 0:
            badge_r = QRectF(r.right() - 28, r.bottom() - 22, 22, 16)
            painter.setBrush(QBrush(QColor("#dce9f5")))
            painter.setPen(QPen(QColor("#0078d4"), 1))
            painter.drawRoundedRect(badge_r, 8, 8)
            fb = QFont("Segoe UI", 7, QFont.Weight.Bold)
            painter.setFont(fb)
            painter.setPen(QColor("#0078d4"))
            painter.drawText(badge_r, Qt.AlignmentFlag.AlignCenter, str(self.member_count))

    def hoverEnterEvent(self, e):
        self._hovered = True;  self.update()
        super().hoverEnterEvent(e)

    def hoverLeaveEvent(self, e):
        self._hovered = False;  self.update()
        super().hoverLeaveEvent(e)

    def mousePressEvent(self, e):
        self._press_pos = e.pos()
        self._is_dbl = False
        super().mousePressEvent(e)

    def mouseReleaseEvent(self, e):
        if (e.pos() - self._press_pos).manhattanLength() < 5 and not self._is_dbl:
            self.clicked.emit(self.node_name)
        self._is_dbl = False
        super().mouseReleaseEvent(e)

    def mouseDoubleClickEvent(self, e):
        self._is_dbl = True
        self.double_clicked.emit(self.node_name)
        super().mouseDoubleClickEvent(e)

    def contextMenuEvent(self, e):
        self.right_clicked.emit(self.node_name, e.scenePos())
        e.accept()

    def itemChange(self, change, value):
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionHasChanged:
            for edge in self._connected_edges():
                if isinstance(edge, MemberConnector):
                    edge.prepareGeometryChange()
                edge.update()
        return super().itemChange(change, value)

    def _connected_edges(self) -> list:
        if self.scene() is None:
            return []
        return [i for i in self.scene().items()
                if (isinstance(i, PolicyEdge) and (i.src_node is self or i.dst_node is self))
                or (isinstance(i, MemberConnector) and i.subnet_node is self)]


# ── MemberNode ────────────────────────────────────────────────────────────────
class MemberNode(QGraphicsObject):
    clicked = pyqtSignal(str)

    def __init__(self, name: str, display: str):
        super().__init__()
        self.node_name    = name
        self.display_text = display
        self._hovered     = False
        self._connector   = None
        self._press_pos   = QPointF()

        self.setFlags(
            QGraphicsItem.GraphicsItemFlag.ItemIsMovable |
            QGraphicsItem.GraphicsItemFlag.ItemIsSelectable |
            QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges
        )
        self.setAcceptHoverEvents(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setZValue(2)
        self.setToolTip(name)

    def set_connector(self, connector: "MemberConnector"):
        self._connector = connector

    def boundingRect(self) -> QRectF:
        return QRectF(-MEMBER_W/2 - 4, -MEMBER_H/2 - 4,
                      MEMBER_W + 8, MEMBER_H + 8)

    def shape(self) -> QPainterPath:
        p = QPainterPath()
        p.addRoundedRect(QRectF(-MEMBER_W/2, -MEMBER_H/2, MEMBER_W, MEMBER_H), 6, 6)
        return p

    def paint(self, painter: QPainter, option, widget=None):
        r = QRectF(-MEMBER_W/2, -MEMBER_H/2, MEMBER_W, MEMBER_H)
        bg     = C_MEMBER_HOVER if self._hovered else C_MEMBER_BG
        border = C_NODE_SEL if self.isSelected() else C_MEMBER_HDR
        bw     = 2.5 if self.isSelected() else 1.5

        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(0, 0, 0, 20))
        painter.drawRoundedRect(r.adjusted(2, 2, 2, 2), 6, 6)

        painter.setPen(QPen(border, bw, Qt.PenStyle.DashLine))
        painter.setBrush(QBrush(bg))
        painter.drawRoundedRect(r, 6, 6)

        fn = QFont("Segoe UI", 8, QFont.Weight.Bold)
        fm = QFontMetrics(fn)
        painter.setFont(fn)
        painter.setPen(QColor("#0060a8"))
        name_text = fm.elidedText(self.node_name, Qt.TextElideMode.ElideRight, MEMBER_W - 12)
        painter.drawText(
            QRectF(r.x() + 6, r.y() + 2, r.width() - 12, MEMBER_H * 0.52),
            Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, name_text
        )

        fa = QFont("Consolas", 7)
        fa_fm = QFontMetrics(fa)
        addr_text = fa_fm.elidedText(
            self.display_text, Qt.TextElideMode.ElideRight, MEMBER_W - 12)
        painter.setFont(fa)
        painter.setPen(QColor("#555555"))
        painter.drawText(
            QRectF(r.x() + 6, r.y() + MEMBER_H * 0.50, r.width() - 12, MEMBER_H * 0.48),
            Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, addr_text
        )

    def hoverEnterEvent(self, e):
        self._hovered = True;  self.update()
        super().hoverEnterEvent(e)

    def hoverLeaveEvent(self, e):
        self._hovered = False;  self.update()
        super().hoverLeaveEvent(e)

    def mousePressEvent(self, e):
        self._press_pos = e.pos()
        super().mousePressEvent(e)

    def mouseReleaseEvent(self, e):
        if (e.pos() - self._press_pos).manhattanLength() < 5:
            self.clicked.emit(self.node_name)
        super().mouseReleaseEvent(e)

    def itemChange(self, change, value):
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionHasChanged:
            if self._connector:
                self._connector.prepareGeometryChange()
                self._connector.update()
        return super().itemChange(change, value)


# ── MemberConnector ───────────────────────────────────────────────────────────
class MemberConnector(QGraphicsItem):
    def __init__(self, subnet_node: SubnetNode, member_node: MemberNode):
        super().__init__()
        self.subnet_node = subnet_node
        self.member_node = member_node
        self.setZValue(0.5)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable, False)

    def boundingRect(self) -> QRectF:
        sp  = self.subnet_node.pos()
        mp  = self.member_node.pos()
        pad = 6
        return QRectF(
            min(sp.x(), mp.x()) - pad,
            min(sp.y(), mp.y()) - pad,
            max(abs(sp.x() - mp.x()) + pad * 2, 1),
            max(abs(sp.y() - mp.y()) + pad * 2, 1),
        )

    def paint(self, painter: QPainter, option, widget=None):
        sp = self.subnet_node.pos()
        mp = self.member_node.pos()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        pen = QPen(QColor("#4a9dd4"), 1.2)
        pen.setDashPattern([2.0, 5.0])
        pen.setStyle(Qt.PenStyle.CustomDashLine)
        painter.setPen(pen)
        painter.drawLine(sp, mp)


# ── PolicyEdge ────────────────────────────────────────────────────────────────
class PolicyEdge(QGraphicsItem):
    def __init__(self, src: SubnetNode, dst: SubnetNode, conn: dict, curve_offset: float = 0):
        super().__init__()
        self.src_node     = src
        self.dst_node     = dst
        self.conn         = conn
        self.curve_offset = curve_offset
        self._hovered     = False
        self.setZValue(0)
        self.setAcceptHoverEvents(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable, True)

    def _color(self) -> QColor:
        if self.conn["all_disabled"]:
            return C_DISABLED
        if self.conn["has_accept"] and self.conn["has_deny"]:
            return C_MIXED
        return C_ACCEPT if self.conn["has_accept"] else C_DENY

    def _endpoints(self) -> tuple[QPointF, QPointF]:
        sp, dp = self.src_node.pos(), self.dst_node.pos()
        line   = QLineF(sp, dp)

        def clip(cx, cy, line_ref):
            r = QRectF(cx - NODE_W/2, cy - NODE_H/2, NODE_W, NODE_H)
            for pts in [(r.topLeft(), r.topRight()),
                        (r.topRight(), r.bottomRight()),
                        (r.bottomRight(), r.bottomLeft()),
                        (r.bottomLeft(), r.topLeft())]:
                seg = QLineF(*pts)
                itype, pt = line_ref.intersects(seg)
                if itype == QLineF.IntersectionType.BoundedIntersection and pt is not None:
                    return pt
            return QPointF(cx, cy)

        start = clip(sp.x(), sp.y(), line)
        end   = clip(dp.x(), dp.y(), QLineF(line.p2(), line.p1()))
        return start, end

    def _ctrl(self, start: QPointF, end: QPointF) -> QPointF | None:
        if self.curve_offset == 0:
            return None
        dx = end.x() - start.x()
        dy = end.y() - start.y()
        length = math.hypot(dx, dy)
        if length < 1:
            return None
        mid = QPointF((start.x() + end.x()) / 2, (start.y() + end.y()) / 2)
        px  = -dy / length
        py  =  dx / length
        return QPointF(mid.x() + px * self.curve_offset,
                       mid.y() + py * self.curve_offset)

    def _build_path(self, start, end) -> tuple[QPainterPath, QPointF | None]:
        ctrl = self._ctrl(start, end)
        path = QPainterPath(start)
        if ctrl:
            path.quadTo(ctrl, end)
        else:
            path.lineTo(end)
        return path, ctrl

    def boundingRect(self) -> QRectF:
        start, end = self._endpoints()
        ctrl = self._ctrl(start, end)
        pad  = 24
        xs = [start.x(), end.x()]
        ys = [start.y(), end.y()]
        if ctrl:
            xs.append(ctrl.x());  ys.append(ctrl.y())
        return QRectF(min(xs) - pad, min(ys) - pad,
                      max(xs) - min(xs) + pad*2, max(ys) - min(ys) + pad*2)

    def shape(self) -> QPainterPath:
        start, end = self._endpoints()
        path, _    = self._build_path(start, end)
        stroker    = QPainterPathStroker()
        stroker.setWidth(16)
        return stroker.createStroke(path)

    def paint(self, painter: QPainter, option, widget=None):
        start, end = self._endpoints()
        if (start - end).manhattanLength() < 2:
            return

        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        color = self._color()
        lw    = 2.5 if (self._hovered or self.isSelected()) else 2.0
        pen   = QPen(color, lw,
                     Qt.PenStyle.DashLine if self.conn["all_disabled"]
                     else Qt.PenStyle.SolidLine)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen)

        path, ctrl = self._build_path(start, end)
        painter.drawPath(path)

        if ctrl:
            ang = math.atan2(end.y() - ctrl.y(), end.x() - ctrl.x())
        else:
            ang = math.atan2(end.y() - start.y(), end.x() - start.x())

        sz = 10
        p1 = QPointF(end.x() - sz * math.cos(ang - math.pi/6),
                     end.y() - sz * math.sin(ang - math.pi/6))
        p2 = QPointF(end.x() - sz * math.cos(ang + math.pi/6),
                     end.y() - sz * math.sin(ang + math.pi/6))
        painter.setBrush(QBrush(color))
        painter.setPen(QPen(color, 1))
        painter.drawPolygon(QPolygonF([end, p1, p2]))

        n = self.conn["count"]
        if ctrl:
            t = 0.5
            mx = (1-t)**2 * start.x() + 2*(1-t)*t * ctrl.x() + t**2 * end.x()
            my = (1-t)**2 * start.y() + 2*(1-t)*t * ctrl.y() + t**2 * end.y()
        else:
            mx = (start.x() + end.x()) / 2
            my = (start.y() + end.y()) / 2

        br = QRectF(mx - 10, my - 8, 20, 16)
        painter.setBrush(QBrush(color))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(br)
        fb = QFont("Segoe UI", 7, QFont.Weight.Bold)
        painter.setFont(fb)
        painter.setPen(QColor("white"))
        painter.drawText(br, Qt.AlignmentFlag.AlignCenter, str(n))

    def hoverEnterEvent(self, e):
        self._hovered = True;  self.update()
        super().hoverEnterEvent(e)

    def hoverLeaveEvent(self, e):
        self._hovered = False;  self.update()
        super().hoverLeaveEvent(e)


# ── NetworkScene ──────────────────────────────────────────────────────────────
class NetworkScene(QGraphicsScene):
    node_selected      = pyqtSignal(str)
    edge_selected      = pyqtSignal(dict)
    subnet_drilled     = pyqtSignal(str)
    node_right_clicked = pyqtSignal(str, QPointF)

    def __init__(self):
        super().__init__()
        self._node_items: dict[str, SubnetNode] = {}
        self._show_any  = True
        self._topology  = None
        self._expanded_subnets: dict[str, list] = {}
        self.selectionChanged.connect(self._on_selection)

    def clear(self):
        super().clear()
        self._node_items.clear()
        self._topology = None
        self._expanded_subnets.clear()

    def _on_selection(self):
        items = self.selectedItems()
        if not items:
            return
        item = items[0]
        if isinstance(item, SubnetNode):
            self.node_selected.emit(item.node_name)
        elif isinstance(item, MemberNode):
            self.node_selected.emit(item.node_name)
        elif isinstance(item, PolicyEdge):
            self.edge_selected.emit(item.conn)

    # ── build ──────────────────────────────────────────────────────────────────
    def build(self, topology, show_any: bool | None = None):
        self.clear()
        self._topology = topology
        if show_any is not None:
            self._show_any = show_any
        if not topology:
            return

        subnets = topology.get_subnets()
        conns   = topology.get_connections()

        if not self._show_any:
            conns = [c for c in conns
                     if not _is_virtual(c["src"]) and not _is_virtual(c["dst"])]

        all_nodes: set[str] = set(subnets)
        for c in conns:
            all_nodes.add(c["src"])
            all_nodes.add(c["dst"])

        G = nx.DiGraph()
        G.add_nodes_from(all_nodes)
        for c in conns:
            G.add_edge(c["src"], c["dst"])

        if len(G) == 0:
            return

        try:
            raw_pos = nx.kamada_kawai_layout(G)
        except Exception:
            try:
                raw_pos = nx.spring_layout(G, seed=42)
            except Exception:
                try:
                    raw_pos = nx.circular_layout(G)
                except Exception:
                    raw_pos = _circular_layout_pure(G)

        SCALE = 320
        for name, (rx, ry) in raw_pos.items():
            addr    = topology.addresses.get(name)
            cidr    = addr.display_addr if addr else ""
            mcount  = len(topology.get_subnet_members(name)) if addr else 0
            virtual = (name not in topology.addresses)
            node    = SubnetNode(name, cidr, mcount, virtual)
            node.setPos(rx * SCALE, ry * SCALE)
            node.double_clicked.connect(self.subnet_drilled)
            node.right_clicked.connect(self.node_right_clicked)
            node.clicked.connect(lambda n=name: self._handle_subnet_click(n))
            self.addItem(node)
            self._node_items[name] = node

        conn_keys = {(c["src"], c["dst"]) for c in conns}
        for c in conns:
            src_n = self._node_items.get(c["src"])
            dst_n = self._node_items.get(c["dst"])
            if not src_n or not dst_n:
                continue
            bidir  = (c["dst"], c["src"]) in conn_keys
            offset = CURVE_OFFSET if bidir else 0
            self.addItem(PolicyEdge(src_n, dst_n, c, curve_offset=offset))

    # ── expand / collapse ──────────────────────────────────────────────────────
    def _handle_subnet_click(self, name: str):
        if not self._topology:
            return
        members = self._topology.get_subnet_members(name)
        if not members:
            return
        if name in self._expanded_subnets:
            self._collapse_subnet(name)
        else:
            self._expand_subnet(name, members)

    def _expand_subnet(self, name: str, members: list):
        subnet_node = self._node_items.get(name)
        if not subnet_node:
            return

        n      = len(members)
        radius = max(EXPAND_RING_R, n * 30)
        center = subnet_node.pos()
        items  = []

        for i, member in enumerate(members):
            angle = 2 * math.pi * i / n - math.pi / 2
            x = center.x() + radius * math.cos(angle)
            y = center.y() + radius * math.sin(angle)

            mnode = MemberNode(member.name, member.display_addr)
            mnode.setPos(x, y)
            mnode.clicked.connect(self.node_selected)
            self.addItem(mnode)

            connector = MemberConnector(subnet_node, mnode)
            self.addItem(connector)
            mnode.set_connector(connector)

            items.append((mnode, connector))

        self._expanded_subnets[name] = items
        subnet_node.set_expanded(True)

    def _collapse_subnet(self, name: str):
        for mnode, connector in self._expanded_subnets.pop(name, []):
            self.removeItem(connector)
            self.removeItem(mnode)
        node = self._node_items.get(name)
        if node:
            node.set_expanded(False)

    # ── search ─────────────────────────────────────────────────────────────────
    def search(self, text: str):
        text = text.strip().lower()
        for name, node in self._node_items.items():
            if not text:
                node.set_search_state(False, False)
            elif text in name.lower():
                node.set_search_state(True, False)
            else:
                node.set_search_state(False, True)

    # ── any-node toggle ────────────────────────────────────────────────────────
    def set_show_any(self, show: bool):
        if show != self._show_any and self._topology:
            self.build(self._topology, show_any=show)

    @property
    def node_items(self) -> dict[str, SubnetNode]:
        return self._node_items


def _is_virtual(name: str) -> bool:
    return name == "__ANY__" or (name.startswith("[") and name.endswith("]"))


def _circular_layout_pure(G) -> dict:
    """Circular layout using only the stdlib math module — no numpy needed."""
    nodes = list(G.nodes())
    n = len(nodes)
    if n == 0:
        return {}
    if n == 1:
        return {nodes[0]: (0.0, 0.0)}
    return {
        node: (math.cos(2 * math.pi * i / n - math.pi / 2),
               math.sin(2 * math.pi * i / n - math.pi / 2))
        for i, node in enumerate(nodes)
    }


# ── NetworkGraphView ──────────────────────────────────────────────────────────
class NetworkGraphView(QGraphicsView):
    def __init__(self):
        super().__init__()
        self.setRenderHints(QPainter.RenderHint.Antialiasing |
                            QPainter.RenderHint.SmoothPixmapTransform)
        self.setDragMode(QGraphicsView.DragMode.RubberBandDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.ViewportAnchor.AnchorViewCenter)
        self.setBackgroundBrush(QBrush(QColor("#f3f3f3")))
        self.setScene(NetworkScene())
        self._pan_active = False
        self._pan_start  = QPointF()

    def scene(self) -> NetworkScene:
        return super().scene()

    def wheelEvent(self, event: QWheelEvent):
        factor = 1.15 if event.angleDelta().y() > 0 else 1 / 1.15
        self.scale(factor, factor)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.MiddleButton:
            self._pan_active = True
            self._pan_start  = event.position()
            self.setCursor(Qt.CursorShape.ClosedHandCursor)
            event.accept()
        else:
            super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        if self._pan_active:
            delta = event.position() - self._pan_start
            self._pan_start = event.position()
            self.horizontalScrollBar().setValue(
                self.horizontalScrollBar().value() - int(delta.x()))
            self.verticalScrollBar().setValue(
                self.verticalScrollBar().value() - int(delta.y()))
            event.accept()
        else:
            super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.MouseButton.MiddleButton:
            self._pan_active = False
            self.setCursor(Qt.CursorShape.ArrowCursor)
            event.accept()
        else:
            super().mouseReleaseEvent(event)

    def fit_all(self):
        self.resetTransform()
        rect = self.scene().itemsBoundingRect()
        if not rect.isEmpty():
            self.fitInView(rect.adjusted(-40, -40, 40, 40),
                           Qt.AspectRatioMode.KeepAspectRatio)
