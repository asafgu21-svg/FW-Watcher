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
C_NODE_HDR   = QColor("#0078d4")
C_NODE_BG    = QColor("#ffffff")
C_NODE_HOVER = QColor("#e6f2fb")
C_NODE_SEL   = QColor("#005a9e")
C_ANY_HDR    = QColor("#5c2d91")
C_HIGHLIGHT  = QColor("#ffd700")

C_ACCEPT  = QColor("#107c10")
C_DENY    = QColor("#c50f1f")
C_MIXED   = QColor("#e87722")
C_DISABLED= QColor("#888888")

NODE_W, NODE_H = 160, 68
CURVE_OFFSET   = 55      # px perpendicular offset for bidirectional edges


# ── SubnetNode ────────────────────────────────────────────────────────────────
class SubnetNode(QGraphicsObject):
    double_clicked = pyqtSignal(str)
    right_clicked  = pyqtSignal(str, QPointF)

    def __init__(self, name: str, cidr: str, member_count: int, virtual=False):
        super().__init__()
        self.node_name    = name
        self.cidr         = cidr
        self.member_count = member_count
        self.virtual      = virtual
        self._hovered     = False
        self._highlighted = False
        self._dimmed      = False

        self.setFlags(
            QGraphicsItem.GraphicsItemFlag.ItemIsMovable |
            QGraphicsItem.GraphicsItemFlag.ItemIsSelectable |
            QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges
        )
        self.setAcceptHoverEvents(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setZValue(1)

    def set_search_state(self, highlighted: bool, dimmed: bool):
        self._highlighted = highlighted
        self._dimmed      = dimmed
        self.setOpacity(0.25 if dimmed else 1.0)
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

        # search-match highlight ring
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

        # name
        fn = QFont("Segoe UI", 9, QFont.Weight.Bold)
        painter.setFont(fn)
        painter.setPen(QColor("white"))
        fm = QFontMetrics(fn)
        display = fm.elidedText(self.node_name, Qt.TextElideMode.ElideRight, NODE_W - 16)
        painter.drawText(QRectF(r.x() + 8, r.y(), r.width() - 16, 26),
                         Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, display)

        # cidr
        fc = QFont("Segoe UI", 8)
        painter.setFont(fc)
        painter.setPen(QColor("#333333"))
        cidr_text = self.cidr if self.cidr else ("Any / External" if self.virtual else "—")
        painter.drawText(QRectF(r.x() + 8, r.y() + 28, r.width() - 40, 18),
                         Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, cidr_text)

        # member badge
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

    def mouseDoubleClickEvent(self, e):
        self.double_clicked.emit(self.node_name)
        super().mouseDoubleClickEvent(e)

    def contextMenuEvent(self, e):
        self.right_clicked.emit(self.node_name, e.scenePos())
        e.accept()

    def itemChange(self, change, value):
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionHasChanged:
            for edge in self._connected_edges():
                edge.update()
        return super().itemChange(change, value)

    def _connected_edges(self) -> list:
        if self.scene() is None:
            return []
        return [i for i in self.scene().items()
                if isinstance(i, PolicyEdge)
                and (i.src_node is self or i.dst_node is self)]


# ── PolicyEdge ────────────────────────────────────────────────────────────────
class PolicyEdge(QGraphicsItem):
    def __init__(self, src: SubnetNode, dst: SubnetNode, conn: dict, curve_offset: float = 0):
        super().__init__()
        self.src_node     = src
        self.dst_node     = dst
        self.conn         = conn
        self.curve_offset = curve_offset   # perpendicular px; 0 = straight line
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

        # arrowhead — tangent at the endpoint
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

        # badge at midpoint of curve
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
        self.selectionChanged.connect(self._on_selection)

    def clear(self):
        super().clear()
        self._node_items.clear()
        self._topology = None

    def _on_selection(self):
        items = self.selectedItems()
        if not items:
            return
        item = items[0]
        if isinstance(item, SubnetNode):
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

        # filter out ANY / interface virtual nodes when toggle is off
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
                raw_pos = nx.circular_layout(G)

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
            self.addItem(node)
            self._node_items[name] = node

        # detect bidirectional pairs → curved arcs
        conn_keys = {(c["src"], c["dst"]) for c in conns}
        for c in conns:
            src_n = self._node_items.get(c["src"])
            dst_n = self._node_items.get(c["dst"])
            if not src_n or not dst_n:
                continue
            bidir  = (c["dst"], c["src"]) in conn_keys
            offset = CURVE_OFFSET if bidir else 0
            self.addItem(PolicyEdge(src_n, dst_n, c, curve_offset=offset))

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
