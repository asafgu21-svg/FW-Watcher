"""
Network topology graph — subnet nodes, policy edges, zoom/pan, drill-down signal.
"""
import math

import networkx as nx
from PyQt6.QtCore import Qt, QRectF, QPointF, QLineF, pyqtSignal
from PyQt6.QtGui import (QPainter, QPen, QBrush, QColor, QFont,
                         QPainterPath, QPolygonF, QFontMetrics,
                         QLinearGradient, QWheelEvent, QPainterPathStroker)
from PyQt6.QtWidgets import (QGraphicsItem, QGraphicsScene, QGraphicsView,
                              QGraphicsObject)

# ── palette ───────────────────────────────────────────────────────────────────
C_NODE_HDR   = QColor("#1565C0")   # rich blue
C_NODE_HDR2  = QColor("#1976D2")   # lighter blue for gradient
C_NODE_BG    = QColor("#FAFAFA")
C_NODE_HOVER = QColor("#E3F2FD")
C_NODE_SEL   = QColor("#0D47A1")
C_ANY_HDR    = QColor("#6A1B9A")
C_ANY_HDR2   = QColor("#7B1FA2")
C_HIGHLIGHT  = QColor("#FFD600")

C_ACCEPT   = QColor("#2E7D32")
C_DENY     = QColor("#C62828")
C_MIXED    = QColor("#E65100")
C_DISABLED = QColor("#607D8B")

C_MEMBER_BDR   = QColor("#1976D2")
C_MEMBER_BG    = QColor("#E3F2FD")
C_MEMBER_HOVER = QColor("#BBDEFB")
C_MEMBER_NAME  = QColor("#0D47A1")
C_MEMBER_ADDR  = QColor("#546E7A")

C_CONTAINER_FILL = QColor(21, 101, 192, 22)   # C_NODE_HDR very transparent
C_CONTAINER_BDR  = QColor("#1565C0")

C_BG = QColor("#ECEFF1")

# ── geometry ──────────────────────────────────────────────────────────────────
NODE_W, NODE_H = 192, 78
HEADER_H       = 34          # taller header → name fully visible

MEMBER_W, MEMBER_H = 152, 48
CONTAINER_COLS = 2
CONTAINER_PAD  = 16
CONTAINER_GAP  = 12
CONTAINER_HDR  = HEADER_H

CURVE_OFFSET = 55


# ── helpers ───────────────────────────────────────────────────────────────────
def _container_dims(n: int) -> tuple[int, int]:
    if n == 0:
        return NODE_W, NODE_H
    cols = min(n, CONTAINER_COLS)
    rows = math.ceil(n / cols)
    w = max(NODE_W, cols * MEMBER_W + (cols - 1) * CONTAINER_GAP + 2 * CONTAINER_PAD)
    h = CONTAINER_HDR + rows * MEMBER_H + (rows - 1) * CONTAINER_GAP + 2 * CONTAINER_PAD
    return int(w), int(h)


def _member_local_pos(i: int, n: int, cw: int, ch: int) -> tuple[float, float]:
    cols = min(n, CONTAINER_COLS)
    col  = i % cols
    row  = i // cols
    x = -cw / 2 + CONTAINER_PAD + col * (MEMBER_W + CONTAINER_GAP) + MEMBER_W / 2
    y = -ch / 2 + CONTAINER_HDR + CONTAINER_PAD + row * (MEMBER_H + CONTAINER_GAP) + MEMBER_H / 2
    return x, y


def _hdr_gradient(rect: QRectF, top: QColor, bot: QColor) -> QLinearGradient:
    g = QLinearGradient(rect.topLeft(), rect.bottomLeft())
    g.setColorAt(0.0, top)
    g.setColorAt(1.0, bot)
    return g


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
        self._expanded    = False
        self._n_expanded  = 0
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

    # ── state ──────────────────────────────────────────────────────────────────
    def set_search_state(self, highlighted: bool, dimmed: bool):
        self._highlighted = highlighted
        self.setOpacity(0.25 if dimmed else 1.0)
        self.update()

    def set_expanded(self, expanded: bool, n: int = 0):
        self._expanded   = expanded
        self._n_expanded = n
        self.prepareGeometryChange()
        self.update()

    # ── geometry ───────────────────────────────────────────────────────────────
    def _dims(self) -> tuple[int, int]:
        if self._expanded and self._n_expanded > 0:
            return _container_dims(self._n_expanded)
        return NODE_W, NODE_H

    def boundingRect(self) -> QRectF:
        w, h = self._dims()
        pad  = 10 if self._highlighted else 4
        return QRectF(-w / 2 - pad, -h / 2 - pad, w + pad * 2, h + pad * 2)

    def shape(self) -> QPainterPath:
        w, h = self._dims()
        p = QPainterPath()
        p.addRoundedRect(QRectF(-w / 2, -h / 2, w, h), 10, 10)
        return p

    # ── paint ──────────────────────────────────────────────────────────────────
    def paint(self, painter: QPainter, option, widget=None):
        if self._expanded and self._n_expanded > 0:
            self._paint_container(painter)
        else:
            self._paint_node(painter)

    def _paint_node(self, painter: QPainter):
        w, h = NODE_W, NODE_H
        r    = QRectF(-w / 2, -h / 2, w, h)
        hdr_top  = C_ANY_HDR   if self.virtual else C_NODE_HDR
        hdr_bot  = C_ANY_HDR2  if self.virtual else C_NODE_HDR2
        bg       = C_NODE_HOVER if self._hovered else C_NODE_BG
        border   = C_NODE_SEL   if self.isSelected() else hdr_top
        bw       = 3 if self.isSelected() else 1.5

        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        if self._highlighted:
            painter.setPen(QPen(C_HIGHLIGHT, 4))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawRoundedRect(r.adjusted(-5, -5, 5, 5), 13, 13)

        # shadow
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(0, 0, 0, 30))
        painter.drawRoundedRect(r.adjusted(3, 4, 3, 4), 10, 10)

        # body
        painter.setPen(QPen(border, bw))
        painter.setBrush(QBrush(bg))
        painter.drawRoundedRect(r, 10, 10)

        # header gradient
        hdr_rect = QRectF(r.x(), r.y(), r.width(), HEADER_H)
        hdr_path = QPainterPath()
        hdr_path.addRoundedRect(hdr_rect, 10, 10)
        hdr_path.addRect(QRectF(r.x(), r.y() + 10, r.width(), HEADER_H - 10))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(_hdr_gradient(hdr_rect, hdr_top, hdr_bot)))
        painter.drawPath(hdr_path)

        # +/− button
        has_members = self.member_count > 0
        btn_w = 24 if has_members else 0
        if has_members:
            btn_r = QRectF(r.right() - btn_w - 4, r.y() + 5, btn_w - 2, HEADER_H - 10)
            painter.setBrush(QBrush(QColor(255, 255, 255, 60)))
            painter.setPen(QPen(QColor(255, 255, 255, 100), 1))
            painter.drawRoundedRect(btn_r, 4, 4)
            fe = QFont("Segoe UI", 12, QFont.Weight.Bold)
            painter.setFont(fe)
            painter.setPen(QColor("white"))
            painter.drawText(btn_r, Qt.AlignmentFlag.AlignCenter,
                             "−" if self._expanded else "+")

        # name
        name_w = int(r.width()) - 12 - btn_w
        fn = QFont("Segoe UI", 9, QFont.Weight.Bold)
        fm = QFontMetrics(fn)
        painter.setFont(fn)
        painter.setPen(QColor("white"))
        display = fm.elidedText(self.node_name, Qt.TextElideMode.ElideRight, name_w)
        painter.drawText(
            QRectF(r.x() + 8, r.y(), name_w, HEADER_H),
            Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, display
        )

        # CIDR
        fc = QFont("Consolas", 8)
        painter.setFont(fc)
        painter.setPen(QColor("#455A64"))
        cidr_text = self.cidr if self.cidr else ("Any / External" if self.virtual else "—")
        cidr_y    = r.y() + HEADER_H + 2
        cidr_h    = h - HEADER_H - 4
        painter.drawText(
            QRectF(r.x() + 10, cidr_y, r.width() - 36, cidr_h),
            Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, cidr_text
        )

        # member badge
        if self.member_count > 0:
            br = QRectF(r.right() - 28, r.bottom() - 20, 22, 15)
            painter.setBrush(QBrush(QColor("#BBDEFB")))
            painter.setPen(QPen(C_NODE_HDR, 1))
            painter.drawRoundedRect(br, 7, 7)
            fb = QFont("Segoe UI", 7, QFont.Weight.Bold)
            painter.setFont(fb)
            painter.setPen(C_NODE_HDR)
            painter.drawText(br, Qt.AlignmentFlag.AlignCenter, str(self.member_count))

    def _paint_container(self, painter: QPainter):
        cw, ch = _container_dims(self._n_expanded)
        r = QRectF(-cw / 2, -ch / 2, cw, ch)
        hdr_top = C_ANY_HDR  if self.virtual else C_NODE_HDR
        hdr_bot = C_ANY_HDR2 if self.virtual else C_NODE_HDR2
        border  = C_NODE_SEL if self.isSelected() else C_CONTAINER_BDR

        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        # shadow
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(0, 0, 0, 25))
        painter.drawRoundedRect(r.adjusted(4, 5, 4, 5), 12, 12)

        # container fill + border
        painter.setPen(QPen(border, 2, Qt.PenStyle.DashLine))
        painter.setBrush(QBrush(C_CONTAINER_FILL))
        painter.drawRoundedRect(r, 12, 12)

        # header strip
        hdr_rect = QRectF(r.x(), r.y(), r.width(), CONTAINER_HDR)
        hdr_path = QPainterPath()
        hdr_path.addRoundedRect(hdr_rect, 12, 12)
        hdr_path.addRect(QRectF(r.x(), r.y() + 12, r.width(), CONTAINER_HDR - 12))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(_hdr_gradient(hdr_rect, hdr_top, hdr_bot)))
        painter.drawPath(hdr_path)

        # collapse button
        btn_r = QRectF(r.right() - 26, r.y() + 5, 22, CONTAINER_HDR - 10)
        painter.setBrush(QBrush(QColor(255, 255, 255, 60)))
        painter.setPen(QPen(QColor(255, 255, 255, 100), 1))
        painter.drawRoundedRect(btn_r, 4, 4)
        fe = QFont("Segoe UI", 12, QFont.Weight.Bold)
        painter.setFont(fe)
        painter.setPen(QColor("white"))
        painter.drawText(btn_r, Qt.AlignmentFlag.AlignCenter, "−")

        # subnet name
        fn = QFont("Segoe UI", 9, QFont.Weight.Bold)
        fm = QFontMetrics(fn)
        painter.setFont(fn)
        painter.setPen(QColor("white"))
        name_w = int(r.width()) - 36
        display = fm.elidedText(self.node_name, Qt.TextElideMode.ElideRight, name_w)
        painter.drawText(
            QRectF(r.x() + 10, r.y(), name_w, CONTAINER_HDR),
            Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, display
        )

        # CIDR in header (right side, smaller)
        fc = QFont("Consolas", 7)
        painter.setFont(fc)
        painter.setPen(QColor(220, 240, 255, 200))
        cidr_text = self.cidr or ""
        cidr_w = int(r.width()) - 36
        fc_fm = QFontMetrics(fc)
        painter.drawText(
            QRectF(r.x() + 10, r.y() + CONTAINER_HDR / 2, cidr_w, CONTAINER_HDR / 2),
            Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
            fc_fm.elidedText(cidr_text, Qt.TextElideMode.ElideRight, cidr_w)
        )

    # ── events ─────────────────────────────────────────────────────────────────
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
                edge.update()
        return super().itemChange(change, value)

    def _connected_edges(self) -> list:
        if self.scene() is None:
            return []
        return [i for i in self.scene().items()
                if isinstance(i, PolicyEdge)
                and (i.src_node is self or i.dst_node is self)]


# ── MemberNode ────────────────────────────────────────────────────────────────
class MemberNode(QGraphicsObject):
    clicked = pyqtSignal(str)

    def __init__(self, name: str, display: str):
        super().__init__()
        self.node_name    = name
        self.display_text = display
        self._hovered     = False
        self._press_pos   = QPointF()

        self.setFlags(
            QGraphicsItem.GraphicsItemFlag.ItemIsSelectable |
            QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges
        )
        self.setAcceptHoverEvents(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setZValue(3)
        self.setToolTip(name)

    def boundingRect(self) -> QRectF:
        return QRectF(-MEMBER_W / 2 - 3, -MEMBER_H / 2 - 3,
                      MEMBER_W + 6, MEMBER_H + 6)

    def shape(self) -> QPainterPath:
        p = QPainterPath()
        p.addRoundedRect(QRectF(-MEMBER_W / 2, -MEMBER_H / 2, MEMBER_W, MEMBER_H), 7, 7)
        return p

    def paint(self, painter: QPainter, option, widget=None):
        r  = QRectF(-MEMBER_W / 2, -MEMBER_H / 2, MEMBER_W, MEMBER_H)
        bg = C_MEMBER_HOVER if self._hovered else C_MEMBER_BG
        bd = C_NODE_SEL if self.isSelected() else C_MEMBER_BDR
        bw = 2.5 if self.isSelected() else 1.5

        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        # shadow
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(0, 0, 0, 18))
        painter.drawRoundedRect(r.adjusted(2, 2, 2, 2), 7, 7)

        # body
        painter.setPen(QPen(bd, bw))
        painter.setBrush(QBrush(bg))
        painter.drawRoundedRect(r, 7, 7)

        # left accent bar
        bar = QRectF(r.x(), r.y() + 6, 4, r.height() - 12)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(C_MEMBER_BDR))
        painter.drawRoundedRect(bar, 2, 2)

        # name
        fn = QFont("Segoe UI", 8, QFont.Weight.Bold)
        fm = QFontMetrics(fn)
        painter.setFont(fn)
        painter.setPen(C_MEMBER_NAME)
        name_txt = fm.elidedText(self.node_name, Qt.TextElideMode.ElideRight, MEMBER_W - 18)
        painter.drawText(
            QRectF(r.x() + 12, r.y() + 2, MEMBER_W - 18, MEMBER_H * 0.52),
            Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, name_txt
        )

        # address
        fa    = QFont("Consolas", 7)
        fa_fm = QFontMetrics(fa)
        painter.setFont(fa)
        painter.setPen(C_MEMBER_ADDR)
        addr_txt = fa_fm.elidedText(self.display_text, Qt.TextElideMode.ElideRight, MEMBER_W - 18)
        painter.drawText(
            QRectF(r.x() + 12, r.y() + MEMBER_H * 0.50, MEMBER_W - 18, MEMBER_H * 0.48),
            Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, addr_txt
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
        sw, sh = self.src_node._dims()
        dw, dh = self.dst_node._dims()
        line   = QLineF(sp, dp)

        def clip(cx, cy, nw, nh, line_ref):
            r = QRectF(cx - nw / 2, cy - nh / 2, nw, nh)
            for pts in [(r.topLeft(), r.topRight()),
                        (r.topRight(), r.bottomRight()),
                        (r.bottomRight(), r.bottomLeft()),
                        (r.bottomLeft(), r.topLeft())]:
                seg = QLineF(*pts)
                itype, pt = line_ref.intersects(seg)
                if itype == QLineF.IntersectionType.BoundedIntersection and pt is not None:
                    return pt
            return QPointF(cx, cy)

        start = clip(sp.x(), sp.y(), sw, sh, line)
        end   = clip(dp.x(), dp.y(), dw, dh, QLineF(line.p2(), line.p1()))
        return start, end

    def _ctrl(self, start: QPointF, end: QPointF) -> QPointF | None:
        if self.curve_offset == 0:
            return None
        dx, dy = end.x() - start.x(), end.y() - start.y()
        length = math.hypot(dx, dy)
        if length < 1:
            return None
        mid = QPointF((start.x() + end.x()) / 2, (start.y() + end.y()) / 2)
        return QPointF(mid.x() + (-dy / length) * self.curve_offset,
                       mid.y() + ( dx / length) * self.curve_offset)

    def _build_path(self, start, end):
        ctrl = self._ctrl(start, end)
        path = QPainterPath(start)
        path.quadTo(ctrl, end) if ctrl else path.lineTo(end)
        return path, ctrl

    def boundingRect(self) -> QRectF:
        start, end = self._endpoints()
        ctrl = self._ctrl(start, end)
        pad  = 24
        xs = [start.x(), end.x()] + ([ctrl.x()] if ctrl else [])
        ys = [start.y(), end.y()] + ([ctrl.y()] if ctrl else [])
        return QRectF(min(xs) - pad, min(ys) - pad,
                      max(xs) - min(xs) + pad * 2, max(ys) - min(ys) + pad * 2)

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
        lw    = 2.8 if (self._hovered or self.isSelected()) else 2.2
        pen   = QPen(color, lw,
                     Qt.PenStyle.DashLine if self.conn["all_disabled"]
                     else Qt.PenStyle.SolidLine)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen)

        path, ctrl = self._build_path(start, end)
        painter.drawPath(path)

        # arrowhead
        ang = (math.atan2(end.y() - ctrl.y(), end.x() - ctrl.x()) if ctrl
               else math.atan2(end.y() - start.y(), end.x() - start.x()))
        sz = 11
        p1 = QPointF(end.x() - sz * math.cos(ang - math.pi / 6),
                     end.y() - sz * math.sin(ang - math.pi / 6))
        p2 = QPointF(end.x() - sz * math.cos(ang + math.pi / 6),
                     end.y() - sz * math.sin(ang + math.pi / 6))
        painter.setBrush(QBrush(color))
        painter.setPen(QPen(color, 1))
        painter.drawPolygon(QPolygonF([end, p1, p2]))

        # count badge at midpoint
        n  = self.conn["count"]
        if ctrl:
            t  = 0.5
            mx = (1-t)**2 * start.x() + 2*(1-t)*t * ctrl.x() + t**2 * end.x()
            my = (1-t)**2 * start.y() + 2*(1-t)*t * ctrl.y() + t**2 * end.y()
        else:
            mx, my = (start.x() + end.x()) / 2, (start.y() + end.y()) / 2
        br = QRectF(mx - 11, my - 9, 22, 18)
        painter.setBrush(QBrush(color))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(br)
        painter.setFont(QFont("Segoe UI", 7, QFont.Weight.Bold))
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
        self._show_any   = True
        self._topology   = None
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
        if isinstance(item, (SubnetNode, MemberNode)):
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
            all_nodes.update([c["src"], c["dst"]])

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

        SCALE = 340
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
            self.addItem(PolicyEdge(src_n, dst_n, c,
                                    curve_offset=CURVE_OFFSET if bidir else 0))

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
        cw, ch = _container_dims(n)
        items  = []

        for i, member in enumerate(members):
            x, y  = _member_local_pos(i, n, cw, ch)
            mnode = MemberNode(member.name, member.display_addr)
            mnode.setParentItem(subnet_node)
            mnode.setPos(x, y)
            items.append(mnode)

        self._expanded_subnets[name] = items
        subnet_node.set_expanded(True, n)

    def _collapse_subnet(self, name: str):
        for mnode in self._expanded_subnets.pop(name, []):
            mnode.setParentItem(None)
            if mnode.scene():
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

    def set_show_any(self, show: bool):
        if show != self._show_any and self._topology:
            self.build(self._topology, show_any=show)

    @property
    def node_items(self) -> dict[str, SubnetNode]:
        return self._node_items


# ── helpers ───────────────────────────────────────────────────────────────────
def _is_virtual(name: str) -> bool:
    return name == "__ANY__" or (name.startswith("[") and name.endswith("]"))


def _circular_layout_pure(G) -> dict:
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
        self.setBackgroundBrush(QBrush(C_BG))
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
