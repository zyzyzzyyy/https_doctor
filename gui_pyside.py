"""
HTTPS 证书检测工具 - PySide6 现代 UI
使用 QSS 样式表实现现代化界面
"""

import sys
import os
import threading
from datetime import datetime
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTextEdit, QPushButton, QLabel, QTableWidget, QTableWidgetItem,
    QTabWidget, QFileDialog, QMessageBox, QHeaderView, QSizePolicy,
    QFrame, QGraphicsDropShadowEffect, QStyledItemDelegate, QStyleOptionButton,
    QStyle, QAbstractItemView, QListWidget, QListWidgetItem, QStatusBar,
    QButtonGroup
)
from PySide6.QtCore import Qt, QSize, QThread, Signal, QTimer, QMetaObject
from PySide6.QtGui import QFont, QColor, QPalette, QPainter, QBrush, QPen, QIcon

import cert_checker
import report_generator
from concurrent.futures import ThreadPoolExecutor, as_completed


# ============ 配色方案 ============
class Colors:
    """统一配色方案"""
    PRIMARY = "#71C4EF"        # 主色调 - 按钮
    PRIMARY_DARK = "#00668C"   # 深色强调
    PRIMARY_LIGHT = "#B6CCDB"  # 边框

    BG_MAIN = "#F5F4F1"        # 主背景
    BG_PANEL = "#FFFEFB"       # 面板背景
    BG_HEADER = "#3B3C3D"      # 头部背景

    TEXT_PRIMARY = "#1D1C1C"   # 主文字
    TEXT_SECONDARY = "#313D44" # 次要文字
    TEXT_LIGHT = "#FFFFFF"     # 浅色文字

    STATUS_VALID = "#1B8C3C"   # 深绿色
    STATUS_WARNING = "#C88C00" # 深黄色
    STATUS_ERROR = "#B42828"    # 深红色
    STATUS_VALID_BG = "#C8E6C9"
    STATUS_WARNING_BG = "#FFF3C8"
    STATUS_ERROR_BG = "#FFC8C8"

    BTN_DISABLED = "#B4B4B4"


# ============ QSS 样式表 ============
STYLESHEET = f"""
/* 全局样式 */
QMainWindow {{
    background-color: {Colors.BG_MAIN};
}}

/* 头部 */
#headerPanel {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #1a73e8, stop:1 #0d47a1);
    border-radius: 8px;
    padding: 6px 20px;
}}

#titleLabel {{
    color: {Colors.TEXT_LIGHT};
    font-size: 18px;
    font-weight: bold;
}}

/* 面板通用样式 */
.panel {{
    background-color: {Colors.BG_PANEL};
    border-radius: 12px;
    padding: 16px;
}}

/* 区域标题 */
.sectionTitle {{
    color: {Colors.TEXT_PRIMARY};
    font-size: 16px;
    font-weight: bold;
    margin-bottom: 12px;
}}

/* 按钮样式 */
QPushButton#primaryBtn {{
    background-color: {Colors.PRIMARY};
    color: {Colors.TEXT_PRIMARY};
    border: none;
    border-radius: 8px;
    padding: 10px 24px;
    font-size: 14px;
    font-weight: 500;
}}

QPushButton#primaryBtn:hover {{
    background-color: {Colors.PRIMARY_DARK};
}}

QPushButton#primaryBtn:disabled {{
    background-color: {Colors.BTN_DISABLED};
    color: {Colors.TEXT_PRIMARY};
}}

QPushButton#secondaryBtn {{
    background-color: {Colors.PRIMARY};
    color: {Colors.TEXT_PRIMARY};
    border: none;
    border-radius: 8px;
    padding: 10px 20px;
    font-size: 13px;
}}

QPushButton#secondaryBtn:hover {{
    background-color: {Colors.PRIMARY_DARK};
}}

QPushButton#secondaryBtn:disabled {{
background-color: {Colors.BTN_DISABLED};
color: {Colors.TEXT_PRIMARY};
}}

/* 文本输入框 */
QTextEdit {{
    background-color: {Colors.BG_PANEL};
    border: 2px solid {Colors.PRIMARY_LIGHT};
    border-radius: 8px;
    padding: 12px;
    font-size: 13px;
    color: {Colors.TEXT_PRIMARY};
    selection-background-color: #B3D4FC;
}}

QTextEdit:focus {{
    border-color: {Colors.PRIMARY};
}}

QTextEdit QScrollBar {{
    background-color: transparent;
}}

/* 表格样式 */
QTableWidget {{
    background-color: transparent;
    border: none;
    border-radius: 8px;
    gridline-color: transparent;
    selection-background-color: #E3F2FD;
    font-size: 13px;
    outline: none;
}}

QTableWidget::item {{
    padding: 8px;
    border: none;
    wrap-mode: anywhere;
}}

QTableWidget::item:selected {{
    background-color: #E3F2FD;
    color: {Colors.TEXT_PRIMARY};
}}

QHeaderView::section {{
    background-color: {Colors.PRIMARY_LIGHT};
    color: {Colors.TEXT_PRIMARY};
    padding: 10px;
    font-weight: bold;
    border: none;
}}

/* Tab 样式 */
QTabWidget::pane {{
    border: none;
    background-color: {Colors.BG_PANEL};
    border-radius: 8px;
}}

QTabBar::tab {{
    background-color: {Colors.BG_MAIN};
    color: {Colors.TEXT_SECONDARY};
    padding: 10px 20px;
    margin-right: 4px;
    border-top-left-radius: 8px;
    border-top-right-radius: 8px;
}}

QTabBar::tab:selected {{
    background-color: {Colors.BG_PANEL};
    color: {Colors.PRIMARY_DARK};
    font-weight: bold;
}}

QTabBar::tab:hover {{
    background-color: {Colors.PRIMARY_LIGHT}60;
}}

/* 标签页内容 */
QWidget#tabContent {{
    background-color: {Colors.BG_PANEL};
    padding: 16px;
}}

/* 状态栏 */
#statusBar {{
    background-color: {Colors.BG_HEADER};
    color: {Colors.TEXT_LIGHT};
    padding: 8px 16px;
    font-size: 12px;
}}

/* 详情文字 */
.detailText {{
    color: {Colors.TEXT_PRIMARY};
    font-size: 14px;
    line-height: 1.8;
    padding: 16px;
}}
"""


# ============ 状态图标样式 ============
def get_status_style(status: str) -> tuple:
    """返回状态的背景色和文字颜色"""
    colors = {
        "valid": (Colors.STATUS_VALID_BG, Colors.STATUS_VALID),
        "warning": (Colors.STATUS_WARNING_BG, Colors.STATUS_WARNING),
        "error": (Colors.STATUS_ERROR_BG, Colors.STATUS_ERROR)
    }
    return colors.get(status, (Colors.BG_PANEL, Colors.TEXT_SECONDARY))


def get_status_icon(status: str) -> str:
    """返回状态图标文字"""
    icons = {
        "valid": "✅有效",
        "warning": "⚠️警告",
        "error": "❌错误"
    }
    return icons.get(status, "❌错误")


# ============ 主窗口类 ============
class MainWindow(QMainWindow):
    """主窗口类"""

    # 线程安全信号
    result_ready = Signal(dict, int)  # result, index
    status_update = Signal(str)
    check_finished = Signal()

    def __init__(self):
        super().__init__()
        self.results: List[Dict[str, Any]] = []
        self.selected_index: int = -1
        self.is_checking: bool = False
        self.current_check_thread: Optional[QThread] = None
        self._current_filter: str = "all"

        self.setWindowTitle("HTTPS 证书检测工具")
        self.setMinimumSize(1200, 1200)
        self.resize(1200, 1200)  # 默认窗口大小
        self._center_on_screen()
        self._load_icon()
        self._init_ui()
        self._apply_styles()

        # 连接线程安全信号
        self.result_ready.connect(self._on_result_ready)
        self.status_update.connect(self._on_status_update)
        self.check_finished.connect(self._on_check_finished)

    def _center_on_screen(self):
        """将窗口定位到当前屏幕正中央"""
        from PySide6.QtGui import QScreen, QGuiApplication
        screen = QGuiApplication.primaryScreen()
        if screen:
            screen_geometry = screen.availableGeometry()
            window_geometry = self.frameGeometry()
            # 计算中心位置，确保窗口完全在屏幕内
            x = screen_geometry.center().x() - window_geometry.width() // 2
            y = screen_geometry.center().y() - window_geometry.height() // 2
            # 限制在屏幕范围内
            x = max(screen_geometry.left(), min(x, screen_geometry.right() - window_geometry.width()))
            y = max(screen_geometry.top(), min(y, screen_geometry.bottom() - window_geometry.height()))
            self.move(x, y)

    def _load_icon(self):
        """加载窗口图标"""
        import PySide6
        import os
        pyside_path = os.path.dirname(PySide6.__file__)
        icon_path = os.path.join(pyside_path, '..', '..', 'icon.png')
        icon_path = os.path.abspath(icon_path)
        if os.path.exists(icon_path):
            from PySide6.QtGui import QIcon
            self.setWindowIcon(QIcon(icon_path))
        elif os.path.exists('icon.png'):
            from PySide6.QtGui import QIcon
            self.setWindowIcon(QIcon('icon.png'))

    def _init_ui(self):
        """初始化 UI 组件"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(12)
        main_layout.setContentsMargins(16, 16, 16, 16)

        # 头部
        main_layout.addWidget(self._create_header())

        # URL 输入区
        main_layout.addWidget(self._create_input_panel())

        # 按钮区
        main_layout.addWidget(self._create_button_panel())

        # 检测结果表格
        main_layout.addWidget(self._create_results_panel(), 1)

        # 详情面板
        main_layout.addWidget(self._create_detail_panel(), 1)

        # 导出按钮
        main_layout.addWidget(self._create_export_panel())

        # 状态栏
        self._create_status_bar()

    def _create_header(self) -> QFrame:
        """创建头部"""
        frame = QFrame()
        frame.setObjectName("headerPanel")
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(20, 20, 20, 20)

        title = QLabel("HTTPS 证书检测")
        title.setObjectName("titleLabel")
        layout.addWidget(title)
        layout.addStretch()

        return frame

    def _create_input_panel(self) -> QFrame:
        """创建 URL 输入面板"""
        frame = QFrame()
        frame.setObjectName("panel")
        layout = QVBoxLayout(frame)

        label = QLabel("输入待检测的 URL（每行一个）")
        label_font = QFont()
        label_font.setPointSize(14)
        label_font.setBold(True)
        label.setFont(label_font)
        label.setStyleSheet("color: #1D1C1C;")
        layout.addWidget(label)

        input_layout = QHBoxLayout()
        input_layout.setContentsMargins(0, 0, 0, 0)
        input_layout.setSpacing(16)

        self.url_input = QTextEdit()
        self.url_input.setMinimumHeight(120)
        input_layout.addWidget(self.url_input, 1)

        hint = QLabel("例如：\nwww.abc.com\nhttps://www.bcd.com")
        hint.setStyleSheet("color: #888; font-size: 12px; padding: 8px; background: transparent;")
        hint.setAlignment(Qt.Alignment(Qt.AlignTop | Qt.AlignLeft))
        input_layout.addWidget(hint)

        layout.addLayout(input_layout)

        return frame

    def _create_button_panel(self) -> QFrame:
        """创建按钮面板"""
        frame = QFrame()
        frame.setObjectName("panel")
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(12, 8, 12, 8)

        self.toggle_btn = QPushButton("开始检测")
        self.toggle_btn.setObjectName("primaryBtn")
        self.toggle_btn.setMinimumWidth(120)
        self.toggle_btn.clicked.connect(self._on_toggle_check)

        layout.addWidget(self.toggle_btn)
        layout.addStretch()

        return frame

    def _create_results_panel(self) -> QFrame:
        """创建检测结果表格"""
        frame = QFrame()
        frame.setObjectName("panel")
        layout = QVBoxLayout(frame)

        # 标题行：标签 + 筛选按钮
        title_layout = QHBoxLayout()
        title_layout.setSpacing(8)

        label = QLabel("检测结果")
        label_font = QFont()
        label_font.setPointSize(14)
        label_font.setBold(True)
        label.setFont(label_font)
        label.setStyleSheet("color: #1D1C1C;")
        title_layout.addWidget(label)
        title_layout.addSpacing(30)  # 标题和按钮间距
        title_layout.addStretch()

        # 筛选按钮组
        self.filter_group = QButtonGroup()
        self.filter_group.setExclusive(True)

        filter_buttons = [
            ("all", "全部", None),
            ("valid", "有效", Colors.STATUS_VALID),
            ("warning", "警告", Colors.STATUS_WARNING),
            ("error", "错误", Colors.STATUS_ERROR),
        ]

        for btn_id, text, color in filter_buttons:
            btn = QPushButton(text)
            btn.setCheckable(True)
            btn.setCursor(Qt.PointingHandCursor)
            btn.setMinimumHeight(28)
            btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: #e0e0e0;
                    color: #333;
                    border: none;
                    border-radius: 14px;
                    padding: 4px 12px;
                    font-size: 12px;
                }}
                QPushButton:hover {{
                    background-color: #d0d0d0;
                }}
                QPushButton:checked {{
                    background-color: {color or '#666'};
                    color: white;
                }}
            """)
            self.filter_group.addButton(btn)
            self.filter_group.setId(btn, {"all": 0, "valid": 1, "warning": 2, "error": 3}[btn_id])
            title_layout.addWidget(btn)

        # 默认选中"全部"
        self.filter_group.button(0).setChecked(True)
        self.filter_group.idClicked.connect(self._on_filter_changed)

        layout.addLayout(title_layout)
        self._current_filter = "all"

        self.results_table = QTableWidget()
        self.results_table.setColumnCount(7)
        self.results_table.verticalHeader().setVisible(False)  # 隐藏默认行号列
        self.results_table.setWordWrap(True)  # 启用自动换行
        self.results_table.verticalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)  # 自动调整行高
        self.results_table.horizontalHeader().setMinimumSectionSize(60)  # 每列最小宽度60px
        self.results_table.setHorizontalHeaderLabels(["序号", "状态", "URL", "异常原因", "过期时间", "证书链", "TLS版本"])
        self.results_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.results_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        # 设置各列宽度模式
        self.results_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Fixed)  # 序号 - 固定宽度
        self.results_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)  # 状态 - 自适应
        self.results_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)  # URL - 自适应
        self.results_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)  # 异常原因 - 占剩余宽度
        self.results_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)  # 过期时间 - 自适应
        self.results_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)  # 证书链 - 自适应
        self.results_table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeToContents)  # TLS版本 - 自适应
        self.results_table.setColumnWidth(0, 40)   # 序号列固定40px
        self.results_table.itemSelectionChanged.connect(self._on_row_selected)
        self.results_table.setShowGrid(False)
        self.results_table.setAlternatingRowColors(True)

        layout.addWidget(self.results_table)

        return frame

    def _create_detail_panel(self) -> QFrame:
        """创建详情面板"""
        frame = QFrame()
        frame.setObjectName("panel")
        layout = QVBoxLayout(frame)

        label = QLabel("详情信息")
        label_font = QFont()
        label_font.setPointSize(14)
        label_font.setBold(True)
        label.setFont(label_font)
        label.setStyleSheet("color: #1D1C1C;")
        layout.addWidget(label)

        self.detail_tabs = QTabWidget()
        self.detail_tabs.setObjectName("detailTabs")

        # 证书链页面
        self.cert_chain_text = QLabel("选择一条结果查看详情")
        self.cert_chain_text.setObjectName("detailText")
        self.cert_chain_text.setWordWrap(True)
        cert_page = QWidget()
        cert_page.setObjectName("tabContent")
        cert_layout = QVBoxLayout(cert_page)
        cert_layout.addWidget(self.cert_chain_text)
        self.detail_tabs.addTab(cert_page, "证书链")

        # TLS 信息页面
        self.tls_text = QLabel("")
        self.tls_text.setObjectName("detailText")
        self.tls_text.setWordWrap(True)
        tls_page = QWidget()
        tls_page.setObjectName("tabContent")
        tls_layout = QVBoxLayout(tls_page)
        tls_layout.addWidget(self.tls_text)
        self.detail_tabs.addTab(tls_page, "TLS信息")

        # 域名验证页面
        self.domain_text = QLabel("")
        self.domain_text.setObjectName("detailText")
        self.domain_text.setWordWrap(True)
        domain_page = QWidget()
        domain_page.setObjectName("tabContent")
        domain_layout = QVBoxLayout(domain_page)
        domain_layout.addWidget(self.domain_text)
        self.detail_tabs.addTab(domain_page, "域名验证")

        layout.addWidget(self.detail_tabs)

        return frame

    def _create_export_panel(self) -> QFrame:
        """创建导出按钮面板"""
        frame = QFrame()
        frame.setObjectName("panel")
        frame.setMaximumHeight(60)
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(12, 8, 12, 8)

        self.export_html_btn = QPushButton("导出 HTML 报告")
        self.export_html_btn.setObjectName("secondaryBtn")
        self.export_html_btn.setEnabled(False)
        self.export_html_btn.clicked.connect(self._on_export_html)

        self.export_csv_btn = QPushButton("导出 CSV 文件")
        self.export_csv_btn.setObjectName("secondaryBtn")
        self.export_csv_btn.setEnabled(False)
        self.export_csv_btn.clicked.connect(self._on_export_csv)

        layout.addWidget(self.export_html_btn)
        layout.addWidget(self.export_csv_btn)
        layout.addStretch()

        return frame

    def _create_status_bar(self) -> QStatusBar:
        """创建状态栏"""
        status_bar = QStatusBar()
        status_bar.setObjectName("statusBar")
        status_bar.setStyleSheet(f"""
            QStatusBar {{
                background-color: {Colors.BG_HEADER};
                color: {Colors.TEXT_LIGHT};
                padding: 8px 16px;
                font-size: 12px;
            }}
        """)
        self.status_text = QLabel("就绪")
        status_bar.addWidget(self.status_text)
        self.setStatusBar(status_bar)

    def _apply_styles(self):
        """应用样式"""
        self.setStyleSheet(STYLESHEET)

    # ============ 事件处理 ============

    def _on_toggle_check(self):
        """处理开始/停止按钮点击"""
        if not self.is_checking:
            urls = self._get_urls_from_input()
            if not urls:
                QMessageBox.warning(self, "提示", "请输入至少一个 URL")
                return
            self._start_checking(urls)
        else:
            self.is_checking = False
            self._update_ui_state(False)

    def _get_urls_from_input(self) -> List[str]:
        """从输入文本控件获取 URL 列表"""
        text = self.url_input.toPlainText().strip()
        if not text:
            return []

        urls = []
        for line in text.split("\n"):
            line = line.strip()
            if line:
                if not line.startswith(("http://", "https://")):
                    line = "https://" + line
                urls.append(line)
        return urls

    def _start_checking(self, urls: List[str]):
        """开始检测"""
        # 如果有旧的检测线程在运行，先停止它
        if hasattr(self, 'check_thread') and self.check_thread.is_alive():
            self.is_checking = False
            self.check_thread.join(timeout=1)

        self.is_checking = True
        self.results = []
        self.selected_index = -1
        self.completed_count = 0
        self.total_count = len(urls)
        self._clear_results()
        self._clear_detail_panel()
        self._update_ui_state(True)
        self.status_update.emit(f"检测中[0/{len(urls)}]")

        self.check_thread = threading.Thread(target=self._check_worker, args=(urls,))
        self.check_thread.daemon = True
        self.check_thread.start()

    def _check_worker(self, urls: List[str]):
        """证书检测工作线程"""
        total = len(urls)

        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_url = {executor.submit(self._check_single_url, url, i): (i, url) for i, url in enumerate(urls)}

            for future in as_completed(future_to_url):
                if not self.is_checking:
                    executor.shutdown(wait=False)
                    break

                idx, url = future_to_url[future]
                try:
                    result = future.result()
                except Exception as e:
                    result = {
                        "url": url,
                        "status": "error",
                        "error_message": str(e),
                        "cert_chain": [],
                        "cert_chain_complete": False,
                        "expiry": {"expired": False, "days_left": None, "expire_date": None},
                        "revocation": {"status": "unknown", "ocsp_response": ""},
                        "domain_match": {"match": False, "cert_cn": "", "cert_san": []},
                        "tls": {"version": "", "cipher_suite": "", "key_exchange": ""}
                    }

                self.results.append(result)
                self.completed_count += 1
                self.result_ready.emit(result, idx)
                self.status_update.emit(f"检测中[{self.completed_count}/{total}]")

        self.check_finished.emit()

    def _check_single_url(self, url: str, index: int):
        """检测单个URL"""
        return cert_checker.check_certificate(url)

    def _on_result_ready(self, result: Dict[str, Any], index: int):
        """线程安全的结果添加"""
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        self._set_row_data(row, result)
        # 根据当前筛选条件隐藏/显示新行
        if self._current_filter != "all":
            status = result.get("status", "error")
            if status != self._current_filter:
                self.results_table.setRowHidden(row, True)
        self._update_filter_counts()  # 实时更新筛选计数

    def _on_status_update(self, status: str):
        """线程安全的状态更新"""
        self.status_text.setText(status)

    def _on_check_finished(self):
        """线程安全的检测完成处理"""
        self.is_checking = False
        self._update_ui_state(False)
        self.status_text.setText("完成检测")
        self._update_filter_counts()

    def _add_result_row(self, result: Dict[str, Any], row: int):
        """向表格添加结果行"""
        self.results_table.insertRow(row)
        self._set_row_data(row, result)

    def _set_row_data(self, row: int, result: Dict[str, Any]):
        """设置结果行数据"""
        status = result.get("status", "error")
        url = result.get("url", "")
        expiry_info = result.get("expiry", {})
        cert_chain_complete = result.get("cert_chain_complete", False)
        tls_info = result.get("tls", {})
        issues = result.get("issues", [])

        # 序号
        seq_item = QTableWidgetItem(str(row + 1))
        seq_item.setForeground(QColor(Colors.TEXT_SECONDARY))
        seq_item.setTextAlignment(Qt.AlignCenter)
        self.results_table.setItem(row, 0, seq_item)

        # 状态
        status_icon = get_status_icon(status)
        status_item = QTableWidgetItem(status_icon)
        status_item.setData(Qt.UserRole, status)  # 保存status用于筛选
        status_item.setForeground(QColor(get_status_style(status)[1]))
        status_item.setBackground(QColor(get_status_style(status)[0]))
        status_item.setTextAlignment(Qt.AlignCenter)
        self.results_table.setItem(row, 1, status_item)

        # URL - 启用自动换行
        url_item = QTableWidgetItem(url)
        url_item.setForeground(QColor(Colors.TEXT_PRIMARY))
        url_item.setFont(QFont("", -1, QFont.Normal))
        self.results_table.setItem(row, 2, url_item)

        # 异常原因 - 启用自动换行
        if issues:
            issues_display = "；".join(issues)
        else:
            issues_display = "无异常"
        issues_item = QTableWidgetItem(issues_display)
        issues_item.setForeground(QColor(Colors.TEXT_PRIMARY))
        issues_item.setFont(QFont("", -1, QFont.Normal))
        self.results_table.setItem(row, 3, issues_item)

        # 过期时间
        error_message = result.get("error_message", "")
        if expiry_info.get("expired"):
            expiry_display = "已过期"
        elif expiry_info.get("days_left") is not None:
            days = expiry_info['days_left']
            if days <= 30:
                expiry_display = f"{days}天 ⚠️"
            else:
                expiry_display = f"{days}天"
        elif error_message and "连接" in error_message:
            expiry_display = "未知"
        else:
            expiry_display = "未知"

        expiry_item = QTableWidgetItem(expiry_display)
        expiry_item.setForeground(QColor(Colors.TEXT_PRIMARY))
        expiry_item.setTextAlignment(Qt.AlignCenter)
        self.results_table.setItem(row, 4, expiry_item)

        # 证书链
        issues = result.get("issues", [])
        is_error = result.get("status") == "error" and any(
            issue in issues for issue in ["URL无法访问", "检测失败"]
        )
        if is_error:
            chain_display = "未知"
        elif error_message and "连接" in error_message:
            chain_display = "未知"
        elif cert_chain_complete:
            chain_display = "完整"
        else:
            chain_display = "不完整"
        chain_item = QTableWidgetItem(chain_display)
        chain_item.setForeground(QColor(Colors.TEXT_PRIMARY))
        chain_item.setTextAlignment(Qt.AlignCenter)
        self.results_table.setItem(row, 5, chain_item)

        # TLS 版本
        if error_message and "连接" in error_message:
            tls_display = "未知"
        else:
            tls_display = tls_info.get("version", "未知")
        tls_item = QTableWidgetItem(tls_display)
        tls_item.setForeground(QColor(Colors.TEXT_PRIMARY))
        tls_item.setTextAlignment(Qt.AlignCenter)
        self.results_table.setItem(row, 6, tls_item)

    def _on_row_selected(self):
        """处理行选择"""
        selected = self.results_table.selectedItems()
        if selected:
            row = selected[0].row()
            self.selected_index = row
            self._update_detail_panel()

    def _on_filter_changed(self, btn_id: int):
        """筛选按钮切换"""
        filter_map = {0: "all", 1: "valid", 2: "warning", 3: "error"}
        self._current_filter = filter_map.get(btn_id, "all")
        self._apply_filter()
        self._update_filter_counts()

    def _apply_filter(self):
        """根据筛选条件显示/隐藏行"""
        for row in range(self.results_table.rowCount()):
            if self._current_filter == "all":
                self.results_table.setRowHidden(row, False)
            else:
                item = self.results_table.item(row, 1)  # 状态列
                if item:
                    status = item.data(Qt.UserRole) if item.data(Qt.UserRole) else ""
                    if status != self._current_filter:
                        self.results_table.setRowHidden(row, True)
                    else:
                        self.results_table.setRowHidden(row, False)

    def _update_filter_counts(self):
        """更新筛选按钮计数"""
        if not self.results:
            return

        counts = {"all": len(self.results), "valid": 0, "warning": 0, "error": 0}
        for r in self.results:
            status = r.get("status", "error")
            if status in counts:
                counts[status] += 1

        # 更新按钮文字
        buttons = self.filter_group.buttons()
        for btn in buttons:
            btn_id = self.filter_group.id(btn)
            if btn_id == 0:
                btn.setText(f"全部 ({counts['all']})")
            elif btn_id == 1:
                btn.setText(f"✅有效 ({counts['valid']})")
            elif btn_id == 2:
                btn.setText(f"⚠️警告 ({counts['warning']})")
            elif btn_id == 3:
                btn.setText(f"❌错误 ({counts['error']})")

    def _clear_results(self):
        """清除所有结果"""
        self.results_table.setRowCount(0)

    def _clear_detail_panel(self):
        """清除详情面板"""
        self.cert_chain_text.setText("选择一条结果查看详情")
        self.cert_chain_text.setStyleSheet("color: #888888; font-size: 14px;")
        self.tls_text.setText("")
        self.domain_text.setText("")

    def _update_detail_panel(self):
        """更新详情面板"""
        if self.selected_index < 0 or self.selected_index >= len(self.results):
            return

        result = self.results[self.selected_index]
        self._update_cert_chain_detail(result)
        self._update_tls_detail(result)
        self._update_domain_detail(result)

    def _update_cert_chain_detail(self, result: Dict[str, Any]):
        """更新证书链详情"""
        cert_chain = result.get("cert_chain", [])
        cert_chain_complete = result.get("cert_chain_complete", False)
        error_message = result.get("error_message", "")

        if not cert_chain:
            if error_message:
                text = f"❌ 访问失败\n\n⚠️ {error_message}"
            else:
                text = "证书链信息不可用"
            self.cert_chain_text.setText(text)
            self.cert_chain_text.setStyleSheet("color: #1D1C1C; font-size: 14px; line-height: 1.8;")
            return

        lines = []
        for cert in cert_chain:
            cert_type = cert.get("type", "unknown")
            cert_name = cert.get("name", "Unknown")
            cert_status = cert.get("status", "unknown")

            type_labels = {"root": "Root CA", "intermediate": "Intermediate", "server": "Server"}
            label = type_labels.get(cert_type, cert_type)

            icon = "✅" if cert_status == "ok" else "❌"
            lines.append(f"├── {label}: {cert_name} {icon}")

        chain_status = "完整 ✅" if cert_chain_complete else "不完整 ❌"
        lines.append(f"\n证书链状态: {chain_status}")

        if error_message:
            lines.append(f"\n⚠️ 告警: {error_message}")

        self.cert_chain_text.setText("\n".join(lines))
        self.cert_chain_text.setStyleSheet("color: #1D1C1C; font-size: 14px; line-height: 1.8;")

    def _update_tls_detail(self, result: Dict[str, Any]):
        """更新 TLS 详情"""
        tls = result.get("tls", {})
        error_message = result.get("error_message", "")

        if not tls or not tls.get("version"):
            if error_message and "连接" in error_message:
                self.tls_text.setText(f"❌ 访问失败\n\n⚠️ {error_message}")
            else:
                self.tls_text.setText("TLS 信息不可用")
            self.tls_text.setStyleSheet("color: #1D1C1C; font-size: 14px; line-height: 1.8;")
            return

        cipher = tls.get('cipher_suite', '未知')
        if tls.get('cipher_weak'):
            cipher = f"⚠️ {cipher}"

        version = tls.get('version', '未知')
        if version in ("TLSv1", "TLSv1.1"):
            version = f"⚠️ {version} (已弃用)"

        lines = [
            f"版本: {version}",
            f"加密套件: {cipher}",
            f"密钥交换: {tls.get('key_exchange', '未知')}"
        ]

        self.tls_text.setText("\n".join(lines))
        self.tls_text.setStyleSheet("color: #1D1C1C; font-size: 14px; line-height: 1.8;")

    def _update_domain_detail(self, result: Dict[str, Any]):
        """更新域名验证详情"""
        domain_match = result.get("domain_match", {})
        url = result.get("url", "")
        error_message = result.get("error_message", "")

        if not domain_match:
            if error_message and "连接" in error_message:
                self.domain_text.setText(f"❌ 访问失败\n\n⚠️ {error_message}")
            else:
                self.domain_text.setText("域名验证信息不可用")
            self.domain_text.setStyleSheet("color: #1D1C1C; font-size: 14px; line-height: 1.8;")
            return

        match = domain_match.get("match", False)
        cn = domain_match.get("cert_cn", "未知")
        san_list = domain_match.get("cert_san", [])

        match_status = "匹配 ✅" if match else "不匹配 ❌"
        san_display = ", ".join(san_list) if san_list else "无"

        lines = [
            f"访问域名: {url}",
            f"匹配状态: {match_status}",
            f"证书CN: {cn}",
            f"证书SAN: {san_display}"
        ]

        self.domain_text.setText("\n".join(lines))
        self.domain_text.setStyleSheet("color: #1D1C1C; font-size: 14px; line-height: 1.8;")

    def _update_ui_state(self, checking: bool):
        """根据检测状态更新 UI"""
        self.is_checking = checking
        if checking:
            self.toggle_btn.setText("停止")
            self.toggle_btn.setStyleSheet(f"""
                QPushButton#primaryBtn {{
                    background-color: {Colors.STATUS_ERROR};
                    color: {Colors.TEXT_PRIMARY};
                    border: none;
                    border-radius: 8px;
                    padding: 10px 24px;
                    font-size: 14px;
                    font-weight: 500;
                }}
            """)
        else:
            self.toggle_btn.setText("开始检测")
            self.toggle_btn.setStyleSheet(f"""
                QPushButton#primaryBtn {{
                    background-color: {Colors.PRIMARY};
                    color: {Colors.TEXT_PRIMARY};
                    border: none;
                    border-radius: 8px;
                    padding: 10px 24px;
                    font-size: 14px;
                    font-weight: 500;
                }}
                QPushButton#primaryBtn:hover {{
                    background-color: {Colors.PRIMARY_DARK};
                }}
            """)
        self.url_input.setEnabled(not checking)
        has_results = len(self.results) > 0
        self.export_html_btn.setEnabled(not checking and has_results)
        self.export_csv_btn.setEnabled(not checking and has_results)

    def _on_export_html(self):
        """导出 HTML 报告"""
        if not self.results:
            QMessageBox.warning(self, "提示", "没有检测结果可导出")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"https_cert_report_{timestamp}.html"

        path, _ = QFileDialog.getSaveFileName(
            self,
            "导出 HTML 报告",
            default_filename,
            "HTML files (*.html)"
        )

        if path:
            try:
                report_generator.generate_html_report(self.results, path)
                QMessageBox.information(self, "成功", f"报告已导出至: {path}")
            except Exception as e:
                QMessageBox.critical(self, "错误", f"导出失败: {str(e)}")

    def _on_export_csv(self):
        """导出 CSV 文件"""
        if not self.results:
            QMessageBox.warning(self, "提示", "没有检测结果可导出")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"https_cert_report_{timestamp}.csv"

        path, _ = QFileDialog.getSaveFileName(
            self,
            "导出 CSV 文件",
            default_filename,
            "CSV files (*.csv)"
        )

        if path:
            try:
                report_generator.generate_csv_report(self.results, path)
                QMessageBox.information(self, "成功", f"CSV 文件已导出至: {path}")
            except Exception as e:
                QMessageBox.critical(self, "错误", f"导出失败: {str(e)}")

    def closeEvent(self, event):
        """关闭事件"""
        self.is_checking = False
        event.accept()


def main():
    # 设置 Qt 插件路径（修复 PySide6 打包后找不到平台插件的问题）
    import PySide6
    pyside_path = os.path.dirname(PySide6.__file__)
    os.environ['QT_QPA_PLATFORM_PLUGIN_PATH'] = os.path.join(pyside_path, 'plugins', 'platforms')

    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
