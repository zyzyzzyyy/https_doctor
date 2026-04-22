"""
HTTPS 证书检测工具 - wxPython GUI 主窗口
包含 URL 输入框、检测结果表格、详情面板和状态栏
"""

import wx
import wx.grid
import wx.lib.agw.flatnotebook as flatnotebook
import threading
import os
from datetime import datetime
from typing import List, Dict, Any, Optional

import cert_checker
import report_generator


# ============ 配色方案 ============
class Colors:
    """统一配色方案"""
    # 主色调
    PRIMARY = wx.Colour(113, 196, 239)       # accent-100 - 按钮
    PRIMARY_DARK = wx.Colour(0, 102, 140)    # accent-200 - 深色强调
    PRIMARY_LIGHT = wx.Colour(182, 204, 216) # primary-200 - 边框

    # 背景色
    BG_MAIN = wx.Colour(245, 244, 241)      # bg-200 - 主背景
    BG_PANEL = wx.Colour(255, 254, 251)     # bg-100 - 面板背景
    BG_HEADER = wx.Colour(59, 60, 61)        # primary-300 - 头部背景

    # 文字色
    TEXT_PRIMARY = wx.Colour(29, 28, 28)     # text-100 - 主文字
    TEXT_SECONDARY = wx.Colour(49, 61, 68)   # text-200 - 次要文字
    TEXT_LIGHT = wx.Colour(255, 255, 255)    # 浅色文字

    # 状态色 - 更深的颜色
    STATUS_VALID = wx.Colour(27, 140, 60)    # 深绿色 - 有效
    STATUS_WARNING = wx.Colour(200, 140, 0)  # 深黄色 - 警告
    STATUS_ERROR = wx.Colour(180, 40, 40)    # 深红色 - 错误
    STATUS_VALID_BG = wx.Colour(200, 230, 201)  # 浅绿背景
    STATUS_WARNING_BG = wx.Colour(255, 243, 200)  # 浅黄背景
    STATUS_ERROR_BG = wx.Colour(255, 200, 200)   # 浅红背景

    # 按钮禁用色
    BTN_DISABLED = wx.Colour(180, 180, 180)   # 灰色


def _create_emoji_font(point_size: int = 10) -> wx.Font:
    """创建emoji专用字体（使用Segoe UI Emoji）"""
    try:
        # PyInstaller打包后，资源文件在 sys._MEIPASS 目录
        import sys
        if getattr(sys, 'frozen', False):
            base_path = sys._MEIPASS
        else:
            base_path = os.path.dirname(__file__)
        font_path = os.path.join(base_path, "seguiemj.ttf")
        if os.path.exists(font_path):
            wx.Font.AddPrivateFont(font_path)
            return wx.Font(point_size, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL,
                          wx.FONTWEIGHT_NORMAL, face="Segoe UI Emoji")
    except Exception:
        pass
    return wx.Font(point_size, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL)


class MainFrame(wx.Frame):
    """主窗口类"""

    def __init__(self):
        super().__init__(None, title="HTTPS 证书检测工具", size=(1000, 700))

        self.results: List[Dict[str, Any]] = []
        self.selected_index: int = -1
        self.is_checking: bool = False

        # 设置窗口背景色
        self.SetBackgroundColour(Colors.BG_MAIN)

        self._init_ui()
        self._layout()
        self._apply_styles()

    def _init_ui(self):
        """初始化 UI 组件"""
        # 菜单栏
        menubar = wx.MenuBar()

        file_menu = wx.Menu()
        export_html_item = file_menu.Append(wx.ID_SAVE, "导出HTML报告\tCtrl+S", "导出检测结果为HTML报告")
        export_csv_item = file_menu.Append(wx.ID_ANY, "导出CSV文件\tCtrl+Shift+S", "导出检测结果为CSV文件")
        file_menu.AppendSeparator()
        exit_item = file_menu.Append(wx.ID_EXIT, "退出\tCtrl+Q", "退出程序")
        menubar.Append(file_menu, "文件")

        help_menu = wx.Menu()
        about_item = help_menu.Append(wx.ID_ABOUT, "关于", "关于本程序")
        menubar.Append(help_menu, "帮助")

        self.SetMenuBar(menubar)

        # 绑定菜单事件
        self.Bind(wx.EVT_MENU, self._on_export_html, export_html_item)
        self.Bind(wx.EVT_MENU, self._on_export_csv, export_csv_item)
        self.Bind(wx.EVT_MENU, self._on_exit, exit_item)
        self.Bind(wx.EVT_MENU, self._on_about, about_item)

        # ===== 标题栏 =====
        self.header_panel = wx.Panel(self)
        header_sizer = wx.BoxSizer(wx.HORIZONTAL)
        title_font = wx.Font(16, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_BOLD)
        self.title_label = wx.StaticText(self.header_panel, label="HTTPS 证书检测")
        self.title_label.SetFont(title_font)
        self.title_label.SetForegroundColour(Colors.TEXT_LIGHT)
        header_sizer.Add(self.title_label, flag=wx.ALIGN_CENTER_VERTICAL | wx.ALL, border=15)
        self.header_panel.SetBackgroundColour(Colors.BG_HEADER)
        self.header_panel.SetSizer(header_sizer)

        # ===== URL 输入面板 =====
        self.input_panel = wx.Panel(self)
        input_sizer = wx.BoxSizer(wx.VERTICAL)

        # 区域标题
        section_font = wx.Font(10, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_BOLD)
        input_label = wx.StaticText(self.input_panel, label="输入待检测的 URL（每行一个）")
        input_label.SetFont(section_font)
        input_label.SetForegroundColour(Colors.TEXT_PRIMARY)

        self.url_text = wx.TextCtrl(
            self.input_panel,
            style=wx.TE_MULTILINE | wx.TE_PROCESS_ENTER,
            size=(-1, 80)
        )
        self.url_text.SetBackgroundColour(Colors.BG_PANEL)

        input_sizer.Add(input_label, flag=wx.BOTTOM, border=8)
        input_sizer.Add(self.url_text, flag=wx.EXPAND)
        self.input_panel.SetSizer(input_sizer)
        self.input_panel.SetBackgroundColour(Colors.BG_PANEL)

        # ===== 按钮面板 =====
        self.btn_panel = wx.Panel(self)
        btn_sizer = wx.BoxSizer(wx.HORIZONTAL)

        self.toggle_btn = wx.Button(self.btn_panel, label="开始检测", size=(120, -1))
        self._is_checking = False

        # 进度标签
        self.progress_label = wx.StaticText(self.btn_panel, label="")
        progress_font = wx.Font(10, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL)
        self.progress_label.SetFont(progress_font)
        self.progress_label.SetForegroundColour(Colors.TEXT_SECONDARY)

        btn_sizer.Add(self.toggle_btn, flag=wx.RIGHT, border=10)
        btn_sizer.AddStretchSpacer(1)
        btn_sizer.Add(self.progress_label, flag=wx.ALIGN_CENTER_VERTICAL)
        self.btn_panel.SetSizer(btn_sizer)
        self.btn_panel.SetBackgroundColour(Colors.BG_PANEL)

        self.Bind(wx.EVT_BUTTON, self._on_toggle_check, self.toggle_btn)

        # ===== 检测结果表格 =====
        self.results_panel = wx.Panel(self)
        results_sizer = wx.BoxSizer(wx.VERTICAL)

        results_label = wx.StaticText(self.results_panel, label="检测结果")
        results_label.SetFont(section_font)
        results_label.SetForegroundColour(Colors.TEXT_PRIMARY)

        self.results_grid = wx.grid.Grid(self.results_panel)
        self.results_grid.CreateGrid(0, 5)
        self.results_grid.SetColLabelValue(0, "状态")
        self.results_grid.SetColLabelValue(1, "URL")
        self.results_grid.SetColLabelValue(2, "过期时间")
        self.results_grid.SetColLabelValue(3, "证书链")
        self.results_grid.SetColLabelValue(4, "TLS版本")
        self.results_grid.SetColSize(0, 60)
        self.results_grid.SetColSize(1, 300)
        self.results_grid.SetColSize(2, 100)
        self.results_grid.SetColSize(3, 120)
        self.results_grid.SetColSize(4, 80)

        # 设置表格样式
        self.results_grid.SetLabelBackgroundColour(Colors.PRIMARY_LIGHT)
        self.results_grid.SetLabelTextColour(Colors.TEXT_PRIMARY)
        self.results_grid.SetGridLineColour(Colors.PRIMARY_LIGHT)

        # 创建emoji字体供状态列使用
        self.emoji_font = _create_emoji_font(10)

        self.results_grid.Bind(wx.grid.EVT_GRID_SELECT_CELL, self._on_grid_select)

        results_sizer.Add(results_label, flag=wx.BOTTOM, border=8)
        results_sizer.Add(self.results_grid, flag=wx.EXPAND, proportion=1)
        self.results_panel.SetSizer(results_sizer)
        self.results_panel.SetBackgroundColour(Colors.BG_PANEL)

        # ===== 详情面板 =====
        self.detail_panel = wx.Panel(self)
        detail_sizer = wx.BoxSizer(wx.VERTICAL)

        detail_label = wx.StaticText(self.detail_panel, label="详情信息")
        detail_label.SetFont(section_font)
        detail_label.SetForegroundColour(Colors.TEXT_PRIMARY)

        # 使用 FlatNotebook 替代普通 Notebook，隐藏关闭按钮
        self.notebook = flatnotebook.FlatNotebook(
            self.detail_panel,
            style=flatnotebook.FNB_NO_X_BUTTON | flatnotebook.FNB_NO_TAB_FOCUS | flatnotebook.FNB_X_ON_TAB
        )
        self.notebook.SetActiveTabColour(Colors.BG_PANEL)
        self.notebook.SetTabAreaColour(Colors.PRIMARY_LIGHT)

        # 证书链页面
        self.cert_chain_page = wx.Panel(self.notebook)
        self.cert_chain_sizer = wx.BoxSizer(wx.VERTICAL)
        self.cert_chain_text = wx.StaticText(self.cert_chain_page, label="")
        cert_font = wx.Font(10, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL)
        self.cert_chain_text.SetFont(cert_font)
        self.cert_chain_sizer.Add(self.cert_chain_text, flag=wx.EXPAND | wx.ALL, border=10)
        self.cert_chain_page.SetSizer(self.cert_chain_sizer)
        self.notebook.AddPage(self.cert_chain_page, "证书链")

        # TLS 信息页面
        self.tls_page = wx.Panel(self.notebook)
        self.tls_sizer = wx.BoxSizer(wx.VERTICAL)
        self.tls_text = wx.StaticText(self.tls_page, label="")
        self.tls_text.SetFont(cert_font)
        self.tls_sizer.Add(self.tls_text, flag=wx.EXPAND | wx.ALL, border=10)
        self.tls_page.SetSizer(self.tls_sizer)
        self.notebook.AddPage(self.tls_page, "TLS信息")

        # 域名验证页面
        self.domain_page = wx.Panel(self.notebook)
        self.domain_sizer = wx.BoxSizer(wx.VERTICAL)
        self.domain_text = wx.StaticText(self.domain_page, label="")
        self.domain_text.SetFont(cert_font)
        self.domain_sizer.Add(self.domain_text, flag=wx.EXPAND | wx.ALL, border=10)
        self.domain_page.SetSizer(self.domain_sizer)
        self.notebook.AddPage(self.domain_page, "域名验证")

        detail_sizer.Add(detail_label, flag=wx.BOTTOM, border=8)
        detail_sizer.Add(self.notebook, flag=wx.EXPAND, proportion=1)
        self.detail_panel.SetSizer(detail_sizer)
        self.detail_panel.SetBackgroundColour(Colors.BG_PANEL)

        # ===== 导出按钮面板 =====
        self.export_btn_panel = wx.Panel(self)
        export_btn_sizer = wx.BoxSizer(wx.HORIZONTAL)
        self.export_html_btn = wx.Button(self.export_btn_panel, label="导出 HTML 报告")
        self.export_csv_btn = wx.Button(self.export_btn_panel, label="导出 CSV 文件")
        self.export_html_btn.Enable(False)
        self.export_csv_btn.Enable(False)
        export_btn_sizer.Add(self.export_html_btn, flag=wx.RIGHT, border=10)
        export_btn_sizer.Add(self.export_csv_btn)
        self.export_btn_panel.SetSizer(export_btn_sizer)
        self.export_btn_panel.SetBackgroundColour(Colors.BG_PANEL)

        self.Bind(wx.EVT_BUTTON, self._on_export_html, self.export_html_btn)
        self.Bind(wx.EVT_BUTTON, self._on_export_csv, self.export_csv_btn)

        # ===== 自定义状态栏（用Panel实现，完全可控） =====
        self.statusbar = wx.Panel(self, size=(-1, 25))
        statusbar_sizer = wx.BoxSizer(wx.HORIZONTAL)
        statusbar_font = wx.Font(9, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL)
        self.status_text = wx.StaticText(self.statusbar, label="就绪")
        self.status_text.SetFont(statusbar_font)
        self.status_text.SetForegroundColour(Colors.TEXT_LIGHT)
        statusbar_sizer.Add(self.status_text, flag=wx.ALIGN_CENTER_VERTICAL | wx.ALL, border=5)
        self.statusbar.SetSizer(statusbar_sizer)
        self.statusbar.SetBackgroundColour(Colors.BG_HEADER)

        # 保存引用 - 这些变量在前面已用 self. 定义
        pass

    def _apply_styles(self):
        """应用统一样式"""
        # 按钮样式
        self.toggle_btn.SetBackgroundColour(Colors.PRIMARY)
        self.toggle_btn.SetForegroundColour(Colors.TEXT_LIGHT)

        # 导出按钮样式 - 初始状态为禁用（灰色）
        self.export_html_btn.SetBackgroundColour(Colors.BTN_DISABLED)
        self.export_html_btn.SetForegroundColour(Colors.TEXT_LIGHT)
        self.export_csv_btn.SetBackgroundColour(Colors.BTN_DISABLED)
        self.export_csv_btn.SetForegroundColour(Colors.TEXT_LIGHT)

    def _layout(self):
        """布局主窗口"""
        main_sizer = wx.BoxSizer(wx.VERTICAL)
        main_sizer.Add(self.header_panel, flag=wx.EXPAND)
        main_sizer.Add(self.input_panel, flag=wx.EXPAND | wx.ALL, border=10)
        main_sizer.Add(self.btn_panel, flag=wx.EXPAND | wx.LEFT | wx.RIGHT, border=10)
        main_sizer.Add(self.results_panel, flag=wx.EXPAND | wx.LEFT | wx.RIGHT, border=10, proportion=1)
        main_sizer.Add(self.detail_panel, flag=wx.EXPAND | wx.LEFT | wx.RIGHT, border=10, proportion=1)
        main_sizer.Add(self.export_btn_panel, flag=wx.EXPAND | wx.ALL, border=10)
        main_sizer.Add(self.statusbar, flag=wx.EXPAND)

        self.SetSizer(main_sizer)

    def _on_toggle_check(self, event):
        """处理开始/停止按钮点击"""
        if not self._is_checking:
            # 开始检测
            urls = self._get_urls_from_input()
            if not urls:
                wx.MessageBox("请输入至少一个 URL", "提示", wx.OK | wx.ICON_WARNING)
                return
            self._start_checking(urls)
        else:
            # 停止检测
            self.is_checking = False
            self._update_ui_state(False)

    def _on_export_html(self, event):
        """处理导出 HTML 报告按钮点击"""
        if not self.results:
            wx.MessageBox("没有检测结果可导出", "提示", wx.OK | wx.ICON_WARNING)
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"https_cert_report_{timestamp}.html"

        dlg = wx.FileDialog(
            self,
            wildcard="HTML files (*.html)|*.html",
            style=wx.FD_SAVE | wx.FD_OVERWRITE_PROMPT,
            defaultFile=default_filename
        )

        if dlg.ShowModal() == wx.ID_OK:
            path = dlg.GetPath()
            try:
                report_generator.generate_html_report(self.results, path)
                wx.MessageBox(f"报告已导出至: {path}", "成功", wx.OK | wx.ICON_INFORMATION)
            except Exception as e:
                wx.MessageBox(f"导出失败: {str(e)}", "错误", wx.OK | wx.ICON_ERROR)

        dlg.Destroy()

    def _on_export_csv(self, event):
        """处理导出 CSV 文件按钮点击"""
        if not self.results:
            wx.MessageBox("没有检测结果可导出", "提示", wx.OK | wx.ICON_WARNING)
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"https_cert_report_{timestamp}.csv"

        dlg = wx.FileDialog(
            self,
            wildcard="CSV files (*.csv)|*.csv",
            style=wx.FD_SAVE | wx.FD_OVERWRITE_PROMPT,
            defaultFile=default_filename
        )

        if dlg.ShowModal() == wx.ID_OK:
            path = dlg.GetPath()
            try:
                report_generator.generate_csv_report(self.results, path)
                wx.MessageBox(f"CSV 文件已导出至: {path}", "成功", wx.OK | wx.ICON_INFORMATION)
            except Exception as e:
                wx.MessageBox(f"导出失败: {str(e)}", "错误", wx.OK | wx.ICON_ERROR)

        dlg.Destroy()

    def _on_exit(self, event):
        """处理退出菜单项"""
        self.Close()

    def _on_about(self, event):
        """处理关于菜单项"""
        wx.MessageBox(
            "HTTPS 证书检测工具 v1.0\n\n"
            "用于检测 HTTPS 网站的证书状态、过期时间、证书链完整性等。",
            "关于",
            wx.OK | wx.ICON_INFORMATION
        )

    def _on_grid_select(self, event):
        """处理表格单元格选择"""
        row = event.GetRow()
        self.selected_index = row
        self._update_detail_panel()
        event.Skip()

    def _get_urls_from_input(self) -> List[str]:
        """从输入文本控件获取 URL 列表"""
        text = self.url_text.GetValue().strip()
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
        """开始检测给定 URL 的证书"""
        self.is_checking = True
        self.results = []
        self.selected_index = -1
        self._clear_results()
        self._clear_detail_panel()
        self._update_ui_state(True)
        self._update_progress(0, len(urls), "")

        thread = threading.Thread(target=self._check_worker, args=(urls,))
        thread.daemon = True
        thread.start()

    def _check_worker(self, urls: List[str]):
        """证书检测工作线程"""
        total = len(urls)

        for i, url in enumerate(urls):
            if not self.is_checking:
                break

            wx.CallAfter(self._update_status, f"检测中: {url}")
            wx.CallAfter(self._update_progress, i + 1, total, url)

            try:
                result = cert_checker.check_certificate(url)
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
            wx.CallAfter(self._add_result_row, result, i)

        wx.CallAfter(self._on_check_complete)

    def _update_ui_state(self, checking: bool):
        """根据检测状态更新 UI"""
        self._is_checking = checking
        if checking:
            self.toggle_btn.SetLabel("停止")
            self.toggle_btn.SetBackgroundColour(Colors.STATUS_ERROR)
        else:
            self.toggle_btn.SetLabel("开始检测")
            self.toggle_btn.SetBackgroundColour(Colors.PRIMARY)
        self.url_text.Enable(not checking)
        has_results = len(self.results) > 0
        self.export_html_btn.Enable(not checking and has_results)
        self.export_csv_btn.Enable(not checking and has_results)
        # 更新导出按钮颜色
        if not checking and has_results:
            self.export_html_btn.SetBackgroundColour(Colors.PRIMARY)
            self.export_csv_btn.SetBackgroundColour(Colors.PRIMARY)
        else:
            self.export_html_btn.SetBackgroundColour(Colors.BTN_DISABLED)
            self.export_csv_btn.SetBackgroundColour(Colors.BTN_DISABLED)

    def _update_status(self, status: str):
        """更新状态栏文本"""
        self.status_text.SetLabel(status)

    def _update_progress(self, current: int, total: int, url: str = ""):
        """更新进度标签"""
        if url:
            # 提取域名显示
            from urllib.parse import urlparse
            parsed = urlparse(url)
            domain = parsed.netloc or url
            self.progress_label.SetLabel(f"[{current}/{total}] {domain} 检测中...")
            self.progress_label.SetForegroundColour(Colors.PRIMARY)
        else:
            self.progress_label.SetLabel(f"[{current}/{total}]")
            self.progress_label.SetForegroundColour(Colors.TEXT_SECONDARY)

    def _clear_results(self):
        """清除所有结果行"""
        if self.results_grid.GetNumberRows() > 0:
            self.results_grid.DeleteRows(0, self.results_grid.GetNumberRows())

    def _add_result_row(self, result: Dict[str, Any], row: int):
        """向表格添加结果行"""
        self.results_grid.AppendRows(1)
        self._set_row_data(row, result)

    def _set_row_data(self, row: int, result: Dict[str, Any]):
        """设置结果行数据"""
        status = result.get("status", "error")
        url = result.get("url", "")
        expiry_info = result.get("expiry", {})
        cert_chain_complete = result.get("cert_chain_complete", False)
        tls_info = result.get("tls", {})

        # 状态图标和颜色
        status_icons = {
            "valid": "✅ 有效",
            "warning": "⚠️ 警告",
            "error": "❌ 错误"
        }
        status_icon = status_icons.get(status, "❌ 错误")

        status_bg_colors = {
            "valid": Colors.STATUS_VALID_BG,
            "warning": Colors.STATUS_WARNING_BG,
            "error": Colors.STATUS_ERROR_BG
        }
        status_text_colors = {
            "valid": Colors.STATUS_VALID,
            "warning": Colors.STATUS_WARNING,
            "error": Colors.STATUS_ERROR
        }

        # 设置状态单元格颜色
        attr = wx.grid.GridCellAttr()
        attr.SetBackgroundColour(status_bg_colors.get(status, Colors.BG_PANEL))
        attr.SetFont(self.emoji_font)
        self.results_grid.SetRowAttr(row, attr)

        # 设置状态文字颜色
        self.results_grid.SetCellTextColour(row, 0, status_text_colors.get(status, Colors.STATUS_ERROR))

        # 过期时间显示
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

        # 证书链显示
        if error_message and "连接" in error_message:
            chain_display = "访问失败"
        elif cert_chain_complete:
            chain_display = "完整"
        else:
            chain_display = "不完整"

        # TLS 版本
        if error_message and "连接" in error_message:
            tls_display = "未知"
        else:
            tls_display = tls_info.get("version", "未知")

        self.results_grid.SetCellValue(row, 0, status_icon)
        self.results_grid.SetCellValue(row, 1, url)
        self.results_grid.SetCellValue(row, 2, expiry_display)
        self.results_grid.SetCellValue(row, 3, chain_display)
        self.results_grid.SetCellValue(row, 4, tls_display)

        # URL 列设为只读
        self.results_grid.SetReadOnly(row, 1)

    def _clear_detail_panel(self):
        """清除详情面板内容"""
        self.cert_chain_text.SetLabel("")
        self.tls_text.SetLabel("")
        self.domain_text.SetLabel("")

    def _update_detail_panel(self):
        """更新详情面板显示选中结果"""
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
            self.cert_chain_text.SetLabel(text)
            self.cert_chain_page.Layout()
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

        self.cert_chain_text.SetLabel("\n".join(lines))
        self.cert_chain_page.Layout()

    def _update_tls_detail(self, result: Dict[str, Any]):
        """更新 TLS 详情"""
        tls = result.get("tls", {})
        error_message = result.get("error_message", "")

        if not tls or not tls.get("version"):
            if error_message and "连接" in error_message:
                self.tls_text.SetLabel("❌ 访问失败\n\n⚠️ " + error_message)
            else:
                self.tls_text.SetLabel("TLS 信息不可用")
            self.tls_page.Layout()
            return

        cipher = tls.get('cipher_suite', '未知')
        if tls.get('cipher_weak'):
            cipher = f"⚠️ {cipher}"

        version = tls.get('version', '未知')
        version_display = version
        if version in ("TLSv1", "TLSv1.1"):
            version_display = f"⚠️ {version} (已弃用)"

        lines = [
            f"版本: {version_display}",
            f"加密套件: {cipher}",
            f"密钥交换: {tls.get('key_exchange', '未知')}"
        ]

        self.tls_text.SetLabel("\n".join(lines))
        self.tls_page.Layout()

    def _update_domain_detail(self, result: Dict[str, Any]):
        """更新域名验证详情"""
        domain_match = result.get("domain_match", {})
        url = result.get("url", "")
        error_message = result.get("error_message", "")

        if not domain_match:
            if error_message and "连接" in error_message:
                self.domain_text.SetLabel("❌ 访问失败\n\n⚠️ " + error_message)
            else:
                self.domain_text.SetLabel("域名验证信息不可用")
            self.domain_page.Layout()
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

        self.domain_text.SetLabel("\n".join(lines))
        self.domain_page.Layout()

    def _on_check_complete(self):
        """处理检测完成"""
        self.is_checking = False
        self._update_ui_state(False)
        self._update_status("检测完成")
        self.progress_label.SetLabel(f"[{len(self.results)}/{len(self.results)}] ✅")
        self.progress_label.SetForegroundColour(Colors.STATUS_VALID)


class App(wx.App):
    """应用程序类"""

    def OnInit(self):
        frame = MainFrame()
        frame.Show()
        self.SetTopWindow(frame)
        return True


def main():
    """入口函数"""
    app = App()
    app.MainLoop()


if __name__ == "__main__":
    main()
