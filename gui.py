"""
HTTPS 证书检测工具 - wxPython GUI 主窗口
包含 URL 输入框、检测结果表格、详情面板和状态栏
"""

import wx
import wx.grid
import wx.lib.agw.flatnotebook as flatnotebook
import threading
from typing import List, Dict, Any, Optional

import cert_checker
import report_generator


class MainFrame(wx.Frame):
    """主窗口类"""

    def __init__(self):
        super().__init__(None, title="HTTPS 证书检测工具", size=(1000, 700))

        self.results: List[Dict[str, Any]] = []
        self.selected_index: int = -1
        self.is_checking: bool = False

        self._init_ui()
        self._layout()

    def _init_ui(self):
        """初始化 UI 组件"""
        # 菜单栏
        menubar = wx.MenuBar()

        file_menu = wx.Menu()
        export_item = file_menu.Append(wx.ID_SAVE, "导出HTML报告\tCtrl+S", "导出检测结果为HTML报告")
        exit_item = file_menu.Append(wx.ID_EXIT, "退出\tCtrl+Q", "退出程序")
        menubar.Append(file_menu, "文件")

        help_menu = wx.Menu()
        about_item = help_menu.Append(wx.ID_ABOUT, "关于", "关于本程序")
        menubar.Append(help_menu, "帮助")

        self.SetMenuBar(menubar)

        # 工具栏
        toolbar = self.CreateToolBar()
        start_tool = toolbar.AddTool(wx.ID_ANY, "开始检测", wx.Bitmap(self._make_check_icon()))
        export_tool = toolbar.AddTool(wx.ID_ANY, "导出报告", wx.Bitmap(self._make_export_icon()))
        toolbar.AddSeparator()
        stop_tool = toolbar.AddTool(wx.ID_ANY, "停止", wx.Bitmap(self._make_stop_icon()))
        toolbar.Realize()

        self.toolbar = toolbar
        self.start_tool = start_tool
        self.stop_tool = stop_tool
        self.export_tool = export_tool

        # 绑定工具栏事件
        self.Bind(wx.EVT_TOOL, self._on_start_check, start_tool)
        self.Bind(wx.EVT_TOOL, self._on_export, export_tool)
        self.Bind(wx.EVT_TOOL, self._on_stop, stop_tool)

        # 绑定菜单事件
        self.Bind(wx.EVT_MENU, self._on_export, export_item)
        self.Bind(wx.EVT_MENU, self._on_exit, exit_item)
        self.Bind(wx.EVT_MENU, self._on_about, about_item)

        # URL 输入面板
        input_panel = wx.Panel(self)
        input_sizer = wx.BoxSizer(wx.VERTICAL)
        input_label = wx.StaticText(input_panel, label="输入 URL（每行一个）:")
        self.url_text = wx.TextCtrl(
            input_panel,
            style=wx.TE_MULTILINE | wx.TE_PROCESS_ENTER,
            size=(-1, 100)
        )
        input_sizer.Add(input_label, flag=wx.BOTTOM, border=5)
        input_sizer.Add(self.url_text, flag=wx.EXPAND)
        input_panel.SetSizer(input_sizer)

        # 按钮面板
        btn_panel = wx.Panel(self)
        btn_sizer = wx.BoxSizer(wx.HORIZONTAL)
        self.start_btn = wx.Button(btn_panel, label="开始检测")
        self.stop_btn = wx.Button(btn_panel, label="停止")
        self.stop_btn.Enable(False)
        self.status_label = wx.StaticText(btn_panel, label="状态: 就绪")
        self.progress_label = wx.StaticText(btn_panel, label="0/0")
        btn_sizer.Add(self.start_btn, flag=wx.RIGHT, border=10)
        btn_sizer.Add(self.stop_btn, flag=wx.RIGHT, border=10)
        btn_sizer.Add(self.status_label, flag=wx.LEFT, border=10)
        btn_sizer.Add(self.progress_label, flag=wx.LEFT, border=5)
        btn_sizer.AddStretchSpacer()
        btn_panel.SetSizer(btn_sizer)

        self.Bind(wx.EVT_BUTTON, self._on_start_check, self.start_btn)
        self.Bind(wx.EVT_BUTTON, self._on_stop, self.stop_btn)

        # 检测结果表格
        results_panel = wx.Panel(self)
        results_sizer = wx.BoxSizer(wx.VERTICAL)
        results_label = wx.StaticText(results_panel, label="检测结果")
        self.results_grid = wx.grid.Grid(results_panel)
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
        self.results_grid.Bind(wx.grid.EVT_GRID_SELECT_CELL, self._on_grid_select)
        results_sizer.Add(results_label, flag=wx.BOTTOM, border=5)
        results_sizer.Add(self.results_grid, flag=wx.EXPAND, proportion=1)
        results_panel.SetSizer(results_sizer)

        # 详情面板
        detail_panel = wx.Panel(self)
        detail_sizer = wx.BoxSizer(wx.VERTICAL)
        detail_label = wx.StaticText(detail_panel, label="详情面板")
        self.notebook = flatnotebook.FlatNotebook(
            detail_panel,
            style=flatnotebook.FNB_BOTTOM | flatnotebook.FNB_NO_X_BUTTON
        )

        # 证书链页面
        self.cert_chain_page = wx.Panel(self.notebook)
        self.cert_chain_sizer = wx.BoxSizer(wx.VERTICAL)
        self.cert_chain_text = wx.StaticText(self.cert_chain_page, label="")
        self.cert_chain_sizer.Add(self.cert_chain_text, flag=wx.EXPAND | wx.ALL, border=10)
        self.cert_chain_page.SetSizer(self.cert_chain_sizer)
        self.notebook.AddPage(self.cert_chain_page, "证书链")

        # TLS 信息页面
        self.tls_page = wx.Panel(self.notebook)
        self.tls_sizer = wx.BoxSizer(wx.VERTICAL)
        self.tls_text = wx.StaticText(self.tls_page, label="")
        self.tls_sizer.Add(self.tls_text, flag=wx.EXPAND | wx.ALL, border=10)
        self.tls_page.SetSizer(self.tls_sizer)
        self.notebook.AddPage(self.tls_page, "TLS信息")

        # 域名验证页面
        self.domain_page = wx.Panel(self.notebook)
        self.domain_sizer = wx.BoxSizer(wx.VERTICAL)
        self.domain_text = wx.StaticText(self.domain_page, label="")
        self.domain_sizer.Add(self.domain_text, flag=wx.EXPAND | wx.ALL, border=10)
        self.domain_page.SetSizer(self.domain_sizer)
        self.notebook.AddPage(self.domain_page, "域名验证")

        detail_sizer.Add(detail_label, flag=wx.BOTTOM, border=5)
        detail_sizer.Add(self.notebook, flag=wx.EXPAND, proportion=1)
        detail_panel.SetSizer(detail_sizer)

        # 导出按钮面板
        self.export_btn_panel = wx.Panel(self)
        export_btn_sizer = wx.BoxSizer(wx.HORIZONTAL)
        self.export_btn = wx.Button(self.export_btn_panel, label="导出 HTML 报告")
        self.export_btn.Enable(False)
        export_btn_sizer.Add(self.export_btn)
        self.export_btn_panel.SetSizer(export_btn_sizer)
        self.Bind(wx.EVT_BUTTON, self._on_export, self.export_btn)

        # 状态栏
        self.statusbar = self.CreateStatusBar()
        self.statusbar.SetStatusText("就绪")

        # 保存引用
        self.input_panel = input_panel
        self.results_panel = results_panel
        self.detail_panel = detail_panel
        self.btn_panel = btn_panel

    def _layout(self):
        """布局主窗口"""
        main_sizer = wx.BoxSizer(wx.VERTICAL)
        main_sizer.Add(self.input_panel, flag=wx.EXPAND | wx.ALL, border=10)
        main_sizer.Add(self.btn_panel, flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, border=10)
        main_sizer.Add(self.results_panel, flag=wx.EXPAND | wx.LEFT | wx.RIGHT, border=10, proportion=1)
        main_sizer.Add(self.detail_panel, flag=wx.EXPAND | wx.ALL, border=10, proportion=1)
        main_sizer.Add(self.export_btn_panel, flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, border=10)

        self.SetSizer(main_sizer)

    def _make_check_icon(self) -> wx.Image:
        """创建勾选图标"""
        img = wx.Image(16, 16)
        img.Replace(0, 0, 0, 0, 0, 0)
        dc = wx.MemoryDC()
        bmp = wx.Bitmap(img)
        dc.SelectObject(bmp)
        dc.SetPen(wx.GREEN_PEN)
        dc.SetBrush(wx.GREEN_BRUSH)
        dc.DrawCircle(8, 8, 6)
        dc.SetPen(wx.WHITE_PEN)
        dc.DrawLine(4, 8, 7, 11)
        dc.DrawLine(7, 11, 12, 5)
        dc.SelectObject(wx.NullBitmap)
        return img

    def _make_export_icon(self) -> wx.Image:
        """创建导出图标"""
        img = wx.Image(16, 16)
        img.Replace(0, 0, 0, 0, 0, 0)
        return img

    def _make_stop_icon(self) -> wx.Image:
        """创建停止图标"""
        img = wx.Image(16, 16)
        img.Replace(0, 0, 0, 0, 0, 0)
        dc = wx.MemoryDC()
        bmp = wx.Bitmap(img)
        dc.SelectObject(bmp)
        dc.SetPen(wx.RED_PEN)
        dc.SetBrush(wx.RED_BRUSH)
        dc.DrawCircle(8, 8, 6)
        dc.SetPen(wx.WHITE_PEN)
        dc.DrawLine(4, 4, 12, 12)
        dc.DrawLine(12, 4, 4, 12)
        dc.SelectObject(wx.NullBitmap)
        return img

    def _on_start_check(self, event):
        """处理开始检测按钮点击"""
        urls = self._get_urls_from_input()
        if not urls:
            wx.MessageBox("请输入至少一个 URL", "提示", wx.OK | wx.ICON_WARNING)
            return

        self._start_checking(urls)

    def _on_stop(self, event):
        """处理停止按钮点击"""
        self.is_checking = False
        self._update_ui_state(False)

    def _on_export(self, event):
        """处理导出按钮点击"""
        if not self.results:
            wx.MessageBox("没有检测结果可导出", "提示", wx.OK | wx.ICON_WARNING)
            return

        dlg = wx.FileDialog(
            self,
            wildcard="HTML files (*.html)|*.html",
            style=wx.FD_SAVE | wx.FD_OVERWRITE_PROMPT,
            defaultFile="https_cert_report.html"
        )

        if dlg.ShowModal() == wx.ID_OK:
            path = dlg.GetPath()
            try:
                report_generator.generate_html_report(self.results, path)
                wx.MessageBox(f"报告已导出至: {path}", "成功", wx.OK | wx.ICON_INFORMATION)
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
        self._update_progress(0, len(urls))

        thread = threading.Thread(target=self._check_worker, args=(urls,))
        thread.daemon = True
        thread.start()

    def _check_worker(self, urls: List[str]):
        """证书检测工作线程"""
        total = len(urls)

        for i, url in enumerate(urls):
            if not self.is_checking:
                break

            wx.CallAfter(self._update_status, f"检测中... {url}")

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
            wx.CallAfter(self._update_progress, i + 1, total)

        wx.CallAfter(self._on_check_complete)

    def _update_ui_state(self, checking: bool):
        """根据检测状态更新 UI"""
        self.start_btn.Enable(not checking)
        self.stop_btn.Enable(checking)
        self.url_text.Enable(not checking)
        self.export_btn.Enable(not checking and len(self.results) > 0)

    def _update_status(self, status: str):
        """更新状态栏文本"""
        self.statusbar.SetStatusText(status)
        self.status_label.SetLabel(f"状态: {status}")

    def _update_progress(self, current: int, total: int):
        """更新进度标签"""
        self.progress_label.SetLabel(f"{current}/{total}")

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

        # 状态图标
        status_icons = {"valid": "✓", "warning": "⚠", "error": "✗"}
        status_icon = status_icons.get(status, "✗")

        # 设置状态单元格颜色
        status_colors = {"valid": wx.Colour(200, 230, 200), "warning": wx.Colour(255, 243, 200), "error": wx.Colour(255, 200, 200)}
        attr = wx.grid.GridCellAttr()
        attr.SetBackgroundColour(status_colors.get(status, wx.WHITE))
        self.results_grid.SetRowAttr(row, attr)

        # 过期时间显示
        if expiry_info.get("expired"):
            expiry_display = "已过期"
        elif expiry_info.get("days_left") is not None:
            expiry_display = f"{expiry_info['days_left']}天后"
        else:
            expiry_display = "未知"

        # 证书链显示
        chain_display = "完整" if cert_chain_complete else "不完整"

        # TLS 版本
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
        error_message = result.get("error_message")

        if not cert_chain:
            text = "证书链信息不可用"
            if error_message:
                text += f"\n\n错误: {error_message}"
            self.cert_chain_text.SetLabel(text)
            return

        lines = []
        for cert in cert_chain:
            cert_type = cert.get("type", "unknown")
            cert_name = cert.get("name", "Unknown")
            cert_status = cert.get("status", "unknown")

            type_labels = {"root": "Root CA", "intermediate": "Intermediate", "server": "Server"}
            label = type_labels.get(cert_type, cert_type)

            icon = "✓" if cert_status == "ok" else "✗"
            lines.append(f"├── {label}: {cert_name} {icon}")

        chain_status = "完整 ✓" if cert_chain_complete else "不完整 ✗"
        lines.append(f"\n证书链状态: {chain_status}")

        if error_message:
            lines.append(f"\n错误信息: {error_message}")

        self.cert_chain_text.SetLabel("\n".join(lines))

    def _update_tls_detail(self, result: Dict[str, Any]):
        """更新 TLS 详情"""
        tls = result.get("tls", {})

        if not tls or not tls.get("version"):
            self.tls_text.SetLabel("TLS 信息不可用")
            return

        lines = [
            f"版本: {tls.get('version', '未知')}",
            f"加密套件: {tls.get('cipher_suite', '未知')}",
            f"密钥交换: {tls.get('key_exchange', '未知')}"
        ]

        self.tls_text.SetLabel("\n".join(lines))

    def _update_domain_detail(self, result: Dict[str, Any]):
        """更新域名验证详情"""
        domain_match = result.get("domain_match", {})
        url = result.get("url", "")

        if not domain_match:
            self.domain_text.SetLabel("域名验证信息不可用")
            return

        match = domain_match.get("match", False)
        cn = domain_match.get("cert_cn", "未知")
        san_list = domain_match.get("cert_san", [])

        match_status = "匹配 ✓" if match else "不匹配 ✗"
        san_display = ", ".join(san_list) if san_list else "无"

        lines = [
            f"访问域名: {url}",
            f"匹配状态: {match_status}",
            f"证书CN: {cn}",
            f"证书SAN: {san_display}"
        ]

        self.domain_text.SetLabel("\n".join(lines))

    def _on_check_complete(self):
        """处理检测完成"""
        self.is_checking = False
        self._update_ui_state(False)
        self._update_status("检测完成")
        self.progress_label.SetLabel(f"{len(self.results)}/{len(self.results)}")
        self.export_btn.Enable(len(self.results) > 0)


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