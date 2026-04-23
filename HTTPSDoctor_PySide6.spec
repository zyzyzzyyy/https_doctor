# -*- mode: python ; coding: utf-8 -*-
import os

# 获取路径
pyside_path = os.path.dirname(__import__('PySide6').__file__)

# 核心 Qt DLLs
core_dlls = [
    'Qt6Core.dll',
    'Qt6Gui.dll',
    'Qt6Widgets.dll',
]

binaries = []
for dll in core_dlls:
    dll_path = os.path.join(pyside_path, dll)
    if os.path.exists(dll_path):
        binaries.append((dll_path, '.'))

# Qt plugins - 只包含 platforms
platforms_src = os.path.join(pyside_path, 'plugins', 'platforms')
datas = [
    (platforms_src, 'PySide6/plugins/platforms'),
]

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=[
        'shiboken6',
        'PySide6.QtCore',
        'PySide6.QtGui',
        'PySide6.QtWidgets',
        'PySide6',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter', 'test', 'unittest',
        'numpy', 'pandas', 'scipy', 'sklearn',
        'matplotlib', 'PIL', 'cv2',
        'flask', 'django', 'fastapi',
        'sqlalchemy', 'pytest', 'sympy',
    ],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure, compressed=False)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='HTTPS_Doctor',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    upx_dir=r'D:\Tools\upx-5.1.1-win64',
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)