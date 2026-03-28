# -*- mode: python ; coding: utf-8 -*-
# SOCeal – Project VALE PyInstaller spec file
# Build with: pyinstaller soceal.spec --clean

import os

block_cipher = None
project_root = os.path.dirname(os.path.abspath(SPECPATH))

a = Analysis(
    [os.path.join(project_root, 'src', 'main.py')],
    pathex=[os.path.join(project_root, 'src')],
    binaries=[],
    datas=[
        (os.path.join(project_root, 'src', 'ui', 'SOCeal_dashboard.html'), os.path.join('src', 'ui')),
        (os.path.join(project_root, 'config', 'config.yaml'), 'config'),
        (os.path.join(project_root, 'config', 'rules.json'), 'config'),
    ],
    hiddenimports=[
        'win32evtlog',
        'win32event',
        'win32con',
        'win32api',
        'pywintypes',
        'engineio.async_drivers.threading',
        'flask.json',
        'yaml',
        'psutil',
        'watchdog',
        'watchdog.observers',
        'watchdog.events',
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'numpy', 'scipy'],
    cipher=block_cipher,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='SOCeal',
    debug=False,
    strip=False,
    upx=True,
    console=True,
    icon=None,
    manifest=None,
)
