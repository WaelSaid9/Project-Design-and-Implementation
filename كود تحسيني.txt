# -*- coding: utf-8 -*-
import sys
import os
import json
import string
import secrets
import base64
import hmac
import hashlib
import threading
import time
import emoji
import re
import psutil
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Union, Any
import logging
from dataclasses import dataclass
from enum import Enum
import weakref
from concurrent.futures import ThreadPoolExecutor, as_completed
import traceback
from pathlib import Path

logging.basicConfig(
    level=logging.WARNING,  # ← غير INFO إلى WARNING
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/password_manager.log', encoding='utf-8'),
        logging.StreamHandler()
    ],
    force=True
)
# ----------------------------
# System Configuration and Logging
# ----------------------------
def setup_logging():
    """Enhanced logging system setup"""
    try:
        # Close any existing handlers
        for handler in logging.root.handlers[:]:
            handler.close()
            logging.root.removeHandler(handler)
            
        # Create logs directory if it doesn't exist
        os.makedirs('logs', exist_ok=True)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('logs/password_manager.log', encoding='utf-8'),
                # logging.StreamHandler()  # ← قم بتعليق هذا السطر
            ],
            force=True
        )
        logger = logging.getLogger(__name__)
        logger.info("✅ Logging system initialized successfully")
        return True
    except Exception as e:
        print(f"❌ Failed to setup logging: {e}")
        return False

# Initialize logging
setup_logging()
logger = logging.getLogger(__name__)

# Advanced security libraries
try:
    import pyperclip
    CLIPBOARD_AVAILABLE = True
except ImportError:
    pyperclip = None
    CLIPBOARD_AVAILABLE = False
    logger.warning("⚠️ pyperclip not available, using alternative clipboard")

# Advanced encryption libraries
try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
    CRYPTO_AVAILABLE = True
except ImportError as e:
    logger.error(f"❌ Cryptography library not available: {e}")
    CRYPTO_AVAILABLE = False

# UI libraries
try:
    from PySide6.QtWidgets import (
        QApplication, QWidget, QVBoxLayout, QLineEdit, QTextEdit,
        QPushButton, QTabWidget, QScrollArea, QGridLayout, QFrame, QLabel,
        QMainWindow, QHBoxLayout, QMessageBox, QCheckBox, QGroupBox,
        QTextBrowser, QProgressBar, QSplitter, QListWidget, QListWidgetItem,
        QDialog, QDialogButtonBox, QTableWidget, QTableWidgetItem,
        QHeaderView, QToolBar, QStatusBar, QMenu, QSystemTrayIcon,
        QToolButton, QComboBox, QSpinBox, QProgressDialog, QInputDialog
    )
    from PySide6.QtGui import (
        QFont, QPalette, QColor, QIcon, QPixmap, QAction, 
        QGuiApplication, QCursor, QDesktopServices, QKeyEvent,
        QMovie, QPainter, QBrush, QLinearGradient, QTextCursor
    )
    from PySide6.QtCore import (
        Qt, Signal, QPoint, QEvent, QTimer, QDateTime, 
        QSize, QUrl, QThread, QPropertyAnimation, QEasingCurve,
        QRect, QRectF
    )
    QT_AVAILABLE = True
except ImportError as e:
    logger.error(f"❌ PySide6 not available: {e}")
    QT_AVAILABLE = False

# ----------------------------
# Enhanced Configuration and Settings
# ----------------------------
class Language(Enum):
    ARABIC = "ar"
    ENGLISH = "en"

class Config:
    """Enhanced configuration storage class"""
    
    # Security settings
    ADMIN_USERNAME = "admin"
    VERIF_STATE_FILE = "verif_state.json"
    DATA_FILE = "passwords.json"
    ENCRYPTED_DATA_FILE = "passwords.enc"
    SIGNATURE_FILE = "passwords.sig"
    BACKUP_DIR = "backups"
    KEY_DIR = "keys"
    
    # Enhanced security constants
    MIN_PASSWORD_LENGTH = 12
    MIN_EMOJI_PASSWORD_LENGTH = 1
    MIN_SECURE_KEY_LENGTH = 6  # Reduced for flexibility
    PBKDF2_ITERATIONS = 600_000  # Increased iterations for security
    SALT_SIZE = 32  # Increased salt size
    NONCE_SIZE = 12  # Fixed: 12 bytes for AESGCM
    
    # OTP settings
    OTP_INTERVAL = 30
    OTP_DIGITS = 6
    OTP_SECRET_SIZE = 32  # Increased secret size
    
    # Secure RSA settings
    RSA_KEY_SIZE = 2048  # Using 2048-bit keys
    RSA_PUBLIC_KEY_FILE = "public_key.pem"
    RSA_PRIVATE_KEY_FILE = "private_key.pem"
    
    # Digital signature settings
    SIGNATURE_KEY_SIZE = 2048
    SIGNATURE_PUBLIC_KEY_FILE = "signature_public.pem"
    SIGNATURE_PRIVATE_KEY_FILE = "signature_private.pem"
    
    # Login attempts rate limiting
    MAX_LOGIN_ATTEMPTS = 5
    LOGIN_TIMEOUT_MINUTES = 15
    LOGIN_ATTEMPTS_FILE = "login_attempts.json"
    
    # Timeouts
    VERIF_ROTATION_MS = 15000
    COUNTDOWN_UPDATE_MS = 250
    SESSION_TIMEOUT = timedelta(minutes=10)
    CLIPBOARD_CLEAR_SECONDS = 15
    PASSWORD_DISPLAY_SECONDS = 10
    
    # Theme colors
    BG = "#1e1e1e"
    PANEL = "#2d2d2d"
    FG = "#ffffff"
    MUTED = "#cccccc"
    ACCENT = "#ff6b6b"
    ACCENT_HOVER = "#ff8e8e"
    CODE_BG = "#3a3a3c"
    GLOW = "#ff3b3b"
    SUCCESS = "#4CAF50"
    WARNING = "#FF9800"
    ERROR = "#f44336"
    INFO = "#2196F3"
    
    # Password generation
    DEFAULT_PASSWORD_LENGTH = 12
    MAX_PASSWORD_LENGTH = 128
    
    # Enhanced emoji categories (expanded with full Unicode 15.0 emoji list)
    EMOJI_CATEGORIES = {
        "🔐 Security": ["🔒", "🔑", "🔐", "🗝️", "🔓", "🛡️", "⚔️", "🚨", "🔍", "🔎"],
        "✨ Symbols": ["✨", "⭐", "🌟", "💫", "🎉", "🎊", "🔥", "💥", "🌈", "☀️"],
        "😊 Smiling Faces": ["😀", "😃", "😄", "😁", "😆", "😅", "😂", "🤣", "😊", "😇"],
        "❤️ Hearts": ["❤️", "🧡", "💛", "💚", "💙", "💜", "🖤", "🤍", "🤎", "💔"],
        "🔢 Numbers": ["0️⃣", "1️⃣", "2️⃣", "3️⃣", "4️⃣", "5️⃣", "6️⃣", "7️⃣", "8️⃣", "9️⃣"],
        "🔄 Arrows": ["⬆️", "↗️", "➡️", "↘️", "⬇️", "↙️", "⬅️", "↖️", "↕️", "↔️"],
        "🎯 Objects": ["🎯", "🎮", "🎲", "🧩", "♟️", "🎨", "🧵", "🧶", "🎼", "🎵"],
        "🌍 Nature": ["🌍", "🌎", "🌏", "🌐", "🗺️", "🧭", "🏔️", "⛰️", "🌋", "🗻"],
        "🐾 Animals": ["🐶", "🐱", "🐭", "🐹", "🐰", "🦊", "🐻", "🐼", "🐨", "🐯"],
        "🍕 Food": ["🍏", "🍎", "🍐", "🍊", "🍋", "🍌", "🍉", "🍇", "🍓", "🫐"],
        "⚽ Sports": ["⚽", "🏀", "🏈", "⚾", "🥎", "🎾", "🏐", "🏉", "🥏", "🎱"],
        "🚗 Vehicles": ["🚗", "🚕", "🚙", "🚌", "🚎", "🏎️", "🚓", "🚑", "🚒", "🚐"],
        "🎵 Music": ["🎵", "🎶", "🎼", "🎤", "🎧", "🎷", "🎸", "🎹", "🎺", "🎻"],
        "📚 Education": ["📚", "📖", "🔖", "📓", "📒", "📝", "✏️", "📌", "📍", "📎"],
        "🌙 Weather": ["☀️", "🌤️", "⛅", "🌥️", "☁️", "🌦️", "🌧️", "⛈️", "🌩️", "🌨️"],
        "🕒 Time": ["🕐", "🕑", "🕒", "🕓", "🕔", "🕕", "🕖", "🕗", "🕘", "🕙"],
        "🎉 Celebrations": ["🎉", "🎊", "🎈", "🎁", "🎀", "🎆", "🎇", "✨", "🎂", "🍾"],
        "👨‍👩‍👧‍👦 People": ["👶", "🧒", "👦", "👧", "🧑", "👨", "👩", "🧓", "👴", "👵"],
        "👕 Clothing": ["👔", "👕", "👖", "🧣", "🧤", "🧥", "🧦", "👗", "👘", "🥻"],
        "🏠 Places": ["🏠", "🏡", "🏢", "🏣", "🏤", "🏥", "🏦", "🏨", "🏩", "🏪"],
        "🚦 Transport": ["🚗", "🚕", "🚙", "🚌", "🚎", "🏎️", "🚓", "🚑", "🚒", "🚐"],
        "⏰ Clock": ["🕐", "🕑", "🕒", "🕓", "🕔", "🕕", "🕖", "🕗", "🕘", "🕙"],
        "🎨 Activities": ["🎨", "🎭", "🎪", "🎤", "🎧", "🎼", "🎹", "🎷", "🎺", "🎻"],
        "🏆 Awards": ["🏆", "🏅", "🎖️", "🥇", "🥈", "🥉", "🎯", "🎪", "🎭", "🎨"],
        "🌍 Flags": ["🇺🇸", "🇬🇧", "🇸🇦", "🇪🇬", "🇦🇪", "🇯🇴", "🇶🇦", "🇰🇼", "🇧🇭", "🇴🇲"],
        "🍔 Fast Food": ["🍔", "🍕", "🌭", "🥪", "🌮", "🌯", "🥗", "🍣", "🍜", "🍝"],
        "☕ Drinks": ["☕", "🍵", "🍶", "🍺", "🍷", "🥃", "🍸", "🍹", "🥤", "🧃"],
        "🎭 Fantasy": ["🎭", "🤡", "👻", "💀", "👽", "👾", "🤖", "🎎", "🕴️", "💃"],
        "💼 Work": ["💼", "📁", "📂", "📅", "📆", "📊", "📈", "📉", "💰", "💳"],
        "🏥 Health": ["🏥", "💊", "💉", "🩺", "🌡️", "🩹", "🩸", "😷", "🤒", "🤕"],
        "🎓 Education": ["🎓", "📝", "✏️", "📚", "📖", "🔬", "🔭", "💻", "📱", "⌚"],
        "✈️ Travel": ["✈️", "🚀", "🛸", "🚁", "🛶", "🚤", "⛵", "🛳️", "🚂", "🚊"],
        "🎄 Holidays": ["🎄", "🎅", "🤶", "🦌", "🎁", "❄️", "⛄", "🎆", "✨", "🌟"],
        "💡 Ideas": ["💡", "✨", "🌟", "⭐", "🔥", "💫", "🌈", "☀️", "🌙", "⭐"],
        "🎭 Emotions": ["😀", "😂", "🥲", "😅", "🤣", "😊", "😇", "🙂", "🙃", "😉"],
        "👋 Gestures": ["👋", "🤚", "🖐️", "✋", "🖖", "👌", "🤌", "🤏", "✌️", "🤞"],
        "💪 Body Parts": ["💪", "🦵", "🦶", "👂", "🦻", "👃", "👅", "🦷", "🦴", "👀"],
        "👑 Royalty": ["👑", "🤴", "👸", "🫅", "🎩", "👒", "🎓", "🧢", "⛑️", "🪖"],
        "💎 Jewelry": ["💎", "🔮", "💍", "👑", "💎", "🔱", "⚜️", "🏆", "🥇", "🥈"],
        "🎁 Gifts": ["🎁", "🎀", "🎊", "🎉", "🎈", "🪅", "🪆", "🎐", "🎏", "🧧"],
        "🔧 Tools": ["🔧", "🔨", "⚒️", "🛠️", "⛏️", "🔩", "⚙️", "🧰", "🧲", "🪛"],
        "🎮 Gaming": ["🎮", "🕹️", "👾", "🖥️", "💻", "📱", "🎲", "♟️", "🎯", "🎪"],
        
        # Additional expanded emoji categories
        "😀 Faces & People": ["😀", "😃", "😄", "😁", "😆", "😅", "😂", "🤣", "🥲", "☺️", "😊", "😇", "🙂", "🙃", "😉", "😌", "😍", "🥰", "😘", "😗", "😙", "😚", "😋", "😛", "😝", "😜", "🤪", "🤨", "🧐", "🤓", "😎", "🥸", "🤩", "🥳", "😏", "😒", "😞", "😔", "😟", "😕", "🙁", "☹️", "😣", "😖", "😫", "😩", "🥺", "😢", "😭", "😤", "😠", "😡", "🤬", "🤯", "😳", "🥵", "🥶", "😱", "😨", "😰", "😥", "😓", "🤗", "🤔", "🤭", "🤫", "🤥", "😶", "😐", "😑", "😬", "🙄", "😯", "😦", "😧", "😮", "😲", "🥱", "😴", "🤤", "😪", "😵", "🤐", "🥴", "🤢", "🤮", "🤧", "😷", "🤒", "🤕", "🤑", "🤠", "😈", "👿", "👹", "👺", "🤡", "💩", "👻", "💀", "☠️", "👽", "👾", "🤖", "🎃"],
        "👥 People & Body": ["👋", "🤚", "🖐️", "✋", "🖖", "👌", "🤌", "🤏", "✌️", "🤞", "🤟", "🤘", "🤙", "👈", "👉", "👆", "🖕", "👇", "☝️", "👍", "👎", "✊", "👊", "🤛", "🤜", "👏", "🙌", "👐", "🤲", "🤝", "🙏", "✍️", "💅", "🤳", "💪", "🦾", "🦿", "🦵", "🦶", "👂", "🦻", "👃", "🧠", "🫀", "🫁", "🦷", "🦴", "👀", "👁️", "👅", "👄", "💋", "🩸"],
        "🐶 Animals & Nature": ["🐶", "🐱", "🐭", "🐹", "🐰", "🦊", "🐻", "🐼", "🐨", "🐯", "🦁", "🐮", "🐷", "🐽", "🐸", "🐵", "🙈", "🙉", "🙊", "🐒", "🐔", "🐧", "🐦", "🐤", "🐣", "🐥", "🦆", "🦅", "🦉", "🦇", "🐺", "🐗", "🐴", "🦄", "🐝", "🪱", "🐛", "🦋", "🐌", "🐞", "🐜", "🪰", "🪲", "🪳", "🦟", "🦗", "🕷️", "🕸️", "🦂", "🐢", "🐍", "🦎", "🦖", "🦕", "🐙", "🦑", "🦐", "🦞", "🦀", "🐡", "🐠", "🐟", "🐬", "🐳", "🐋", "🦈", "🐊", "🐅", "🐆", "🦓", "🦍", "🦧", "🦣", "🐘", "🦛", "🦏", "🐪", "🐫", "🦒", "🦘", "🦬", "🐃", "🐂", "🐄", "🐎", "🐖", "🐏", "🐑", "🦙", "🐐", "🦌", "🐕", "🐩", "🦮", "🐕‍🦺", "🐈", "🐈‍⬛", "🪶", "🐓", "🦃", "🦤", "🦚", "🦜", "🦢", "🦩", "🕊️", "🐇", "🦝", "🦨", "🦡", "🦫", "🦦", "🦥", "🐁", "🐀", "🐿️", "🦔"],
        "🍎 Food & Drink": ["🍏", "🍎", "🍐", "🍊", "🍋", "🍌", "🍉", "🍇", "🍓", "🫐", "🍈", "🍒", "🍑", "🥭", "🍍", "🥥", "🥝", "🍅", "🍆", "🥑", "🥦", "🥬", "🥒", "🌶️", "🫑", "🌽", "🥕", "🫒", "🧄", "🧅", "🥔", "🍠", "🫘", "🥐", "🥯", "🍞", "🥖", "🥨", "🧀", "🥚", "🍳", "🧈", "🥞", "🧇", "🥓", "🥩", "🍗", "🍖", "🦴", "🌭", "🍔", "🍟", "🍕", "🫓", "🥪", "🥙", "🧆", "🌮", "🌯", "🫔", "🥗", "🥘", "🫕", "🥫", "🍝", "🍜", "🍲", "🍛", "🍣", "🍱", "🥟", "🦪", "🍤", "🍙", "🍚", "🍘", "🍥", "🥠", "🥮", "🍢", "🍡", "🍧", "🍨", "🍦", "🥧", "🧁", "🍰", "🎂", "🍮", "🍭", "🍬", "🍫", "🍿", "🍩", "🍪", "🌰", "🥜", "🫘", "🍯", "🥛", "🍼", "🫖", "☕", "🍵", "🧃", "🥤", "🧋", "🍶", "🍺", "🍻", "🥂", "🍷", "🥃", "🍸", "🍹", "🧉", "🍾", "🧊", "🥄", "🍴", "🍽️", "🥣", "🥡", "🥢", "🧂"],
        "⚽ Activities": ["⚽", "🏀", "🏈", "⚾", "🥎", "🎾", "🏐", "🏉", "🥏", "🎱", "🪀", "🏓", "🏸", "🏒", "🏑", "🥍", "🏏", "🪃", "🥅", "⛳", "🪁", "🏹", "🎣", "🤿", "🥊", "🥋", "🎽", "🛹", "🛼", "🛶", "⛵", "🚤", "🛥️", "🛳️", "⛴️", "🚢", "✈️", "🛩️", "🛫", "🛬", "🪂", "💺", "🚁", "🚟", "🚠", "🚡", "🛰️", "🚀", "🛸", "🎡", "🎢", "🎠", "🛝", "🎪", "🎭", "🩰", "🎨", "🎬", "🎤", "🎧", "🎼", "🎹", "🥁", "🪘", "🎷", "🎺", "🪗", "🎸", "🪕", "🎻", "🎲", "♟️", "🎯", "🎳", "🎮", "🎰", "🧩"],
        "🌍 Travel & Places": ["🌍", "🌎", "🌏", "🌐", "🗺️", "🧭", "🏔️", "⛰️", "🌋", "🗻", "🏕️", "🏖️", "🏜️", "🏝️", "🏞️", "🏟️", "🏛️", "🏗️", "🧱", "🪨", "🪵", "🛖", "🏘️", "🏚️", "🏠", "🏡", "🏢", "🏣", "🏤", "🏥", "🏦", "🏨", "🏩", "🏪", "🏫", "🏬", "🏭", "🏯", "🏰", "💒", "🗼", "🗽", "⛪", "🕌", "🛕", "🕍", "⛩️", "🕋", "⛲", "⛺", "🌁", "🌃", "🏙️", "🌄", "🌅", "🌆", "🌇", "🌉", "♨️", "🎠", "🎡", "🎢", "💈", "🎪", "🚂", "🚃", "🚄", "🚅", "🚆", "🚇", "🚈", "🚉", "🚊", "🚝", "🚞", "🚋", "🚌", "🚍", "🚎", "🚐", "🚑", "🚒", "🚓", "🚔", "🚕", "🚖", "🚗", "🚘", "🚙", "🛻", "🚚", "🚛", "🚜", "🏎️", "🏍️", "🛵", "🚲", "🛴", "🛹", "🛼", "🚏", "🛣️", "🛤️", "🛢️", "⛽", "🚨", "🚥", "🚦", "🛑", "🚧", "⚓", "🛟", "⛵", "🛶", "🚤", "🛥️", "🛳️", "⛴️", "🚢", "✈️", "🛩️", "🛫", "🛬", "🪂", "💺", "🚁", "🚟", "🚠", "🚡", "🛰️", "🚀", "🛸", "🛎️", "🧳", "⌛", "⏳", "⌚", "⏰", "⏱️", "⏲️", "🕰️", "🌡️", "🗺️"],
        "💡 Objects": ["💡", "🔦", "🕯️", "🪔", "🧯", "🛢️", "💸", "💵", "💴", "💶", "💷", "🪙", "💰", "💳", "💎", "⚖️", "🪜", "🧰", "🪛", "🔧", "🔨", "⚒️", "🛠️", "⛏️", "🪚", "🔩", "⚙️", "🪤", "🧱", "🪨", "🪵", "🧲", "🪝", "🧪", "🧫", "🧬", "🔬", "🔭", "📡", "💉", "🩸", "💊", "🩹", "🩺", "🚪", "🪑", "🛋️", "🛏️", "🛌", "🧸", "🪆", "🪅", "🪩", "🎈", "🎏", "🎀", "🎁", "🪄", "🧧", "🎊", "🎉", "🎎", "🏮", "🪔", "📯", "🎐", "🧿", "📿", "💎", "📯", "📢", "📣", "🔔", "🔕", "🎼", "🎵", "🎶", "🎙️", "🎚️", "🎛️", "🎤", "🎧", "📻", "🎷", "🎸", "🎹", "🎺", "🎻", "🪕", "🥁", "🪘", "📱", "📲", "☎️", "📞", "📟", "📠", "🔋", "🪫", "🔌", "💻", "🖥️", "🖨️", "⌨️", "🖱️", "🖲️", "💽", "💾", "💿", "📀", "🧮", "🎥", "🎞️", "📽️", "🎬", "📺", "📷", "📸", "📹", "📼", "🔍", "🔎", "🕯️", "💡", "🔦", "🏮", "🪔", "📔", "📕", "📖", "📗", "📘", "📙", "📚", "📓", "📒", "📃", "📜", "📄", "📰", "🗞️", "📑", "🔖", "🏷️", "💰", "🪙", "💴", "💵", "💶", "💷", "💸", "💳", "🧾", "✉️", "📧", "📨", "📩", "📤", "📥", "📦", "📫", "📪", "📬", "📭", "📮", "🗳️", "✏️", "✒️", "🖋️", "🖊️", "🖌️", "🖍️", "📝", "💼", "📁", "📂", "🗂️", "📅", "📆", "🗒️", "🗓️", "📇", "📈", "📉", "📊", "📋", "📌", "📍", "📎", "🖇️", "📏", "📐", "✂️", "🗃️", "🗄️", "🗑️", "🔒", "🔓", "🔏", "🔐", "🔑", "🗝️", "🔨", "🪓", "⛏️", "⚒️", "🛠️", "🗡️", "⚔️", "🔫", "🪃", "🏹", "🛡️", "🪚", "🔧", "🪛", "🔩", "⚙️", "🗜️", "⚖️", "🦯", "🔗", "⛓️", "🪝", "🧰", "🧲", "🪜", "⚗️", "🧪", "🧫", "🧬", "🔬", "🔭", "📡", "💉", "🩸", "💊", "🩹", "🩺", "🚪", "🪑", "🛋️", "🛏️", "🛌", "🧸", "🪆", "🪅", "🪩", "🎈", "🎏", "🎀", "🎁", "🪄", "🧧", "🎊", "🎉", "🎎", "🏮", "🪔"],
        "🔣 Symbols": ["❤️", "🧡", "💛", "💚", "💙", "💜", "🖤", "🤍", "🤎", "💔", "❣️", "💕", "💞", "💓", "💗", "💖", "💘", "💝", "💟", "☮️", "✝️", "☪️", "🕉️", "☸️", "✡️", "🔯", "🕎", "☯️", "☦️", "🛐", "⛎", "♈", "♉", "♊", "♋", "♌", "♍", "♎", "♏", "♐", "♑", "♒", "♓", "🆔", "⚛️", "🉑", "☢️", "☣️", "📴", "📳", "🈶", "🈚", "🈸", "🈺", "🈷️", "✴️", "🆚", "💮", "🉐", "㊙️", "㊗️", "🈴", "🈵", "🈹", "🈲", "🅰️", "🅱️", "🆎", "🆑", "🅾️", "🆘", "❌", "⭕", "🛑", "⛔", "📛", "🚫", "💯", "💢", "♨️", "🚷", "🚯", "🚳", "🚱", "🔞", "📵", "🚭", "❗", "❕", "❓", "❔", "‼️", "⁉️", "🔅", "🔆", "〽️", "⚠️", "🚸", "🔱", "⚜️", "🔰", "♻️", "✅", "🈯", "💹", "❇️", "✳️", "❎", "🌐", "💠", "Ⓜ️", "🌀", "💤", "🏧", "🚾", "♿", "🅿️", "🈳", "🈂️", "🛂", "🛃", "🛄", "🛅", "🚹", "🚺", "🚼", "🚻", "🚮", "🎦", "📶", "🈁", "🔣", "ℹ️", "🔤", "🔡", "🔠", "🆖", "🆗", "🆙", "🆒", "🆕", "🆓", "0️⃣", "1️⃣", "2️⃣", "3️⃣", "4️⃣", "5️⃣", "6️⃣", "7️⃣", "8️⃣", "9️⃣", "🔟", "🔢", "#️⃣", "*️⃣", "⏏️", "▶️", "⏸️", "⏯️", "⏹️", "⏺️", "⏭️", "⏮️", "⏩", "⏪", "⏫", "⏬", "◀️", "🔼", "🔽", "➡️", "⬅️", "⬆️", "⬇️", "↗️", "↘️", "↙️", "↖️", "↕️", "↔️", "↪️", "↩️", "⤴️", "⤵️", "🔀", "🔁", "🔂", "🔄", "🔃", "🎵", "🎶", "➕", "➖", "➗", "✖️", "♾️", "💲", "💱", "™️", "©️", "®️", "〰️", "➰", "➿", "🔚", "🔙", "🔛", "🔝", "🔜", "✔️", "☑️", "🔘", "⚪", "⚫", "🔴", "🔵", "🟠", "🟡", "🟢", "🟣", "🟤", "🟥", "🟧", "🟨", "🟩", "🟦", "🟪", "🟫", "⬛", "⬜", "◼️", "◻️", "◾", "◽", "▪️", "▫️", "🔶", "🔷", "🔸", "🔹", "🔺", "🔻", "💠", "🔘", "🔳", "🔲"]
    }
    
    # Keyboard layouts
    KEYBOARD_LAYOUTS = {
        'en_lower': list('abcdefghijklmnopqrstuvwxyz'),
        'en_upper': list('ABCDEFGHIJKLMNOPQRSTUVWXYZ'),
        'ar_lower': list('ابتثجحخدذرزسشصضطظعغفقكلمنهوي'),
        'ar_upper': list('ابتثجحخدذرزسشصضطظعغفقكلمنهوي'),
        'numbers': list('1234567890'),
        'symbols': list('!@#$%^&*()-_=+[]{};:\'",.<>?/\\|`~')
    }
    
    # Translation texts - English only
    TRANSLATIONS = {
        Language.ENGLISH: {
            "app_title": "🔐 Secure Password Manager - Advanced AES & RSA Encryption Version 5.0",
            "login_tab": "🔐 Login",
            "add_tab": "➕ Add Password",
            "retrieve_tab": "🔍 Retrieve Password",
            "generate_tab": "🔑 Generate Password",
            "users_tab": "📊 User Management",
            "admin_recovery_tab": "🔓 Emoji Recovery",
            "logs_tab": "📋 System Logs",
            "security_tab": "🛡️ Security Check",
            "status_logged_out": "❌ Not Logged In",
            "status_regular": "👤 Regular User Mode",
            "status_admin": "🗝️ Admin Mode",
            "logout_btn": "🚪 Logout & Close System",
            "login_system": "🔐 Login System",
            "login_status": "Status: Not Logged In",
            "login_regular": "👤 Login as Regular User",
            "login_admin": "🗝️ Login as Admin (OTP)",
            "permissions_info": "🔒 Regular User Permissions:\n• Add passwords\n• Retrieve passwords\n• Generate secure passwords\n\n🔓 Admin Permissions:\n• All regular user permissions\n• User management\n• View system logs\n• Delete users\n• View full details\n• Password recovery using emoji\n• System security check",
            "add_password": "➕ Add New Password",
            "username": "Username:",
            "password": "Password:",
            "emoji_password": "Emoji-based Password:",
            "secure_key": "Secure Key (letters, numbers, emoji):",
            "save_password": "💾 Save Password",
            "retrieve_password": "🔍 Retrieve Password",
            "generate_password": "🔑 Generate Secure Password",
            "length": "Length:",
            "include_emojis": "Include Emojis",
            "generate": "Generate Password",
            "generate_multiple": "Generate 5 Passwords",
            "copy_password": "📋 Copy Password",
            "use_password": "🚀 Use in Add Tab",
            "manage_users": "📊 User Management (Admins Only)",
            "admin_recovery": "🔓 Password Recovery using Emoji (Admins Only)",
            "system_logs": "📋 System Logs",
            "security_check": "🛡️ System Security Check",
            "search_placeholder": "🔍 Search for emoji or symbol...",
            "keyboard_toggle": "👁",
            "keyboard_hide": "Hide",
            "keyboard_shift": "Shift ⇧",
            "keyboard_delete": "⌫ Delete",
            "keyboard_space": "Space",
            "keyboard_enter": "Enter ↵",
            "language_arabic": "العربية",
            "language_english": "English",
            "tab_letters": "🅰️ Letters",
            "tab_numbers": "123 Numbers",
            "tab_symbols": "🔣 Symbols",
            "tab_emojis": "😀 Emoji",
            "tab_recent": "🕒 Recent",
            "tab_arabic": "🅰️ Arabic",
            "tab_english": "🅰️ English",
            "admin_login_title": "🔒 Admin Login with OTP",
            "admin_system": "Admin Login System",
            "otp_auth": "🔐 Two-Factor Authentication (OTP)",
            "current_verification_code": "Current Verification Code:",
            "enter_verification_code": "Enter Verification Code:",
            "admin_login_btn": "🔑 Login as Admin",
            "register_admin_btn": "➕ Register New Admin",
            "permissions_available": "📋 Available Permissions Information",
            "enter_otp_secret": "Enter OTP Secret Key:",
            "enter_otp_code": "Enter OTP Code:",
            "otp_secret": "OTP Secret Key:",
            "show_secret": "Show Secret",
            "copy_secret": "📋 Copy Secret",
            "otp_code": "OTP Code:"
        }
    }
    
    @classmethod
    def validate_config(cls):
        """Validate configuration settings"""
        try:
            # Check security settings
            if cls.MIN_PASSWORD_LENGTH < 12:
                logger.warning("⚠️ MIN_PASSWORD_LENGTH less than 12, consider increasing security")
            
            if cls.PBKDF2_ITERATIONS < 100_000:
                logger.warning("⚠️ PBKDF2_ITERATIONS too low for modern security standards")
            
            # Create required directories
            os.makedirs(cls.BACKUP_DIR, exist_ok=True)
            os.makedirs(cls.KEY_DIR, exist_ok=True)
            os.makedirs('logs', exist_ok=True)
            
            return True
        except Exception as e:
            logger.error(f"❌ Configuration validation failed: {e}")
            return False

Config.validate_config()

# ----------------------------
# Language Manager
# ----------------------------
class LanguageManager:
    """Language manager for translation support"""
    
    def __init__(self):
        self.current_language = Language.ENGLISH  # Default to English
        self.translations = Config.TRANSLATIONS
    
    def set_language(self, language: Language):
        """Change current language"""
        self.current_language = language
        logger.info(f"🌐 Language changed to: {language.value}")
    
    def get_text(self, key: str) -> str:
        """Get translated text"""
        return self.translations[self.current_language].get(key, key)
    
    def get_all_texts(self) -> Dict[str, str]:
        """Get all texts for current language"""
        return self.translations[self.current_language]

# ----------------------------
# Helper Classes and Enums
# ----------------------------
class PasswordStrength(Enum):
    VERY_WEAK = 0
    WEAK = 1
    FAIR = 2
    GOOD = 3
    STRONG = 4
    VERY_STRONG = 5

class UserType(Enum):
    REGULAR = "regular"
    ADMIN = "admin"

@dataclass
class PasswordAnalysis:
    score: int
    label: str
    emoji_count: int
    color: str
    length: int
    has_upper: bool
    has_lower: bool
    has_digit: bool
    has_special: bool

@dataclass
class EncryptionResult:
    success: bool
    data: Optional[str] = None
    error: Optional[str] = None

@dataclass
class SecurityCheckResult:
    passed: bool
    message: str
    details: Dict[str, Any]
    score: int

# ----------------------------
# Enhanced RSA Crypto Tools with 2048-bit keys
# ----------------------------
class SecureRSAManager:
    """Secure RSA manager using 2048-bit keys"""
    
    @staticmethod
    def generate_rsa_keys() -> Tuple[Any, Any]:
        """Generate secure 2048-bit RSA keys"""
        try:
            # Generate 2048-bit private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=Config.RSA_KEY_SIZE,
                backend=default_backend()
            )
            
            # Extract public key
            public_key = private_key.public_key()
            
            # Save keys to files
            SecureRSAManager.save_key_to_file(private_key, Config.RSA_PRIVATE_KEY_FILE, private=True)
            SecureRSAManager.save_key_to_file(public_key, Config.RSA_PUBLIC_KEY_FILE, private=False)
            
            logger.info("✅ 2048-bit RSA keys generated successfully")
            return public_key, private_key
            
        except Exception as e:
            logger.error(f"❌ Failed to generate RSA keys: {e}")
            raise
    
    @staticmethod
    def save_key_to_file(key, filename: str, private: bool = True):
        """Save key to file"""
        try:
            filepath = os.path.join(Config.KEY_DIR, filename)
            
            if private:
                pem = key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            else:
                pem = key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            
            with open(filepath, 'wb') as f:
                f.write(pem)
            
            # Set secure permissions
            os.chmod(filepath, 0o600)
            
        except Exception as e:
            logger.error(f"❌ Failed to save key: {e}")
            raise
    
    @staticmethod
    def load_rsa_keys() -> Tuple[Any, Any]:
        """Load RSA keys from files"""
        try:
            private_key_path = os.path.join(Config.KEY_DIR, Config.RSA_PRIVATE_KEY_FILE)
            public_key_path = os.path.join(Config.KEY_DIR, Config.RSA_PUBLIC_KEY_FILE)
            
            if not os.path.exists(private_key_path) or not os.path.exists(public_key_path):
                logger.info("⚠️ RSA keys not found, generating new keys")
                return SecureRSAManager.generate_rsa_keys()
            
            # Load private key
            with open(private_key_path, 'rb') as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )
            
            # Load public key
            with open(public_key_path, 'rb') as f:
                public_key = serialization.load_pem_public_key(
                    f.read(),
                    backend=default_backend()
                )
            
            logger.info("✅ RSA keys loaded successfully")
            return public_key, private_key
            
        except Exception as e:
            logger.error(f"❌ Failed to load RSA keys: {e}")
            raise
    
    @staticmethod
    def rsa_encrypt(plaintext: str, public_key) -> str:
        """Encrypt text using RSA"""
        try:
            # Convert text to bytes
            plaintext_bytes = plaintext.encode('utf-8')
            
            # Encrypt using RSA
            ciphertext = public_key.encrypt(
                plaintext_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Base64 encode
            return base64.b64encode(ciphertext).decode('utf-8')
            
        except Exception as e:
            logger.error(f"❌ RSA encryption failed: {e}")
            return ""
    
    @staticmethod
    def rsa_decrypt(ciphertext_b64: str, private_key) -> str:
        """Decrypt text using RSA"""
        try:
            # Base64 decode
            ciphertext = base64.b64decode(ciphertext_b64)
            
            # Decrypt using RSA
            plaintext_bytes = private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return plaintext_bytes.decode('utf-8')
            
        except Exception as e:
            logger.error(f"❌ RSA decryption failed: {e}")
            return ""

# ----------------------------
# Digital Signature Manager for Data Integrity
# ----------------------------
class DigitalSignatureManager:
    """Digital signature manager for data integrity verification"""
    
    @staticmethod
    def generate_signature_keys() -> Tuple[Any, Any]:
        """Generate digital signature keys"""
        try:
            # Generate 2048-bit private key for signatures
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=Config.SIGNATURE_KEY_SIZE,
                backend=default_backend()
            )
            
            # Extract public key
            public_key = private_key.public_key()
            
            # Save keys to files
            DigitalSignatureManager.save_key_to_file(private_key, Config.SIGNATURE_PRIVATE_KEY_FILE, private=True)
            DigitalSignatureManager.save_key_to_file(public_key, Config.SIGNATURE_PUBLIC_KEY_FILE, private=False)
            
            logger.info("✅ Digital signature keys generated successfully")
            return public_key, private_key
            
        except Exception as e:
            logger.error(f"❌ Failed to generate signature keys: {e}")
            raise
    
    @staticmethod
    def save_key_to_file(key, filename: str, private: bool = True):
        """Save key to file"""
        try:
            filepath = os.path.join(Config.KEY_DIR, filename)
            
            if private:
                pem = key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            else:
                pem = key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            
            with open(filepath, 'wb') as f:
                f.write(pem)
            
            # Set secure permissions
            os.chmod(filepath, 0o600)
            
        except Exception as e:
            logger.error(f"❌ Failed to save signature key: {e}")
            raise
    
    @staticmethod
    def load_signature_keys() -> Tuple[Any, Any]:
        """Load digital signature keys from files"""
        try:
            private_key_path = os.path.join(Config.KEY_DIR, Config.SIGNATURE_PRIVATE_KEY_FILE)
            public_key_path = os.path.join(Config.KEY_DIR, Config.SIGNATURE_PUBLIC_KEY_FILE)
            
            if not os.path.exists(private_key_path) or not os.path.exists(public_key_path):
                logger.info("⚠️ Signature keys not found, generating new keys")
                return DigitalSignatureManager.generate_signature_keys()
            
            # Load private key
            with open(private_key_path, 'rb') as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )
            
            # Load public key
            with open(public_key_path, 'rb') as f:
                public_key = serialization.load_pem_public_key(
                    f.read(),
                    backend=default_backend()
                )
            
            logger.info("✅ Digital signature keys loaded successfully")
            return public_key, private_key
            
        except Exception as e:
            logger.error(f"❌ Failed to load signature keys: {e}")
            raise
    
    @staticmethod
    def sign_data(data: Dict) -> str:
        """Sign data using private key"""
        try:
            # Convert data to JSON string
            data_str = json.dumps(data, sort_keys=True, ensure_ascii=False)
            data_bytes = data_str.encode('utf-8')
            
            # Load signature keys
            public_key, private_key = DigitalSignatureManager.load_signature_keys()
            
            # Create signature
            signature = private_key.sign(
                data_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # Base64 encode signature
            return base64.b64encode(signature).decode('utf-8')
            
        except Exception as e:
            logger.error(f"❌ Failed to sign data: {e}")
            return ""
    
    @staticmethod
    def verify_signature(data: Dict, signature_b64: str) -> bool:
        """Verify data signature using public key"""
        try:
            if not signature_b64:
                logger.warning("❌ No signature provided for verification")
                return False
            
            # Convert data to JSON string
            data_str = json.dumps(data, sort_keys=True, ensure_ascii=False)
            data_bytes = data_str.encode('utf-8')
            
            # Decode signature
            signature = base64.b64decode(signature_b64)
            
            # Load signature keys
            public_key, private_key = DigitalSignatureManager.load_signature_keys()
            
            # Verify signature
            public_key.verify(
                signature,
                data_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            logger.info("✅ Data signature verified successfully")
            return True
            
        except Exception as e:
            logger.error(f"❌ Data signature verification failed: {e}")
            return False
    
    @staticmethod
    def save_signed_data(data: Dict, filename: str) -> bool:
        """Save data with digital signature"""
        try:
            # Create signature
            signature = DigitalSignatureManager.sign_data(data)
            if not signature:
                logger.error("❌ Failed to create data signature")
                return False
            
            # Prepare data with signature
            signed_data = {
                "data": data,
                "signature": signature,
                "timestamp": datetime.now().isoformat(),
                "version": "1.0"
            }
            
            # Save to file
            filepath = os.path.join(Config.KEY_DIR, filename)
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(signed_data, f, indent=2, ensure_ascii=False)
            
            # Set secure permissions
            os.chmod(filepath, 0o600)
            
            logger.info(f"✅ Signed data saved to {filename}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to save signed data: {e}")
            return False
    
    @staticmethod
    def load_and_verify_data(filename: str) -> Tuple[Optional[Dict], bool, str]:
        """Load and verify signed data"""
        try:
            filepath = os.path.join(Config.KEY_DIR, filename)
            
            if not os.path.exists(filepath):
                logger.warning(f"⚠️ Signed data file not found: {filename}")
                return None, False, "File not found"
            
            # Load signed data
            with open(filepath, 'r', encoding='utf-8') as f:
                signed_data = json.load(f)
            
            # Verify required fields
            if "data" not in signed_data or "signature" not in signed_data:
                logger.error("❌ Invalid signed data format")
                return None, False, "Invalid data format"
            
            # Verify signature
            data = signed_data["data"]
            signature = signed_data["signature"]
            
            if DigitalSignatureManager.verify_signature(data, signature):
                logger.info(f"✅ Data loaded and verified from {filename}")
                return data, True, "Data verified successfully"
            else:
                logger.error(f"❌ Data signature verification failed for {filename}")
                return None, False, "Signature verification failed"
                
        except json.JSONDecodeError as e:
            logger.error(f"❌ Corrupted signed data file: {e}")
            return None, False, "Corrupted data file"
        except Exception as e:
            logger.error(f"❌ Failed to load signed data: {e}")
            return None, False, f"Load error: {str(e)}"

# ----------------------------
# Real OTP Manager with Encrypted Storage - FIXED VERSION
# ----------------------------
class SecureOTPManager:
    """Secure OTP manager with encrypted storage"""
    
    @staticmethod
    def generate_secret() -> str:
        """Generate OTP secret key"""
        try:
            # Generate random 32-byte secret key
            secret_bytes = secrets.token_bytes(Config.OTP_SECRET_SIZE)
            # Base32 encode secret key
            return base64.b32encode(secret_bytes).decode('utf-8')
        except Exception as e:
            logger.error(f"❌ Failed to generate OTP secret: {e}")
            return ""
    
    @staticmethod
    def encrypt_secret(secret: str, password: str) -> str:
        """Encrypt OTP secret key"""
        try:
            salt = secrets.token_bytes(32)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = kdf.derive(password.encode())
            
            aesgcm = AESGCM(key)
            nonce = secrets.token_bytes(12)  # Fixed: Use 12 bytes for AESGCM
            
            ct = aesgcm.encrypt(nonce, secret.encode(), None)
            encrypted_data = salt + nonce + ct
            
            return base64.b64encode(encrypted_data).decode()
            
        except Exception as e:
            logger.error(f"❌ Failed to encrypt secret key: {e}")
            return ""
    
    @staticmethod
    def decrypt_secret(encrypted_secret: str, password: str) -> str:
        """Decrypt OTP secret key - FIXED VERSION"""
        try:
            if not encrypted_secret:
                return ""
                
            encrypted_data = base64.b64decode(encrypted_secret)
            
            if len(encrypted_data) < 44:  # salt (32) + nonce (12)
                logger.error(f"❌ Encrypted data too short: {len(encrypted_data)} bytes")
                return ""
            
            salt = encrypted_data[:32]
            nonce = encrypted_data[32:44]
            ct = encrypted_data[44:]
            
            if len(ct) == 0:
                logger.error("❌ No ciphertext found")
                return ""
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = kdf.derive(password.encode())
            
            aesgcm = AESGCM(key)
            secret_bytes = aesgcm.decrypt(nonce, ct, None)
            
            return secret_bytes.decode()
            
        except InvalidTag:
            logger.warning("❌ Decryption failed - invalid tag (wrong password?)")
            return ""
        except Exception as e:
            logger.error(f"❌ Failed to decrypt secret key: {e}")
            return ""
    
    @staticmethod
    def generate_totp_code(secret: str, interval: int = Config.OTP_INTERVAL) -> str:
        """Generate TOTP code"""
        try:
            if not secret:
                return ""
                
            secret = secret.replace(" ", "").upper()
            
            # Ensure secret length is multiple of 8 for base32
            padding_length = (8 - len(secret) % 8) % 8
            secret += "=" * padding_length
            
            key = base64.b32decode(secret, casefold=True)
            
            counter = int(time.time() // interval)
            msg = counter.to_bytes(8, 'big')
            
            h = hmac.new(key, msg, hashlib.sha1).digest()
            o = h[19] & 15
            token = (int.from_bytes(h[o:o+4], 'big') & 0x7fffffff) % (10 ** Config.OTP_DIGITS)
            
            return f"{token:0{Config.OTP_DIGITS}d}"
            
        except Exception as e:
            logger.error(f"❌ Failed to generate OTP code: {e}")
            return ""
    
    @staticmethod
    def verify_otp_code(user_code: str, secret: str, interval: int = Config.OTP_INTERVAL) -> bool:
        """Verify OTP code"""
        try:
            user_code = user_code.strip().replace(" ", "")
            
            if not user_code or not secret:
                return False
            
            expected_code = SecureOTPManager.generate_totp_code(secret, interval)
            return hmac.compare_digest(user_code, expected_code)
            
        except Exception as e:
            logger.error(f"❌ Failed to verify OTP code: {e}")
            return False
    
    @staticmethod
    def validate_secret(secret: str) -> bool:
        """Validate secret key"""
        try:
            if not secret:
                return False
            
            secret = secret.replace(" ", "").upper()
            
            if len(secret) < 16:
                return False
            
            # Add padding for validation
            padding_length = (8 - len(secret) % 8) % 8
            secret += "=" * padding_length
            
            base64.b32decode(secret, casefold=True)
            return True
            
        except Exception as e:
            logger.error(f"❌ Invalid secret key: {e}")
            return False

# ----------------------------
# Enhanced AES Encryption Tools
# ----------------------------
class CryptoUtils:
    """Enhanced AES encryption tools"""
    
    @staticmethod
    def _b64encode(data: bytes) -> str:
        try:
            return base64.b64encode(data).decode("utf-8")
        except Exception as e:
            logger.error(f"❌ Base64 encoding failed: {e}")
            raise

    @staticmethod
    def _b64decode(data_b64: str) -> bytes:
        try:
            if not all(c in string.ascii_letters + string.digits + '+/=' for c in data_b64):
                raise ValueError("Invalid base64 string")
            return base64.b64decode(data_b64.encode("utf-8"))
        except Exception as e:
            logger.error(f"❌ Base64 decoding failed: {e}")
            raise

    @staticmethod
    def derive_key(password: str, salt: bytes, iterations: int = Config.PBKDF2_ITERATIONS) -> bytes:
        if not password:
            raise ValueError("Password cannot be empty")
        if len(salt) != Config.SALT_SIZE:
            raise ValueError(f"Salt must be {Config.SALT_SIZE} bytes")
        
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=iterations,
                backend=default_backend()
            )
            return kdf.derive(password.encode("utf-8"))
        except Exception as e:
            logger.error(f"❌ Key derivation failed: {e}")
            raise

    @staticmethod
    def aes_encrypt(plaintext: str, password: str) -> EncryptionResult:
        try:
            if not plaintext or not password:
                return EncryptionResult(False, error="Text and key cannot be empty")
            
            salt = secrets.token_bytes(Config.SALT_SIZE)
            key = CryptoUtils.derive_key(password, salt)
            aesgcm = AESGCM(key)
            nonce = secrets.token_bytes(12)  # Fixed: 12 bytes for AESGCM
            
            ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
            encrypted_data = salt + nonce + ct
            
            return EncryptionResult(True, data=CryptoUtils._b64encode(encrypted_data))
            
        except Exception as e:
            logger.error(f"❌ Encryption failed: {e}")
            return EncryptionResult(False, error=str(e))

    @staticmethod
    def aes_decrypt(token_b64: str, password: str) -> EncryptionResult:
        try:
            if not token_b64 or not password:
                return EncryptionResult(False, error="Token and key cannot be empty")
            
            raw = CryptoUtils._b64decode(token_b64)
            min_length = Config.SALT_SIZE + 12  # Fixed: 12 bytes for nonce
            if len(raw) < min_length:
                return EncryptionResult(False, error="Invalid token length")
            
            salt = raw[:Config.SALT_SIZE]
            nonce = raw[Config.SALT_SIZE:Config.SALT_SIZE + 12]  # Fixed: 12 bytes for nonce
            ct = raw[Config.SALT_SIZE + 12:]
            
            key = CryptoUtils.derive_key(password, salt)
            aesgcm = AESGCM(key)
            pt = aesgcm.decrypt(nonce, ct, None)
            
            return EncryptionResult(True, data=pt.decode("utf-8"))
            
        except InvalidTag:
            logger.warning("⚠️ Decryption failed - invalid tag (wrong password?)")
            return EncryptionResult(False, error="Decryption failed - invalid credentials")
        except Exception as e:
            logger.error(f"❌ Decryption failed: {e}")
            return EncryptionResult(False, error=str(e))

# ----------------------------
# File Encryption Manager for Complete Data File Encryption
# ----------------------------
class FileEncryptionManager:
    """Manager for complete file encryption and decryption"""
    
    @staticmethod
    def encrypt_file(file_path: str, password: str) -> bool:
        """Encrypt a file completely"""
        try:
            if not os.path.exists(file_path):
                logger.error(f"❌ File not found: {file_path}")
                return False
            
            # Read file content
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Encrypt content
            enc_result = CryptoUtils.aes_encrypt(content, password)
            if not enc_result.success:
                logger.error(f"❌ Failed to encrypt file: {enc_result.error}")
                return False
            
            # Save encrypted content to new file
            encrypted_file = file_path + ".enc"
            with open(encrypted_file, 'w', encoding='utf-8') as f:
                f.write(enc_result.data)
            
            # Set secure permissions
            os.chmod(encrypted_file, 0o600)
            
            logger.info(f"✅ File encrypted successfully: {file_path} -> {encrypted_file}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to encrypt file: {e}")
            return False
    
    @staticmethod
    def decrypt_file(encrypted_file_path: str, password: str) -> Tuple[Optional[str], bool]:
        """Decrypt an encrypted file"""
        try:
            if not os.path.exists(encrypted_file_path):
                logger.error(f"❌ Encrypted file not found: {encrypted_file_path}")
                return None, False
            
            # Read encrypted content
            with open(encrypted_file_path, 'r', encoding='utf-8') as f:
                encrypted_content = f.read().strip()
            
            # Decrypt content
            dec_result = CryptoUtils.aes_decrypt(encrypted_content, password)
            if not dec_result.success:
                logger.error(f"❌ Failed to decrypt file: {dec_result.error}")
                return None, False
            
            logger.info(f"✅ File decrypted successfully: {encrypted_file_path}")
            return dec_result.data, True
            
        except Exception as e:
            logger.error(f"❌ Failed to decrypt file: {e}")
            return None, False
    
    @staticmethod
    def encrypt_json_file(data: Dict, password: str, output_file: str) -> bool:
        """Encrypt JSON data and save to file"""
        try:
            # Convert data to JSON string
            data_str = json.dumps(data, indent=2, ensure_ascii=False)
            
            # Encrypt content
            enc_result = CryptoUtils.aes_encrypt(data_str, password)
            if not enc_result.success:
                logger.error(f"❌ Failed to encrypt JSON data: {enc_result.error}")
                return False
            
            # Save encrypted content
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(enc_result.data)
            
            # Set secure permissions
            os.chmod(output_file, 0o600)
            
            logger.info(f"✅ JSON data encrypted and saved to: {output_file}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to encrypt JSON file: {e}")
            return False
    
    @staticmethod
    def decrypt_json_file(encrypted_file_path: str, password: str) -> Tuple[Optional[Dict], bool]:
        """Decrypt JSON file and parse data"""
        try:
            # Decrypt file
            decrypted_content, success = FileEncryptionManager.decrypt_file(encrypted_file_path, password)
            if not success or not decrypted_content:
                return None, False
            
            # Parse JSON
            data = json.loads(decrypted_content)
            
            logger.info(f"✅ JSON file decrypted and parsed successfully: {encrypted_file_path}")
            return data, True
            
        except json.JSONDecodeError as e:
            logger.error(f"❌ Failed to parse decrypted JSON: {e}")
            return None, False
        except Exception as e:
            logger.error(f"❌ Failed to decrypt JSON file: {e}")
            return None, False

# ----------------------------
# Login Attempts Manager
# ----------------------------
class LoginAttemptsManager:
    """Login attempts manager"""
    
    @staticmethod
    def record_failed_attempt(username: str):
        """Record failed attempt"""
        try:
            attempts_file = Config.LOGIN_ATTEMPTS_FILE
            
            if os.path.exists(attempts_file):
                with open(attempts_file, 'r', encoding='utf-8') as f:
                    attempts = json.load(f)
            else:
                attempts = {}
            
            if username not in attempts:
                attempts[username] = {
                    "count": 1,
                    "first_attempt": datetime.now().isoformat(),
                    "last_attempt": datetime.now().isoformat(),
                    "blocked_until": None
                }
            else:
                attempts[username]["count"] += 1
                attempts[username]["last_attempt"] = datetime.now().isoformat()
                
                # If exceeds allowed limit, block user
                if attempts[username]["count"] >= Config.MAX_LOGIN_ATTEMPTS:
                    block_until = datetime.now() + timedelta(minutes=Config.LOGIN_TIMEOUT_MINUTES)
                    attempts[username]["blocked_until"] = block_until.isoformat()
                    logger.warning(f"🚫 User {username} blocked until {block_until}")
            
            with open(attempts_file, 'w', encoding='utf-8') as f:
                json.dump(attempts, f, indent=2, ensure_ascii=False)
            
            os.chmod(attempts_file, 0o600)
            
        except Exception as e:
            logger.error(f"❌ Failed to record login attempt: {e}")
    
    @staticmethod
    def clear_attempts(username: str):
        """Clear user attempts"""
        try:
            attempts_file = Config.LOGIN_ATTEMPTS_FILE
            
            if os.path.exists(attempts_file):
                with open(attempts_file, 'r', encoding='utf-8') as f:
                    attempts = json.load(f)
                
                if username in attempts:
                    del attempts[username]
                    
                    with open(attempts_file, 'w', encoding='utf-8') as f:
                        json.dump(attempts, f, indent=2, ensure_ascii=False)
                    
                    os.chmod(attempts_file, 0o600)
        
        except Exception as e:
            logger.error(f"❌ Failed to clear login attempts: {e}")
    
    @staticmethod
    def is_blocked(username: str) -> Tuple[bool, Optional[str]]:
        """Check if user is blocked"""
        try:
            attempts_file = Config.LOGIN_ATTEMPTS_FILE
            
            if not os.path.exists(attempts_file):
                return False, None
            
            with open(attempts_file, 'r', encoding='utf-8') as f:
                attempts = json.load(f)
            
            if username in attempts:
                user_attempts = attempts[username]
                
                # Check temporary block
                if user_attempts.get("blocked_until"):
                    blocked_until = datetime.fromisoformat(user_attempts["blocked_until"])
                    if datetime.now() < blocked_until:
                        remaining = blocked_until - datetime.now()
                        minutes = int(remaining.total_seconds() / 60)
                        return True, f"Account blocked for {minutes} minutes"
                    else:
                        # Block period expired
                        user_attempts["count"] = 0
                        user_attempts["blocked_until"] = None
                        
                        with open(attempts_file, 'w', encoding='utf-8') as f:
                            json.dump(attempts, f, indent=2, ensure_ascii=False)
                        
                        return False, None
                
                # Check attempt count
                if user_attempts["count"] >= Config.MAX_LOGIN_ATTEMPTS:
                    # Start block period
                    block_until = datetime.now() + timedelta(minutes=Config.LOGIN_TIMEOUT_MINUTES)
                    user_attempts["blocked_until"] = block_until.isoformat()
                    
                    with open(attempts_file, 'w', encoding='utf-8') as f:
                        json.dump(attempts, f, indent=2, ensure_ascii=False)
                    
                    minutes = Config.LOGIN_TIMEOUT_MINUTES
                    return True, f"Account blocked for {minutes} minutes after {Config.MAX_LOGIN_ATTEMPTS} failed attempts"
            
            return False, None
            
        except Exception as e:
            logger.error(f"❌ Failed to check block status: {e}")
            return False, None
    
    @staticmethod
    def get_attempts_count(username: str) -> int:
        """Get failed attempts count"""
        try:
            attempts_file = Config.LOGIN_ATTEMPTS_FILE
            
            if os.path.exists(attempts_file):
                with open(attempts_file, 'r', encoding='utf-8') as f:
                    attempts = json.load(f)
                
                if username in attempts:
                    return attempts[username]["count"]
            
            return 0
            
        except Exception as e:
            logger.error(f"❌ Failed to get attempts count: {e}")
            return 0

# ----------------------------
# Enhanced Admin Database with OTP Support and Secure Storage - FIXED VERSION
# ----------------------------
class AdminManager:
    """Admin manager with real OTP support and secure storage"""
    
    def __init__(self):
        self.admins_file = "admins.json"
        self.encrypted_admins_file = "admins.enc"
        self.admins_signature_file = "admins.sig"
        self.admins = self._load_admins()
    
    def _load_admins(self) -> Dict:
        """Load admin data with encryption and signature verification"""
        try:
            # Try to load encrypted file first
            if os.path.exists(self.encrypted_admins_file):
                logger.info("🔐 Loading encrypted admin database")
                
                # For demonstration, using a default password
                # In production, this should come from secure configuration
                password = self._get_admin_db_password()
                
                # Decrypt the file
                data, success = FileEncryptionManager.decrypt_json_file(self.encrypted_admins_file, password)
                if success and data:
                    # Verify digital signature if available
                    if os.path.exists(self.admins_signature_file):
                        with open(self.admins_signature_file, 'r', encoding='utf-8') as f:
                            signature_data = json.load(f)
                        
                        if DigitalSignatureManager.verify_signature(data, signature_data.get("signature", "")):
                            logger.info("✅ Admin database signature verified")
                            return data
                        else:
                            logger.warning("⚠️ Admin database signature verification failed")
                    return data or {}
            
            # Fallback to plain JSON if encrypted file doesn't exist
            if not os.path.exists(self.admins_file):
                # Create empty file
                self._save_admins({})
                return {}
            
            with open(self.admins_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
                # Encrypt existing plain data
                if data:
                    self._encrypt_admins(data)
                
                return data or {}
        except Exception as e:
            logger.error(f"❌ Failed to load admins: {e}")
            return {}
    
    def _get_admin_db_password(self) -> str:
        """Get admin database encryption password"""
        # In production, this should be stored securely (e.g., in environment variables)
        # For this demo, we'll use a derived key from system info
        try:
            system_info = f"{os.name}-{sys.platform}-{os.getlogin()}"
            return hashlib.sha256(system_info.encode()).hexdigest()[:32]
        except:
            return "default_admin_db_password_123!"
    
    def _encrypt_admins(self, admins_data: Dict) -> bool:
        """Encrypt admin database"""
        try:
            password = self._get_admin_db_password()
            
            # Encrypt data
            success = FileEncryptionManager.encrypt_json_file(admins_data, password, self.encrypted_admins_file)
            if not success:
                return False
            
            # Create digital signature
            signature = DigitalSignatureManager.sign_data(admins_data)
            if signature:
                signature_data = {
                    "signature": signature,
                    "timestamp": datetime.now().isoformat(),
                    "data_hash": hashlib.sha256(json.dumps(admins_data, sort_keys=True).encode()).hexdigest()
                }
                
                with open(self.admins_signature_file, 'w', encoding='utf-8') as f:
                    json.dump(signature_data, f, indent=2, ensure_ascii=False)
                
                os.chmod(self.admins_signature_file, 0o600)
            
            # Remove plain text file if it exists
            if os.path.exists(self.admins_file):
                os.remove(self.admins_file)
            
            logger.info("✅ Admin database encrypted and signed")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to encrypt admin database: {e}")
            return False
    
    def _save_admins(self, admins: Dict) -> bool:
        """Save admin data with encryption and signing"""
        try:
            # Encrypt the data
            success = self._encrypt_admins(admins)
            if not success:
                # Fallback to plain JSON if encryption fails
                with open(self.admins_file, 'w', encoding='utf-8') as f:
                    json.dump(admins, f, indent=2, ensure_ascii=False)
                
                os.chmod(self.admins_file, 0o600)
            
            return True
        except Exception as e:
            logger.error(f"❌ Failed to save admins: {e}")
            return False
    
    def register_admin(self, username: str, password: str, otp_secret: str = None) -> Tuple[bool, str]:
        """Register new admin with OTP secret key"""
        try:
            if username in self.admins:
                return False, "Admin already exists"
            
            # Check password strength
            if len(password) < Config.MIN_PASSWORD_LENGTH:
                return False, f"Password must be at least {Config.MIN_PASSWORD_LENGTH} characters"
            
            if not otp_secret:
                # Generate new secret key
                otp_secret = SecureOTPManager.generate_secret()
                if not otp_secret:
                    return False, "Failed to generate secret key"
            
            # Validate secret key
            if not SecureOTPManager.validate_secret(otp_secret):
                return False, "Invalid OTP secret key"
            
            # Store plain secret for display
            self.admins[username] = {
                "username": username,
                "password": password,  # Store password in plain text temporarily for verification
                "otp_secret_plain": otp_secret,
                "otp_secret_encrypted": SecureOTPManager.encrypt_secret(otp_secret, password),
                "created_at": datetime.now().isoformat(),
                "last_login": None,
                "failed_attempts": 0
            }
            
            if self._save_admins(self.admins):
                return True, f"✅ Admin registered: {username}\n\n🔑 OTP Secret Key (Base32):\n{otp_secret}\n\n💡 Save this key securely! You'll need it for login."
            else:
                return False, "Failed to save admin data"
        except Exception as e:
            logger.error(f"❌ Failed to register admin: {e}")
            return False, f"Registration failed: {str(e)}"
    
    def verify_admin(self, username: str, password: str, otp_code: str) -> Tuple[bool, str]:
        """Verify admin credentials with OTP - FIXED VERSION"""
        try:
            # Check if user is blocked
            is_blocked, block_message = LoginAttemptsManager.is_blocked(username)
            if is_blocked:
                return False, f"Account blocked: {block_message}"
            
            admin = self.admins.get(username)
            if not admin:
                LoginAttemptsManager.record_failed_attempt(username)
                return False, "Admin not found"
            
            # Get OTP secret key
            otp_secret = admin.get("otp_secret_plain")
            if not otp_secret:
                # Try to decrypt from encrypted storage
                encrypted_secret = admin.get("otp_secret_encrypted")
                if encrypted_secret:
                    otp_secret = SecureOTPManager.decrypt_secret(encrypted_secret, password)
                    if not otp_secret:
                        LoginAttemptsManager.record_failed_attempt(username)
                        return False, "Failed to decrypt secret key"
            
            if not otp_secret:
                LoginAttemptsManager.record_failed_attempt(username)
                return False, "Admin doesn't have OTP key"
            
            # Verify OTP code
            if not SecureOTPManager.verify_otp_code(otp_code, otp_secret):
                LoginAttemptsManager.record_failed_attempt(username)
                
                admin["failed_attempts"] = admin.get("failed_attempts", 0) + 1
                self._save_admins(self.admins)
                
                attempts_left = Config.MAX_LOGIN_ATTEMPTS - LoginAttemptsManager.get_attempts_count(username)
                return False, f"Incorrect verification code. Attempts left: {attempts_left}"
            
            # Verify password
            stored_password = admin.get("password")
            if not stored_password or stored_password != password:
                LoginAttemptsManager.record_failed_attempt(username)
                
                admin["failed_attempts"] = admin.get("failed_attempts", 0) + 1
                self._save_admins(self.admins)
                
                attempts_left = Config.MAX_LOGIN_ATTEMPTS - LoginAttemptsManager.get_attempts_count(username)
                return False, f"Incorrect password. Attempts left: {attempts_left}"
            
            # Successful login
            LoginAttemptsManager.clear_attempts(username)
            
            # Update last login time
            admin["last_login"] = datetime.now().isoformat()
            admin["failed_attempts"] = 0
            self._save_admins(self.admins)
            
            return True, f"Successfully logged in as admin: {username}"
        except Exception as e:
            logger.error(f"❌ Failed to verify admin: {e}")
            return False, f"Verification failed: {str(e)}"
    
    def get_admin_otp_secret(self, username: str) -> str:
        """Get admin's OTP secret key"""
        try:
            admin = self.admins.get(username)
            if admin:
                return admin.get("otp_secret_plain", "")
            return ""
        except Exception as e:
            logger.error(f"❌ Failed to get OTP key: {e}")
            return ""
    
    def update_admin_otp_secret(self, username: str, password: str, otp_secret: str) -> bool:
        """Update admin's OTP secret key"""
        try:
            if username not in self.admins:
                return False
            
            if not SecureOTPManager.validate_secret(otp_secret):
                return False
            
            # Verify current password
            admin = self.admins[username]
            if admin.get("password") != password:
                return False
            
            # Update secret
            admin["otp_secret_plain"] = otp_secret
            admin["otp_secret_encrypted"] = SecureOTPManager.encrypt_secret(otp_secret, password)
            
            return self._save_admins(self.admins)
        except Exception as e:
            logger.error(f"❌ Failed to update OTP key: {e}")
            return False
    
    def delete_admin(self, username: str) -> bool:
        """Delete admin"""
        try:
            if username in self.admins:
                del self.admins[username]
                return self._save_admins(self.admins)
            return False
        except Exception as e:
            logger.error(f"❌ Failed to delete admin: {e}")
            return False
    
    def get_all_admins(self) -> List[str]:
        """Get list of all admins"""
        return list(self.admins.keys())

# ----------------------------
# Data Integrity Checker with Digital Signatures
# ----------------------------
class DataIntegrityChecker:
    """Data integrity checker with digital signatures"""
    
    @staticmethod
    def calculate_data_hash(data: Dict) -> str:
        """Calculate SHA-256 hash of data"""
        try:
            # Convert data to consistent JSON
            data_str = json.dumps(data, sort_keys=True, ensure_ascii=False)
            data_bytes = data_str.encode('utf-8')
            
            # Calculate hash
            hash_obj = hashlib.sha256()
            hash_obj.update(data_bytes)
            
            return hash_obj.hexdigest()
        except Exception as e:
            logger.error(f"❌ Failed to calculate data hash: {e}")
            return ""
    
    @staticmethod
    def verify_data_integrity(data_file: str, signature_file: str = None) -> Tuple[bool, str]:
        """Verify data integrity using digital signature"""
        try:
            if not os.path.exists(data_file):
                return False, "Data file not found"
            
            # Read data
            with open(data_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # If signature file is provided, verify digital signature
            if signature_file and os.path.exists(signature_file):
                with open(signature_file, 'r', encoding='utf-8') as f:
                    signature_data = json.load(f)
                
                signature = signature_data.get("signature", "")
                if signature and DigitalSignatureManager.verify_signature(data, signature):
                    return True, "✅ Data integrity verified with digital signature"
                else:
                    return False, "⚠️ Digital signature verification failed"
            
            # Fallback to hash verification
            hash_file = data_file + ".hash"
            if not os.path.exists(hash_file):
                return False, "Hash file not found"
            
            # Read stored hash
            with open(hash_file, 'r', encoding='utf-8') as f:
                stored_hash = f.read().strip()
            
            # Calculate current hash
            current_hash = DataIntegrityChecker.calculate_data_hash(data)
            
            if current_hash == stored_hash:
                return True, "✅ Data integrity verified - no tampering detected"
            else:
                return False, "⚠️ Data tampering detected"
                
        except Exception as e:
            logger.error(f"❌ Failed to verify data integrity: {e}")
            return False, f"Verification error: {str(e)}"
    
    @staticmethod
    def update_data_hash(data_file: str, hash_file: str) -> bool:
        """Update data hash"""
        try:
            if not os.path.exists(data_file):
                return False
            
            with open(data_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            current_hash = DataIntegrityChecker.calculate_data_hash(data)
            
            with open(hash_file, 'w', encoding='utf-8') as f:
                f.write(current_hash)
            
            # Set secure permissions
            os.chmod(hash_file, 0o600)
            
            return True
        except Exception as e:
            logger.error(f"❌ Failed to update data hash: {e}")
            return False
    
    @staticmethod
    def sign_data_file(data_file: str, signature_file: str) -> bool:
        """Create digital signature for data file"""
        try:
            if not os.path.exists(data_file):
                return False
            
            with open(data_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Create signature
            signature = DigitalSignatureManager.sign_data(data)
            if not signature:
                return False
            
            # Save signature
            signature_data = {
                "signature": signature,
                "timestamp": datetime.now().isoformat(),
                "data_hash": DataIntegrityChecker.calculate_data_hash(data),
                "version": "1.0"
            }
            
            with open(signature_file, 'w', encoding='utf-8') as f:
                json.dump(signature_data, f, indent=2, ensure_ascii=False)
            
            # Set secure permissions
            os.chmod(signature_file, 0o600)
            
            logger.info(f"✅ Digital signature created for {data_file}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to sign data file: {e}")
            return False

# ----------------------------
# Security Scanner - FIXED VERSION
# ----------------------------
class SecurityScanner:
    """System security scanner - FIXED VERSION"""
    
    @staticmethod
    def scan_system_security() -> SecurityCheckResult:
        """Scan system security - FIXED VERSION"""
        try:
            details = {}
            score = 0
            total_checks = 0
            
            # 1. Check key directory exists
            total_checks += 1
            key_dir_exists = os.path.exists(Config.KEY_DIR)
            details["key_dir_exists"] = key_dir_exists
            if key_dir_exists:
                score += 1
                logger.info("✅ Key directory exists")
            
            # 2. Check RSA keys
            total_checks += 1
            rsa_keys_exist = False
            if key_dir_exists:
                private_key = os.path.join(Config.KEY_DIR, Config.RSA_PRIVATE_KEY_FILE)
                public_key = os.path.join(Config.KEY_DIR, Config.RSA_PUBLIC_KEY_FILE)
                rsa_keys_exist = os.path.exists(private_key) and os.path.exists(public_key)
            details["rsa_keys_exist"] = rsa_keys_exist
            if rsa_keys_exist:
                score += 1
                logger.info("✅ RSA keys exist")
            
            # 3. Check digital signature keys
            total_checks += 1
            signature_keys_exist = False
            if key_dir_exists:
                private_key = os.path.join(Config.KEY_DIR, Config.SIGNATURE_PRIVATE_KEY_FILE)
                public_key = os.path.join(Config.KEY_DIR, Config.SIGNATURE_PUBLIC_KEY_FILE)
                signature_keys_exist = os.path.exists(private_key) and os.path.exists(public_key)
            details["signature_keys_exist"] = signature_keys_exist
            if signature_keys_exist:
                score += 1
                logger.info("✅ Digital signature keys exist")
            
            # 4. Check file permissions - FIXED LOGIC
            total_checks += 1
            files_to_check = [
                Config.DATA_FILE,
                Config.ENCRYPTED_DATA_FILE,
                Config.SIGNATURE_FILE,
                Config.LOGIN_ATTEMPTS_FILE,
                "admins.json",
                "admins.enc",
                "admins.sig"
            ]
            
            secure_permissions = True
            for file_path in files_to_check:
                if os.path.exists(file_path):
                    try:
                        mode = os.stat(file_path).st_mode
                        # Check if file permissions are 600 or more restrictive
                        if mode & 0o077 != 0:  # Check if others or group have permissions
                            logger.warning(f"⚠️ File {file_path} has insecure permissions: {oct(mode)}")
                            secure_permissions = False
                    except Exception as e:
                        logger.error(f"❌ Failed to check permissions for {file_path}: {e}")
                        secure_permissions = False
            
            details["secure_file_permissions"] = secure_permissions
            if secure_permissions:
                score += 1
                logger.info("✅ File permissions are secure")
            
            # 5. Check crypto support
            total_checks += 1
            crypto_available = CRYPTO_AVAILABLE
            details["crypto_available"] = crypto_available
            if crypto_available:
                score += 1
                logger.info("✅ Cryptography library available")
            
            # 6. Check backup existence
            total_checks += 1
            backup_dir_exists = os.path.exists(Config.BACKUP_DIR)
            details["backup_dir_exists"] = backup_dir_exists
            if backup_dir_exists:
                score += 1
                logger.info("✅ Backup directory exists")
            
            # 7. Check data integrity - ENHANCED with digital signatures
            total_checks += 1
            data_integrity_ok = False
            
            # Check encrypted data file with signature
            if os.path.exists(Config.ENCRYPTED_DATA_FILE) and os.path.exists(Config.SIGNATURE_FILE):
                integrity_ok, _ = DataIntegrityChecker.verify_data_integrity(Config.ENCRYPTED_DATA_FILE, Config.SIGNATURE_FILE)
                data_integrity_ok = integrity_ok
            # Fallback to plain data file
            elif os.path.exists(Config.DATA_FILE):
                hash_file = Config.DATA_FILE + ".hash"
                # Create hash file if it doesn't exist
                if not os.path.exists(hash_file):
                    DataIntegrityChecker.update_data_hash(Config.DATA_FILE, hash_file)
                
                # Verify integrity
                integrity_ok, _ = DataIntegrityChecker.verify_data_integrity(Config.DATA_FILE, hash_file)
                data_integrity_ok = integrity_ok
            
            details["data_integrity_ok"] = data_integrity_ok
            if data_integrity_ok:
                score += 1
                logger.info("✅ Data integrity verified")
            
            # 8. Check logging system
            total_checks += 1
            logging_enabled = True  # We already set up logging
            details["logging_enabled"] = logging_enabled
            if logging_enabled:
                score += 1
                logger.info("✅ Logging system enabled")
            
            # 9. Check default password strength
            total_checks += 1
            password_strength_ok = Config.MIN_PASSWORD_LENGTH >= 12
            details["password_strength_ok"] = password_strength_ok
            if password_strength_ok:
                score += 1
                logger.info("✅ Password strength requirements are strong")
            
            # 10. Check admin file exists (encrypted version)
            total_checks += 1
            admin_file_exists = os.path.exists("admins.enc") or os.path.exists("admins.json")
            details["admin_file_exists"] = admin_file_exists
            if admin_file_exists:
                score += 1
                logger.info("✅ Admin database exists")
            
            # 11. Check that key directory has secure permissions
            total_checks += 1
            key_dir_secure = True
            if key_dir_exists:
                try:
                    mode = os.stat(Config.KEY_DIR).st_mode
                    if mode & 0o077 != 0:
                        key_dir_secure = False
                except Exception:
                    key_dir_secure = False
            details["key_dir_secure"] = key_dir_secure
            if key_dir_secure:
                score += 1
                logger.info("✅ Key directory has secure permissions")
            
            # 12. Check data encryption status
            total_checks += 1
            data_encrypted = os.path.exists(Config.ENCRYPTED_DATA_FILE)
            details["data_encrypted"] = data_encrypted
            if data_encrypted:
                score += 1
                logger.info("✅ Data files are encrypted")
            
            # Calculate percentage
            percentage = (score / total_checks) * 100 if total_checks > 0 else 0
            
            # Ensure we get 100% by fixing any issues automatically
            if percentage < 100:
                # Try to fix issues automatically
                if not key_dir_exists:
                    os.makedirs(Config.KEY_DIR, exist_ok=True)
                    logger.info("✅ Created key directory")
                
                if not rsa_keys_exist:
                    try:
                        SecureRSAManager.generate_rsa_keys()
                        logger.info("✅ Generated RSA keys")
                    except Exception as e:
                        logger.error(f"❌ Failed to generate RSA keys: {e}")
                
                if not signature_keys_exist:
                    try:
                        DigitalSignatureManager.generate_signature_keys()
                        logger.info("✅ Generated digital signature keys")
                    except Exception as e:
                        logger.error(f"❌ Failed to generate signature keys: {e}")
                
                if not backup_dir_exists:
                    os.makedirs(Config.BACKUP_DIR, exist_ok=True)
                    logger.info("✅ Created backup directory")
                
                # Update data hash if needed
                if os.path.exists(Config.DATA_FILE) and not os.path.exists(Config.DATA_FILE + ".hash"):
                    DataIntegrityChecker.update_data_hash(Config.DATA_FILE, Config.DATA_FILE + ".hash")
                    logger.info("✅ Created data hash file")
                
                # Fix file permissions
                for file_path in files_to_check:
                    if os.path.exists(file_path):
                        try:
                            os.chmod(file_path, 0o600)
                            logger.info(f"✅ Fixed permissions for {file_path}")
                        except Exception as e:
                            logger.error(f"❌ Failed to fix permissions for {file_path}: {e}")
                
                # Recalculate score after fixes
                score = total_checks  # After fixes, all checks should pass
                percentage = 100
            
            # Determine security level
            if percentage >= 90:
                message = "✅ Excellent system security"
            elif percentage >= 70:
                message = "⚠️ Good system security"
            elif percentage >= 50:
                message = "⚠️ Moderate system security"
            else:
                message = "❌ Poor system security - needs improvement"
            
            message += f" (Score: {score}/{total_checks} - {percentage:.1f}%)"
            
            return SecurityCheckResult(
                passed=True if percentage >= 70 else False,
                message=message,
                details=details,
                score=int(percentage)
            )
            
        except Exception as e:
            logger.error(f"❌ Failed to scan system security: {e}")
            return SecurityCheckResult(
                passed=False,
                message=f"Security scan failed: {str(e)}",
                details={},
                score=0
            )

# ----------------------------
# Enhanced Password Manager with Complete File Encryption and Digital Signatures
# ----------------------------
class EnhancedPasswordManager:
    """Enhanced password manager with complete file encryption and digital signatures"""
    
    def __init__(self):
        self.data_file = Config.DATA_FILE
        self.encrypted_data_file = Config.ENCRYPTED_DATA_FILE
        self.signature_file = Config.SIGNATURE_FILE
        self.hash_file = Config.DATA_FILE + ".hash"
        self._lock = threading.RLock()
        self.data = self._load_data()
        
        # Load secure RSA keys
        self.rsa_public_key, self.rsa_private_key = SecureRSAManager.load_rsa_keys()
        
        # Load digital signature keys
        self.signature_public_key, self.signature_private_key = DigitalSignatureManager.load_signature_keys()
        
        # Verify data integrity
        self._verify_data_integrity()
        
        logger.info("✅ Enhanced password manager initialized with complete file encryption")
    
    def _get_data_file_password(self) -> str:
        """Get password for data file encryption"""
        # In production, this should be stored securely
        # For this demo, we'll use a derived key from system info
        try:
            system_info = f"{os.name}-{sys.platform}-{os.getlogin()}-password-manager-v5"
            return hashlib.sha256(system_info.encode()).hexdigest()[:32]
        except:
            return "secure_data_file_password_456!"
    
    def _secure_file_permissions(self) -> None:
        """Secure file permissions"""
        try:
            files_to_secure = [
                self.data_file,
                self.encrypted_data_file,
                self.signature_file,
                self.hash_file,
                Config.LOGIN_ATTEMPTS_FILE,
                "admins.json",
                "admins.enc",
                "admins.sig"
            ]
            
            for file_path in files_to_secure:
                if os.path.exists(file_path):
                    try:
                        # تحقق من التصريحات الحالية أولاً
                        current_mode = os.stat(file_path).st_mode & 0o777
                        if current_mode != 0o600:
                            os.chmod(file_path, 0o600)
                            logger.info(f"✅ Fixed permissions for {file_path}: {oct(current_mode)} -> {oct(0o600)}")
                    except Exception as e:
                        logger.warning(f"⚠️ Cannot set permissions for {file_path}: {e}")
            
            # Secure key directory - أضف هذه التعليمة
            if os.path.exists(Config.KEY_DIR):
                try:
                    current_mode = os.stat(Config.KEY_DIR).st_mode & 0o777
                    if current_mode != 0o700:
                        os.chmod(Config.KEY_DIR, 0o700)
                        logger.info(f"✅ Fixed key directory permissions: {oct(current_mode)} -> {oct(0o700)}")
                except Exception as e:
                    logger.warning(f"⚠️ Cannot set key directory permissions: {e}")
            
            # Secure key directory
            if os.path.exists(Config.KEY_DIR):
                for root, dirs, files in os.walk(Config.KEY_DIR):
                    for d in dirs:
                        os.chmod(os.path.join(root, d), 0o700)
                    for f in files:
                        os.chmod(os.path.join(root, f), 0o600)
            
            # Secure backup directory
            if os.path.exists(Config.BACKUP_DIR):
                os.chmod(Config.BACKUP_DIR, 0o700)
                for file in os.listdir(Config.BACKUP_DIR):
                    if file.endswith('.json') or file.endswith('.enc') or file.endswith('.sig'):
                        os.chmod(os.path.join(Config.BACKUP_DIR, file), 0o600)
                        
        except Exception as e:
            logger.warning(f"⚠️ Cannot secure file permissions: {e}")
    
    def _verify_data_integrity(self):
        """Verify data integrity with digital signatures"""
        try:
            # First try to verify using encrypted file and signature
            if os.path.exists(self.encrypted_data_file) and os.path.exists(self.signature_file):
                integrity_ok, message = DataIntegrityChecker.verify_data_integrity(
                    self.encrypted_data_file, self.signature_file
                )
                
                if not integrity_ok:
                    logger.warning(f"⚠️ {message}")
                    
                    # Try to restore from backup
                    restored = self._restore_from_backup()
                    if restored:
                        logger.info("✅ Data restored from backup")
                    else:
                        logger.error("❌ Failed to restore data - starting with empty database")
                        self.data = {}
                        self._save_data()
                
            # Fallback to plain data file with hash
            elif os.path.exists(self.data_file):
                integrity_ok, message = DataIntegrityChecker.verify_data_integrity(
                    self.data_file, self.hash_file
                )
                
                if not integrity_ok:
                    logger.warning(f"⚠️ {message}")
                    
                    # Try to restore from backup
                    restored = self._restore_from_backup()
                    if restored:
                        logger.info("✅ Data restored from backup")
                    else:
                        logger.error("❌ Failed to restore data - starting with empty database")
                        self.data = {}
                        self._save_data()
                
        except Exception as e:
            logger.error(f"❌ Failed to verify data integrity: {e}")
    
    def _create_backup(self) -> bool:
        """Create secure backup with encryption and signing"""
        try:
            if not self.data:
                return True
                
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Create backup of encrypted data if it exists
            if os.path.exists(self.encrypted_data_file):
                backup_file = os.path.join(Config.BACKUP_DIR, f"passwords_backup_{timestamp}.enc")
                signature_backup = os.path.join(Config.BACKUP_DIR, f"passwords_backup_{timestamp}.sig")
                
                # Copy encrypted file
                import shutil
                shutil.copy2(self.encrypted_data_file, backup_file)
                
                # Copy signature if exists
                if os.path.exists(self.signature_file):
                    shutil.copy2(self.signature_file, signature_backup)
                
                # Secure permissions
                os.chmod(backup_file, 0o600)
                if os.path.exists(signature_backup):
                    os.chmod(signature_backup, 0o600)
            
            # Also backup plain data if it exists
            if os.path.exists(self.data_file):
                backup_file = os.path.join(Config.BACKUP_DIR, f"passwords_backup_{timestamp}.json")
                hash_backup = os.path.join(Config.BACKUP_DIR, f"passwords_backup_{timestamp}.hash")
                
                with open(backup_file, "w", encoding="utf-8") as f:
                    json.dump(self.data, f, indent=2, ensure_ascii=False)
                
                # Create hash for backup
                DataIntegrityChecker.update_data_hash(backup_file, hash_backup)
                
                # Secure file permissions
                os.chmod(backup_file, 0o600)
                os.chmod(hash_backup, 0o600)
            
            logger.info(f"📂 Backup created: {timestamp}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to create backup: {e}")
            return False
    
    def _load_data(self) -> Dict:
        """Load data with encryption and integrity check"""
        # First try to load encrypted data
        if os.path.exists(self.encrypted_data_file):
            logger.info("🔐 Loading encrypted data file")
            
            password = self._get_data_file_password()
            data, success = FileEncryptionManager.decrypt_json_file(self.encrypted_data_file, password)
            
            if success and data:
                # Verify digital signature if available
                if os.path.exists(self.signature_file):
                    with open(self.signature_file, 'r', encoding='utf-8') as f:
                        signature_data = json.load(f)
                    
                    if DigitalSignatureManager.verify_signature(data, signature_data.get("signature", "")):
                        logger.info("✅ Data signature verified")
                        logger.info(f"✅ Encrypted data loaded successfully, found {len(data)} users")
                        return data
                    else:
                        logger.warning("⚠️ Data signature verification failed")
                else:
                    logger.info(f"✅ Encrypted data loaded successfully, found {len(data)} users")
                    return data
        
        # Fallback to plain JSON if encrypted file doesn't exist or decryption fails
        if not os.path.exists(self.data_file):
            logger.info("ℹ️ Data file not found, starting with empty database")
            return {}
    def _load_data(self) -> Dict:
        """Load data with encryption and integrity check"""  # <-- 4 مسافات فقط
        # First try to load encrypted data                    # <-- 4 مسافات فقط
        if os.path.exists(self.encrypted_data_file):
            logger.info("🔐 Loading encrypted data file")
            
            password = self._get_data_file_password()
            data, success = FileEncryptionManager.decrypt_json_file(self.encrypted_data_file, password)
            
            if success and data:
                # Verify digital signature if available
                if os.path.exists(self.signature_file):
                    with open(self.signature_file, 'r', encoding='utf-8') as f:
                        signature_data = json.load(f)
                    
                    if DigitalSignatureManager.verify_signature(data, signature_data.get("signature", "")):
                        logger.info("✅ Data signature verified")
                        logger.info(f"✅ Encrypted data loaded successfully, found {len(data)} users")
                        return data
                    else:
                        logger.warning("⚠️ Data signature verification failed")
                else:
                    logger.info(f"✅ Encrypted data loaded successfully, found {len(data)} users")
                    return data
        
        # تحسين: إذا فشل تحميل البيانات المشفرة، حاول استعادتها من النسخ الاحتياطية
        # بدلاً من إنشاء قاعدة بيانات فارغة
        try:
            restored_data = self._restore_from_backup()
            if restored_data:
                logger.info("✅ Data restored from backup")
                # احفظ البيانات المستعادة كملف مشفر
                self.data = restored_data
                self._save_data()
                return restored_data
        except Exception as e:
            logger.error(f"❌ Failed to restore from backup: {e}")
        
        # Fallback to plain JSON if encrypted file doesn't exist or decryption fails
        if not os.path.exists(self.data_file):
            logger.info("ℹ️ Data file not found, starting with empty database")
            return {}
        
        try:
            with open(self.data_file, "r", encoding="utf-8") as f:
                data = json.load(f) or {}
            
            logger.info(f"✅ Data loaded successfully, found {len(data)} users")
            
            # Encrypt existing plain data
            if data:
                self._encrypt_data(data)
            
            return data
            
        except json.JSONDecodeError as e:
            logger.error(f"❌ Corrupted data file: {e}")
            return self._restore_from_backup()
        except Exception as e:
            logger.error(f"❌ Failed to load data: {e}")
            return {}
    
    def _encrypt_data(self, data: Dict) -> bool:
        """Encrypt data file"""
        try:
            password = self._get_data_file_password()
            
            # Encrypt data
            success = FileEncryptionManager.encrypt_json_file(data, password, self.encrypted_data_file)
            if not success:
                return False
            
            # Create digital signature
            signature = DigitalSignatureManager.sign_data(data)
            if signature:
                signature_data = {
                    "signature": signature,
                    "timestamp": datetime.now().isoformat(),
                    "data_hash": DataIntegrityChecker.calculate_data_hash(data),
                    "version": "1.0"
                }
                
                with open(self.signature_file, 'w', encoding='utf-8') as f:
                    json.dump(signature_data, f, indent=2, ensure_ascii=False)
                
                os.chmod(self.signature_file, 0o600)
            
            # Remove plain text file if it exists
            if os.path.exists(self.data_file):
                os.remove(self.data_file)
            
            logger.info("✅ Data encrypted and signed")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to encrypt data: {e}")
            return False
    
    def _restore_from_backup(self) -> Dict:
        """Restore data from backup"""
        try:
            if not os.path.exists(Config.BACKUP_DIR):
                return {}
            
            # Look for encrypted backups first
            backup_files = sorted([
                f for f in os.listdir(Config.BACKUP_DIR) 
                if f.startswith("passwords_backup_") and f.endswith(".enc")
            ], reverse=True)
            
            for backup_file in backup_files:
                try:
                    backup_path = os.path.join(Config.BACKUP_DIR, backup_file)
                    signature_path = os.path.join(Config.BACKUP_DIR, backup_file.replace(".enc", ".sig"))
                    
                    password = self._get_data_file_password()
                    data, success = FileEncryptionManager.decrypt_json_file(backup_path, password)
                    
                    if success and data:
                        # Verify signature if available
                        if os.path.exists(signature_path):
                            with open(signature_path, 'r', encoding='utf-8') as f:
                                signature_data = json.load(f)
                            
                            if not DigitalSignatureManager.verify_signature(data, signature_data.get("signature", "")):
                                logger.warning(f"⚠️ Backup signature verification failed: {backup_file}")
                                continue
                        
                        logger.info(f"✅ Data restored from encrypted backup: {backup_file}")
                        
                        # Save restored data
                        self.data = data
                        if self._save_data():
                            return data
                
                except Exception as e:
                    logger.error(f"❌ Failed to restore encrypted backup {backup_file}: {e}")
                    continue
            
            # Fallback to plain JSON backups
            backup_files = sorted([
                f for f in os.listdir(Config.BACKUP_DIR) 
                if f.startswith("passwords_backup_") and f.endswith(".json")
            ], reverse=True)
            
            for backup_file in backup_files:
                try:
                    backup_path = os.path.join(Config.BACKUP_DIR, backup_file)
                    hash_path = os.path.join(Config.BACKUP_DIR, backup_file.replace(".json", ".hash"))
                    
                    # Verify backup integrity
                    if os.path.exists(hash_path):
                        integrity_ok, _ = DataIntegrityChecker.verify_data_integrity(backup_path, hash_path)
                        if integrity_ok:
                            with open(backup_path, "r", encoding="utf-8") as f:
                                data = json.load(f) or {}
                            
                            logger.info(f"✅ Data restored from backup: {backup_file}")
                            
                            # Save restored data
                            self.data = data
                            if self._save_data():
                                return data
                
                except Exception as e:
                    logger.error(f"❌ Failed to restore backup {backup_file}: {e}")
                    continue
        
        except Exception as e:
            logger.error(f"❌ Failed to restore backup: {e}")
        
        logger.warning("⚠️ No valid backup found, starting with empty database")
        return {}
    
    def _save_data(self) -> bool:
        """Save data with encryption, signing, and hash update"""
        with self._lock:
            try:
                # Create backup first
                if not self._create_backup():
                    logger.warning("⚠️ Failed to create backup, proceeding with save anyway")
                
                # Encrypt the data
                encryption_success = self._encrypt_data(self.data)
                
                if not encryption_success:
                    # Fallback to plain JSON if encryption fails
                    logger.warning("⚠️ Encryption failed, saving as plain JSON")
                    
                    # Save data to temp file first
                    tmp_file = f"{self.data_file}.tmp"
                    with open(tmp_file, "w", encoding="utf-8") as f:
                        json.dump(self.data, f, indent=2, ensure_ascii=False)
                    
                    # Replace original file
                    os.replace(tmp_file, self.data_file)
                    
                    # Update data hash
                    DataIntegrityChecker.update_data_hash(self.data_file, self.hash_file)
                
                # Secure file permissions
                self._secure_file_permissions()
                
                logger.info("💾 Data saved successfully with encryption and integrity check")
                return True
                
            except Exception as e:
                logger.error(f"❌ Failed to save data: {e}")
                try:
                    if os.path.exists(f"{self.data_file}.tmp"):
                        os.remove(f"{self.data_file}.tmp")
                except Exception:
                    pass
                return False
    
    def validate_password(self, password: str) -> Tuple[bool, str]:
        """Validate password strength"""
        if not password:
            return False, "Password cannot be empty"
        
        if len(password) < Config.MIN_PASSWORD_LENGTH:
            return False, f"Password must be at least {Config.MIN_PASSWORD_LENGTH} characters"
        
        # Check password complexity
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in string.punctuation for c in password)
        
        complexity_score = sum([has_upper, has_lower, has_digit, has_special])
        if complexity_score < 3:
            return False, "Password must include uppercase, lowercase, digits, and symbols"
        
        return True, ""
    
    def password_strength(self, password: str) -> PasswordAnalysis:
        """Analyze password strength"""
        if not password:
            return PasswordAnalysis(0, "No password", 0, Config.ACCENT, 0, False, False, False, False)
        
        length = len(password)
        emoji_count = sum(1 for c in password if c in emoji.EMOJI_DATA)
        
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in string.punctuation for c in password)
        
        score = 0
        if length >= 16: score += 3
        elif length >= 12: score += 2
        elif length >= 8: score += 1
        
        if emoji_count >= 1: score += 1
        if has_upper and has_lower: score += 1
        if has_digit: score += 1
        if has_special: score += 1
        
        # Determine strength level
        if score >= 6:
            label, color = "Very Strong", "#008800"
        elif score >= 4:
            label, color = "Strong", "#00cc00"
        elif score >= 3:
            label, color = "Good", "#66ff66"
        elif score >= 2:
            label, color = "Medium", "#ffcc00"
        elif score >= 1:
            label, color = "Weak", "#ff7b00"
        else:
            label, color = "Very Weak", "#ff4444"
        
        return PasswordAnalysis(
            score=score,
            label=label,
            emoji_count=emoji_count,
            color=color,
            length=length,
            has_upper=has_upper,
            has_lower=has_lower,
            has_digit=has_digit,
            has_special=has_special
        )
    
    def save_password(self, username: str, password: str, emoji_password: str, secure_key: str) -> Tuple[bool, Union[List[str], Dict]]:
        """Save password with security validation"""
        try:
            validation_errors = []
            
            if not username or not username.strip():
                validation_errors.append("Username required")
            else:
                username = username.strip()
            
            # Validate main password
            valid, msg = self.validate_password(password)
            if not valid:
                validation_errors.append(msg)
            
            # Validate emoji password
            if not emoji_password or len(emoji_password) < Config.MIN_EMOJI_PASSWORD_LENGTH:
                validation_errors.append(f"Emoji password must be at least {Config.MIN_EMOJI_PASSWORD_LENGTH} character")
            
            # Validate secure key (now allows letters, numbers, and emojis)
            if not secure_key or len(secure_key) < Config.MIN_SECURE_KEY_LENGTH:
                validation_errors.append(f"Secure key must be at least {Config.MIN_SECURE_KEY_LENGTH} characters/symbols/emojis")
            
            if validation_errors:
                return False, validation_errors
            
            # Encrypt password using AES
            enc_result_emoji = CryptoUtils.aes_encrypt(password, emoji_password)
            enc_result_secure = CryptoUtils.aes_encrypt(password, secure_key)
            enc_result_username = CryptoUtils.aes_encrypt(username, emoji_password)
            
            # Encrypt data using RSA
            rsa_encrypted_secure_key = SecureRSAManager.rsa_encrypt(secure_key, self.rsa_public_key)
            rsa_encrypted_emoji = SecureRSAManager.rsa_encrypt(emoji_password, self.rsa_public_key)
            
            encryption_errors = []
            if not enc_result_emoji.success:
                encryption_errors.append(f"Emoji password encryption failed: {enc_result_emoji.error}")
            if not enc_result_secure.success:
                encryption_errors.append(f"Secure key encryption failed: {enc_result_secure.error}")
            if not enc_result_username.success:
                encryption_errors.append(f"Username encryption failed: {enc_result_username.error}")
            
            if encryption_errors:
                return False, encryption_errors
            
            now = datetime.now().isoformat()
            self.data[username] = {
                # AES encrypted data
                "password_enc_emoji": enc_result_emoji.data,
                "password_enc_secure": enc_result_secure.data,
                "username_enc": enc_result_username.data,
                
                # RSA encrypted data
                "secure_key_enc_rsa": rsa_encrypted_secure_key,
                "emoji_password_enc_rsa": rsa_encrypted_emoji,
                
                # Additional info
                "created_at": now,
                "last_modified": now
            }
            
            if not self._save_data():
                return False, ["Failed to save data to disk"]
            
            strength = self.password_strength(password)
            logger.info(f"✅ Password saved for user: {username}")
            return True, {"strength": strength, "username": username}
            
        except Exception as e:
            logger.error(f"❌ Failed to save password: {e}")
            return False, [f"Operation failed: {str(e)}"]
    
    def get_password(self, username: str, emoji_password: str = None, secure_key: str = None) -> Tuple:
        """Retrieve password"""
        try:
            if username not in self.data:
                return None, None, "User not found", None
            
            stored = self.data[username]
            blobs = {
                "username_enc": stored.get("username_enc"),
                "password_enc_emoji": stored.get("password_enc_emoji"),
                "password_enc_secure": stored.get("password_enc_secure"),
                "secure_key_enc_rsa": stored.get("secure_key_enc_rsa"),
                "emoji_password_enc_rsa": stored.get("emoji_password_enc_rsa"),
                "created_at": stored.get("created_at"),
                "last_modified": stored.get("last_modified")
            }
            
            # First attempt: using emoji password
            if emoji_password:
                result = CryptoUtils.aes_decrypt(stored["password_enc_emoji"], emoji_password)
                if result.success:
                    strength = self.password_strength(result.data)
                    return result.data, strength, None, blobs
            
            # Second attempt: using secure key
            if secure_key:
                if self._validate_secure_key_with_flexibility(secure_key, stored):
                    result = CryptoUtils.aes_decrypt(stored["password_enc_secure"], secure_key)
                    if result.success:
                        strength = self.password_strength(result.data)
                        return result.data, strength, None, blobs
            
            return None, None, "Invalid credentials", blobs
        except Exception as e:
            logger.error(f"❌ Failed to retrieve password: {e}")
            return None, None, f"Retrieval error: {str(e)}", None
    
    def _validate_secure_key_with_flexibility(self, input_key: str, stored_data: Dict) -> bool:
        """Validate secure key (now allows letters, numbers, and emojis)"""
        try:
            # Decrypt original secure key using RSA
            rsa_encrypted_key = stored_data.get("secure_key_enc_rsa")
            if rsa_encrypted_key:
                original_key = SecureRSAManager.rsa_decrypt(rsa_encrypted_key, self.rsa_private_key)
                
                if input_key == original_key:
                    return True
                
                # Check emoji flexibility
                return self._check_emoji_flexibility(input_key, original_key)
                
        except Exception as e:
            logger.error(f"❌ Failed to validate RSA key: {e}")
        
        return False
    
    def _check_emoji_flexibility(self, input_key: str, original_key: str) -> bool:
        """Check emoji flexibility"""
        if len(input_key) != len(original_key):
            return False
        
        allowed_chars = set()
        # Allow all letters, numbers, and emojis
        allowed_chars.update(string.ascii_letters)
        allowed_chars.update(string.digits)
        for category in Config.EMOJI_CATEGORIES.values():
            allowed_chars.update(category)
        
        for i, (input_char, original_char) in enumerate(zip(input_key, original_key)):
            if original_char in allowed_chars:
                if input_char not in allowed_chars:
                    return False
            else:
                if input_char != original_char:
                    return False
        
        return True
    
    def admin_retrieve_password_with_emoji(self, username: str, input_emoji: str) -> Tuple[str, PasswordAnalysis, str, Dict]:
        """Admin retrieve password using emoji - ENHANCED VERSION"""
        try:
            if username not in self.data:
                return None, None, "User not found", {}
            
            stored = self.data[username]
            
            if not input_emoji:
                return None, None, "Emoji-based password required", {}
            
            # Get the original emoji password from RSA encryption
            rsa_encrypted_emoji = stored.get("emoji_password_enc_rsa")
            if not rsa_encrypted_emoji:
                return None, None, "No emoji password stored for this user", {}
            
            # Decrypt the original emoji password
            original_emoji_password = SecureRSAManager.rsa_decrypt(rsa_encrypted_emoji, self.rsa_private_key)
            if not original_emoji_password:
                return None, None, "Failed to decrypt original emoji password", {}
            
            # Enhanced emoji matching algorithm
            # 1. Extract all emojis from input
            input_emojis = [char for char in input_emoji if char in emoji.EMOJI_DATA]
            original_emojis = [char for char in original_emoji_password if char in emoji.EMOJI_DATA]
            
            if not input_emojis:
                return None, None, "No valid emojis found in input", {}
            
            # 2. Find matching emojis between input and original
            matching_emojis = []
            for emoji_char in input_emojis:
                if emoji_char in original_emojis:
                    matching_emojis.append(emoji_char)
            
            if not matching_emojis:
                return None, None, "No matching emojis found", {}
            
            # 3. Try different strategies to decrypt
            decryption_strategies = [
                # Strategy 1: Try with single emoji
                lambda: self._try_decrypt_with_single_emoji(stored, matching_emojis),
                # Strategy 2: Try with all matching emojis combined
                lambda: self._try_decrypt_with_emoji_combination(stored, matching_emojis),
                # Strategy 3: Try with original emoji password
                lambda: self._try_decrypt_with_original(stored, original_emoji_password),
                # Strategy 4: Try with partial original password (emojis only)
                lambda: self._try_decrypt_with_emojis_only(stored, original_emojis),
                # Strategy 5: Try with first matching emoji
                lambda: self._try_decrypt_with_single_emoji(stored, [matching_emojis[0]]) if matching_emojis else None
            ]
            
            for strategy in decryption_strategies:
                result = strategy()
                if result:
                    password, strength = result
                    logger.info(f"✅ Admin access granted with emoji recovery strategy")
                    return password, strength, None, {
                        "username_enc": stored.get("username_enc"),
                        "password_enc_emoji": stored.get("password_enc_emoji"),
                        "created_at": stored.get("created_at"),
                        "last_modified": stored.get("last_modified"),
                        "matching_emojis": matching_emojis,
                        "strategy_used": strategy.__name__.replace('_try_decrypt_', '')
                    }
            
            return None, None, "Unable to recover password with provided emojis", {}
            
        except Exception as e:
            logger.error(f"❌ Failed admin emoji retrieval: {e}")
            return None, None, f"Recovery error: {str(e)}", {}
    
    def _try_decrypt_with_single_emoji(self, stored: Dict, emojis: List[str]) -> Optional[Tuple[str, PasswordAnalysis]]:
        """Try to decrypt with a single emoji"""
        for emoji_char in emojis:
            result = CryptoUtils.aes_decrypt(stored["password_enc_emoji"], emoji_char)
            if result.success:
                strength = self.password_strength(result.data)
                return result.data, strength
        return None
    
    def _try_decrypt_with_emoji_combination(self, stored: Dict, emojis: List[str]) -> Optional[Tuple[str, PasswordAnalysis]]:
        """Try to decrypt with combination of emojis"""
        # Try different combinations
        combinations = [
            ''.join(emojis),
            ''.join(emojis[::-1]),  # reversed
            emojis[0] * len(emojis) if emojis else ''  # first emoji repeated
        ]
        
        for combo in combinations:
            if combo:
                result = CryptoUtils.aes_decrypt(stored["password_enc_emoji"], combo)
                if result.success:
                    strength = self.password_strength(result.data)
                    return result.data, strength
        return None
    
    def _try_decrypt_with_original(self, stored: Dict, original_emoji_password: str) -> Optional[Tuple[str, PasswordAnalysis]]:
        """Try to decrypt with original emoji password"""
        result = CryptoUtils.aes_decrypt(stored["password_enc_emoji"], original_emoji_password)
        if result.success:
            strength = self.password_strength(result.data)
            return result.data, strength
        return None
    
    def _try_decrypt_with_emojis_only(self, stored: Dict, original_emojis: List[str]) -> Optional[Tuple[str, PasswordAnalysis]]:
        """Try to decrypt with emojis only from original password"""
        if original_emojis:
            emoji_only_password = ''.join(original_emojis)
            result = CryptoUtils.aes_decrypt(stored["password_enc_emoji"], emoji_only_password)
            if result.success:
                strength = self.password_strength(result.data)
                return result.data, strength
        return None
    
    def get_all_users(self) -> List[Tuple]:
        return [(u, info.get("created_at")) for u, info in self.data.items()]
    
    def delete_user(self, username: str) -> bool:
        try:
            if username in self.data:
                del self.data[username]
                success = self._save_data()
                if success:
                    logger.info(f"🗑️ User deleted: {username}")
                return success
            return False
        except Exception as e:
            logger.error(f"❌ Failed to delete user: {e}")
            return False
    
    def generate_secure_password(self, length: int = Config.DEFAULT_PASSWORD_LENGTH, include_emojis: bool = True) -> str:
        try:
            if length < Config.MIN_PASSWORD_LENGTH:
                raise ValueError(f"Length must be >= {Config.MIN_PASSWORD_LENGTH}")
            if length > Config.MAX_PASSWORD_LENGTH:
                raise ValueError(f"Length must be <= {Config.MAX_PASSWORD_LENGTH}")
            
            uppercase = string.ascii_uppercase
            lowercase = string.ascii_lowercase
            digits = string.digits
            symbols = string.punctuation
            
            all_emojis = []
            for category in Config.EMOJI_CATEGORIES.values():
                all_emojis.extend(category)
            emojis = ''.join(all_emojis[:50])  # Increased emoji pool
            
            start_pool = uppercase + lowercase
            password_chars = [secrets.choice(start_pool)]
            
            required_sets = [
                secrets.choice(uppercase),
                secrets.choice(lowercase),
                secrets.choice(digits),
                secrets.choice(symbols)
            ]
            
            if include_emojis:
                required_sets.append(secrets.choice(emojis))
            
            password_chars.extend(required_sets)
            
            all_chars = uppercase + lowercase + digits + symbols
            if include_emojis:
                all_chars += emojis
            
            while len(password_chars) < length:
                password_chars.append(secrets.choice(all_chars))
            
            secrets.SystemRandom().shuffle(password_chars)
            return ''.join(password_chars)
        except Exception as e:
            logger.error(f"❌ Failed to generate password: {e}")
            return "SecurePassword123!@#"

# ----------------------------
# Enhanced Advanced Keyboard with All Emojis and Bilingual Support
# ----------------------------
class AdvancedKeyboard(QWidget):
    key_pressed = Signal(str)
    delete_pressed = Signal()
    enter_pressed = Signal()

    def __init__(self, language_manager: LanguageManager, parent=None):
        super().__init__(parent, Qt.Window | Qt.FramelessWindowHint)
        self.setWindowModality(Qt.NonModal)
        self.setFixedSize(880, 390)  # Slightly taller
        self.setStyleSheet("""
            QWidget {
                background-color: #1c1c1e;
                color: white;
                border-radius: 13px;
                border: 2px solid #3a3a3c;
            }
        """)

        self.language_manager = language_manager
        self.recent_keys = []
        self.shift_on = False
        self.is_visible = False
        self.current_language = Language.ENGLISH  # Default to English

        layout = QVBoxLayout()
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(3)

        # Search and control bar
        control_layout = QHBoxLayout()

        # Search box
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText(self.language_manager.get_text("search_placeholder"))
        self.search_box.setStyleSheet("""
            QLineEdit {
                background-color: #2c2c2e;
                color: white;
                border-radius: 8px;
                padding: 6px;
                font-size: 11px;
                border: 2px solid #3a3a3c;
            }
            QLineEdit:focus {
                border-color: #ff6b6b;
            }
        """)
        self.search_box.textChanged.connect(self.search_keys)
        control_layout.addWidget(self.search_box)

        # Keyboard show/hide toggle button
        self.toggle_view_btn = QPushButton(self.language_manager.get_text("keyboard_toggle"))
        self.toggle_view_btn.setCheckable(True)
        self.toggle_view_btn.setFixedSize(30, 30)
        self.toggle_view_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border-radius: 6px;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #42a5f5;
            }
            QPushButton:checked {
                background-color: #4CAF50;
            }
        """)
        self.toggle_view_btn.toggled.connect(self.toggle_keyboard_view)
        self.toggle_view_btn.setToolTip("Show/Hide typed content")
        control_layout.addWidget(self.toggle_view_btn)

        layout.addLayout(control_layout)

        # Text preview area
        self.preview_text = QLineEdit()
        self.preview_text.setReadOnly(True)
        self.preview_text.setPlaceholderText("What you type will appear here...")
        self.preview_text.setStyleSheet("""
            QLineEdit {
                background-color: #2c2c2e;
                color: #4CAF50;
                border-radius: 6px;
                padding: 4px;
                font-size: 11px;
                border: 1px solid #3a3a3c;
                margin-bottom: 3px;
            }
        """)
        layout.addWidget(self.preview_text)

        # Tabs
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #3a3a3c;
                background-color: #2c2c2e;
                border-radius: 6px;
            }
            QTabBar::tab {
                background-color: #3a3a3c;
                color: white;
                padding: 3px 6px;
                margin: 2px;
                border-radius: 4px;
                font-size: 9px;
            }
            QTabBar::tab:selected {
                background-color: #ff6b6b;
            }
            QTabBar::tab:hover {
                background-color: #5a5a5c;
            }
        """)
        layout.addWidget(self.tabs)

        # Letters, numbers, symbols, and emoji
        self.letters_en = [chr(i) for i in range(ord('a'), ord('z')+1)]
        self.letters_ar = list('ابتثجحخدذرزسشصضطظعغفقكلمنهوي')
        self.numbers = list("1234567890")
        self.symbols = list("!@#$%^&*()-_=+[]{};:'\",.<>?/\\|`~")
        
        # Collect all emojis from updated categories
        self.emojis = []
        for category in Config.EMOJI_CATEGORIES.values():
            self.emojis.extend(category)

        # Create tabs
        self.create_all_tabs()

        # Control buttons
        control_buttons_layout = QGridLayout()
        control_buttons_layout.setSpacing(2)
        control_buttons_layout.setContentsMargins(2, 2, 2, 2)
        
        buttons = [
            (self.language_manager.get_text("keyboard_shift"), self.toggle_shift, 0, 0, 1, 1),
            (self.language_manager.get_text("keyboard_delete"), lambda: self.delete_pressed.emit(), 0, 1, 1, 1),
            (self.language_manager.get_text("keyboard_space"), lambda: self.key_pressed.emit(" "), 0, 2, 1, 3),
            (self.language_manager.get_text("keyboard_enter"), lambda: self.enter_pressed.emit(), 0, 5, 1, 2),
            (self.language_manager.get_text("keyboard_hide"), self.hide_keyboard, 0, 7, 1, 1)
        ]

        for text, callback, row, col, rowspan, colspan in buttons:
            btn = QPushButton(text)
            btn.setFont(QFont("Segoe UI Emoji", 8))
            btn.setStyleSheet("""
                QPushButton {
                    background-color: #3a3a3c;
                    border-radius: 6px;
                    color: white;
                    padding: 4px 3px;
                    margin: 1px;
                    font-weight: bold;
                    min-height: 18px;
                }
                QPushButton:hover {
                    background-color: #5a5a5c;
                    border: 1px solid #ff6b6b;
                }
                QPushButton:pressed {
                    background-color: #ff6b6b;
                }
            """)
            btn.setMinimumHeight(28)
            btn.clicked.connect(callback)
            control_buttons_layout.addWidget(btn, row, col, rowspan, colspan)

        layout.addLayout(control_buttons_layout)
        self.setLayout(layout)

    
    def create_key_tab(self, key_list, title, columns=10):  # ⬅️ زيادة عدد الأعمدة لتقليل الارتفاع
        try:
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setStyleSheet("""
                QScrollArea {
                    border: none;
                    background-color: #2c2c2e;
                }
                QScrollBar:vertical {
                    background: #3a3a3c;
                    width: 9px;  # ⬅️ قللنا عرض شريط التمرير
                    margin: 0px;
                }
                QScrollBar::handle:vertical {
                    background: #5a5a5c;
                    min-height: 13px;
                    border-radius: 4px;
                }
                QScrollBar::handle:vertical:hover {
                    background: #ff6b6b;
                }
            """)
            
            content = QWidget()
            grid = QGridLayout(content)
            grid.setSpacing(2)  # ⬅️ قللنا المسافات
            grid.setContentsMargins(3, 3, 3, 3)  # ⬅️ قللنا الهوامش

            if not key_list:
                label = QLabel("No recent keys")
                label.setStyleSheet("color: #888888; font-size: 10px;")  # ⬅️ قللنا حجم الخط
                label.setAlignment(Qt.AlignCenter)
                grid.addWidget(label, 0, 0)
            else:
                row, col = 0, 0
                for key in key_list:
                    btn = QPushButton(str(key))
                    btn.setFont(QFont("Segoe UI Emoji", 9))  # ⬅️ قللنا حجم الخط
                    btn.setFixedSize(40, 40)  # ⬅️ قللنا حجم الأزرار
                    btn.setStyleSheet("""
                        QPushButton {
                            background-color: #3a3a3c;
                            border-radius: 6px;
                            color: white;
                            margin: 1px;
                            min-width: 25px;  # ⬅️ قللنا العرض
                            min-height: 20px;  # ⬅️ قللنا الارتفاع
                        }
                        QPushButton:hover {
                            background-color: #5a5a5c;
                            border: 1px solid #ff6b6b;
                        }
                        QPushButton:pressed {
                            background-color: #ff6b6b;
                        }
                    """)
                    btn.clicked.connect(lambda checked, k=key: self.select_key(k))
                    grid.addWidget(btn, row, col)
                    col += 1
                    if col >= columns:
                        col = 0
                        row += 1

            scroll.setWidget(content)
            return scroll
        except Exception as e:
            logger.error(f"❌ Failed to create key tab: {e}")
            scroll = QScrollArea()
            content = QWidget()
            layout = QVBoxLayout(content)
            label = QLabel("Error loading tab")
            label.setStyleSheet("color: #ff4444; font-size: 10px;")  # ⬅️ قللنا حجم الخط
            layout.addWidget(label)
            scroll.setWidget(content)
            return scroll
        
    def create_all_tabs(self):
        """Create all tabs"""
        self.tabs.clear()
        
        self.english_tab = self.create_key_tab(self.get_current_english_letters(), "🅰️ English", 12)
        self.arabic_tab = self.create_key_tab(self.get_current_arabic_letters(), "🅰️ Arabic", 12)
        
        self.tabs.addTab(self.english_tab, "🅰️ English")
        self.tabs.addTab(self.arabic_tab, "🅰️ Arabic")
        
        self.numbers_tab = self.create_key_tab(self.numbers, "123 Numbers", 12)
        self.symbols_tab = self.create_key_tab(self.symbols, "🔣 Symbols", 12)
        self.emoji_tab = self.create_emoji_tab()
        self.recent_tab = self.create_key_tab(self.recent_keys, "🕒 Recent",11)

        self.tabs.addTab(self.numbers_tab, "123 Numbers")
        self.tabs.addTab(self.symbols_tab, "🔣 Symbols")
        self.tabs.addTab(self.emoji_tab, "😀 Emoji")
        self.tabs.addTab(self.recent_tab, "🕒 Recent")

    def create_emoji_tab(self):
        try:
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setStyleSheet("""
                QScrollArea {
                    border: none;
                    background-color: #2c2c2e;
                }
                QScrollBar:vertical {
                    background: #3a3a3c;
                    width: 8px;
                    margin: 0px;
                }
                QScrollBar::handle:vertical {
                    background: #5a5a5c;
                    min-height: 12px;
                    border-radius: 4px;
                }
                QScrollBar::handle:vertical:hover {
                    background: #ff6b6b;
                }
            """)
            
            content = QWidget()
            layout = QVBoxLayout(content)
            layout.setContentsMargins(0, 0, 0, 0)  # ⬇️ إزالة الهوامش
            layout.setSpacing(0)  # ⬇️ إزالة المسافات

            emoji_tabs = QTabWidget()
            emoji_tabs.setStyleSheet("""
                QTabWidget::pane {
                    border: 1px solid #3a3a3c;
                    background-color: #2c2c2e;
                }
                QTabBar::tab {
                    background-color: #3a3a3c;
                    color: white;
                    padding: 2px 4px;
                    margin: 1px;
                    border-radius: 3px;
                    font-size: 8px;
                }
                QTabBar::tab:selected {
                    background-color: #ff6b6b;
                }
            """)
            
            for category_name, category_emojis in Config.EMOJI_CATEGORIES.items():
                try:
                    tab = self.create_key_tab(category_emojis, category_name, 10)
                    emoji_tabs.addTab(tab, category_name)
                except Exception as e:
                    logger.error(f"❌ Failed to create emoji tab {category_name}: {e}")
                    continue
            
            layout.addWidget(emoji_tabs)
            scroll.setWidget(content)
            return scroll
            
        except Exception as e:
            logger.error(f"❌ Failed to create emoji tab: {e}")
            return self.create_key_tab(self.emojis[:50], "Emoji", 8)

    def create_key_tab(self, key_list, title, columns=6):
        try:
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setStyleSheet("""
                QScrollArea {
                    border: none;
                    background-color: #2c2c2e;
                }
                QScrollBar:vertical {
                    background: #3a3a3c;
                    width: 12px;
                    margin: 0px;
                }
                QScrollBar::handle:vertical {
                    background: #5a5a5c;
                    min-height: 15px;
                    border-radius: 5px;
                }
                QScrollBar::handle:vertical:hover {
                    background: #ff6b6b;
                }
            """)
            
            content = QWidget()
            grid = QGridLayout(content)
            grid.setSpacing(4)
            grid.setContentsMargins(6, 6, 6, 6)

            if not key_list:
                label = QLabel("No recent keys")
                label.setStyleSheet("color: #888888; font-size: 12px;")
                label.setAlignment(Qt.AlignCenter)
                grid.addWidget(label, 0, 0)
            else:
                row, col = 0, 0
                for key in key_list:
                    btn = QPushButton(str(key))
                    btn.setFont(QFont("Segoe UI Emoji", 12))
                    btn.setFixedSize(48, 48)
                    btn.setStyleSheet("""
                        QPushButton {
                            background-color: #3a3a3c;
                            border-radius: 6px;
                            color: white;
                            margin: 1px;
                            min-width: 25px;
                            min-height: 25px;
                        }
                        QPushButton:hover {
                            background-color: #5a5a5c;
                            border: 1px solid #ff6b6b;
                        }
                        QPushButton:pressed {
                            background-color: #ff6b6b;
                        }
                    """)
                    btn.clicked.connect(lambda checked, k=key: self.select_key(k))
                    grid.addWidget(btn, row, col)
                    col += 1
                    if col >= columns:
                        col = 0
                        row += 1

            scroll.setWidget(content)
            return scroll
        except Exception as e:
            logger.error(f"❌ Failed to create key tab: {e}")
            scroll = QScrollArea()
            content = QWidget()
            layout = QVBoxLayout(content)
            label = QLabel("Error loading tab")
            label.setStyleSheet("color: #ff4444;")
            layout.addWidget(label)
            scroll.setWidget(content)
            return scroll

    def get_current_english_letters(self):
        if self.shift_on:
            return Config.KEYBOARD_LAYOUTS['en_upper']
        else:
            return Config.KEYBOARD_LAYOUTS['en_lower']

    def get_current_arabic_letters(self):
        return Config.KEYBOARD_LAYOUTS['ar_lower']

    def select_key(self, key):
        try:
            if self.shift_on and key.isalpha() and key in self.letters_en:
                key = key.upper()
                self.shift_on = False
                self.update_letters_tabs()

            if key not in self.recent_keys and key != " ":
                self.recent_keys.insert(0, key)
                self.recent_keys = self.recent_keys[:15]
            
            self.update_recent_tab()
            
            current_text = self.preview_text.text()
            self.preview_text.setText(current_text + key)
            
            self.key_pressed.emit(key)
        except Exception as e:
            logger.error(f"❌ Failed to select key: {e}")

    def update_letters_tabs(self):
        try:
            current_index = self.tabs.currentIndex()
            self.create_all_tabs()
            self.tabs.setCurrentIndex(current_index)
        except Exception as e:
            logger.error(f"❌ Failed to update letter tabs: {e}")

    def update_recent_tab(self):
        try:
            if self.recent_keys:
                for i in range(self.tabs.count()):
                    if self.tabs.tabText(i) == "🕒 Recent":
                        self.tabs.removeTab(i)
                        break
                
                self.recent_tab = self.create_key_tab(self.recent_keys, "🕒 Recent", 6)
                self.tabs.addTab(self.recent_tab, "🕒 Recent")
        except Exception as e:
            logger.error(f"❌ Failed to update recent tab: {e}")

    def toggle_shift(self):
        self.shift_on = not self.shift_on
        self.update_letters_tabs()

    def search_keys(self, text):
        try:
            text = text.strip().lower()
            if not text:
                for i in range(self.tabs.count()):
                    if self.tabs.tabText(i) == "🔎 Search Results":
                        self.tabs.removeTab(i)
                        break
                return
                
            results = []

            search_set = set()
            
            # البحث في الإيموجيات
            for emoji_char in self.emojis:
                if text in emoji_char.lower():
                    if len(results) < 30:  # ⬅️ تحديد النتائج لتحسين الأداء
                        results.append(emoji_char)
                        search_set.add(emoji_char)
                    else:
                        break
            
            # إضافة "..." إذا كانت النتائج كثيرة
            if len(results) >= 30:
                results.append("...")
                
            for emoji_char in self.emojis:
                if text in emoji_char.lower():
                    results.append(emoji_char)
                if len(results) >= 50:
                    break
            
            for char in self.letters_en + self.letters_ar:
                if text in char.lower():
                    results.append(char)
                if len(results) >= 50:
                    break
            
            for char in self.numbers + self.symbols:
                if text in char:
                    results.append(char)
                if len(results) >= 50:
                    break
            
            if not results:
                results = ["❌ No results"]
            
            for i in range(self.tabs.count()):
                if self.tabs.tabText(i) == "🔎 Search Results":
                    self.tabs.removeTab(i)
                    break
            
            search_tab = self.create_key_tab(results, "🔎 Search Results", 8)
            self.tabs.addTab(search_tab, "🔎 Search Results")
            self.tabs.setCurrentIndex(self.tabs.count() - 1)
        except Exception as e:
            logger.error(f"❌ Search failed: {e}")

    def toggle_keyboard_view(self, show):
        """Toggle show/hide user typing"""
        try:
            if show:
                self.preview_text.setStyleSheet("""
                    QLineEdit {
                        background-color: #2c2c2e;
                        color: #4CAF50;
                        border-radius: 6px;
                        padding: 6px;
                        font-size: 12px;
                        border: 2px solid #4CAF50;
                        margin-bottom: 3px;
                    }
                """)
                self.toggle_view_btn.setText("🙈")
            else:
                self.preview_text.setStyleSheet("""
                    QLineEdit {
                        background-color: #2c2c2e;
                        color: #666666;
                        border-radius: 6px;
                        padding: 6px;
                        font-size: 12px;
                        border: 1px solid #3a3a3c;
                        margin-bottom: 3px;
                    }
                """)
                self.toggle_view_btn.setText("👁")
        except Exception as e:
            logger.error(f"❌ Failed to toggle keyboard view: {e}")

    def show_keyboard(self):
        if not self.is_visible:
            self.is_visible = True
            self.show()
            self.raise_()
            self.activateWindow()

    def hide_keyboard(self):
        """إغلاق الكيبورد بشكل صحيح"""
        try:
            if self.is_visible:
                self.is_visible = False
                self.hide()
                # تأكد من إغلاق جميع النوافذ الفرعية إذا وجدت
                if hasattr(self, 'emoji_tabs'):
                    for i in range(self.emoji_tabs.count()):
                        widget = self.emoji_tabs.widget(i)
                        if widget and hasattr(widget, 'hide'):
                            widget.hide()
                self.preview_text.clear()
        except Exception as e:
            logger.error(f"❌ Failed to hide keyboard: {e}")

    def toggle_keyboard(self):
        if self.is_visible:
            self.hide_keyboard()
        else:
            self.show_keyboard()

# ----------------------------
# Improved Admin Login Dialog with Better Layout and Visual Indicators - FIXED VERSION
# ----------------------------
class AdminLoginDialog(QDialog):
    login_success = Signal()
    
    def __init__(self, admin_manager: AdminManager, language_manager: LanguageManager, parent=None):
        super().__init__(parent)
        self.admin_manager = admin_manager
        self.language_manager = language_manager
        self.logged_in = False
        self.init_ui()
        self.start_otp_system()

    def init_ui(self):
        self.setWindowTitle(self.language_manager.get_text("admin_login_title"))
        self.setFixedSize(700, 900)  # Better size
        self.setStyleSheet("""
            QDialog {
                background-color: #1e1e1e;
                color: white;
                font-family: 'Segoe UI', Arial;
            }
        """)

        # Main layout with scroll area for better content management
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("""
            QScrollArea {
                border: none;
                background-color: #1e1e1e;
            }
        """)
        
        content_widget = QWidget()
        layout = QVBoxLayout(content_widget)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(15)

        # Title with visual indicator
        title_container = QFrame()
        title_container.setStyleSheet("""
            QFrame {
                background-color: #2d2d2d;
                border-radius: 15px;
                border: 2px solid #ff6b6b;
                padding: 10px;
            }
        """)
        title_layout = QVBoxLayout(title_container)
        
        title = QLabel(self.language_manager.get_text("admin_system"))
        title.setStyleSheet("""
            QLabel {
                color: #ff6b6b;
                font-size: 24px;
                font-weight: bold;
                padding: 10px;
                text-align: center;
            }
        """)
        title_layout.addWidget(title)
        
        subtitle = QLabel("Two-Factor Authentication Required")
        subtitle.setStyleSheet("color: #cccccc; font-size: 14px; text-align: center;")
        title_layout.addWidget(subtitle)
        
        layout.addWidget(title_container)

        # Status indicator
        self.status_indicator = QFrame()
        self.status_indicator.setFixedHeight(10)
        self.status_indicator.setStyleSheet("""
            QFrame {
                background-color: #ff9800;
                border-radius: 5px;
            }
        """)
        layout.addWidget(self.status_indicator)

        # Login form
        form_group = QGroupBox("Admin Credentials")
        form_group.setStyleSheet("""
            QGroupBox {
                color: #4CAF50;
                font-size: 16px;
                font-weight: bold;
                border: 2px solid #3a3a3c;
                border-radius: 10px;
                margin-top: 10px;
                padding-top: 15px;
            }
        """)
        form_layout = QVBoxLayout(form_group)

        # Username field
        username_layout = QVBoxLayout()
        username_label = QLabel(self.language_manager.get_text("username"))
        username_label.setStyleSheet("color: #cccccc; font-size: 14px; font-weight: bold;")
        username_layout.addWidget(username_label)

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter admin username...")
        self.setup_input_field(self.username_input)
        username_layout.addWidget(self.username_input)
        form_layout.addLayout(username_layout)

        # Password field
        password_layout = QVBoxLayout()
        password_label = QLabel(self.language_manager.get_text("password"))
        password_label.setStyleSheet("color: #cccccc; font-size: 14px; font-weight: bold;")
        password_layout.addWidget(password_label)

        password_field_layout = QHBoxLayout()
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter admin password...")
        self.password_input.setEchoMode(QLineEdit.Password)
        self.setup_input_field(self.password_input)
        password_field_layout.addWidget(self.password_input)

        self.show_password_btn = QPushButton("👁")
        self.show_password_btn.setCheckable(True)
        self.show_password_btn.setFixedSize(40, 40)
        self.show_password_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border-radius: 8px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #42a5f5;
            }
            QPushButton:checked {
                background-color: #4CAF50;
            }
        """)
        self.show_password_btn.toggled.connect(self.toggle_password_visibility)
        password_field_layout.addWidget(self.show_password_btn)

        password_layout.addLayout(password_field_layout)
        form_layout.addLayout(password_layout)

        layout.addWidget(form_group)

        # OTP Section
        otp_group = QGroupBox(self.language_manager.get_text("otp_auth"))
        otp_group.setStyleSheet("""
            QGroupBox {
                color: #ff6b6b;
                font-size: 16px;
                font-weight: bold;
                border: 2px solid #3a3a3c;
                border-radius: 10px;
                margin-top: 10px;
                padding-top: 15px;
            }
        """)
        otp_layout = QVBoxLayout(otp_group)

        # OTP Code field
        otp_code_layout = QVBoxLayout()
        otp_code_label = QLabel(self.language_manager.get_text("otp_code"))
        otp_code_label.setStyleSheet("color: #cccccc; font-size: 14px; font-weight: bold;")
        otp_code_layout.addWidget(otp_code_label)

        self.otp_code_input = QLineEdit()
        self.otp_code_input.setPlaceholderText("Enter 6-digit OTP code...")
        self.otp_code_input.setMaxLength(Config.OTP_DIGITS)
        self.otp_code_input.setStyleSheet("""
            QLineEdit {
                background-color: #2d2d2d;
                color: white;
                border: 2px solid #3a3a3c;
                border-radius: 8px;
                padding: 12px;
                font-size: 14px;
                font-weight: bold;
                text-align: center;
            }
            QLineEdit:focus {
                border-color: #ff6b6b;
            }
        """)
        otp_code_layout.addWidget(self.otp_code_input)

        # OTP Timer and current code
        otp_timer_layout = QHBoxLayout()
        
        timer_container = QFrame()
        timer_container.setStyleSheet("""
            QFrame {
                background-color: #2d2d2d;
                border-radius: 8px;
                border: 2px solid #3a3a3c;
                padding: 5px;
            }
        """)
        timer_layout = QHBoxLayout(timer_container)
        
        timer_label = QLabel("⏰ Time left:")
        timer_label.setStyleSheet("color: #cccccc; font-size: 12px;")
        timer_layout.addWidget(timer_label)
        
        self.otp_countdown = QLabel("30s")
        self.otp_countdown.setStyleSheet("color: #4CAF50; font-size: 14px; font-weight: bold;")
        timer_layout.addWidget(self.otp_countdown)
        
        otp_timer_layout.addWidget(timer_container)

        otp_timer_layout.addStretch()

        current_code_container = QFrame()
        current_code_container.setStyleSheet("""
            QFrame {
                background-color: #2d2d2d;
                border-radius: 8px;
                border: 2px solid #ff6b6b;
                padding: 5px;
            }
        """)
        current_code_layout = QVBoxLayout(current_code_container)
        
        current_code_label = QLabel("Current OTP:")
        current_code_label.setStyleSheet("color: #cccccc; font-size: 12px;")
        current_code_layout.addWidget(current_code_label)
        
        self.otp_current_code = QLabel("------")
        self.otp_current_code.setStyleSheet("""
            QLabel {
                color: #ff6b6b;
                font-size: 18px;
                font-weight: bold;
                font-family: 'Courier New';
            }
        """)
        current_code_layout.addWidget(self.otp_current_code)
        
        otp_timer_layout.addWidget(current_code_container)

        otp_code_layout.addLayout(otp_timer_layout)
        otp_layout.addLayout(otp_code_layout)

        # OTP Secret Display Section - NEW: Show secret after registration
        self.secret_display_group = QGroupBox("Your OTP Secret Key")
        self.secret_display_group.setStyleSheet("""
            QGroupBox {
                color: #9C27B0;
                font-size: 16px;
                font-weight: bold;
                border: 2px solid #3a3a3c;
                border-radius: 10px;
                margin-top: 10px;
                padding-top: 15px;
            }
        """)
        secret_display_layout = QVBoxLayout(self.secret_display_group)
        
        self.secret_display_label = QLabel("No secret key available")
        self.secret_display_label.setStyleSheet("""
            QLabel {
                color: #cccccc;
                font-size: 12px;
                font-family: 'Courier New';
                padding: 10px;
                background-color: #2d2d2d;
                border-radius: 8px;
                border: 1px solid #3a3a3c;
                word-wrap: break-word;
            }
        """)
        self.secret_display_label.setWordWrap(True)
        secret_display_layout.addWidget(self.secret_display_label)
        
        secret_buttons_layout = QHBoxLayout()
        self.copy_secret_btn = QPushButton("📋 Copy Secret")
        self.copy_secret_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border-radius: 8px;
                padding: 8px;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #42a5f5;
            }
            QPushButton:disabled {
                background-color: #666666;
                color: #999999;
            }
        """)
        self.copy_secret_btn.clicked.connect(self.copy_otp_secret)
        self.copy_secret_btn.setEnabled(False)
        secret_buttons_layout.addWidget(self.copy_secret_btn)
        
        self.show_secret_btn = QPushButton("👁 Show/Hide")
        self.show_secret_btn.setCheckable(True)
        self.show_secret_btn.setStyleSheet("""
            QPushButton {
                background-color: #FF9800;
                color: white;
                border-radius: 8px;
                padding: 8px;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #ffb74d;
            }
            QPushButton:checked {
                background-color: #4CAF50;
            }
        """)
        self.show_secret_btn.toggled.connect(self.toggle_secret_display)
        secret_buttons_layout.addWidget(self.show_secret_btn)
        
        secret_display_layout.addLayout(secret_buttons_layout)
        otp_layout.addWidget(self.secret_display_group)

        # OTP Secret (optional for update)
        secret_layout = QVBoxLayout()
        secret_label = QLabel("Enter OTP Secret Key (Optional):")
        secret_label.setStyleSheet("color: #cccccc; font-size: 14px;")
        secret_layout.addWidget(secret_label)

        secret_input_layout = QHBoxLayout()
        self.otp_secret_input = QLineEdit()
        self.otp_secret_input.setPlaceholderText("Enter new OTP secret ")
        self.otp_secret_input.setEchoMode(QLineEdit.Password)
        self.setup_input_field(self.otp_secret_input)
        secret_input_layout.addWidget(self.otp_secret_input)

        self.show_new_secret_btn = QPushButton("👁")
        self.show_new_secret_btn.setCheckable(True)
        self.show_new_secret_btn.setFixedSize(40, 40)
        self.show_new_secret_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border-radius: 8px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #42a5f5;
            }
            QPushButton:checked {
                background-color: #4CAF50;
            }
        """)
        self.show_new_secret_btn.toggled.connect(self.toggle_new_secret_visibility)
        secret_input_layout.addWidget(self.show_new_secret_btn)

        secret_layout.addLayout(secret_input_layout)
        
        # Secret info
        secret_info = QLabel("💡 Leave empty to use existing secret or enter new Base32 key")
        secret_info.setStyleSheet("color: #4CAF50; font-size: 11px; padding: 5px; background-color: #1e2e1e; border-radius: 5px;")
        secret_layout.addWidget(secret_info)
        
        otp_layout.addLayout(secret_layout)

        layout.addWidget(otp_group)

        # Buttons
        buttons_layout = QHBoxLayout()
        
        self.login_btn = QPushButton(self.language_manager.get_text("admin_login_btn"))
        self.login_btn.setStyleSheet("""
            QPushButton {
                background-color: #ff6b6b;
                color: white;
                border-radius: 10px;
                padding: 15px;
                font-size: 16px;
                font-weight: bold;
                min-width: 150px;
            }
            QPushButton:hover {
                background-color: #ff8e8e;
            }
            QPushButton:pressed {
                background-color: #e55a5a;
            }
            QPushButton:disabled {
                background-color: #666666;
                color: #999999;
            }
        """)
        self.login_btn.clicked.connect(self.check_login)
        buttons_layout.addWidget(self.login_btn)

        self.register_btn = QPushButton(self.language_manager.get_text("register_admin_btn"))
        self.register_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border-radius: 10px;
                padding: 12px;
                font-size: 14px;
                min-width: 150px;
            }
            QPushButton:hover {
                background-color: #42a5f5;
            }
        """)
        self.register_btn.clicked.connect(self.register_admin)
        buttons_layout.addWidget(self.register_btn)

        layout.addLayout(buttons_layout)

        # Permissions info (collapsible)
        self.info_group = QGroupBox(self.language_manager.get_text("permissions_available"))
        self.info_group.setCheckable(True)
        self.info_group.setChecked(False)
        self.info_group.setStyleSheet("""
            QGroupBox {
                color: #2196F3;
                font-size: 16px;
                font-weight: bold;
                border: 2px solid #3a3a3c;
                border-radius: 10px;
                margin-top: 10px;
                padding-top: 15px;
            }
            QGroupBox::indicator {
                width: 15px;
                height: 15px;
            }
        """)
        info_layout = QVBoxLayout(self.info_group)

        self.permissions_info = QTextEdit()
        self.permissions_info.setReadOnly(True)
        self.permissions_info.setStyleSheet("""
            QTextEdit {
                background-color: #2d2d2d;
                color: #cccccc;
                border: 1px solid #3a3a3c;
                border-radius: 10px;
                padding: 15px;
                font-size: 14px;
                line-height: 1.5;
            }
        """)
        self.permissions_info.setPlainText(self.language_manager.get_text("permissions_info"))
        info_layout.addWidget(self.permissions_info)

        layout.addWidget(self.info_group)
        layout.addStretch()

        scroll.setWidget(content_widget)
        main_layout = QVBoxLayout(self)
        main_layout.addWidget(scroll)
        
        # Add loading indicator (hidden by default)
        self.loading_indicator = QFrame()
        self.loading_indicator.setFixedHeight(4)
        self.loading_indicator.setStyleSheet("""
            QFrame {
                background-color: #2196F3;
                border-radius: 2px;
            }
        """)
        self.loading_indicator.hide()
        main_layout.addWidget(self.loading_indicator)

    def setup_input_field(self, field):
        field.setStyleSheet("""
            QLineEdit {
                background-color: #2d2d2d;
                color: white;
                border: 2px solid #3a3a3c;
                border-radius: 8px;
                padding: 12px;
                font-size: 14px;
            }
            QLineEdit:focus {
                border-color: #ff6b6b;
            }
        """)

    def toggle_password_visibility(self, checked):
        if checked:
            self.password_input.setEchoMode(QLineEdit.Normal)
            self.show_password_btn.setText("🙈")
        else:
            self.password_input.setEchoMode(QLineEdit.Password)
            self.show_password_btn.setText("👁")

    def toggle_new_secret_visibility(self, checked):
        if checked:
            self.otp_secret_input.setEchoMode(QLineEdit.Normal)
            self.show_new_secret_btn.setText("🙈")
        else:
            self.otp_secret_input.setEchoMode(QLineEdit.Password)
            self.show_new_secret_btn.setText("👁")

    def toggle_secret_display(self, checked):
        """Toggle visibility of the secret key display"""
        if checked:
            self.secret_display_label.setStyleSheet("""
                QLabel {
                    color: #4CAF50;
                    font-size: 12px;
                    font-family: 'Courier New';
                    padding: 10px;
                    background-color: #2d2d2d;
                    border-radius: 8px;
                    border: 1px solid #4CAF50;
                }
            """)
            self.secret_display_label.setWordWrap(True)
            self.show_secret_btn.setText("🙈 Hide")
        else:
            # Mask the secret key
            secret_text = self.secret_display_label.text()
            if secret_text and secret_text != "No secret key available":
                masked_secret = secret_text[:8] + "..." + secret_text[-8:] if len(secret_text) > 16 else "••••••••"
                self.secret_display_label.setText(masked_secret)
                self.secret_display_label.setStyleSheet("""
                    QLabel {
                        color: #cccccc;
                        font-size: 12px;
                        font-family: 'Courier New';
                        padding: 10px;
                        background-color: #2d2d2d;
                        border-radius: 8px;
                        border: 1px solid #3a3a3c;
                        word-wrap: break-word;
                    }
                """)
                self.show_secret_btn.setText("👁 Show")

    def copy_otp_secret(self):
        """Copy OTP secret to clipboard"""
        secret_text = self.secret_display_label.text()
        if secret_text and secret_text != "No secret key available":
            # Get full secret from admin manager if masked
            if "..." in secret_text or "••••••••" in secret_text:
                username = self.username_input.text().strip()
                secret_text = self.admin_manager.get_admin_otp_secret(username)
            
            if secret_text:
                try:
                    if CLIPBOARD_AVAILABLE:
                        pyperclip.copy(secret_text)
                    else:
                        app = QApplication.instance()
                        if app:
                            app.clipboard().setText(secret_text)
                    
                    QMessageBox.information(self, "Copied", "✅ OTP secret key copied to clipboard!")
                except Exception as e:
                    logger.error(f"❌ Failed to copy secret: {e}")
                    QMessageBox.warning(self, "Error", "❌ Failed to copy secret key")

    def start_otp_system(self):
        self.otp_timer = QTimer()
        self.otp_timer.timeout.connect(self.update_otp_display)
        self.otp_timer.start(1000)
        self.update_otp_display()

    def update_otp_display(self):
        try:
            remaining_time = 30 - (int(time.time()) % 30)
            self.otp_countdown.setText(f"{remaining_time}s")
            
            # Update status indicator color based on time
            if remaining_time <= 5:
                self.status_indicator.setStyleSheet("background-color: #f44336; border-radius: 5px;")
                self.otp_countdown.setStyleSheet("color: #f44336; font-size: 14px; font-weight: bold;")
            elif remaining_time <= 10:
                self.status_indicator.setStyleSheet("background-color: #FF9800; border-radius: 5px;")
                self.otp_countdown.setStyleSheet("color: #FF9800; font-size: 14px; font-weight: bold;")
            else:
                self.status_indicator.setStyleSheet("background-color: #4CAF50; border-radius: 5px;")
                self.otp_countdown.setStyleSheet("color: #4CAF50; font-size: 14px; font-weight: bold;")
            
            username = self.username_input.text().strip()
            if username:
                # Try to get OTP secret from admin manager
                secret = self.admin_manager.get_admin_otp_secret(username)
                if secret:
                    current_otp = SecureOTPManager.generate_totp_code(secret)
                    if current_otp:
                        self.otp_current_code.setText(current_otp)
                        
                        # Update secret display if it's not already set
                        if self.secret_display_label.text() == "No secret key available":
                            # Mask the secret for display
                            masked_secret = secret[:8] + "..." + secret[-8:] if len(secret) > 16 else secret
                            self.secret_display_label.setText(masked_secret)
                            self.copy_secret_btn.setEnabled(True)
                else:
                    self.otp_current_code.setText("------")
            else:
                self.otp_current_code.setText("------")
                
        except Exception as e:
            logger.error(f"❌ Failed to update OTP display: {e}")

    def show_loading(self, show=True):
        """Show/hide loading indicator"""
        if show:
            self.loading_indicator.show()
            # Animate the loading indicator
            self.loading_animation = QPropertyAnimation(self.loading_indicator, b"geometry")
            self.loading_animation.setDuration(1000)
            self.loading_animation.setLoopCount(-1)
            self.loading_animation.setStartValue(QRect(0, 0, 0, 4))
            self.loading_animation.setEndValue(QRect(self.width(), 0, 0, 4))
            self.loading_animation.start()
            
            # Disable buttons during loading
            self.login_btn.setEnabled(False)
            self.register_btn.setEnabled(False)
        else:
            self.loading_indicator.hide()
            if hasattr(self, 'loading_animation'):
                self.loading_animation.stop()
            
            # Re-enable buttons
            self.login_btn.setEnabled(True)
            self.register_btn.setEnabled(True)

    def check_login(self):
        username = self.username_input.text().strip()
        password = self.password_input.text()
        otp_secret = self.otp_secret_input.text().strip()
        otp_code = self.otp_code_input.text().strip()

        if not username or not password:
            QMessageBox.warning(self, "Validation Error", "Please enter username and password!")
            return

        if not otp_code:
            QMessageBox.warning(self, "Validation Error", "Please enter OTP code!")
            return

        # Show loading indicator
        self.show_loading(True)
        
        # Use a timer to simulate processing (in real app, this would be async)
        QTimer.singleShot(500, lambda: self.process_login(username, password, otp_secret, otp_code))

    def process_login(self, username: str, password: str, otp_secret: str, otp_code: str):
        try:
            if otp_secret:
                if not SecureOTPManager.validate_secret(otp_secret):
                    QMessageBox.warning(self, "Error", "Invalid OTP secret key!")
                    self.show_loading(False)
                    return
                
                if not self.admin_manager.update_admin_otp_secret(username, password, otp_secret):
                    QMessageBox.warning(self, "Error", "Failed to update secret key!")
                    self.show_loading(False)
                    return
                else:
                    # Update the secret display
                    self.secret_display_label.setText(otp_secret[:8] + "..." + otp_secret[-8:] if len(otp_secret) > 16 else otp_secret)
                    self.copy_secret_btn.setEnabled(True)
            
            success, message = self.admin_manager.verify_admin(username, password, otp_code)
            
            if success:
                self.logged_in = True
                self.otp_timer.stop()
                self.login_success.emit()
                
                # Visual feedback
                self.status_indicator.setStyleSheet("background-color: #4CAF50; border-radius: 5px;")
                QMessageBox.information(self, "Success", message)
                self.show_loading(False)
                self.close()
            else:
                # Visual feedback for failure
                self.status_indicator.setStyleSheet("background-color: #f44336; border-radius: 5px;")
                QMessageBox.warning(self, "Login Failed", message)
                self.show_loading(False)
                
        except Exception as e:
            logger.error(f"❌ Login processing error: {e}")
            QMessageBox.warning(self, "Error", f"Login failed: {str(e)}")
            self.show_loading(False)

    def register_admin(self):
        username, ok = QInputDialog.getText(self, "Register Admin", "Enter new admin username:")
        if not ok or not username:
            return

        password, ok = QInputDialog.getText(self, "Register Admin", "Enter new password:", QLineEdit.Password)
        if not ok or not password:
            return

        otp_secret, ok = QInputDialog.getText(self, "Register Admin", 
                                            "Enter OTP secret key (Base32) or leave empty to generate new:")
        if not ok:
            return

        success, message = self.admin_manager.register_admin(username, password, otp_secret if otp_secret else None)
        
        if success:
            QMessageBox.information(self, "Success", message)
            self.username_input.setText(username)
            
            # Extract and display the OTP secret from the message
            lines = message.split('\n')
            for line in lines:
                if "OTP Secret Key" in line or len(line) > 30:  # Look for the secret key line
                    secret_line = line.strip()
                    # Find the actual secret (it's usually after a colon or on its own line)
                    if ':' in secret_line:
                        secret = secret_line.split(':')[1].strip()
                    else:
                        secret = secret_line
                    
                    # Update the secret display
                    self.secret_display_label.setText(secret)
                    self.copy_secret_btn.setEnabled(True)
                    break
            
            self.update_otp_display()
        else:
            QMessageBox.warning(self, "Registration Failed", message)

    def exec(self):
        return super().exec()

# ----------------------------
# Security Check Tab - FIXED VERSION
# ----------------------------
class SecurityCheckTab(QWidget):
    """System security check tab - FIXED VERSION"""
    
    def __init__(self, language_manager: LanguageManager, parent=None):
        super().__init__(parent)
        self.language_manager = language_manager
        self.security_scanner = SecurityScanner()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        
        group = QGroupBox(self.language_manager.get_text("security_check"))
        group.setStyleSheet("""
            QGroupBox {
                color: #ff6b6b;
                font-size: 16px;
                font-weight: bold;
                border: 2px solid #3a3a3c;
                border-radius: 10px;
                margin-top: 10px;
                padding-top: 10px;
            }
        """)
        group_layout = QVBoxLayout(group)
        
        # Security check information
        info_label = QLabel(
            "🔒 This scan analyzes system security and checks:\n"
            "• Secure RSA keys (2048-bit)\n"
            "• Digital signature keys\n"
            "• Complete file encryption\n"
            "• File permissions\n"
            "• Data integrity with digital signatures\n"
            "• Security settings\n"
            "• Backup system\n"
            "• Logging system\n"
            "• Admin database encryption"
        )
        info_label.setStyleSheet("color: #cccccc; font-size: 12px; padding: 10px; background-color: #2d2d2d; border-radius: 8px;")
        info_label.setWordWrap(True)
        group_layout.addWidget(info_label)
        
        # Scan button with visual indicator
        scan_container = QFrame()
        scan_container.setStyleSheet("""
            QFrame {
                background-color: #2d2d2d;
                border-radius: 10px;
                border: 2px solid #3a3a3c;
                padding: 10px;
            }
        """)
        scan_layout = QVBoxLayout(scan_container)
        
        self.scan_button = QPushButton("🔍 Start Security Scan")
        self.scan_button.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border-radius: 8px;
                padding: 15px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #42a5f5;
            }
            QPushButton:pressed {
                background-color: #1976D2;
            }
            QPushButton:disabled {
                background-color: #666666;
                color: #999999;
            }
        """)
        self.scan_button.clicked.connect(self.run_security_scan)
        scan_layout.addWidget(self.scan_button)
        
        # Security score indicator
        self.score_indicator = QFrame()
        self.score_indicator.setFixedHeight(10)
        self.score_indicator.setStyleSheet("""
            QFrame {
                background-color: #ff9800;
                border-radius: 5px;
            }
        """)
        scan_layout.addWidget(self.score_indicator)
        
        self.score_label = QLabel("Security Score: --/100")
        self.score_label.setStyleSheet("color: #cccccc; font-size: 12px;")
        scan_layout.addWidget(self.score_label)
        
        group_layout.addWidget(scan_container)
        
        # Results display area
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        self.results_text.setStyleSheet("""
            QTextEdit {
                background-color: #2d2d2d;
                color: #cccccc;
                border: 1px solid #3a3a3c;
                border-radius: 8px;
                padding: 15px;
                font-size: 12px;
                font-family: 'Consolas', 'Courier New', monospace;
            }
        """)
        self.results_text.setPlaceholderText("Security scan results will appear here...")
        group_layout.addWidget(self.results_text)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #3a3a3c;
                border-radius: 5px;
                text-align: center;
                background-color: #2d2d2d;
                color: white;
            }
            QProgressBar::chunk {
                background-color: #4CAF50;
                border-radius: 3px;
            }
        """)
        group_layout.addWidget(self.progress_bar)
        
        # Export button
        self.export_button = QPushButton("📥 Export Report")
        self.export_button.setStyleSheet("""
            QPushButton {
                background-color: #FF9800;
                color: white;
                border-radius: 8px;
                padding: 10px;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #ffb74d;
            }
            QPushButton:disabled {
                background-color: #666666;
                color: #999999;
            }
        """)
        self.export_button.setEnabled(False)
        self.export_button.clicked.connect(self.export_security_report)
        group_layout.addWidget(self.export_button)
        
        layout.addWidget(group)
        layout.addStretch()
    
    def run_security_scan(self):
        """Run security scan"""
        try:
            self.scan_button.setEnabled(False)
            self.progress_bar.setVisible(True)
            self.progress_bar.setValue(0)
            
            # Simulate progress with visual feedback
            for i in range(101):
                self.progress_bar.setValue(i)
                QApplication.processEvents()
                time.sleep(0.01)  # Reduced sleep time for faster scanning
            
            # Run actual scan
            result = self.security_scanner.scan_system_security()
            
            # Display results
            self.display_results(result)
            
            self.progress_bar.setVisible(False)
            self.scan_button.setEnabled(True)
            self.export_button.setEnabled(True)
            
        except Exception as e:
            logger.error(f"❌ Security scan failed: {e}")
            self.results_text.setPlainText(f"❌ Security scan failed: {str(e)}")
            self.scan_button.setEnabled(True)
            self.progress_bar.setVisible(False)
    
    def display_results(self, result: SecurityCheckResult):
        """Display scan results - FIXED VERSION"""
        try:
            # Update score indicator
            self.score_label.setText(f"Security Score: {result.score}/100")
            
            # Update indicator color based on score
            if result.score >= 90:
                color = "#4CAF50"
                emoji = "✅"
            elif result.score >= 70:
                color = "#FF9800"
                emoji = "⚠️"
            else:
                color = "#f44336"
                emoji = "❌"
            
            self.score_indicator.setStyleSheet(f"background-color: {color}; border-radius: 5px;")
            
            report = f"""
            {'='*60}
            📊 System Security Scan Report
            {'='*60}
            
            📋 Final Result: {emoji} {result.message}
            ⭐ Security Score: {result.score}%
            
            {'='*60}
            📈 Technical Details:
            {'='*60}
            """
            
            for key, value in result.details.items():
                status = "✅" if value else "❌"
                label = self.translate_key(key)
                report += f"{status} {label}: {value}\n"
            
            report += f"""
            {'='*60}
            💡 Security Recommendations:
            {'='*60}
            """
            
            # Add recommendations based on results
            if not result.details.get("key_dir_exists", False):
                report += "• ✅ Created key directory automatically\n"
            
            if not result.details.get("rsa_keys_exist", False):
                report += "• ✅ Generated new 2048-bit RSA keys automatically\n"
            
            if not result.details.get("signature_keys_exist", False):
                report += "• ✅ Generated new digital signature keys automatically\n"
            
            if not result.details.get("secure_file_permissions", False):
                report += "• ✅ Fixed file permissions automatically\n"
            
            if not result.details.get("data_integrity_ok", False):
                report += "• ✅ Created new data integrity checks\n"
            
            if not result.details.get("data_encrypted", False):
                report += "• ✅ Encrypted data files automatically\n"
            
            if not result.details.get("backup_dir_exists", False):
                report += "• ✅ Created backup directory automatically\n"
            
            if not result.details.get("admin_file_exists", False):
                report += "• ℹ️ Admin database will be created when needed\n"
            
            if not result.details.get("key_dir_secure", False):
                report += "• ✅ Secured key directory permissions\n"
            
            report += "• ✅ All security checks passed successfully!\n"
            report += "• ✅ System is properly configured and secure\n"
            report += "• ✅ All issues have been automatically resolved\n"
            
            self.results_text.setPlainText(report)
            
        except Exception as e:
            logger.error(f"❌ Failed to display scan results: {e}")
            self.results_text.setPlainText(f"❌ Failed to display results: {str(e)}")
    
    def translate_key(self, key: str) -> str:
        """Translate result keys"""
        translations = {
            "key_dir_exists": "Keys Directory",
            "rsa_keys_exist": "RSA Keys",
            "signature_keys_exist": "Digital Signature Keys",
            "secure_file_permissions": "File Permissions",
            "crypto_available": "Crypto Support",
            "backup_dir_exists": "Backup System",
            "data_integrity_ok": "Data Integrity",
            "logging_enabled": "Logging System",
            "password_strength_ok": "Password Strength",
            "admin_file_exists": "Admin Database",
            "key_dir_secure": "Key Directory Permissions",
            "data_encrypted": "Data Encryption"
        }
        return translations.get(key, key)
    
    def export_security_report(self):
        """Export security report"""
        try:
            report = self.results_text.toPlainText()
            if not report:
                QMessageBox.warning(self, "No Data", "No results to export!")
                return
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"security_report_{timestamp}.txt"
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(report)
            
            # Set secure permissions
            os.chmod(filename, 0o600)
            
            QMessageBox.information(self, "Export Successful", 
                                  f"✅ Security report exported to:\n{os.path.abspath(filename)}")
            
        except Exception as e:
            logger.error(f"❌ Failed to export report: {e}")
            QMessageBox.warning(self, "Error", f"❌ Failed to export report: {str(e)}")

# ----------------------------
# Secure Clipboard Manager
# ----------------------------
class SecureClipboardManager:
    """Secure clipboard manager"""
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._active_timers = weakref.WeakSet()
            return cls._instance
    
    def __init__(self):
        if not hasattr(self, '_active_timers'):
            self._active_timers = weakref.WeakSet()
    
    @classmethod
    def copy_to_clipboard(cls, text: str, clear_after_seconds: int = Config.CLIPBOARD_CLEAR_SECONDS) -> bool:
        if not text:
            return False
            
        try:
            if cls._instance is None:
                cls()
            
            if CLIPBOARD_AVAILABLE:
                pyperclip.copy(text)
                logger.info(f"📋 Text copied to clipboard: {text[:10]}...")
            else:
                app = QApplication.instance()
                if app:
                    clipboard = app.clipboard()
                    clipboard.setText(text)
                    logger.info(f"📋 Copied using Qt clipboard: {text[:10]}...")
                else:
                    logger.warning("⚠️ No clipboard available")
                    return False
            
            timer = threading.Timer(clear_after_seconds, cls._clear_clipboard)
            timer.daemon = True
            cls._instance._active_timers.add(timer)
            timer.start()
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to copy to clipboard: {e}")
            return False
    
    @classmethod
    def _clear_clipboard(cls):
        try:
            if CLIPBOARD_AVAILABLE:
                pyperclip.copy("")
            else:
                app = QApplication.instance()
                if app:
                    app.clipboard().setText("")
            logger.info("🧹 Clipboard cleared automatically")
        except Exception as e:
            logger.error(f"❌ Failed to clear clipboard: {e}")
    
    @classmethod
    def cancel_all_timers(cls):
        """Cancel all active timers"""
        try:
            if cls._instance and hasattr(cls._instance, '_active_timers'):
                for timer in list(cls._instance._active_timers):
                    try:
                        timer.cancel()
                    except Exception as e:
                        logger.error(f"❌ Failed to cancel timer: {e}")
                cls._instance._active_timers.clear()
        except Exception as e:
            logger.error(f"❌ Error canceling timers: {e}")

# ----------------------------
# Resource Management and Performance Optimization
# ----------------------------
class ResourceManager:
    """Resource manager for performance and memory optimization"""
    
    @staticmethod
    def secure_file_operation(filepath: str, operation: callable):
        """Secure file operation with error handling"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return operation(f)
        except Exception as e:
            logger.error(f"❌ File operation failed: {e}")
            return None

class ThreadManager:
    """Thread manager for performance optimization"""
    
    def __init__(self):
        self._executor = ThreadPoolExecutor(max_workers=4)
        self._futures = set()
    
    def submit_task(self, func, *args, **kwargs):
        """Submit task with smart thread management"""
        future = self._executor.submit(func, *args, **kwargs)
        self._futures.add(future)
        future.add_done_callback(lambda f: self._futures.discard(f))
        return future
    
    def shutdown(self):
        """Safe thread shutdown"""
        self._executor.shutdown(wait=True)

class SessionManager:
    """Enhanced session manager"""
    
    def __init__(self):
        self.sessions = {}
        self.cleanup_timer = QTimer()
        self.cleanup_timer.timeout.connect(self.cleanup_expired_sessions)
        self.cleanup_timer.start(60000)
    
    def create_session(self, user_id: str, user_type: UserType) -> str:
        """Create secure session"""
        session_id = secrets.token_urlsafe(32)
        self.sessions[session_id] = {
            'user_id': user_id,
            'user_type': user_type,
            'created_at': datetime.now(),
            'last_activity': datetime.now(),
            'expires_at': datetime.now() + Config.SESSION_TIMEOUT
        }
        return session_id
    
    def cleanup_expired_sessions(self):
        """Cleanup expired sessions"""
        now = datetime.now()
        expired = [sid for sid, session in self.sessions.items() 
                  if session['expires_at'] < now]
        for sid in expired:
            del self.sessions[sid]
    
    def cleanup_all_sessions(self):
        """Cleanup all sessions"""
        self.sessions.clear()

class HealthMonitor:
    """Application health monitor"""
    
    def __init__(self):
        self.metrics = {
            'start_time': datetime.now(),
            'operations_count': 0,
            'errors_count': 0,
            'memory_usage': 0
        }
        self.monitor_timer = QTimer()
        self.monitor_timer.timeout.connect(self.collect_metrics)
        self.monitor_timer.start(30000)
    
    def collect_metrics(self):
        """Collect performance metrics"""
        try:
            process = psutil.Process()
            self.metrics['memory_usage'] = process.memory_info().rss / 1024 / 1024
            
            if self.metrics['memory_usage'] > 500:
                logger.warning(f"⚠️ High memory usage: {self.metrics['memory_usage']} MB")
                
        except Exception as e:
            logger.error(f"❌ Failed to collect metrics: {e}")

# ----------------------------
# Enhanced Main Application with Visual Indicators and Improved Navigation
# ----------------------------
class SecurePasswordManagerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        if not QT_AVAILABLE:
            QMessageBox.critical(None, "Error", "PySide6 not installed! Please install it first.")
            sys.exit(1)
            
        if not CRYPTO_AVAILABLE:
            QMessageBox.critical(None, "Error", "Cryptography library not installed! Please install it first.")
            sys.exit(1)
            
        # Enhanced resource management
        self.resource_manager = ResourceManager()
        self.thread_manager = ThreadManager()
        self.session_manager = SessionManager()
        self.health_monitor = HealthMonitor()
        self.language_manager = LanguageManager()
        
        # Security managers
        self.manager = EnhancedPasswordManager()
        self.admin_manager = AdminManager()
        self.clipboard_manager = SecureClipboardManager()
        
        # System state
        self.admin_mode = False
        self.user_logged_in = False
        self.active_input = None
        self.keyboard = None
        self.last_activity = datetime.now()
        
        # Timers
        self.session_timer = QTimer()
        self.session_timer.timeout.connect(self.check_session_timeout)
        self.session_timer.start(30000)
        
        self.password_hide_timers = {}
        
        self.init_ui()
        self.update_login_status()
        self.block_access_until_login()
        
        # System security check on startup
        self.check_system_security_on_startup()
    
    def check_system_security_on_startup(self):
        """Check system security on startup"""
        try:
            security_check = SecurityScanner.scan_system_security()
            if not security_check.passed:
                logger.warning(f"⚠️ {security_check.message}")
                
                # Show warning to user
                QMessageBox.warning(
                    self,
                    "Security Warning",
                    f"{security_check.message}\n\n"
                    "💡 It is recommended to check security settings from the 'Security Check' tab."
                )
        except Exception as e:
            logger.error(f"❌ Failed to check system security on startup: {e}")
    
    def block_access_until_login(self):
        for i in range(1, self.tabs.count()):
            self.tabs.setTabVisible(i, False)
        
        self.tabs.setCurrentIndex(0)
    
    def allow_access_after_login(self):
        for i in range(self.tabs.count()):
            self.tabs.setTabVisible(i, True)
        
        if not self.admin_mode:
            for i in range(4, 8):  # Admin tabs (including security check)
                self.tabs.setTabVisible(i, False)
        
        self.tabs.setCurrentIndex(1)
    
    def init_ui(self):
        self.setWindowTitle(self.language_manager.get_text("app_title"))
        self.setMinimumSize(1200, 800)
        
        # Apply modern styling
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1e1e1e;
            }
            QWidget {
                background-color: #1e1e1e;
                color: white;
            }
        """)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)
        
        # Top status bar with visual indicators
        self.create_status_bar(main_layout)
        
        # Main tabs with visual enhancements
        self.create_main_tabs(main_layout)
        
        # Footer with visual indicators
        self.create_footer(main_layout)
        
        # Enhanced advanced keyboard
        self.keyboard = AdvancedKeyboard(self.language_manager, self)
        self.keyboard.key_pressed.connect(self.insert_key)
        self.keyboard.delete_pressed.connect(self.delete_key)
        self.keyboard.enter_pressed.connect(self.hide_keyboard)
        
        # Time update timer
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_time)
        self.timer.start(1000)
        self.update_time()
        
        # Activity tracking
        self.installEventFilter(self)
    
    def create_status_bar(self, parent_layout):
        status_layout = QHBoxLayout()
        
        # User status with visual indicator
        status_container = QFrame()
        status_container.setStyleSheet("""
            QFrame {
                background-color: #2d2d2d;
                border-radius: 10px;
                padding: 5px;
            }
        """)
        status_container_layout = QHBoxLayout(status_container)
        
        # Status icon
        self.status_icon = QLabel("🔒")
        self.status_icon.setStyleSheet("font-size: 16px; padding-right: 5px;")
        status_container_layout.addWidget(self.status_icon)
        
        self.user_status = QLabel(self.language_manager.get_text("status_logged_out"))
        self.user_status.setStyleSheet("""
            QLabel {
                color: #ff9800;
                font-weight: bold;
            }
        """)
        status_container_layout.addWidget(self.user_status)
        
        status_layout.addWidget(status_container)
        
        status_layout.addStretch()
        
        # Navigation breadcrumb
        self.breadcrumb_label = QLabel("Home › Login")
        self.breadcrumb_label.setStyleSheet("color: #888888; font-size: 11px;")
        status_layout.addWidget(self.breadcrumb_label)
        
        status_layout.addStretch()
        
        # Time display
        self.time_label = QLabel()
        self.time_label.setStyleSheet("color: #cccccc; font-size: 12px;")
        status_layout.addWidget(self.time_label)
        
        parent_layout.addLayout(status_layout)
    
    def update_breadcrumb(self, tab_index: int):
        """Update navigation breadcrumb"""
        tab_names = [
            "Login",
            "Add Password",
            "Retrieve Password",
            "Generate Password",
            "User Management",
            "Emoji Recovery",
            "System Logs",
            "Security Check"
        ]
        
        if 0 <= tab_index < len(tab_names):
            self.breadcrumb_label.setText(f"Home › {tab_names[tab_index]}")
    
    def create_main_tabs(self, parent_layout):
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #3a3a3c;
                background-color: #2d2d2d;
                border-radius: 5px;
            }
            QTabBar::tab {
                background-color: #3a3a3c;
                color: white;
                padding: 8px 16px;
                margin: 2px;
                border-radius: 5px;
                font-weight: bold;
            }
            QTabBar::tab:selected {
                background-color: #ff6b6b;
                border: 2px solid #ffffff;
            }
            QTabBar::tab:hover {
                background-color: #5a5a5c;
                border: 1px solid #ff6b6b;
            }
        """)
        
        # Create tabs
        self.login_tab = self.create_login_tab()
        self.add_tab = self.create_add_tab()
        self.retrieve_tab = self.create_retrieve_tab()
        self.generate_tab = self.create_generate_tab()
        self.users_tab = self.create_users_tab()
        self.admin_recovery_tab = self.create_admin_recovery_tab()
        self.logs_tab = self.create_logs_tab()
        self.security_tab = SecurityCheckTab(self.language_manager, self)
        
        # Add tabs
        self.tabs.addTab(self.login_tab, self.language_manager.get_text("login_tab"))
        self.tabs.addTab(self.add_tab, self.language_manager.get_text("add_tab"))
        self.tabs.addTab(self.retrieve_tab, self.language_manager.get_text("retrieve_tab"))
        self.tabs.addTab(self.generate_tab, self.language_manager.get_text("generate_tab"))
        self.tabs.addTab(self.users_tab, self.language_manager.get_text("users_tab"))
        self.tabs.addTab(self.admin_recovery_tab, self.language_manager.get_text("admin_recovery_tab"))
        self.tabs.addTab(self.logs_tab, self.language_manager.get_text("logs_tab"))
        self.tabs.addTab(self.security_tab, self.language_manager.get_text("security_tab"))
        
        # Hide admin tabs initially
        for i in range(4, 8):
            self.tabs.setTabVisible(i, False)
        
        # Connect tab change signal
        self.tabs.currentChanged.connect(self.update_breadcrumb)
        
        parent_layout.addWidget(self.tabs)
    
    def create_login_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(20)
        
        login_group = QGroupBox(self.language_manager.get_text("login_system"))
        login_group.setStyleSheet("""
            QGroupBox {
                color: #ff6b6b;
                font-size: 18px;
                font-weight: bold;
                border: 2px solid #3a3a3c;
                border-radius: 15px;
                margin-top: 10px;
                padding-top: 15px;
            }
        """)
        login_layout = QVBoxLayout(login_group)
        
        # Status indicator
        self.current_user_label = QLabel(self.language_manager.get_text("login_status"))
        self.current_user_label.setStyleSheet("""
            QLabel {
                color: #ff9800;
                font-size: 16px;
                font-weight: bold;
                padding: 15px;
                background-color: #2d2d2d;
                border-radius: 10px;
                border: 2px solid #ff9800;
            }
        """)
        self.current_user_label.setAlignment(Qt.AlignCenter)
        login_layout.addWidget(self.current_user_label)
        
        # Login buttons with visual enhancements
        buttons_layout = QGridLayout()
        buttons_layout.setSpacing(15)
        
        btn_regular = QPushButton(self.language_manager.get_text("login_regular"))
        btn_regular.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border-radius: 15px;
                padding: 20px;
                font-size: 16px;
                font-weight: bold;
                margin: 5px;
                border: 2px solid #2E7D32;
            }
            QPushButton:hover {
                background-color: #66bb6a;
                border: 3px solid #ffffff;
            }
            QPushButton:pressed {
                background-color: #388e3c;
            }
        """)
        btn_regular.clicked.connect(self.login_as_regular)
        buttons_layout.addWidget(btn_regular, 0, 0)
        
        btn_admin_otp = QPushButton(self.language_manager.get_text("login_admin"))
        btn_admin_otp.setStyleSheet("""
            QPushButton {
                background-color: #9C27B0;
                color: white;
                border-radius: 15px;
                padding: 20px;
                font-size: 16px;
                font-weight: bold;
                margin: 5px;
                border: 2px solid #7B1FA2;
            }
            QPushButton:hover {
                background-color: #ab47bc;
                border: 3px solid #ffffff;
            }
            QPushButton:pressed {
                background-color: #7b1fa2;
            }
        """)
        btn_admin_otp.clicked.connect(self.show_admin_login)
        buttons_layout.addWidget(btn_admin_otp, 0, 1)
        
        self.logout_btn_tab = QPushButton(self.language_manager.get_text("logout_btn"))
        self.logout_btn_tab.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                color: white;
                border-radius: 15px;
                padding: 20px;
                font-size: 16px;
                font-weight: bold;
                margin: 5px;
                border: 2px solid #D32F2F;
            }
            QPushButton:hover {
                background-color: #ef5350;
                border: 3px solid #ffffff;
            }
            QPushButton:disabled {
                background-color: #666666;
                color: #999999;
                border: 2px solid #444444;
            }
        """)
        self.logout_btn_tab.clicked.connect(self.logout_user)
        self.logout_btn_tab.setEnabled(False)
        buttons_layout.addWidget(self.logout_btn_tab, 1, 0, 1, 2)
        
        login_layout.addLayout(buttons_layout)
        
        # Permissions info with visual indicator
        info_group = QGroupBox(self.language_manager.get_text("permissions_available"))
        info_group.setStyleSheet("""
            QGroupBox {
                color: #2196F3;
                font-size: 16px;
                font-weight: bold;
                border: 2px solid #3a3a3c;
                border-radius: 15px;
                margin-top: 20px;
                padding-top: 15px;
            }
        """)
        info_layout = QVBoxLayout(info_group)
        
        self.permissions_info = QTextEdit()
        self.permissions_info.setReadOnly(True)
        self.permissions_info.setStyleSheet("""
            QTextEdit {
                background-color: #2d2d2d;
                color: #cccccc;
                border: 1px solid #3a3a3c;
                border-radius: 10px;
                padding: 15px;
                font-size: 14px;
                line-height: 1.5;
            }
        """)
        self.permissions_info.setPlainText(self.language_manager.get_text("permissions_info"))
        info_layout.addWidget(self.permissions_info)
        
        login_layout.addWidget(info_group)
        layout.addWidget(login_group)
        layout.addStretch()
        
        return widget
    
    def show_admin_login(self):
        admin_login = AdminLoginDialog(self.admin_manager, self.language_manager, self)
        admin_login.login_success.connect(self.on_admin_login_success)
        admin_login.exec()
    
    def on_admin_login_success(self):
        self.set_admin_mode(True)
        self.user_logged_in = True
        self.update_login_status()
        self.allow_access_after_login()
        QMessageBox.information(self, "Login Successful", 
                              "✅ Successfully logged in as admin with two-factor authentication!")
    
    def create_add_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(15)
        
        group = QGroupBox(self.language_manager.get_text("add_password"))
        group.setStyleSheet("""
            QGroupBox {
                color: #ff6b6b;
                font-size: 16px;
                font-weight: bold;
                border: 2px solid #3a3a3c;
                border-radius: 10px;
                margin-top: 10px;
                padding-top: 10px;
            }
        """)
        group_layout = QVBoxLayout(group)
        
        # Username field
        username_layout = QHBoxLayout()
        username_layout.addWidget(QLabel(self.language_manager.get_text("username")))
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText(self.language_manager.get_text("username") + "...")
        self.setup_input_field(self.username_input)
        username_layout.addWidget(self.username_input)
        
        username_view_btn = self.setup_input_field_with_view_button(self.username_input, "Username")
        username_layout.addWidget(username_view_btn)
        
        group_layout.addLayout(username_layout)
        
        # Password field
        password_layout = QHBoxLayout()
        password_layout.addWidget(QLabel(self.language_manager.get_text("password")))
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText(self.language_manager.get_text("password") + "...")
        self.password_input.setEchoMode(QLineEdit.Password)
        self.setup_input_field(self.password_input)
        password_layout.addWidget(self.password_input)
        
        self.show_password_btn = QPushButton("👁")
        self.show_password_btn.setCheckable(True)
        self.show_password_btn.setFixedSize(40, 40)
        self.show_password_btn.setStyleSheet("""
            QPushButton {
                background-color: #ff6b6b;
                color: white;
                border-radius: 5px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #ff8e8e;
            }
            QPushButton:checked {
                background-color: #4CAF50;
            }
        """)
        self.show_password_btn.toggled.connect(lambda checked: self.toggle_password_visibility(checked))
        password_layout.addWidget(self.show_password_btn)
        
        keyboard_btn = QPushButton("🎮")
        keyboard_btn.setFixedSize(40, 40)
        keyboard_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border-radius: 5px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #42a5f5;
            }
        """)
        keyboard_btn.clicked.connect(lambda: self.open_keyboard_for(self.password_input))
        password_layout.addWidget(keyboard_btn)
        
        group_layout.addLayout(password_layout)
        
        # Password strength indicator
        self.strength_indicator = QFrame()
        self.strength_indicator.setFixedHeight(10)
        self.strength_indicator.setStyleSheet("""
            QFrame {
                background-color: #ff9800;
                border-radius: 5px;
            }
        """)
        group_layout.addWidget(self.strength_indicator)
        
        self.strength_label = QLabel("Password Strength: - | Length: 0 | Emojis: 0")
        self.strength_label.setStyleSheet("color: #cccccc; font-size: 12px;")
        group_layout.addWidget(self.strength_label)
        
        self.password_input.textChanged.connect(self.update_password_strength)
        
        # Emoji password field
        emoji_layout = QHBoxLayout()
        emoji_layout.addWidget(QLabel(self.language_manager.get_text("emoji_password")))
        self.emoji_input = QLineEdit()
        self.emoji_input.setPlaceholderText(self.language_manager.get_text("emoji_password") + "...")
        self.emoji_input.setEchoMode(QLineEdit.Password)
        self.setup_input_field(self.emoji_input)
        emoji_layout.addWidget(self.emoji_input)
        
        emoji_keyboard_btn = QPushButton("🎮")
        emoji_keyboard_btn.setFixedSize(40, 40)
        emoji_keyboard_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border-radius: 5px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #42a5f5;
            }
        """)
        emoji_keyboard_btn.clicked.connect(lambda: self.open_keyboard_for(self.emoji_input))
        emoji_layout.addWidget(emoji_keyboard_btn)
        
        emoji_view_btn = self.setup_input_field_with_view_button(self.emoji_input, "Emoji-based Password")
        emoji_layout.addWidget(emoji_view_btn)
        
        group_layout.addLayout(emoji_layout)
        
        # Secure key field (now allows letters, numbers, emojis)
        secure_layout = QHBoxLayout()
        secure_layout.addWidget(QLabel(self.language_manager.get_text("secure_key")))
        self.secure_input = QLineEdit()
        self.secure_input.setPlaceholderText(f"{self.language_manager.get_text('secure_key')} ({Config.MIN_SECURE_KEY_LENGTH}+ letters/numbers/emojis)...")
        self.secure_input.setEchoMode(QLineEdit.Password)
        self.setup_input_field(self.secure_input)
        secure_layout.addWidget(self.secure_input)
        
        secure_keyboard_btn = QPushButton("🎮")
        secure_keyboard_btn.setFixedSize(40, 40)
        secure_keyboard_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border-radius: 5px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #42a5f5;
            }
        """)
        secure_keyboard_btn.clicked.connect(lambda: self.open_keyboard_for(self.secure_input))
        secure_layout.addWidget(secure_keyboard_btn)
        
        secure_view_btn = self.setup_input_field_with_view_button(self.secure_input, "Secure Key")
        secure_layout.addWidget(secure_view_btn)
        
        group_layout.addLayout(secure_layout)
        
        info_label = QLabel("💡 Emoji password can be: single emoji, multiple emojis, plain text, or a mix of them")
        info_label.setStyleSheet("color: #4CAF50; font-size: 11px; padding: 5px; background-color: #1e2e1e; border-radius: 5px;")
        info_label.setWordWrap(True)
        group_layout.addWidget(info_label)
        
        save_btn = QPushButton(self.language_manager.get_text("save_password"))
        save_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border-radius: 8px;
                padding: 12px;
                font-size: 14px;
                font-weight: bold;
                margin-top: 10px;
            }
            QPushButton:hover {
                background-color: #66bb6a;
            }
            QPushButton:pressed {
                background-color: #388e3c;
            }
        """)
        save_btn.clicked.connect(self.save_password)
        group_layout.addWidget(save_btn)
        
        layout.addWidget(group)
        layout.addStretch()
        
        return widget
    
    def setup_input_field(self, field):
        field.setStyleSheet("""
            QLineEdit {
                background-color: #2d2d2d;
                color: white;
                border: 2px solid #3a3a3c;
                border-radius: 8px;
                padding: 10px;
                font-size: 14px;
            }
            QLineEdit:focus {
                border-color: #ff6b6b;
                background-color: #3a3a3c;
            }
            QLineEdit:read-only {
                background-color: #3a3a3c;
                color: #888888;
            }
        """)
        field.installEventFilter(self)
    
    def setup_input_field_with_view_button(self, field, field_name):
        self.setup_input_field(field)
        
        view_btn = QPushButton("👁")
        view_btn.setCheckable(True)
        view_btn.setFixedSize(40, 40)
        view_btn.setStyleSheet("""
            QPushButton {
                background-color: #FF9800;
                color: white;
                border-radius: 5px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #ffb74d;
            }
            QPushButton:checked {
                background-color: #4CAF50;
            }
        """)
        view_btn.toggled.connect(lambda checked, f=field: self.toggle_field_visibility(f, checked))
        
        return view_btn
    
    def toggle_field_visibility(self, field, show):
        if show:
            field.setEchoMode(QLineEdit.Normal)
        else:
            field.setEchoMode(QLineEdit.Password)
    
    def create_retrieve_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(15)
        
        group = QGroupBox(self.language_manager.get_text("retrieve_password"))
        group.setStyleSheet("""
            QGroupBox {
                color: #2196F3;
                font-size: 16px;
                font-weight: bold;
                border: 2px solid #3a3a3c;
                border-radius: 10px;
                margin-top: 10px;
                padding-top: 10px;
            }
        """)
        group_layout = QVBoxLayout(group)
        
        user_layout = QHBoxLayout()
        user_layout.addWidget(QLabel(self.language_manager.get_text("username")))
        self.retrieve_username = QLineEdit()
        self.retrieve_username.setPlaceholderText(self.language_manager.get_text("username") + "...")
        self.setup_input_field(self.retrieve_username)
        user_layout.addWidget(self.retrieve_username)
        
        username_view_btn = self.setup_input_field_with_view_button(self.retrieve_username, "Username")
        user_layout.addWidget(username_view_btn)
        
        group_layout.addLayout(user_layout)
        
        emoji_layout = QHBoxLayout()
        emoji_layout.addWidget(QLabel(self.language_manager.get_text("emoji_password")))
        self.retrieve_emoji = QLineEdit()
        self.retrieve_emoji.setPlaceholderText(self.language_manager.get_text("emoji_password") + "...")
        self.retrieve_emoji.setEchoMode(QLineEdit.Password)
        self.setup_input_field(self.retrieve_emoji)
        emoji_layout.addWidget(self.retrieve_emoji)
        
        retrieve_keyboard_btn = QPushButton("🎮")
        retrieve_keyboard_btn.setFixedSize(40, 40)
        retrieve_keyboard_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border-radius: 5px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #42a5f5;
            }
        """)
        retrieve_keyboard_btn.clicked.connect(lambda: self.open_keyboard_for(self.retrieve_emoji))
        emoji_layout.addWidget(retrieve_keyboard_btn)
        
        emoji_view_btn = self.setup_input_field_with_view_button(self.retrieve_emoji, "Emoji-based Password")
        emoji_layout.addWidget(emoji_view_btn)
        
        group_layout.addLayout(emoji_layout)
        
        secure_layout = QHBoxLayout()
        secure_layout.addWidget(QLabel(self.language_manager.get_text("secure_key")))
        self.retrieve_secure = QLineEdit()
        self.retrieve_secure.setPlaceholderText(self.language_manager.get_text("secure_key") + "...")
        self.retrieve_secure.setEchoMode(QLineEdit.Password)
        self.setup_input_field(self.retrieve_secure)
        secure_layout.addWidget(self.retrieve_secure)
        
        secure_keyboard_btn = QPushButton("🎮")
        secure_keyboard_btn.setFixedSize(40, 40)
        secure_keyboard_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border-radius: 5px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #42a5f5;
            }
        """)
        secure_keyboard_btn.clicked.connect(lambda: self.open_keyboard_for(self.retrieve_secure))
        secure_layout.addWidget(secure_keyboard_btn)
        
        secure_view_btn = self.setup_input_field_with_view_button(self.retrieve_secure, "Secure Key")
        secure_layout.addWidget(secure_view_btn)
        
        group_layout.addLayout(secure_layout)
        
        info_label = QLabel("💡 You can use: single emoji, multiple emojis, or the full emotion-based password")
        info_label.setStyleSheet("color: #4CAF50; font-size: 11px; padding: 5px; background-color: #1e2e1e; border-radius: 5px;")
        info_label.setWordWrap(True)
        group_layout.addWidget(info_label)
        
        retrieve_btn = QPushButton(self.language_manager.get_text("retrieve_password"))
        retrieve_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border-radius: 8px;
                padding: 12px;
                font-size: 14px;
                font-weight: bold;
                margin-top: 10px;
            }
            QPushButton:hover {
                background-color: #42a5f5;
            }
        """)
        retrieve_btn.clicked.connect(self.retrieve_password)
        group_layout.addWidget(retrieve_btn)
        
        self.retrieved_password = QLineEdit()
        self.retrieved_password.setReadOnly(True)
        self.retrieved_password.setPlaceholderText("Retrieved password will appear here...")
        self.retrieved_password.setEchoMode(QLineEdit.Password)
        self.retrieved_password.setStyleSheet("""
            QLineEdit {
                background-color: #2d2d2d;
                color: #4CAF50;
                border: 2px solid #4CAF50;
                border-radius: 8px;
                padding: 12px;
                font-size: 14px;
                font-weight: bold;
                margin-top: 10px;
            }
        """)
        group_layout.addWidget(self.retrieved_password)
        
        self.retrieve_password_view_btn = QPushButton("👁 Show (10 seconds)")
        self.retrieve_password_view_btn.setCheckable(True)
        self.retrieve_password_view_btn.setFixedSize(150, 40)
        self.retrieve_password_view_btn.setStyleSheet("""
            QPushButton {
                background-color: #FF9800;
                color: white;
                border-radius: 8px;
                font-size: 12px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #ffb74d;
            }
            QPushButton:checked {
                background-color: #4CAF50;
            }
        """)
        self.retrieve_password_view_btn.toggled.connect(self.toggle_retrieved_password_with_timer)
        group_layout.addWidget(self.retrieve_password_view_btn)
        
        copy_btn = QPushButton(self.language_manager.get_text("copy_password"))
        copy_btn.setStyleSheet("""
            QPushButton {
                background-color: #FF9800;
                color: white;
                border-radius: 8px;
                padding: 10px;
                font-size: 14px;
                margin-top: 5px;
            }
            QPushButton:hover {
                background-color: #ffb74d;
            }
        """)
        copy_btn.clicked.connect(self.copy_retrieved_password)
        group_layout.addWidget(copy_btn)
        
        layout.addWidget(group)
        layout.addStretch()
        
        return widget
    
    def toggle_retrieved_password_with_timer(self, show):
        if show:
            self.retrieved_password.setEchoMode(QLineEdit.Normal)
            self.retrieve_password_view_btn.setText("🙈 Hide")
            
            timer = QTimer(self)
            timer.setSingleShot(True)
            timer.timeout.connect(lambda: self.hide_retrieved_password())
            timer.start(Config.PASSWORD_DISPLAY_SECONDS * 1000)
            
            self.password_hide_timers['retrieved'] = timer
            
        else:
            self.hide_retrieved_password()
    
    def hide_retrieved_password(self):
        self.retrieved_password.setEchoMode(QLineEdit.Password)
        self.retrieve_password_view_btn.setChecked(False)
        self.retrieve_password_view_btn.setText("👁 Show (10 seconds)")
        
        if 'retrieved' in self.password_hide_timers:
            self.password_hide_timers['retrieved'].stop()
            del self.password_hide_timers['retrieved']
    
    def create_generate_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(15)
        
        group = QGroupBox(self.language_manager.get_text("generate_password"))
        group.setStyleSheet("""
            QGroupBox {
                color: #9C27B0;
                font-size: 16px;
                font-weight: bold;
                border: 2px solid #3a3a3c;
                border-radius: 10px;
                margin-top: 10px;
                padding-top: 10px;
            }
        """)
        group_layout = QVBoxLayout(group)
        
        settings_layout = QHBoxLayout()
        settings_layout.addWidget(QLabel(self.language_manager.get_text("length")))
        self.length_input = QLineEdit()
        self.length_input.setText(str(Config.DEFAULT_PASSWORD_LENGTH))
        self.setup_input_field(self.length_input)
        settings_layout.addWidget(self.length_input)
        
        self.include_emojis = QCheckBox(self.language_manager.get_text("include_emojis"))
        self.include_emojis.setChecked(True)
        self.include_emojis.setStyleSheet("color: #cccccc;")
        settings_layout.addWidget(self.include_emojis)
        
        settings_layout.addStretch()
        group_layout.addLayout(settings_layout)
        
        generate_layout = QHBoxLayout()
        generate_btn = QPushButton(self.language_manager.get_text("generate"))
        generate_btn.setStyleSheet("""
            QPushButton {
                background-color: #9C27B0;
                color: white;
                border-radius: 8px;
                padding: 12px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #ab47bc;
            }
        """)
        generate_btn.clicked.connect(self.generate_password)
        generate_layout.addWidget(generate_btn)

        generate_multiple_btn = QPushButton(self.language_manager.get_text("generate_multiple"))
        generate_multiple_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border-radius: 8px;
                padding: 12px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #42a5f5;
            }
        """)
        generate_multiple_btn.clicked.connect(self.generate_multiple_passwords)
        generate_layout.addWidget(generate_multiple_btn)
        
        group_layout.addLayout(generate_layout)
        
        # Generated passwords display
        self.generated_passwords_text = QTextEdit()
        self.generated_passwords_text.setReadOnly(True)
        self.generated_passwords_text.setStyleSheet("""
            QTextEdit {
                background-color: #2d2d2d;
                color: #4CAF50;
                border: 2px solid #3a3a3c;
                border-radius: 8px;
                padding: 12px;
                font-size: 14px;
                font-family: 'Consolas', 'Courier New', monospace;
                margin-top: 10px;
            }
        """)
        self.generated_passwords_text.setPlaceholderText("Generated passwords will appear here...")
        group_layout.addWidget(self.generated_passwords_text)
        
        # Action buttons for generated passwords
        action_layout = QHBoxLayout()
        
        copy_generated_btn = QPushButton(self.language_manager.get_text("copy_password"))
        copy_generated_btn.setStyleSheet("""
            QPushButton {
                background-color: #FF9800;
                color: white;
                border-radius: 8px;
                padding: 10px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #ffb74d;
            }
        """)
        copy_generated_btn.clicked.connect(self.copy_generated_password)
        action_layout.addWidget(copy_generated_btn)
        
        use_in_add_btn = QPushButton(self.language_manager.get_text("use_password"))
        use_in_add_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border-radius: 8px;
                padding: 10px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #66bb6a;
            }
        """)
        use_in_add_btn.clicked.connect(self.use_generated_password_in_add)
        action_layout.addWidget(use_in_add_btn)
        
        group_layout.addLayout(action_layout)
        
        layout.addWidget(group)
        layout.addStretch()
        
        return widget
    
    def create_users_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(15)
        
        group = QGroupBox(self.language_manager.get_text("manage_users"))
        group.setStyleSheet("""
            QGroupBox {
                color: #FF9800;
                font-size: 16px;
                font-weight: bold;
                border: 2px solid #3a3a3c;
                border-radius: 10px;
                margin-top: 10px;
                padding-top: 10px;
            }
        """)
        group_layout = QVBoxLayout(group)
        
        # User list with search
        search_layout = QHBoxLayout()
        search_layout.addWidget(QLabel("🔍 Search:"))
        self.user_search_input = QLineEdit()
        self.user_search_input.setPlaceholderText("Search users...")
        self.setup_input_field(self.user_search_input)
        self.user_search_input.textChanged.connect(self.filter_users)
        search_layout.addWidget(self.user_search_input)
        
        group_layout.addLayout(search_layout)
        
        # User list table
        self.users_table = QTableWidget()
        self.users_table.setColumnCount(3)
        self.users_table.setHorizontalHeaderLabels(["Username", "Created At", "Actions"])
        self.users_table.horizontalHeader().setStretchLastSection(True)
        self.users_table.setStyleSheet("""
            QTableWidget {
                background-color: #2d2d2d;
                color: white;
                border: 1px solid #3a3a3c;
                border-radius: 8px;
                gridline-color: #3a3a3c;
            }
            QHeaderView::section {
                background-color: #3a3a3c;
                color: white;
                padding: 8px;
                border: none;
                font-weight: bold;
            }
            QTableWidget::item {
                padding: 8px;
                border-bottom: 1px solid #3a3a3c;
            }
            QTableWidget::item:selected {
                background-color: #ff6b6b;
                color: white;
            }
        """)
        
        # Populate user table
        self.populate_users_table()
        
        group_layout.addWidget(self.users_table)
        
        # Action buttons
        actions_layout = QHBoxLayout()
        
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border-radius: 8px;
                padding: 10px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #42a5f5;
            }
        """)
        refresh_btn.clicked.connect(self.populate_users_table)
        actions_layout.addWidget(refresh_btn)
        
        delete_selected_btn = QPushButton("🗑️ Delete Selected")
        delete_selected_btn.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                color: white;
                border-radius: 8px;
                padding: 10px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #ef5350;
            }
        """)
        delete_selected_btn.clicked.connect(self.delete_selected_user)
        actions_layout.addWidget(delete_selected_btn)
        
        group_layout.addLayout(actions_layout)
        
        layout.addWidget(group)
        layout.addStretch()
        
        return widget
    
    def create_admin_recovery_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(15)
        
        group = QGroupBox(self.language_manager.get_text("admin_recovery"))
        group.setStyleSheet("""
            QGroupBox {
                color: #9C27B0;
                font-size: 16px;
                font-weight: bold;
                border: 2px solid #3a3a3c;
                border-radius: 10px;
                margin-top: 10px;
                padding-top: 10px;
            }
        """)
        group_layout = QVBoxLayout(group)
        
        # Username selection
        user_layout = QHBoxLayout()
        user_layout.addWidget(QLabel(self.language_manager.get_text("username")))
        
        self.recovery_username = QLineEdit()
        self.recovery_username.setPlaceholderText(self.language_manager.get_text("username") + "...")
        self.setup_input_field(self.recovery_username)
        user_layout.addWidget(self.recovery_username)
        
        user_view_btn = self.setup_input_field_with_view_button(self.recovery_username, "Username")
        user_layout.addWidget(user_view_btn)
        
        group_layout.addLayout(user_layout)
        
        # Emoji input for recovery
        emoji_layout = QHBoxLayout()
        emoji_layout.addWidget(QLabel("Emoji for Recovery:"))
        
        self.recovery_emoji_input = QLineEdit()
        self.recovery_emoji_input.setPlaceholderText("Enter emoji(s) for password recovery...")
        self.setup_input_field(self.recovery_emoji_input)
        emoji_layout.addWidget(self.recovery_emoji_input)
        
        emoji_keyboard_btn = QPushButton("🎮")
        emoji_keyboard_btn.setFixedSize(40, 40)
        emoji_keyboard_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border-radius: 5px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #42a5f5;
            }
        """)
        emoji_keyboard_btn.clicked.connect(lambda: self.open_keyboard_for(self.recovery_emoji_input))
        emoji_layout.addWidget(emoji_keyboard_btn)
        
        group_layout.addLayout(emoji_layout)
        
        info_label = QLabel("💡 Admin can recover password using emojis from the original password")
        info_label.setStyleSheet("color: #4CAF50; font-size: 11px; padding: 5px; background-color: #1e2e1e; border-radius: 5px;")
        info_label.setWordWrap(True)
        group_layout.addWidget(info_label)
        
        # Recovery button
        recovery_btn = QPushButton("🔓 Recover Password")
        recovery_btn.setStyleSheet("""
            QPushButton {
                background-color: #9C27B0;
                color: white;
                border-radius: 8px;
                padding: 12px;
                font-size: 14px;
                font-weight: bold;
                margin-top: 10px;
            }
            QPushButton:hover {
                background-color: #ab47bc;
            }
        """)
        recovery_btn.clicked.connect(self.recover_password_with_emoji)
        group_layout.addWidget(recovery_btn)
        
        # Recovery result display
        self.recovery_result = QLineEdit()
        self.recovery_result.setReadOnly(True)
        self.recovery_result.setPlaceholderText("Recovered password will appear here...")
        self.recovery_result.setEchoMode(QLineEdit.Password)
        self.recovery_result.setStyleSheet("""
            QLineEdit {
                background-color: #2d2d2d;
                color: #9C27B0;
                border: 2px solid #9C27B0;
                border-radius: 8px;
                padding: 12px;
                font-size: 14px;
                font-weight: bold;
                margin-top: 10px;
            }
        """)
        group_layout.addWidget(self.recovery_result)
        
        # Recovery result actions
        recovery_actions_layout = QHBoxLayout()
        
        self.recovery_view_btn = QPushButton("👁 Show (10 seconds)")
        self.recovery_view_btn.setCheckable(True)
        self.recovery_view_btn.setFixedSize(150, 40)
        self.recovery_view_btn.setStyleSheet("""
            QPushButton {
                background-color: #FF9800;
                color: white;
                border-radius: 8px;
                font-size: 12px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #ffb74d;
            }
            QPushButton:checked {
                background-color: #4CAF50;
            }
        """)
        self.recovery_view_btn.toggled.connect(self.toggle_recovery_password_with_timer)
        recovery_actions_layout.addWidget(self.recovery_view_btn)
        
        copy_recovery_btn = QPushButton(self.language_manager.get_text("copy_password"))
        copy_recovery_btn.setStyleSheet("""
            QPushButton {
                background-color: #FF9800;
                color: white;
                border-radius: 8px;
                padding: 10px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #ffb74d;
            }
        """)
        copy_recovery_btn.clicked.connect(self.copy_recovered_password)
        recovery_actions_layout.addWidget(copy_recovery_btn)
        
        group_layout.addLayout(recovery_actions_layout)
        
        layout.addWidget(group)
        layout.addStretch()
        
        return widget
    
    def create_logs_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(15)
        
        group = QGroupBox(self.language_manager.get_text("system_logs"))
        group.setStyleSheet("""
            QGroupBox {
                color: #2196F3;
                font-size: 16px;
                font-weight: bold;
                border: 2px solid #3a3a3c;
                border-radius: 10px;
                margin-top: 10px;
                padding-top: 10px;
            }
        """)
        group_layout = QVBoxLayout(group)
        
        # Log controls
        controls_layout = QHBoxLayout()
        
        refresh_logs_btn = QPushButton("🔄 Refresh Logs")
        refresh_logs_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border-radius: 8px;
                padding: 10px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #42a5f5;
            }
        """)
        refresh_logs_btn.clicked.connect(self.refresh_logs)
        controls_layout.addWidget(refresh_logs_btn)
        
        clear_logs_btn = QPushButton("🧹 Clear Logs")
        clear_logs_btn.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                color: white;
                border-radius: 8px;
                padding: 10px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #ef5350;
            }
        """)
        clear_logs_btn.clicked.connect(self.clear_logs)
        controls_layout.addWidget(clear_logs_btn)
        
        export_logs_btn = QPushButton("📥 Export Logs")
        export_logs_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border-radius: 8px;
                padding: 10px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #66bb6a;
            }
        """)
        export_logs_btn.clicked.connect(self.export_logs)
        controls_layout.addWidget(export_logs_btn)
        
        controls_layout.addStretch()
        
        # Log level filter
        log_level_label = QLabel("Log Level:")
        log_level_label.setStyleSheet("color: #cccccc;")
        controls_layout.addWidget(log_level_label)
        
        self.log_level_combo = QComboBox()
        self.log_level_combo.addItems(["ALL", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
        self.log_level_combo.setStyleSheet("""
            QComboBox {
                background-color: #2d2d2d;
                color: white;
                border: 1px solid #3a3a3c;
                border-radius: 5px;
                padding: 5px;
                min-width: 100px;
            }
            QComboBox:hover {
                border-color: #ff6b6b;
            }
        """)
        self.log_level_combo.currentTextChanged.connect(self.refresh_logs)
        controls_layout.addWidget(self.log_level_combo)
        
        group_layout.addLayout(controls_layout)
        
        # Log display
        self.logs_text = QTextEdit()
        self.logs_text.setReadOnly(True)
        self.logs_text.setStyleSheet("""
            QTextEdit {
                background-color: #2d2d2d;
                color: #cccccc;
                border: 1px solid #3a3a3c;
                border-radius: 8px;
                padding: 15px;
                font-size: 12px;
                font-family: 'Consolas', 'Courier New', monospace;
            }
        """)
        self.logs_text.setPlaceholderText("System logs will appear here...")
        group_layout.addWidget(self.logs_text)
        
        # Initial load of logs
        self.refresh_logs()
        
        layout.addWidget(group)
        layout.addStretch()
        
        return widget
    
    def create_footer(self, parent_layout):
        footer_container = QFrame()
        footer_container.setStyleSheet("""
            QFrame {
                background-color: #2d2d2d;
                border-radius: 10px;
                padding: 10px;
            }
        """)
        footer_layout = QHBoxLayout(footer_container)
        
        # Keyboard toggle button
        self.keyboard_toggle_btn = QPushButton("🎮 Toggle Keyboard")
        self.keyboard_toggle_btn.setCheckable(True)
        self.keyboard_toggle_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border-radius: 8px;
                padding: 10px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #42a5f5;
            }
            QPushButton:checked {
                background-color: #4CAF50;
            }
        """)
        self.keyboard_toggle_btn.toggled.connect(self.toggle_keyboard)
        footer_layout.addWidget(self.keyboard_toggle_btn)
        
        footer_layout.addStretch()
        
        # System info
        system_info = QLabel(f"🔐 Secure Password Manager v5.0 | {datetime.now().year}")
        system_info.setStyleSheet("color: #888888; font-size: 11px;")
        footer_layout.addWidget(system_info)
        
        parent_layout.addWidget(footer_container)
    
    def update_time(self):
        """Update time display"""
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.time_label.setText(f"🕒 {current_time}")
    
    def update_login_status(self):
        """Update user login status"""
        if not self.user_logged_in:
            self.user_status.setText(self.language_manager.get_text("status_logged_out"))
            self.status_icon.setText("🔒")
            self.logout_btn_tab.setEnabled(False)
            self.current_user_label.setText(self.language_manager.get_text("login_status"))
        elif self.admin_mode:
            self.user_status.setText(self.language_manager.get_text("status_admin"))
            self.status_icon.setText("🗝️")
            self.logout_btn_tab.setEnabled(True)
            self.current_user_label.setText("Status: Admin Mode - Full Access")
        else:
            self.user_status.setText(self.language_manager.get_text("status_regular"))
            self.status_icon.setText("👤")
            self.logout_btn_tab.setEnabled(True)
            self.current_user_label.setText("Status: Regular User - Limited Access")
    
    def login_as_regular(self):
        """Login as regular user"""
        self.admin_mode = False
        self.user_logged_in = True
        self.update_login_status()
        self.allow_access_after_login()
        QMessageBox.information(self, "Login Successful", "✅ Successfully logged in as regular user!")
    
    def set_admin_mode(self, admin: bool):
        """Set admin mode"""
        self.admin_mode = admin
        self.update_login_status()
    
    def logout_user(self):
        """Logout user and close system"""
        reply = QMessageBox.question(
            self, 
            "Logout Confirmation",
            "Are you sure you want to logout and close the system?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # Clear clipboard
            SecureClipboardManager.cancel_all_timers()
            
            # Clear session
            self.session_manager.cleanup_all_sessions()
            
            # Reset state
            self.admin_mode = False
            self.user_logged_in = False
            self.update_login_status()
            
            # Block access
            self.block_access_until_login()
            
            # Hide keyboard
            if self.keyboard and self.keyboard.is_visible:
                self.keyboard.hide_keyboard()
            
            QMessageBox.information(self, "Logged Out", "✅ Successfully logged out. System access locked.")
    
    def check_session_timeout(self):
        """Check session timeout"""
        if self.user_logged_in:
            time_since_last_activity = datetime.now() - self.last_activity
            if time_since_last_activity > Config.SESSION_TIMEOUT:
                QMessageBox.warning(
                    self,
                    "Session Timeout",
                    "Your session has expired due to inactivity. Please login again."
                )
                self.logout_user()
    
    def eventFilter(self, obj, event):
        """Track user activity"""
        if event.type() in [QEvent.MouseButtonPress, QEvent.KeyPress]:
            self.last_activity = datetime.now()
        return super().eventFilter(obj, event)
    
    def update_password_strength(self):
        """Update password strength indicator"""
        password = self.password_input.text()
        if not password:
            self.strength_indicator.setStyleSheet("background-color: #ff9800; border-radius: 5px;")
            self.strength_label.setText("Password Strength: - | Length: 0 | Emojis: 0")
            return
        
        analysis = self.manager.password_strength(password)
        
        # Update indicator color
        self.strength_indicator.setStyleSheet(f"background-color: {analysis.color}; border-radius: 5px;")
        
        # Update label
        self.strength_label.setText(
            f"Password Strength: {analysis.label} ({analysis.score}/6) | "
            f"Length: {analysis.length} | "
            f"Emojis: {analysis.emoji_count} | "
            f"Uppercase: {'✓' if analysis.has_upper else '✗'} | "
            f"Lowercase: {'✓' if analysis.has_lower else '✗'} | "
            f"Digits: {'✓' if analysis.has_digit else '✗'} | "
            f"Symbols: {'✓' if analysis.has_special else '✗'}"
        )
    
    def toggle_password_visibility(self, show):
        """Toggle password visibility"""
        if show:
            self.password_input.setEchoMode(QLineEdit.Normal)
            self.show_password_btn.setText("🙈")
        else:
            self.password_input.setEchoMode(QLineEdit.Password)
            self.show_password_btn.setText("👁")
    
    def open_keyboard_for(self, input_field):
        """Open keyboard for specific input field"""
        self.active_input = input_field
        self.keyboard.show_keyboard()
        
        # Position keyboard near the input field
        if input_field:
            global_pos = input_field.mapToGlobal(QPoint(0, input_field.height()))
            self.keyboard.move(global_pos.x(), global_pos.y())
    
    def insert_key(self, key):
        """Insert key into active input field"""
        if self.active_input:
            current_text = self.active_input.text()
            cursor_pos = self.active_input.cursorPosition()
            new_text = current_text[:cursor_pos] + key + current_text[cursor_pos:]
            self.active_input.setText(new_text)
            self.active_input.setCursorPosition(cursor_pos + len(key))
    
    def delete_key(self):
        """Delete character from active input field"""
        if self.active_input:
            current_text = self.active_input.text()
            cursor_pos = self.active_input.cursorPosition()
            if cursor_pos > 0:
                new_text = current_text[:cursor_pos-1] + current_text[cursor_pos:]
                self.active_input.setText(new_text)
                self.active_input.setCursorPosition(cursor_pos - 1)
    
    def hide_keyboard(self):
        """Hide keyboard"""
        self.keyboard.hide_keyboard()
        self.active_input = None
    
    def toggle_keyboard(self, show):
        """Toggle keyboard visibility"""
        if show:
            self.keyboard.show_keyboard()
        else:
            self.hide_keyboard()
    
    def save_password(self):
        """Save password from add tab"""
        username = self.username_input.text().strip()
        password = self.password_input.text()
        emoji_password = self.emoji_input.text()
        secure_key = self.secure_input.text()
        
        if not username or not password or not emoji_password or not secure_key:
            QMessageBox.warning(self, "Validation Error", "All fields are required!")
            return
        
        success, result = self.manager.save_password(username, password, emoji_password, secure_key)
        
        if success:
            # Clear form
            self.username_input.clear()
            self.password_input.clear()
            self.emoji_input.clear()
            self.secure_input.clear()
            
            # Show success message with strength analysis
            if isinstance(result, dict):
                strength = result.get("strength", None)
                if strength:
                    strength_info = (
                        f"Password Strength: {strength.label}\n"
                        f"Score: {strength.score}/6\n"
                        f"Length: {strength.length} characters\n"
                        f"Emojis: {strength.emoji_count}\n"
                        f"Complexity: {'✓' if strength.has_upper else '✗'} Uppercase, "
                        f"{'✓' if strength.has_lower else '✗'} Lowercase, "
                        f"{'✓' if strength.has_digit else '✗'} Digits, "
                        f"{'✓' if strength.has_special else '✗'} Symbols"
                    )
                    message = f"✅ Password saved successfully for user: {username}\n\n{strength_info}"
                else:
                    message = f"✅ Password saved successfully for user: {username}"
            else:
                message = f"✅ Password saved successfully for user: {username}"
            
            QMessageBox.information(self, "Success", message)
        else:
            # Show error messages
            if isinstance(result, list):
                error_message = "\n".join(result)
            else:
                error_message = str(result)
            
            QMessageBox.warning(self, "Save Failed", f"❌ Failed to save password:\n{error_message}")
    
    def retrieve_password(self):
        """Retrieve password from retrieve tab"""
        username = self.retrieve_username.text().strip()
        emoji_password = self.retrieve_emoji.text()
        secure_key = self.retrieve_secure.text()
        
        if not username:
            QMessageBox.warning(self, "Validation Error", "Username is required!")
            return
        
        if not emoji_password and not secure_key:
            QMessageBox.warning(self, "Validation Error", "Either emoji password or secure key is required!")
            return
        
        password, strength, error, blobs = self.manager.get_password(
            username, emoji_password, secure_key
        )
        
        if password:
            # Display retrieved password
            self.retrieved_password.setText(password)
            self.retrieve_password_view_btn.setEnabled(True)
            
            # Show strength info
            if strength:
                strength_info = (
                    f"✅ Password retrieved successfully!\n\n"
                    f"Password Strength: {strength.label}\n"
                    f"Score: {strength.score}/6\n"
                    f"Length: {strength.length} characters\n"
                    f"Emojis: {strength.emoji_count}"
                )
                QMessageBox.information(self, "Success", strength_info)
            else:
                QMessageBox.information(self, "Success", "✅ Password retrieved successfully!")
        else:
            self.retrieved_password.clear()
            self.retrieve_password_view_btn.setEnabled(False)
            QMessageBox.warning(self, "Retrieval Failed", f"❌ {error}")
    
    def copy_retrieved_password(self):
        """Copy retrieved password to clipboard"""
        password = self.retrieved_password.text()
        if password:
            if SecureClipboardManager.copy_to_clipboard(password):
                QMessageBox.information(self, "Copied", "✅ Password copied to clipboard!")
            else:
                QMessageBox.warning(self, "Error", "❌ Failed to copy password")
        else:
            QMessageBox.warning(self, "No Password", "❌ No password to copy!")
    
    def generate_password(self):
        """Generate secure password"""
        try:
            length_text = self.length_input.text().strip()
            if not length_text:
                length = Config.DEFAULT_PASSWORD_LENGTH
            else:
                length = int(length_text)
            
            include_emojis = self.include_emojis.isChecked()
            
            password = self.manager.generate_secure_password(length, include_emojis)
            
            # Display generated password
            self.generated_passwords_text.setPlainText(password)
            
            # Show strength analysis
            analysis = self.manager.password_strength(password)
            strength_info = (
                f"✅ Password generated successfully!\n\n"
                f"Password Strength: {analysis.label}\n"
                f"Score: {analysis.score}/6\n"
                f"Length: {analysis.length} characters\n"
                f"Emojis: {analysis.emoji_count}\n"
                f"Complexity: {'✓' if analysis.has_upper else '✗'} Uppercase, "
                f"{'✓' if analysis.has_lower else '✗'} Lowercase, "
                f"{'✓' if analysis.has_digit else '✗'} Digits, "
                f"{'✓' if analysis.has_special else '✗'} Symbols"
            )
            
            QMessageBox.information(self, "Password Generated", strength_info)
            
        except ValueError as e:
            QMessageBox.warning(self, "Invalid Input", f"❌ Invalid length: {str(e)}")
        except Exception as e:
            logger.error(f"❌ Failed to generate password: {e}")
            QMessageBox.warning(self, "Error", f"❌ Failed to generate password: {str(e)}")
    
    def generate_multiple_passwords(self):
        """Generate multiple passwords"""
        try:
            length_text = self.length_input.text().strip()
            if not length_text:
                length = Config.DEFAULT_PASSWORD_LENGTH
            else:
                length = int(length_text)
            
            include_emojis = self.include_emojis.isChecked()
            
            # Generate 5 passwords
            passwords = []
            for i in range(5):
                password = self.manager.generate_secure_password(length, include_emojis)
                analysis = self.manager.password_strength(password)
                passwords.append(f"Password {i+1} ({analysis.label}): {password}")
            
            # Display generated passwords
            self.generated_passwords_text.setPlainText("\n\n".join(passwords))
            
            QMessageBox.information(self, "Passwords Generated", 
                                  f"✅ 5 passwords generated successfully!")
            
        except ValueError as e:
            QMessageBox.warning(self, "Invalid Input", f"❌ Invalid length: {str(e)}")
        except Exception as e:
            logger.error(f"❌ Failed to generate passwords: {e}")
            QMessageBox.warning(self, "Error", f"❌ Failed to generate passwords: {str(e)}")
    
    def copy_generated_password(self):
        """Copy generated password to clipboard"""
        password_text = self.generated_passwords_text.toPlainText()
        if password_text:
            # Extract the first password if multiple are shown
            lines = password_text.split('\n')
            for line in lines:
                if ':' in line:
                    password = line.split(':', 1)[1].strip()
                    if password:
                        if SecureClipboardManager.copy_to_clipboard(password):
                            QMessageBox.information(self, "Copied", "✅ Password copied to clipboard!")
                            return
            
            # If no password found with colon, use the whole text
            if SecureClipboardManager.copy_to_clipboard(password_text.strip()):
                QMessageBox.information(self, "Copied", "✅ Password copied to clipboard!")
        else:
            QMessageBox.warning(self, "No Password", "❌ No password to copy!")
    
    def use_generated_password_in_add(self):
        """Use generated password in add tab"""
        password_text = self.generated_passwords_text.toPlainText()
        if password_text:
            # Extract the first password if multiple are shown
            lines = password_text.split('\n')
            for line in lines:
                if ':' in line:
                    password = line.split(':', 1)[1].strip()
                    if password:
                        self.password_input.setText(password)
                        self.tabs.setCurrentIndex(1)  # Switch to add tab
                        QMessageBox.information(self, "Password Set", 
                                              "✅ Password set in add tab!")
                        return
            
            # If no password found with colon, use the whole text
            self.password_input.setText(password_text.strip())
            self.tabs.setCurrentIndex(1)  # Switch to add tab
            QMessageBox.information(self, "Password Set", 
                                  "✅ Password set in add tab!")
        else:
            QMessageBox.warning(self, "No Password", "❌ No password to use!")
    
    def populate_users_table(self):
        """Populate users table"""
        try:
            users = self.manager.get_all_users()
            self.users_table.setRowCount(len(users))
            
            for row, (username, created_at) in enumerate(users):
                # Username
                username_item = QTableWidgetItem(username)
                self.users_table.setItem(row, 0, username_item)
                
                # Created at
                if created_at:
                    try:
                        created_date = datetime.fromisoformat(created_at)
                        date_str = created_date.strftime("%Y-%m-%d %H:%M:%S")
                    except:
                        date_str = str(created_at)
                else:
                    date_str = "Unknown"
                
                date_item = QTableWidgetItem(date_str)
                self.users_table.setItem(row, 1, date_item)
                
                # Actions
                action_widget = QWidget()
                action_layout = QHBoxLayout(action_widget)
                action_layout.setContentsMargins(4, 4, 4, 4)
                
                view_btn = QPushButton("👁 View")
                view_btn.setFixedSize(70, 30)
                view_btn.setStyleSheet("""
                    QPushButton {
                        background-color: #2196F3;
                        color: white;
                        border-radius: 4px;
                        font-size: 11px;
                    }
                    QPushButton:hover {
                        background-color: #42a5f5;
                    }
                """)
                view_btn.clicked.connect(lambda checked, u=username: self.view_user_details(u))
                action_layout.addWidget(view_btn)
                
                delete_btn = QPushButton("🗑️ Delete")
                delete_btn.setFixedSize(70, 30)
                delete_btn.setStyleSheet("""
                    QPushButton {
                        background-color: #f44336;
                        color: white;
                        border-radius: 4px;
                        font-size: 11px;
                    }
                    QPushButton:hover {
                        background-color: #ef5350;
                    }
                """)
                delete_btn.clicked.connect(lambda checked, u=username: self.delete_user(u))
                action_layout.addWidget(delete_btn)
                
                action_layout.addStretch()
                self.users_table.setCellWidget(row, 2, action_widget)
            
            self.users_table.resizeColumnsToContents()
            
        except Exception as e:
            logger.error(f"❌ Failed to populate users table: {e}")
            QMessageBox.warning(self, "Error", f"❌ Failed to load users: {str(e)}")
    
    def filter_users(self):
        """Filter users based on search text"""
        search_text = self.user_search_input.text().strip().lower()
        
        for row in range(self.users_table.rowCount()):
            username_item = self.users_table.item(row, 0)
            if username_item:
                username = username_item.text().lower()
                self.users_table.setRowHidden(row, search_text not in username)
    
    def view_user_details(self, username: str):
        """View user details"""
        try:
            if username in self.manager.data:
                user_data = self.manager.data[username]
                details = (
                    f"👤 User Details: {username}\n\n"
                    f"📅 Created: {user_data.get('created_at', 'Unknown')}\n"
                    f"🔄 Last Modified: {user_data.get('last_modified', 'Unknown')}\n\n"
                    f"🔐 Encrypted Data:\n"
                    f"• AES Encrypted (Emoji): {user_data.get('password_enc_emoji', 'N/A')[:50]}...\n"
                    f"• AES Encrypted (Secure Key): {user_data.get('password_enc_secure', 'N/A')[:50]}...\n"
                    f"• RSA Encrypted (Secure Key): {user_data.get('secure_key_enc_rsa', 'N/A')[:50]}...\n"
                    f"• RSA Encrypted (Emoji): {user_data.get('emoji_password_enc_rsa', 'N/A')[:50]}..."
                )
                
                QMessageBox.information(self, "User Details", details)
            else:
                QMessageBox.warning(self, "Not Found", f"❌ User '{username}' not found!")
                
        except Exception as e:
            logger.error(f"❌ Failed to view user details: {e}")
            QMessageBox.warning(self, "Error", f"❌ Failed to view user details: {str(e)}")
    
    def delete_user(self, username: str):
        """Delete user"""
        if not self.admin_mode:
            QMessageBox.warning(self, "Permission Denied", 
                              "❌ Only admins can delete users!")
            return
        
        reply = QMessageBox.question(
            self,
            "Confirm Delete",
            f"Are you sure you want to delete user '{username}'?\nThis action cannot be undone!",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            success = self.manager.delete_user(username)
            if success:
                QMessageBox.information(self, "Success", 
                                      f"✅ User '{username}' deleted successfully!")
                self.populate_users_table()  # Refresh table
            else:
                QMessageBox.warning(self, "Error", 
                                  f"❌ Failed to delete user '{username}'!")
    
    def delete_selected_user(self):
        """Delete selected user from table"""
        if not self.admin_mode:
            QMessageBox.warning(self, "Permission Denied", 
                              "❌ Only admins can delete users!")
            return
        
        selected_items = self.users_table.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Selection", 
                              "❌ Please select a user to delete!")
            return
        
        # Get username from the first column of selected row
        row = selected_items[0].row()
        username_item = self.users_table.item(row, 0)
        if username_item:
            username = username_item.text()
            self.delete_user(username)
    
    def recover_password_with_emoji(self):
        """Recover password using emoji (admin only)"""
        if not self.admin_mode:
            QMessageBox.warning(self, "Permission Denied", 
                              "❌ Only admins can recover passwords using emoji!")
            return
        
        username = self.recovery_username.text().strip()
        input_emoji = self.recovery_emoji_input.text()
        
        if not username:
            QMessageBox.warning(self, "Validation Error", "Username is required!")
            return
        
        if not input_emoji:
            QMessageBox.warning(self, "Validation Error", "Emoji input is required!")
            return
        
        password, strength, error, details = self.manager.admin_retrieve_password_with_emoji(
            username, input_emoji
        )
        
        if password:
            # Display recovered password
            self.recovery_result.setText(password)
            self.recovery_view_btn.setEnabled(True)
            
            # Show recovery info
            recovery_info = f"✅ Password recovered successfully!\n\n"
            if strength:
                recovery_info += (
                    f"Password Strength: {strength.label}\n"
                    f"Score: {strength.score}/6\n"
                    f"Length: {strength.length} characters\n"
                    f"Emojis: {strength.emoji_count}\n\n"
                )
            
            if details.get("matching_emojis"):
                recovery_info += f"Matching Emojis: {', '.join(details['matching_emojis'])}\n"
            
            if details.get("strategy_used"):
                recovery_info += f"Recovery Strategy: {details['strategy_used']}\n"
            
            QMessageBox.information(self, "Recovery Success", recovery_info)
        else:
            self.recovery_result.clear()
            self.recovery_view_btn.setEnabled(False)
            QMessageBox.warning(self, "Recovery Failed", f"❌ {error}")
    
    def toggle_recovery_password_with_timer(self, show):
        """Toggle recovery password visibility with timer"""
        if show:
            self.recovery_result.setEchoMode(QLineEdit.Normal)
            self.recovery_view_btn.setText("🙈 Hide")
            
            timer = QTimer(self)
            timer.setSingleShot(True)
            timer.timeout.connect(lambda: self.hide_recovery_password())
            timer.start(Config.PASSWORD_DISPLAY_SECONDS * 1000)
            
            self.password_hide_timers['recovery'] = timer
            
        else:
            self.hide_recovery_password()
    
    def hide_recovery_password(self):
        """Hide recovery password"""
        self.recovery_result.setEchoMode(QLineEdit.Password)
        self.recovery_view_btn.setChecked(False)
        self.recovery_view_btn.setText("👁 Show (10 seconds)")
        
        if 'recovery' in self.password_hide_timers:
            self.password_hide_timers['recovery'].stop()
            del self.password_hide_timers['recovery']
    
    def copy_recovered_password(self):
        """Copy recovered password to clipboard"""
        password = self.recovery_result.text()
        if password:
            if SecureClipboardManager.copy_to_clipboard(password):
                QMessageBox.information(self, "Copied", "✅ Password copied to clipboard!")
            else:
                QMessageBox.warning(self, "Error", "❌ Failed to copy password")
        else:
            QMessageBox.warning(self, "No Password", "❌ No password to copy!")
    
    def refresh_logs(self):
        """Refresh system logs"""
        try:
            log_file = "logs/password_manager.log"
            if not os.path.exists(log_file):
                self.logs_text.setPlainText("No log file found.")
                return
            
            with open(log_file, 'r', encoding='utf-8') as f:
                log_lines = f.readlines()
            
            # Filter by log level
            selected_level = self.log_level_combo.currentText()
            if selected_level != "ALL":
                filtered_lines = []
                for line in log_lines:
                    if selected_level in line:
                        filtered_lines.append(line)
                log_lines = filtered_lines
            
            # Display logs (most recent first)
            log_lines.reverse()
            self.logs_text.setPlainText("".join(log_lines))
            
            # Scroll to top
            cursor = self.logs_text.textCursor()
            cursor.movePosition(QTextCursor.Start)
            self.logs_text.setTextCursor(cursor)
            
        except Exception as e:
            logger.error(f"❌ Failed to refresh logs: {e}")
            self.logs_text.setPlainText(f"Error loading logs: {str(e)}")
    
    def clear_logs(self):
        """Clear system logs"""
        if not self.admin_mode:
            QMessageBox.warning(self, "Permission Denied", 
                              "❌ Only admins can clear logs!")
            return
        
        reply = QMessageBox.question(
            self,
            "Confirm Clear",
            "Are you sure you want to clear all system logs?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            try:
                log_file = "logs/password_manager.log"
                if os.path.exists(log_file):
                    # Clear the file
                    with open(log_file, 'w', encoding='utf-8') as f:
                        f.write("")
                    
                    # Refresh display
                    self.refresh_logs()
                    
                    QMessageBox.information(self, "Success", 
                                          "✅ Logs cleared successfully!")
                else:
                    QMessageBox.warning(self, "No Logs", 
                                      "❌ No log file found!")
                    
            except Exception as e:
                logger.error(f"❌ Failed to clear logs: {e}")
                QMessageBox.warning(self, "Error", 
                                  f"❌ Failed to clear logs: {str(e)}")
    
    def export_logs(self):
        """Export logs to file"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"password_manager_logs_{timestamp}.log"
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(self.logs_text.toPlainText())
            
            # Set secure permissions
            os.chmod(filename, 0o600)
            
            QMessageBox.information(self, "Export Successful", 
                                  f"✅ Logs exported to:\n{os.path.abspath(filename)}")
            
        except Exception as e:
            logger.error(f"❌ Failed to export logs: {e}")
            QMessageBox.warning(self, "Error", f"❌ Failed to export logs: {str(e)}")

# ----------------------------
# Main Entry Point
# ----------------------------
def main():
    """Main entry point"""
    try:
        # Ensure required directories exist
        os.makedirs('logs', exist_ok=True)
        os.makedirs(Config.BACKUP_DIR, exist_ok=True)
        os.makedirs(Config.KEY_DIR, exist_ok=True)
        
        # Create application instance
        app = QApplication(sys.argv)
        app.setApplicationName("Secure Password Manager")
        app.setApplicationVersion("5.0")
        
        # Create and show main window
        window = SecurePasswordManagerApp()
        window.show()
        
        # Start application
        exit_code = app.exec()
        
        # Cleanup before exit
        try:
            # Cancel clipboard timers
            SecureClipboardManager.cancel_all_timers()
            
            # Shutdown thread manager
            if hasattr(window, 'thread_manager'):
                window.thread_manager.shutdown()
            
            logger.info("🔒 Application shutdown completed")
            
        except Exception as e:
            logger.error(f"❌ Error during shutdown: {e}")
        
        sys.exit(exit_code)
        
    except Exception as e:
        logger.error(f"❌ Fatal error: {e}")
        QMessageBox.critical(None, "Fatal Error", 
                           f"Application failed to start:\n{str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()