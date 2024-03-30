import os

# Kurulacak paketlerin listesi
pakets = [
    "requests",
    "urllib3",
    "pyTelegramBotAPI",  # telebot için
    "beautifulsoup4",  # bs4 için
    "configparser",
    "qrcode",
    "youtube_dl",  # Not: youtube_dl artık aktif olarak yt_dlp lehine güncellenmemektedir.
    "yt-dlp",  # yt_dlp için
    "zxcvbn",
    "pyshorteners",
    "Pillow",  # PIL için
    "rich",
    "fake-useragent"  # user_agent için, bu paket istenen işlevselliği sağlayabilir.
]

for paket in pakets:
    os.system(f"pip install {paket}")