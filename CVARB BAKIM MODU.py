from telebot import TeleBot

# Botun token'ını buraya girin
TOKEN = '6649599069:AAGJnA1HwZshdq3qgd3dh0NLDo8RaNhcXo4'
bot = TeleBot(TOKEN)

# /start komutu için bir handler (işleyici) tanımlayın
@bot.message_handler(commands=['start'])
def send_welcome(message):
    bot.reply_to(message, "Selam Dostum! Bot Geçici Olarak Bakımda. En Yakın Zamanda Muhteşem Özelliklerle Açılacak 😉\n\nGeliştirme Kanalımız;\nt.me/CVARB_AI")
    
print(*"BAKIM MODU AÇIK")    

# Botu çalıştır
bot.polling()