import argparse
import base64
import json
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from PIL import Image
from termcolor import colored  # Renkli terminal çıktıları için termcolor kütüphanesini kullanacağız


def sifrele(metin, anahtar):
    anahtar = anahtar.ljust(16)[:16].encode('utf-8')
    cipher = AES.new(anahtar, AES.MODE_ECB)
    metin_padded = pad(metin.encode('utf-8'), AES.block_size)
    return cipher.encrypt(metin_padded)


def coz(sifreli_metin, anahtar):
    anahtar = anahtar.ljust(16)[:16].encode('utf-8')
    cipher = AES.new(anahtar, AES.MODE_ECB)
    cozulmus_metin = unpad(cipher.decrypt(sifreli_metin), AES.block_size)
    return cozulmus_metin.decode('utf-8')


def encode(giris, metinler, cikis, sifre=None):
    img = Image.open(giris).convert('RGB')
    data = img.getdata()

    if sifre:
        sifreli_metinler = [base64.b64encode(sifrele(metin, sifre)).decode('utf-8') for metin in metinler]
    else:
        sifreli_metinler = [base64.b64encode(metin.encode()).decode('utf-8') for metin in metinler]

    json_data = json.dumps(sifreli_metinler)
    print(colored(f"[Bilgi] Gömülecek JSON Veri: {json_data}", "cyan"))

    bits = ''.join(format(ord(c), '08b') for c in json_data)

    new_data = []
    idx = 0
    for pixel in data:
        r, g, b = pixel
        if idx < len(bits):
            r = (r & ~1) | int(bits[idx])
            idx += 1
        if idx < len(bits):
            g = (g & ~1) | int(bits[idx])
            idx += 1
        if idx < len(bits):
            b = (b & ~1) | int(bits[idx])
            idx += 1
        new_data.append((r, g, b))

    img.putdata(new_data)

    # Çıktı dosyasının uzantısını png yap
    cikis_png = os.path.splitext(cikis)[0] + '.png'
    img.save(cikis_png, 'PNG')

    print(colored(f"[Başarılı] Gizli metin başarıyla {cikis_png} dosyasına gömüldü!", "green"))


def decode(giris, sifre=None):
    img = Image.open(giris).convert('RGB')
    data = img.getdata()

    bits = ""
    for pixel in data:
        for channel in pixel:
            bits += str(channel & 1)

    all_bytes = [bits[i:i + 8] for i in range(0, len(bits), 8)]
    decoded_data = ""
    for byte in all_bytes:
        decoded_data += chr(int(byte, 2))
        if decoded_data.endswith(']'):
            break

    try:
        sifreli_metinler = json.loads(decoded_data)
    except json.JSONDecodeError:
        print(colored("[Hata] Gizli mesaj bulunamadı veya veri bozulmuş!", "red"))
        return

    if sifre:
        cozulmus_metinler = [coz(base64.b64decode(m), sifre) for m in sifreli_metinler]
    else:
        cozulmus_metinler = [base64.b64decode(m).decode() for m in sifreli_metinler]

    print(colored("[Çözüm] Gizli Metinler:", "yellow"))
    for i, metin in enumerate(cozulmus_metinler, 1):
        print(f"{i}. {metin}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Görsele metin gömme ve çıkarma aracı (AES destekli)")
    subparsers = parser.add_subparsers(dest="komut", required=True)

    encode_parser = subparsers.add_parser("encode", help="Metinleri görsele gömme")
    encode_parser.add_argument("giris", help="Görsel dosyası (örn: input.jpg)")
    encode_parser.add_argument("--metin", nargs='+', required=True, help="Gömülecek metin/matinler")
    encode_parser.add_argument("--cikti", required=True, help="Çıktı dosyası ismi (örn: output.png olacak)")
    encode_parser.add_argument("--sifre", help="Şifre (isteğe bağlı)", default=None)

    decode_parser = subparsers.add_parser("decode", help="Resimdeki gizli metni çözme")
    decode_parser.add_argument("giris", help="Görsel dosyası (örn: output.png)")
    decode_parser.add_argument("--sifre", help="Şifre (isteğe bağlı)", default=None)

    args = parser.parse_args()

    if args.komut == "encode":
        if args.sifre:
            print(colored("[İşlem] Şifreli metinler görsele gömülüyor...", "magenta"))
        encode(args.giris, args.metin, args.cikti, args.sifre)

    elif args.komut == "decode":
        if args.sifre:
            print(colored("[İşlem] Şifreli metin çözülüyor...", "magenta"))
        decode(args.giris, args.sifre)
