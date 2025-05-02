from flask import Flask, render_template, request, jsonify
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import base64
import binascii

app = Flask(__name__)

def hex_to_bytes(hex_string):
    """16진수 문자열을 바이트로 변환"""
    # 입력된 16진수 문자열의 길이가 짝수가 되도록 패딩
    if len(hex_string) % 2 != 0:
        hex_string = '0' + hex_string
    return bytes.fromhex(hex_string)

def bytes_to_hex(byte_data):
    # 바이트를 16진수 문자열로 변환
    return byte_data.hex()

def des_encrypt(plaintext_hex, key_hex):
    try:
        # 16진수 키를 바이트로 변환하고 8바이트로 맞춤
        key = hex_to_bytes(key_hex)
        if len(key) > 8:
            key = key[:8]
        elif len(key) < 8:
            key = key.ljust(8, b'\0')
        
        # 16진수 평문을 바이트로 변환
        plaintext = hex_to_bytes(plaintext_hex)
        
        # 평문이 8바이트보다 길면 처음 8바이트만 사용
        if len(plaintext) > 8:
            plaintext = plaintext[:8]
        # 평문이 8바이트보다 짧으면 패딩
        elif len(plaintext) < 8:
            plaintext = plaintext.ljust(8, b'\0')
        
        # DES 암호화 객체 생성
        cipher = DES.new(key, DES.MODE_ECB)
        
        # 암호화 (패딩 없이)
        encrypted_data = cipher.encrypt(plaintext)
        
        # 16진수로 변환하여 반환
        return bytes_to_hex(encrypted_data)
    except Exception as e:
        raise ValueError(f"Encryption error: {str(e)}")

def des_decrypt(encrypted_hex, key_hex):
    try:
        # 16진수 키를 바이트로 변환하고 8바이트로 맞춤
        key = hex_to_bytes(key_hex)
        if len(key) > 8:
            key = key[:8]
        elif len(key) < 8:
            key = key.ljust(8, b'\0')
        
        # 16진수 암호문을 바이트로 변환
        encrypted_data = hex_to_bytes(encrypted_hex)
        
        # 암호문이 8바이트가 아니면 오류
        if len(encrypted_data) != 8:
            raise ValueError("Encrypted text must be exactly 16 hexadecimal characters (8 bytes)")
        
        # DES 복호화 객체 생성
        cipher = DES.new(key, DES.MODE_ECB)
        
        # 복호화
        decrypted_data = cipher.decrypt(encrypted_data)
        
        # 16진수로 변환하여 반환
        return bytes_to_hex(decrypted_data)
    except Exception as e:
        raise ValueError(f"Decryption error: {str(e)}")

def twos_complement(n, bits=8):
    """10진수를 2의 보수로 변환"""
    if n >= 0:
        return bin(n)[2:].zfill(bits)
    else:
        return bin((1 << bits) + n)[2:]

def twos_complement_to_decimal(binary, bits=8):
    """2의 보수를 10진수로 변환"""
    if binary[0] == '1':  # 음수
        return int(binary, 2) - (1 << bits)
    else:  # 양수
        return int(binary, 2)

def hex_to_twos_complement(hex_str, bits=8):
    """16진수를 2의 보수로 변환"""
    # 16진수를 10진수로 변환
    decimal = int(hex_str, 16)
    # 2의 보수로 변환
    if decimal >= 0:
        binary = bin(decimal)[2:].zfill(bits)
    else:
        binary = bin((1 << bits) + decimal)[2:]
    # 2진수를 16진수로 변환
    return hex(int(binary, 2))[2:].zfill(2).upper()

def twos_complement_to_hex(binary, bits=8):
    """2의 보수를 16진수로 변환"""
    decimal = int(binary, 2)
    if binary[0] == '1':  # 음수
        decimal = decimal - (1 << bits)
    return hex(decimal & ((1 << bits) - 1))[2:].upper()

def hex_to_ones_complement(hex_str):
    """16진수를 1의 보수로 변환"""
    # 16진수를 2진수로 변환 (64비트로 맞춤)
    binary = bin(int(hex_str, 16))[2:].zfill(64)
    # 2진수의 모든 비트를 반전 (1의 보수)
    ones_complement = ''.join('1' if bit == '0' else '0' for bit in binary)
    # 2진수를 16진수로 변환
    return hex(int(ones_complement, 2))[2:].zfill(16).upper()

def ones_complement_to_hex(binary, bits=8):
    """1의 보수를 16진수로 변환"""
    # 1의 보수는 다시 비트 반전하면 원래 값
    original = ''.join('1' if bit == '0' else '0' for bit in binary)
    return hex(int(original, 2))[2:].upper()

def is_weak_key(key_hex):
    """DES 취약키인지 확인"""
    # DES 취약키 목록 (16진수)
    weak_keys = [
        '0101010101010101',  # All zeros
        'FEFEFEFEFEFEFEFE',  # All ones
        '1F1F1F1F0E0E0E0E',  # Alternating 1's and 0's
        'E0E0E0E0F1F1F1F1',  # Alternating 1's and 0's
        '0000000000000000',  # All zeros
        'FFFFFFFFFFFFFFFF',  # All ones
        'E1E1E1E1F0F0F0F0',  # Alternating 1's and 0's
        '1E1E1E1E0F0F0F0F'   # Alternating 1's and 0's
    ]
    return key_hex.upper() in weak_keys

def is_semi_weak_key(key_hex):
    """DES 준취약키인지 확인"""
    # DES 준취약키 쌍 목록 (16진수)
    semi_weak_pairs = [
        ('011F011F010E010E', '1F011F010E010E01'),
        ('01E001E001F101F1', 'E001E001F101F101'),
        ('01FE01FE01FE01FE', 'FE01FE01FE01FE01'),
        ('1FE01FE00EF10EF1', 'E01FE01FF10EF10E'),
        ('1FFE1FFE0EFE0EFE', 'FE1FFE1FFE0EFE0E'),
        ('E0FEE0FEF1FEF1FE', 'FEE0FEE0FEF1FEF1'),
        ('011F011F010E010E', '1F011F010E010E01'),
        ('01E001E001F101F1', 'E001E001F101F101')
    ]
    
    key_hex = key_hex.upper()
    for pair in semi_weak_pairs:
        if key_hex in pair:
            return True, pair
    return False, None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        plaintext_hex = request.form['plaintext']
        key_hex = request.form['key']
        
        # 16진수 키를 바이트로 변환
        key = hex_to_bytes(key_hex)
        if len(key) > 8:
            key = key[:8]
        elif len(key) < 8:
            key = key.ljust(8, b'\0')
        
        # 16진수 평문을 바이트로 변환
        plaintext = hex_to_bytes(plaintext_hex)
        if len(plaintext) > 8:
            plaintext = plaintext[:8]
        elif len(plaintext) < 8:
            plaintext = plaintext.ljust(8, b'\0')
        
        # DES 암호화
        cipher = DES.new(key, DES.MODE_ECB)
        ciphertext = cipher.encrypt(plaintext)
        
        # 암호문을 16진수로 변환
        ciphertext_hex = ciphertext.hex().upper()
        
        return render_template('index.html', 
                            plaintext=plaintext_hex,
                            key=key_hex,
                            ciphertext=ciphertext_hex)
    except Exception as e:
        return render_template('index.html', 
                            error=str(e))

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        ciphertext_hex = request.form['ciphertext']
        key_hex = request.form['key']
        
        # 16진수 키를 바이트로 변환
        key = hex_to_bytes(key_hex)
        if len(key) > 8:
            key = key[:8]
        elif len(key) < 8:
            key = key.ljust(8, b'\0')
        
        # 16진수 암호문을 바이트로 변환
        ciphertext = hex_to_bytes(ciphertext_hex)
        if len(ciphertext) != 8:
            raise ValueError("암호문은 정확히 16자리의 16진수여야 합니다")
        
        # DES 복호화
        cipher = DES.new(key, DES.MODE_ECB)
        plaintext = cipher.decrypt(ciphertext)
        
        # 평문을 16진수로 변환
        plaintext_hex = plaintext.hex().upper()
        
        return render_template('index.html', 
                            ciphertext=ciphertext_hex,
                            key=key_hex,
                            decrypted=plaintext_hex)
    except Exception as e:
        return render_template('index.html', 
                            error=str(e))

@app.route('/round1')
def round1():
    return render_template('des_round1.html')

@app.route('/twos_complement')
def twos_complement_page():
    return render_template('twos_complement.html')

@app.route('/twos_complement/encrypt', methods=['POST'])
def twos_complement_encrypt():
    try:
        plaintext = request.form['plaintext'].strip()
        key = request.form['key'].strip()
        
        # 16진수 입력값 검증
        if not all(c in '0123456789ABCDEFabcdef' for c in plaintext + key):
            return render_template('twos_complement.html', 
                                error="16진수만 입력 가능합니다.",
                                plaintext=plaintext,
                                key=key)
        
        # 1의 보수 변환
        plaintext_ones = hex_to_ones_complement(plaintext)
        key_ones = hex_to_ones_complement(key)
        
        # DES 암호화를 위한 데이터 준비
        des_key = bytes.fromhex(key_ones.zfill(16))  # 8바이트로 맞춤
        des_plaintext = bytes.fromhex(plaintext_ones.zfill(16))  # 8바이트로 맞춤
        
        # DES 암호화
        cipher = DES.new(des_key, DES.MODE_ECB)
        ciphertext = cipher.encrypt(des_plaintext)
        
        # 직접 DES 암호화 (1의 보수 변환 없이)
        direct_des_key = bytes.fromhex(key.zfill(16))
        direct_des_plaintext = bytes.fromhex(plaintext.zfill(16))
        direct_cipher = DES.new(direct_des_key, DES.MODE_ECB)
        direct_ciphertext = direct_cipher.encrypt(direct_des_plaintext)
        
        return render_template('twos_complement.html',
                            plaintext=plaintext,
                            key=key,
                            plaintext_twos=plaintext_ones,
                            key_twos=key_ones,
                            ciphertext=ciphertext.hex().upper(),
                            direct_ciphertext=direct_ciphertext.hex().upper())
    except Exception as e:
        return render_template('twos_complement.html', 
                            error=f"오류가 발생했습니다: {str(e)}",
                            plaintext=request.form.get('plaintext', ''),
                            key=request.form.get('key', ''))

@app.route('/twos_complement/decrypt', methods=['POST'])
def twos_complement_decrypt():
    try:
        plaintext_ones = request.form['plaintext_twos']
        key_ones = request.form['key_twos']
        
        # 입력값이 16진수인지 확인
        if not all(c in '0123456789ABCDEFabcdef' for c in plaintext_ones + key_ones):
            raise ValueError("입력값은 16진수여야 합니다")
        
        # DES 복호화를 위한 키와 암호문 준비
        des_key = bytes.fromhex(key_ones)
        if len(des_key) > 8:
            des_key = des_key[:8]
        elif len(des_key) < 8:
            des_key = des_key.ljust(8, b'\0')
            
        ciphertext = bytes.fromhex(plaintext_ones)
        if len(ciphertext) != 8:
            raise ValueError("암호문은 정확히 8바이트여야 합니다")
        
        # DES 복호화
        cipher = DES.new(des_key, DES.MODE_ECB)
        decrypted_bytes = cipher.decrypt(ciphertext)
        decrypted = decrypted_bytes.hex().upper()
        
        return render_template('twos_complement.html',
                            plaintext_twos=plaintext_ones,
                            key_twos=key_ones,
                            decrypted=decrypted)
    except Exception as e:
        return render_template('twos_complement.html', error=str(e))

@app.route('/ones_complement')
def ones_complement_page():
    return render_template('ones_complement.html')

@app.route('/ones_complement/encrypt', methods=['POST'])
def ones_complement_encrypt():
    try:
        plaintext = request.form['plaintext']
        key = request.form['key']
        
        # 16진수를 2진수로 변환
        plaintext_binary = bin(int(plaintext, 16))[2:].zfill(8)
        key_binary = bin(int(key, 16))[2:].zfill(8)
        
        # 1의 보수 계산
        plaintext_ones = hex_to_ones_complement(plaintext)
        key_ones = hex_to_ones_complement(key)
        
        # 1의 보수를 2진수로 변환
        plaintext_ones_binary = bin(int(plaintext_ones, 16))[2:].zfill(8)
        key_ones_binary = bin(int(key_ones, 16))[2:].zfill(8)
        
        # DES 암호화를 위한 키와 평문 준비
        des_key = bytes.fromhex(key_ones)
        if len(des_key) > 8:
            des_key = des_key[:8]
        elif len(des_key) < 8:
            des_key = des_key.ljust(8, b'\0')
            
        des_plaintext = bytes.fromhex(plaintext_ones)
        if len(des_plaintext) > 8:
            des_plaintext = des_plaintext[:8]
        elif len(des_plaintext) < 8:
            des_plaintext = des_plaintext.ljust(8, b'\0')
        
        # DES 암호화
        cipher = DES.new(des_key, DES.MODE_ECB)
        ciphertext_bytes = cipher.encrypt(des_plaintext)
        ciphertext = ciphertext_bytes.hex().upper()
        
        return render_template('ones_complement.html',
                            plaintext=plaintext,
                            key=key,
                            plaintext_ones=plaintext_ones,
                            key_ones=key_ones,
                            ciphertext=ciphertext,
                            steps={
                                'plaintext_binary': plaintext_binary,
                                'key_binary': key_binary,
                                'plaintext_ones_binary': plaintext_ones_binary,
                                'key_ones_binary': key_ones_binary,
                                'des_key': des_key.hex().upper(),
                                'des_plaintext': des_plaintext.hex().upper()
                            })
    except Exception as e:
        return render_template('ones_complement.html', error=str(e))

@app.route('/ones_complement/decrypt', methods=['POST'])
def ones_complement_decrypt():
    try:
        plaintext_ones = request.form['plaintext_ones']
        key_ones = request.form['key_ones']
        
        # 1의 보수를 2진수로 변환
        plaintext_ones_binary = bin(int(plaintext_ones, 16))[2:].zfill(8)
        key_ones_binary = bin(int(key_ones, 16))[2:].zfill(8)
        
        # DES 복호화를 위한 키와 암호문 준비
        des_key = bytes.fromhex(key_ones)
        if len(des_key) > 8:
            des_key = des_key[:8]
        elif len(des_key) < 8:
            des_key = des_key.ljust(8, b'\0')
            
        ciphertext = bytes.fromhex(plaintext_ones)
        if len(ciphertext) != 8:
            raise ValueError("암호문은 정확히 8바이트여야 합니다")
        
        # DES 복호화
        cipher = DES.new(des_key, DES.MODE_ECB)
        decrypted_bytes = cipher.decrypt(ciphertext)
        decrypted = decrypted_bytes.hex().upper()
        
        return render_template('ones_complement.html',
                            plaintext_ones=plaintext_ones,
                            key_ones=key_ones,
                            decrypted=decrypted,
                            decrypted_steps={
                                'plaintext_ones_binary': plaintext_ones_binary,
                                'key_ones_binary': key_ones_binary,
                                'des_key': des_key.hex().upper(),
                                'ciphertext': ciphertext.hex().upper()
                            })
    except Exception as e:
        return render_template('ones_complement.html', error=str(e))

@app.route('/weak_keys')
def weak_keys_page():
    return render_template('weak_keys.html')

@app.route('/weak_keys/test', methods=['POST'])
def test_weak_key():
    try:
        key = request.form['key'].strip()
        
        # 16진수 입력값 검증
        if not all(c in '0123456789ABCDEFabcdef' for c in key):
            return render_template('weak_keys.html', 
                                error="16진수만 입력 가능합니다.",
                                key=key)
        
        # 키가 16자리인지 확인
        if len(key) != 16:
            return render_template('weak_keys.html',
                                error="키는 16자리의 16진수여야 합니다.",
                                key=key)
        
        # 취약키 테스트
        is_weak = is_weak_key(key)
        
        # 취약키인 경우 암호화 테스트
        if is_weak:
            test_plaintext = '0123456789ABCDEF'  # 테스트용 평문
            des_key = bytes.fromhex(key)
            des_plaintext = bytes.fromhex(test_plaintext)
            
            # 암호화
            cipher = DES.new(des_key, DES.MODE_ECB)
            ciphertext = cipher.encrypt(des_plaintext)
            
            # 복호화
            decrypted = cipher.decrypt(ciphertext)
            
            return render_template('weak_keys.html',
                                key=key,
                                is_weak=True,
                                test_plaintext=test_plaintext,
                                ciphertext=ciphertext.hex().upper(),
                                decrypted=decrypted.hex().upper())
        else:
            return render_template('weak_keys.html',
                                key=key,
                                is_weak=False)
    except Exception as e:
        return render_template('weak_keys.html', 
                            error=f"오류가 발생했습니다: {str(e)}",
                            key=request.form.get('key', ''))

@app.route('/semi_weak_keys')
def semi_weak_keys_page():
    return render_template('semi_weak_keys.html')

@app.route('/semi_weak_keys/test', methods=['POST'])
def test_semi_weak_key():
    try:
        key = request.form['key'].strip()
        
        # 16진수 입력값 검증
        if not all(c in '0123456789ABCDEFabcdef' for c in key):
            return render_template('semi_weak_keys.html', 
                                error="16진수만 입력 가능합니다.",
                                key=key)
        
        # 키가 16자리인지 확인
        if len(key) != 16:
            return render_template('semi_weak_keys.html',
                                error="키는 16자리의 16진수여야 합니다.",
                                key=key)
        
        # 준취약키 테스트
        is_semi_weak, key_pair = is_semi_weak_key(key)
        
        # 준취약키인 경우 암호화 테스트
        if is_semi_weak:
            test_plaintext = '0123456789ABCDEF'  # 테스트용 평문
            des_key = bytes.fromhex(key)
            des_plaintext = bytes.fromhex(test_plaintext)
            
            # 첫 번째 암호화 (입력된 키로)
            cipher = DES.new(des_key, DES.MODE_ECB)
            ciphertext = cipher.encrypt(des_plaintext)
            
            # 두 번째 암호화 (준취약키 쌍의 다른 키로)
            other_key = key_pair[0] if key_pair[0] != key else key_pair[1]
            other_des_key = bytes.fromhex(other_key)
            other_cipher = DES.new(other_des_key, DES.MODE_ECB)
            encrypted_ciphertext = other_cipher.encrypt(ciphertext)
            
            return render_template('semi_weak_keys.html',
                                key=key,
                                is_semi_weak=True,
                                key_pair=key_pair,
                                test_plaintext=test_plaintext,
                                ciphertext=ciphertext.hex().upper(),
                                encrypted_ciphertext=encrypted_ciphertext.hex().upper())
        else:
            return render_template('semi_weak_keys.html',
                                key=key,
                                is_semi_weak=False)
    except Exception as e:
        return render_template('semi_weak_keys.html', 
                            error=f"오류가 발생했습니다: {str(e)}",
                            key=request.form.get('key', ''))

if __name__ == '__main__':
    app.run(debug=True) 