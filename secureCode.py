from base64 import b64encode
from pickle import BINPUT
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import bcrypt, bcrypt_check

# 사용자 등록 : 패스워드 해시 등록
password = b"test"
b64pwd = b64encode(SHA256.new(password).digest())
bcrypt_hash = bcrypt(b64pwd, 12)

print("password: %s " % password)
print("b64HashedPassword: %s " % b64pwd)
print("password Hash: %s " % bcrypt_hash)

#로그인 : 패스워드 검증
password_to_test = b"test"
print(password_to_test)
try:
    b64pwd = b64encode(SHA256.new(password_to_test).digest())
    bcrypt_check(b64pwd, bcrypt_hash)
except ValueError:
    print("Incorrect password")