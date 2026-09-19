import jwt, time

# Base64 디코딩 없이 원문 그대로 사용
secret = "bXlfc2VjcmV0X2tleV8xMjNfd2hhdGV2ZXJfeW91X3dhbnRfdG9fYmVfdmVyeV9sb25n"

token = jwt.encode({
    'sub': '1',
    'role': 'USER',
    'iat': int(time.time()),
    'exp': int(time.time()) + 86400,
}, secret, algorithm='HS256')

print(token)
