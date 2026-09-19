import jwt, time, base64, hmac, hashlib

keys_to_try = [
    # 시도 1: 원문 그대로
    "bXlfc2VjcmV0X2tleV8xMjNfd2hhdGV2ZXJfeW91X3dhbnRfdG9fYmVfdmVyeV9sb25n",
    # 시도 2: Base64 디코딩
    base64.b64decode("bXlfc2VjcmV0X2tleV8xMjNfd2hhdGV2ZXJfeW91X3dhbnRfdG9fYmVfdmVyeV9sb25n").decode(),
    # 시도 3: JWT_SECRET (hex 값)
    "7231a8280dcd72cc25a191dd2280f07138beaadb9ce072aec94b76c7f27636de",
    # 시도 4: JWT_SECRET bytes
    bytes.fromhex("7231a8280dcd72cc25a191dd2280f07138beaadb9ce072aec94b76c7f27636de"),
]

payload = {
    'sub': '1',
    'role': 'USER',
    'iat': int(time.time()),
    'exp': int(time.time()) + 86400,
}

for i, secret in enumerate(keys_to_try):
    try:
        token = jwt.encode(payload, secret, algorithm='HS256')
        print(f"키{i+1}: {token}")
    except Exception as e:
        print(f"키{i+1} 실패: {e}")
