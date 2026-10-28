# S2/C-a 송신기 이미지 (Step 2 / P1 · E1)
#
# backend 의 netns 를 공유하는 사이드카로 실행된다(Zeek 와 같은 패턴):
#   docker run --rm --network=container:leafy-backend -e ... s2-sender:latest
# 이렇게 하면 db 조회와 sink 전송이 backend 의 eth0 로 나가 Zeek 가 src=backend 로
# 관측한다. Spring 앱 이미지는 손대지 않는다.
#
# 빌드 컨텍스트는 scenarios/network (payload.py, transfer_spec.py 를 함께 담기 위해):
#   docker build -t s2-sender:latest -f sender/Dockerfile .
FROM python:3.12-slim

# psql(postgresql-client)만 추가로 설치한다. 그 외엔 순수 stdlib.
RUN apt-get update \
    && apt-get install -y --no-install-recommends postgresql-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY payload.py /app/payload.py
COPY transfer_spec.py /app/transfer_spec.py
COPY sender/send.py /app/send.py

ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["python", "/app/send.py"]
