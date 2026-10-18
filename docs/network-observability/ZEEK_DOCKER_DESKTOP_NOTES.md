아래처럼 그대로 `.md`에 넣으면 깔끔해.

```md
# Docker Desktop 환경의 Zeek Checksum Offload 주의

## 1. 문제 현상

Docker Desktop의 가상 NIC에서는 checksum offload 영향으로 Zeek가 일부 패킷을 비정상 checksum으로 판단할 수 있었다.

이 상태에서 다음과 같이 실행하면:


zeek -i eth0


connection event가 다음과 같이 기록되는 문제가 발생했다.

conn_state=OTH
bytes=0

즉, 실제 TCP 연결이 정상적으로 이루어졌음에도 Zeek가 연결 상태와 트래픽량을 올바르게 반영하지 못했다.

---

## 2. 원인

Docker Desktop 환경에서는 가상 NIC의 checksum offload 때문에 패킷 캡처 시점에 checksum 값이 아직 계산되지 않은 상태로 보일 수 있다.

Zeek는 기본적으로 checksum 검증을 수행하므로 이러한 패킷을 비정상 패킷으로 판단할 수 있다.

---

## 3. 해결 방법

Observer에서 Zeek 실행 시 `-C` 옵션을 적용해 checksum 검증을 비활성화한다.

```bash
zeek -C -i eth0
```

- `-C`: checksum validation 비활성화
- `-i eth0`: backend의 application network interface만 관측

---

## 4. 검증 결과

`-C` 옵션 적용 후 다음 트래픽을 다시 검증했다.

```text
frontend ↔ backend
backend ↔ db
```

그 결과 다음 값이 정상적으로 기록되는 것을 확인했다.

- `conn_state=SF`
- `duration`
- `bytes_sent`
- `bytes_received`

따라서 실제 connection lifecycle과 전송량을 정상적으로 관측할 수 있었다.

---

## 5. 결론

> **Docker Desktop 환경에서는 현재 PoC 기준 Zeek 실행 시 `-C` 옵션이 필수이다.**

권장 실행 형태:

```bash
zeek -C -i eth0
```

`-C` 옵션을 제거할 경우 Docker Desktop의 checksum offload 영향으로 `conn_state=OTH`, `bytes=0`과 같은 부정확한 Network Event가 생성될 수 있다.
```

파일명은 앞에서 말한 것처럼 이게 제일 잘 맞아:

