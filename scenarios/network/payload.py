"""
S2/C-a 시나리오 - 전송 파일 생성기 (P1의 순수 로직 부분)

Backend가 DB(leaked_users)에서 읽은 CSV를 목표 전송량(기본 10MB)에 맞춰 전송 파일로
만든다. DB 더미 데이터가 목표보다 작으므로 부족분은 "합성(synthetic) 데이터"로 채운다.

원칙 (사용자 계획 §P1):
  - 생성된 전체가 원본 DB 데이터라고 주장하지 않는다.
    원본 바이트와 합성 바이트를 메타데이터에 분리해 기록하고, 합성 구간은 본문 안에서도
    마커 라인으로 명시한다.
  - 결정적(deterministic)이다. 같은 입력이면 항상 같은 바이트/해시가 나온다.
    그래야 S2와 C-a에 "완전히 같은 payload"를 보내 목적지만 다른 대조(E2)가 성립하고,
    두 Sink에서 수신 해시가 일치하는지(E)를 검증할 수 있다.

이 모듈은 네트워크·Docker·DB에 의존하지 않는다. 입력 바이트만 받아 출력 바이트를
만들므로 단독으로 테스트할 수 있다. 실제 DB 조회와 HTTP 전송은 sender(미구현, Step 2)에서
이 모듈을 호출한다.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

DEFAULT_TARGET_BYTES = 10 * 1024 * 1024  # 10MB

# 합성 구간의 시작을 본문 안에서도 분명히 하는 마커. 수신 측/분석자가 원본과 합성을
# 바이트 수준에서도 구분할 수 있게 한다.
SYNTHETIC_MARKER = (
    b"\n# --- SYNTHETIC PADDING: generated to reach target transfer size; "
    b"NOT original DB data ---\n"
)


@dataclass(frozen=True)
class TransferPayload:
    """
    data           : 전송할 전체 바이트 (정확히 target_bytes)
    sha256         : data의 SHA-256 (두 Sink 수신 해시 대조용)
    total_bytes    : len(data) == target_bytes
    original_bytes : 그중 원본 DB 유래 바이트 수
    synthetic_bytes: 그중 합성 패딩 바이트 수 (마커 포함)
    """

    data: bytes
    sha256: str
    total_bytes: int
    original_bytes: int
    synthetic_bytes: int

    @property
    def summary(self) -> dict:
        """사람이 읽는 요약. '전체가 원본'이라는 오해를 막기 위해 분리해 노출한다."""
        return {
            "total_bytes": self.total_bytes,
            "original_bytes": self.original_bytes,
            "synthetic_bytes": self.synthetic_bytes,
            "synthetic_ratio": (
                round(self.synthetic_bytes / self.total_bytes, 4)
                if self.total_bytes
                else 0.0
            ),
            "sha256": self.sha256,
        }


def build_transfer_payload(
    original_csv: bytes,
    target_bytes: int = DEFAULT_TARGET_BYTES,
) -> TransferPayload:
    """
    DB에서 읽은 CSV(original_csv)를 target_bytes 크기의 전송 파일로 만든다.

    - original_csv가 target 이상이면 앞에서 target 바이트만 쓴다 (합성 0).
    - 작으면 마커를 붙이고, 원본 데이터 라인을 반복해 target에 정확히 맞춘다.
      (헤더는 다시 넣지 않는다. 반복 구간은 모두 합성으로 집계한다)
    """
    if target_bytes <= 0:
        raise ValueError(f"target_bytes must be positive: {target_bytes}")
    if not original_csv:
        raise ValueError("original_csv is empty; nothing to transfer")

    if len(original_csv) >= target_bytes:
        data = original_csv[:target_bytes]
        return _finalize(data, original_bytes=len(data), synthetic_bytes=0)

    parts = [original_csv]
    original_bytes = len(original_csv)
    written = original_bytes

    parts.append(SYNTHETIC_MARKER)
    written += len(SYNTHETIC_MARKER)

    # 반복 재료: 원본의 데이터 라인(헤더 제외). 헤더가 없으면 원본 전체를 쓴다.
    filler = _data_rows(original_csv) or original_csv

    while written < target_bytes:
        need = target_bytes - written
        chunk = filler if len(filler) <= need else filler[:need]
        parts.append(chunk)
        written += len(chunk)

    data = b"".join(parts)
    assert len(data) == target_bytes, (len(data), target_bytes)
    return _finalize(
        data,
        original_bytes=original_bytes,
        synthetic_bytes=target_bytes - original_bytes,
    )


def _data_rows(csv_bytes: bytes) -> bytes:
    """CSV에서 첫 줄(헤더)을 뺀 나머지. 헤더만 있거나 줄바꿈이 없으면 b''를 돌려준다."""
    newline = csv_bytes.find(b"\n")
    if newline == -1:
        return b""
    return csv_bytes[newline + 1:]


def _finalize(data: bytes, original_bytes: int, synthetic_bytes: int) -> TransferPayload:
    return TransferPayload(
        data=data,
        sha256=hashlib.sha256(data).hexdigest(),
        total_bytes=len(data),
        original_bytes=original_bytes,
        synthetic_bytes=synthetic_bytes,
    )
