"""
전송 사양(TransferSpec)과 S2/C-a 런 구성 (Step 2 / E2).

핵심 불변식 (사용자 계획 §E2):
    S2 와 C-a 는 "목적지(Destination)"만 다르고, 전송 조건(크기·모드·분할수·전송률·
    프로토콜)은 완전히 동일하다. 그래야 전송량/속도가 아니라 "목적지 허용 여부"가
    정상/공격을 가르는지 검증할 수 있다.

Ground Truth 라벨(should_alert)은 평가 측에서만 쓴다. 송신 코드·탐지기·LLM 입력에는
절대 넣지 않는다 (사용자 계획: [ATTACK]/정답/GT 힌트 주입 금지).
"""

from __future__ import annotations

from dataclasses import dataclass, replace

DEFAULT_TARGET_BYTES = 10 * 1024 * 1024  # 10MB

# 전송 모드
MODE_SINGLE = "single"  # 한 연결로 한 번에
MODE_SPLIT = "split"    # 여러 연결로 분할 (V1 개발/튜닝)
MODE_SLOW = "slow"      # 한 연결을 전송률로 제한해 길게 유지 (V2 저속, P6 조기탐지 대상)


@dataclass(frozen=True)
class Destination:
    """전송 목적지. 허용 여부는 Allowlist 정책에서 오고, 여기엔 식별 정보만 둔다."""
    name: str
    ip: str
    port: int
    # host 는 컨테이너 netns 안에서 쓸 접속 대상(서비스명 또는 IP). 관측/정책 판정은 ip:port 로 한다.
    host: str | None = None

    def connect_host(self) -> str:
        return self.host or self.ip


@dataclass(frozen=True)
class TransferSpec:
    """
    목적지를 제외한 전송 조건. S2/C-a가 이 값을 공유한다.
      mode=split  -> chunks 개의 연결로 나눠 보낸다 (rate_bps 무시)
      mode=slow   -> 한 연결, rate_bps 로 업로드 속도를 제한한다
      mode=single -> 한 연결로 한 번에
    """
    target_bytes: int = DEFAULT_TARGET_BYTES
    mode: str = MODE_SINGLE
    chunks: int = 1
    rate_bps: int | None = None
    protocol: str = "tcp"

    def __post_init__(self):
        if self.mode not in (MODE_SINGLE, MODE_SPLIT, MODE_SLOW):
            raise ValueError(f"unknown mode: {self.mode}")
        if self.mode == MODE_SPLIT and self.chunks < 2:
            raise ValueError("split mode requires chunks >= 2")
        if self.mode == MODE_SLOW and not self.rate_bps:
            raise ValueError("slow mode requires rate_bps")
        if self.target_bytes <= 0:
            raise ValueError("target_bytes must be positive")


@dataclass(frozen=True)
class RunSpec:
    """
    한 번의 실험 실행. scenario 는 "S2"/"C-a", should_alert 는 평가용 GT.
    transfer 는 S2/C-a가 공유하는 전송 조건, destination 만 다르다.
    """
    label: str          # 예: "S2-V1", "C-a-V2"
    scenario: str       # "S2" | "C-a"
    variant: str        # "V1" | "V2" | "dev-slow"
    destination: Destination
    transfer: TransferSpec
    should_alert: bool   # GT (평가 전용). 탐지기/LLM 에 노출 금지.


# --- 개발 기본값 (최종 V2 파라미터는 Step 6에서 동결한다; 아직 FROZEN 아님) ---
DEV_VARIANTS: dict[str, TransferSpec] = {
    # V1: 분할 전송 — 탐지기 개발/튜닝용. 여러 연결의 누적 바이트 집계를 검증한다.
    "V1": TransferSpec(target_bytes=DEFAULT_TARGET_BYTES, mode=MODE_SPLIT, chunks=8),
    # V2: 저속 전송 — Held-out 최종 평가용. 연결이 길게 유지돼 조기탐지(P6)가 필요해진다.
    "V2": TransferSpec(target_bytes=DEFAULT_TARGET_BYTES, mode=MODE_SLOW, rate_bps=256 * 1024),
    # 개발용 저속 케이스 — T(탐지 제한시간) 튜닝용. V2 와 분리(E4: V2는 튜닝에 쓰지 않는다).
    "dev-slow": TransferSpec(target_bytes=DEFAULT_TARGET_BYTES, mode=MODE_SLOW, rate_bps=512 * 1024),
}


def build_pair(
    variant: str,
    sink_authorized: Destination,
    sink_unauthorized: Destination,
    transfer: TransferSpec | None = None,
) -> dict[str, RunSpec]:
    """
    한 variant 에 대해 S2(비인가 Sink)와 C-a(인가 Sink) 런을 만든다.
    두 런은 동일한 TransferSpec 객체를 공유한다 — 목적지만 다르다(E2).
    """
    spec = transfer or DEV_VARIANTS[variant]
    return {
        "S2": RunSpec(
            label=f"S2-{variant}", scenario="S2", variant=variant,
            destination=sink_unauthorized, transfer=spec, should_alert=True,
        ),
        "C-a": RunSpec(
            label=f"C-a-{variant}", scenario="C-a", variant=variant,
            destination=sink_authorized, transfer=spec, should_alert=False,
        ),
    }


def transfer_fields_equal(a: RunSpec, b: RunSpec) -> bool:
    """두 런의 전송 조건이 완전히 같은지(목적지 제외). E2 불변식 검사용."""
    return a.transfer == b.transfer


def with_transfer(run: RunSpec, transfer: TransferSpec) -> RunSpec:
    """전송 조건만 교체한 사본(동결된 파라미터 주입 등)."""
    return replace(run, transfer=transfer)
