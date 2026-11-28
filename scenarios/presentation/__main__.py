import argparse
import sys

from .config import Config


def main():
    p = argparse.ArgumentParser(description="Leafy AIOps 발표용 TUI")
    p.add_argument("--config", required=True, help="환경별 JSON 설정 파일")
    p.add_argument("--profile", help="mac-dev / mac-jh / gc-jh 등 설정 프로필")
    p.add_argument("--check", action="store_true", help="설정 검증만 수행 (주입/네트워크 없음)")
    args = p.parse_args()
    try:
        config = Config.load(args.config, args.profile)
    except (KeyError, ValueError, OSError) as exc:
        p.error(str(exc))
    if args.check:
        print(f"프로필 {config.name}: 설정 검증 통과 (연결 검증은 별도)")
        return 0
    from .app import LeafyApp
    LeafyApp(config).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
