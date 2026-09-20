# Legacy Documentation Archive

이 디렉터리는 프로젝트 진행 과정에서 생성된 이전 설계 및 프로젝트 문서를 보존합니다.

## 목적

- 프로젝트 변경 이력 추적
- 역사적 의사결정 참고자료
- 이전 설계 아이디어 보존

## 구조

각 하위 디렉터리는 문서 보존 날짜로 구분됩니다:

```
legacy_info_files/
└── YYYY-MM-DD/
    └── (보존된 문서들)
```

## 중요

**이 디렉터리의 문서는 참고용입니다.**

현재 프로젝트의 Source of Truth는 다음과 같습니다:

1. `current_info_files/` - 최신 설계 문서
2. 실제 source code와 configuration files

Legacy 문서와 현재 source code가 충돌할 경우, **현재 source code와 current_info_files를 우선**합니다.

## 2026-09-18 Snapshot

프로젝트 구조 재정리 시점의 문서를 보존합니다:

- `README.md` - 기존 프로젝트 개요 및 시작 가이드
- `structure.md` - 기존 디렉터리 구조 설명
