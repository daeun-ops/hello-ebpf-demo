
# hello-ebpf-demo

이 프로젝트는 eBPF(extended Berkeley Packet Filter)를 이용해 리눅스 커널 내부 이벤트를 추적하고  
Go 로더를 통해 커널 공간과 유저 공간 간 데이터를 교환하는 예제입니다!!
초보자가 시작하기에 최소 완성 eBPF 데모 프로젝트로 이해하심됩니다

---

## 구조
	•	User Space?
  - hello-ebpf-loader가 ELF(hello.bpf.o)를 load/attach 하고 Map에서 통계를 읽어옴ㅁ
	•	Kernel Space?
  - hello.bpf.c가 sys_enter_execve tracepoint에서 실행되며, PID별 exec 카운트를 HashMap에 저장합니다.
	•	eBPF Verifier?
  - 로드 시 프로그램을 정적 분석해 안전성을 보장하고 실패 테스트를 통해 (verifier_fail.bpf.c)로 검증 흐름 파악
	•	bpftool로 proggram/map/link 상태를 직접 확인

  
