import sys
import importlib

from scanner_input.main import run as generate_inputs

def main():
    print("=== LLM Vulnerability Scanner ===")

    try:
        scanner_name, attempts = generate_inputs()
    except Exception as e:
        print(f"\n[Error] 데이터 생성 중 오류 발생: {e}")
        sys.exit(1)

    print(f"\n[System] '{scanner_name}' 스캐너 모듈을 로드합니다...")

    module_path = f"scanner.{scanner_name}.main"
    
    try:
        scanner_module = importlib.import_module(module_path)
    except ImportError as e:
        print(f"[Error] {module_path} 모듈을 찾을 수 없거나 임포트 에러가 발생했습니다.")
        print(f"상세 오류: {e}")
        sys.exit(1)

    if hasattr(scanner_module, "execute"):
        print(f"[System] '{scanner_name}' 스캐닝을 시작합니다...\n" + "="*50)
        scanner_module.execute(attempts)
    else:
        print(f"[Error] {module_path} 내에 'execute(attempts)' 함수가 구현되어 있지 않습니다.")
        print("해당 스캐너의 main.py 파일에 데이터를 인자로 받는 execute() 함수를 만들어주세요.")
        sys.exit(1)

if __name__ == "__main__":
    main()