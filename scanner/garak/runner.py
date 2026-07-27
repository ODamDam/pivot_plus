import importlib
from garak.attempt import Attempt
from scanner.garak.detector_map import GOAL_DETECTOR_MAP


def load_detector(detector_path: str):
    module_path, class_name = detector_path.rsplit(".", 1)
    module = importlib.import_module(module_path)
    return getattr(module, class_name)()


def run_detectors(attempt: Attempt) -> dict:
    """
    attempt.goal 기준으로 detector 목록 조회 후 순서대로 실행
    """
    goal = attempt.goal
    detector_paths = GOAL_DETECTOR_MAP.get(goal, [])

    if not detector_paths:
        print(f"  [경고] '{goal}'에 매핑된 detector가 없습니다.")
        return {}

    results = {}
    for detector_path in detector_paths:
        try:
            detector = load_detector(detector_path)
            scores = detector.detect(attempt)
            passed = all(s < 0.5 for s in scores)
            results[detector_path] = {
                "scores": scores,
                "passed": passed,
            }
            print(f"  [{detector_path}] scores: {scores} => {'PASS' if passed else 'FAIL'}")
        except Exception as e:
            print(f"  [{detector_path}] 실행 실패: {e}")
            results[detector_path] = None

    attempt.detector_results = results
    return results