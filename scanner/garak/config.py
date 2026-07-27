import uuid
import datetime
import json
from pathlib import Path
from types import SimpleNamespace

from garak import _config

def init_garak_config(report_prefix: str = "my_experiment", report_dir: str = "./garak_reports") -> dict:

    report_path = Path(report_dir)
    report_path.mkdir(parents=True, exist_ok=True)

    run_id = str(uuid.uuid4())
    starttime_iso = datetime.datetime.now().isoformat()

    report_filename = report_path / f"{report_prefix}.{run_id[:8]}.report.jsonl"
    hitlogfile = report_path / f"{report_prefix}.{run_id[:8]}.hitlog.jsonl"

    _config.transient = SimpleNamespace(
        run_id=run_id,
        starttime_iso=starttime_iso,
        report_filename=str(report_filename),
        hitlogfile=str(hitlogfile),
    )

    _config.system = SimpleNamespace(
        verbose=0,
        parallel_attempts=1,
        parallel_requests=1,
        narrow_output=False,
    )

    _config.run = SimpleNamespace(
        seed=None,
        eval_threshold=0.5,
        deprefix=True,
        generations=1,
    )

    _config.reporting = SimpleNamespace(
        report_dir=str(report_path),
        report_prefix=report_prefix,
    )

    _config.plugins = SimpleNamespace(
        extended_detectors=False,
    )

    _config.loaded = True

    with open(_config.transient.report_filename, "w", encoding="utf-8") as f:
        header = {
            "entry_type": "start_run setup", 
            "run_id": run_id,
            "starttime_iso": starttime_iso
        }
        f.write(json.dumps(header) + "\n")

    return {
        "run_id": run_id,
        "report_filename": str(report_filename),
        "hitlogfile": str(hitlogfile)
    }