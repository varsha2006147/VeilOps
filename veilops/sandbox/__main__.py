"""python -m veilops.sandbox --port 9100 [--tenant t_acme] [--runaway]"""
import argparse

import uvicorn

from .app import SandboxState, create_app


def main() -> None:
    p = argparse.ArgumentParser(prog="veilops-sandbox")
    p.add_argument("--port", type=int, default=9100)
    p.add_argument("--tenant", default="t_acme")
    p.add_argument("--tz", default="Asia/Kolkata")
    p.add_argument("--runaway", action="store_true", help="start with the CPU runaway already on")
    a = p.parse_args()
    st = SandboxState()
    if a.runaway:
        st.burner.start()
    uvicorn.run(create_app(st, a.tenant, a.tz), host="0.0.0.0", port=a.port, log_level="warning")


if __name__ == "__main__":
    main()
