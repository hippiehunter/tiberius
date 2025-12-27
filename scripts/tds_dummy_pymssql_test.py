#!/usr/bin/env python3
"""
End-to-end protocol test for the dummy TDS server using pymssql.

This script:
1) Launches the dummy TDS server.
2) Waits for it to accept connections.
3) Connects using pymssql and runs a query.
4) Logs all steps and server output.
"""

from __future__ import annotations

import datetime as dt
import decimal
import logging
import os
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid
from collections import deque
from pathlib import Path


HOST = os.environ.get("TDS_TEST_HOST", "127.0.0.1")
PORT = int(os.environ.get("TDS_TEST_PORT", "14333"))
QUERY = os.environ.get("TDS_TEST_QUERY", "SELECT 1")
STARTUP_TIMEOUT_SECS = 60
CONNECT_TIMEOUT_SECS = 10
FREETDS_DUMP_LINES = 200
RESULT_SAMPLE_ROWS = 5
RPC_LOG_WAIT_SECS = 2.0
RPC_OUTPUT_EXPECTED = 4242
TLS_ENABLED = os.environ.get("TDS_TEST_TLS", "1") == "1"
TLS_ENCRYPTION = os.environ.get("TDS_TEST_TLS_ENCRYPTION", "require")


def setup_logging(log_path: Path) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(log_path, mode="w"),
        ],
    )
    logging.info("Logging to %s", log_path)


def tail_file(path: Path, max_lines: int) -> list[str]:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            lines = handle.readlines()
    except FileNotFoundError:
        return []
    if len(lines) <= max_lines:
        return [line.rstrip("\n") for line in lines]
    return [line.rstrip("\n") for line in lines[-max_lines:]]


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def normalize_bytes(value):
    if value is None:
        return None
    if isinstance(value, memoryview):
        return value.tobytes()
    if isinstance(value, bytearray):
        return bytes(value)
    return value


def normalize_uuid(value):
    if value is None:
        return None
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        try:
            return str(uuid.UUID(bytes=bytes(value)))
        except (ValueError, AttributeError, TypeError):
            return str(value)
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, AttributeError, TypeError):
        return str(value)


def normalize_decimal(value):
    if value is None:
        return None
    if isinstance(value, decimal.Decimal):
        return value
    return decimal.Decimal(str(value))


def collect_result_sets(cur) -> list[tuple[list[str], list[tuple]]]:
    result_sets: list[tuple[list[str], list[tuple]]] = []
    while True:
        desc = cur.description
        if desc:
            columns = [col[0] for col in desc]
            rows = cur.fetchall()
            result_sets.append((columns, rows))
        more = cur.nextset()
        if not more:
            break
    return result_sets


def log_result_sets(label: str, result_sets: list[tuple[list[str], list[tuple]]]) -> None:
    if not result_sets:
        logging.info("%s: no result sets", label)
        return
    for idx, (columns, rows) in enumerate(result_sets, start=1):
        logging.info(
            "%s: result set %d columns=%s rows=%d",
            label,
            idx,
            columns,
            len(rows),
        )
        if rows:
            logging.info(
                "%s: result set %d sample=%s",
                label,
                idx,
                rows[:RESULT_SAMPLE_ROWS],
            )


def find_result_set(
    result_sets: list[tuple[list[str], list[tuple]]],
    column_name: str,
) -> tuple[list[str], list[tuple]] | None:
    for columns, rows in result_sets:
        lower_cols = [col.lower() for col in columns]
        if column_name.lower() in lower_cols:
            return columns, rows
    return None


def reader_thread(stream, prefix: str, stop_evt: threading.Event, tail: deque[str]) -> None:
    for line in iter(stream.readline, ""):
        if stop_evt.is_set():
            break
        line = line.rstrip("\n")
        msg = f"{prefix} {line}"
        logging.info(msg)
        tail.append(msg)
    stream.close()


def wait_for_log(tail: deque[str], needle: str, timeout: float) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        snapshot = list(tail)
        if any(needle in line for line in snapshot):
            return True
        time.sleep(0.05)
    return False


def wait_for_port(host: str, port: int, timeout: float) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def ensure_pymssql() -> None:
    try:
        import pymssql  # noqa: F401
        return
    except Exception as exc:  # pylint: disable=broad-except
        logging.warning("pymssql import failed: %s", exc)

    if os.environ.get("TDS_TEST_VENV") == "1":
        logging.info("Installing pymssql via pip (venv)")
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "pymssql"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        logging.info("pip output:\n%s", result.stdout)
        if result.returncode != 0:
            raise RuntimeError("pip install pymssql failed in venv")
        import pymssql  # noqa: F401
        return

    logging.info("Installing pymssql via pip")
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "pymssql"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    logging.info("pip output:\n%s", result.stdout)
    if result.returncode != 0 and "externally-managed-environment" in result.stdout:
        venv_dir = Path(__file__).resolve().parents[1] / "target" / "tds_dummy_test_venv"
        logging.warning("System Python is externally managed; creating venv at %s", venv_dir)
        subprocess.run([sys.executable, "-m", "venv", str(venv_dir)], check=True)
        venv_python = venv_dir / "bin" / "python"
        logging.info("Installing pymssql in venv")
        subprocess.run([str(venv_python), "-m", "pip", "install", "pymssql"], check=True)
        logging.info("Re-running test inside venv")
        env = {**os.environ, "TDS_TEST_VENV": "1"}
        result = subprocess.run([str(venv_python), __file__], env=env, check=False)
        raise SystemExit(result.returncode)

    if result.returncode != 0:
        raise RuntimeError("pip install pymssql failed")

    import pymssql  # noqa: F401


def ensure_tls_materials(repo_root: Path) -> tuple[Path, Path]:
    tls_dir = repo_root / "target" / "tds_dummy_tls"
    tls_dir.mkdir(parents=True, exist_ok=True)
    cert_path = tls_dir / "server_cert.pem"
    key_path = tls_dir / "server_key.pem"

    if cert_path.exists() and key_path.exists():
        logging.info("TLS cert/key already exist in %s", tls_dir)
        return cert_path, key_path

    logging.info("Generating self-signed TLS cert/key in %s", tls_dir)
    cmd = [
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        str(key_path),
        "-out",
        str(cert_path),
        "-days",
        "7",
        "-subj",
        "/CN=localhost",
    ]
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    logging.info("openssl output:\n%s", result.stdout)
    if result.returncode != 0:
        raise RuntimeError("openssl failed to generate TLS materials")

    return cert_path, key_path


def execute_and_collect(cur, sql: str, label: str) -> list[tuple[list[str], list[tuple]]]:
    logging.info("%s: executing SQL: %s", label, sql)
    cur.execute(sql)
    result_sets = collect_result_sets(cur)
    log_result_sets(label, result_sets)
    return result_sets


def validate_single_value(label: str, result_sets: list[tuple[list[str], list[tuple]]]) -> None:
    expect(len(result_sets) == 1, f"{label}: expected 1 result set, got {len(result_sets)}")
    columns, rows = result_sets[0]
    expect(
        [col.lower() for col in columns] == ["value"],
        f"{label}: unexpected columns {columns}",
    )
    expect(rows == [(1,)], f"{label}: unexpected rows {rows}")


def validate_multi(label: str, result_sets: list[tuple[list[str], list[tuple]]]) -> None:
    expect(len(result_sets) == 2, f"{label}: expected 2 result sets, got {len(result_sets)}")
    columns0, rows0 = result_sets[0]
    columns1, rows1 = result_sets[1]
    expect(
        [col.lower() for col in columns0] == ["id", "label"],
        f"{label}: unexpected columns in set 1: {columns0}",
    )
    expect(rows0 == [(1, "alpha"), (2, "beta")], f"{label}: unexpected rows {rows0}")
    expect(
        [col.lower() for col in columns1] == ["code", "note"],
        f"{label}: unexpected columns in set 2: {columns1}",
    )
    expect(rows1 == [(100, "gamma")], f"{label}: unexpected rows {rows1}")


def validate_nulls(label: str, result_sets: list[tuple[list[str], list[tuple]]]) -> None:
    expect(len(result_sets) == 1, f"{label}: expected 1 result set, got {len(result_sets)}")
    _columns, rows = result_sets[0]
    expect(len(rows) == 1, f"{label}: expected 1 row, got {len(rows)}")
    expect(all(value is None for value in rows[0]), f"{label}: expected all NULLs {rows}")


def validate_types(label: str, result_sets: list[tuple[list[str], list[tuple]]]) -> None:
    expect(len(result_sets) == 1, f"{label}: expected 1 result set, got {len(result_sets)}")
    columns, rows = result_sets[0]
    expect(len(rows) == 2, f"{label}: expected 2 rows, got {len(rows)}")
    col_map = {name.lower(): idx for idx, name in enumerate(columns)}
    expected_cols = [
        "int_col",
        "bigint_col",
        "float_col",
        "bit_col",
        "nvarchar_col",
        "varbinary_col",
        "guid_col",
        "numeric_col",
        "datetime_col",
    ]
    for col in expected_cols:
        expect(col in col_map, f"{label}: missing column {col} in {columns}")

    row0, row1 = rows
    expect(row0[col_map["int_col"]] == 42, f"{label}: int_col row0 {row0}")
    expect(row1[col_map["int_col"]] == 7, f"{label}: int_col row1 {row1}")
    expect(row0[col_map["bigint_col"]] == 9001, f"{label}: bigint_col row0 {row0}")
    expect(
        row1[col_map["bigint_col"]] == 123456789,
        f"{label}: bigint_col row1 {row1}",
    )

    float0 = float(row0[col_map["float_col"]])
    float1 = float(row1[col_map["float_col"]])
    expect(abs(float0 - 3.14159) < 1e-6, f"{label}: float_col row0 {float0}")
    expect(abs(float1 - 2.71828) < 1e-6, f"{label}: float_col row1 {float1}")

    bit0 = row0[col_map["bit_col"]]
    bit1 = row1[col_map["bit_col"]]
    expect(bool(bit0) is True, f"{label}: bit_col row0 {row0}")
    expect(bool(bit1) is False, f"{label}: bit_col row1 {row1}")
    expect(
        row0[col_map["nvarchar_col"]] == "hello",
        f"{label}: nvarchar_col row0 {row0}",
    )
    expect(
        row1[col_map["nvarchar_col"]] == "world",
        f"{label}: nvarchar_col row1 {row1}",
    )

    bin0 = normalize_bytes(row0[col_map["varbinary_col"]])
    bin1 = normalize_bytes(row1[col_map["varbinary_col"]])
    expect(bin0 == b"\x01\x02\x03", f"{label}: varbinary_col row0 {bin0}")
    expect(bin1 == b"\x04\x05\x06\x07", f"{label}: varbinary_col row1 {bin1}")

    guid0 = normalize_uuid(row0[col_map["guid_col"]])
    guid1 = normalize_uuid(row1[col_map["guid_col"]])
    expect(
        guid0 == "00000000-0000-0000-0000-000000000001",
        f"{label}: guid_col row0 {guid0}",
    )
    expect(
        guid1 == "00000000-0000-0000-0000-000000000002",
        f"{label}: guid_col row1 {guid1}",
    )

    num0 = normalize_decimal(row0[col_map["numeric_col"]])
    num1 = normalize_decimal(row1[col_map["numeric_col"]])
    expect(num0 == decimal.Decimal("123.45"), f"{label}: numeric_col row0 {num0}")
    expect(num1 == decimal.Decimal("99.99"), f"{label}: numeric_col row1 {num1}")

    dt0 = row0[col_map["datetime_col"]]
    dt1 = row1[col_map["datetime_col"]]
    expect(dt0 is not None, f"{label}: datetime_col row0 is None")
    expect(dt1 is not None, f"{label}: datetime_col row1 is None")
    allowed_dt = (dt.datetime, dt.date, str)
    expect(
        isinstance(dt0, allowed_dt),
        f"{label}: datetime_col row0 type {type(dt0)}",
    )
    expect(
        isinstance(dt1, allowed_dt),
        f"{label}: datetime_col row1 type {type(dt1)}",
    )
    logging.info("%s: datetime values types: %s %s", label, type(dt0), type(dt1))


def validate_rpc_params(label: str, result_sets: list[tuple[list[str], list[tuple]]]) -> None:
    param_set = find_result_set(result_sets, "param_ordinal")
    expect(param_set is not None, f"{label}: missing param echo result set")
    columns, rows = param_set
    lower_cols = [col.lower() for col in columns]
    ord_idx = lower_cols.index("param_ordinal")
    val_idx = lower_cols.index("param_value")
    flags_idx = lower_cols.index("param_flags")

    by_ord = {row[ord_idx]: row for row in rows}
    expect(1 in by_ord and 2 in by_ord and 3 in by_ord, f"{label}: missing ordinals {by_ord}")
    expect(str(by_ord[1][val_idx]) == "1", f"{label}: param 1 value {by_ord[1]}")
    expect(
        str(by_ord[2][val_idx]) == "two",
        f"{label}: param 2 value {by_ord[2]}",
    )
    expect(
        str(by_ord[3][val_idx]) == "12.34",
        f"{label}: param 3 value {by_ord[3]}",
    )

    if 4 in by_ord:
        flags = int(by_ord[4][flags_idx])
        expect(flags & 0x01 == 0x01, f"{label}: output param flags {flags}")


def run_rpc(
    cur,
    tail: deque[str],
) -> tuple[list[tuple[list[str], list[tuple]]], bool, object, tuple]:
    logging.info("rpc: calling stored procedure via callproc")
    import pymssql

    out_param = pymssql.output(int, 5)
    params = (1, "two", decimal.Decimal("12.34"), out_param)
    callproc_result = cur.callproc("tds_rpc", params)
    logging.info("rpc: callproc returned %s", callproc_result)
    result_sets = collect_result_sets(cur)
    log_result_sets("rpc", result_sets)
    rpc_seen = wait_for_log(tail, "rpc from=", RPC_LOG_WAIT_SECS)
    if not rpc_seen:
        logging.warning("rpc: server log did not show RPC handler")
    return result_sets, rpc_seen, out_param, callproc_result


def run_rpc_output_only(cur, tail: deque[str]) -> tuple[tuple, bool]:
    logging.info("rpc_out: calling stored procedure via callproc")
    import pymssql

    out_param = pymssql.output(int, 5)
    params = (1, "two", decimal.Decimal("12.34"), out_param)
    callproc_result = cur.callproc("tds_rpc_out", params)
    logging.info("rpc_out: callproc returned %s", callproc_result)
    result_sets = collect_result_sets(cur)
    log_result_sets("rpc_out", result_sets)
    rpc_seen = wait_for_log(tail, 'proc_name="tds_rpc_out"', RPC_LOG_WAIT_SECS)
    if not rpc_seen:
        logging.warning("rpc_out: server log did not show RPC handler")
    return callproc_result, rpc_seen


def run_rpc_output_first(
    cur,
    tail: deque[str],
) -> tuple[list[tuple[list[str], list[tuple]]], bool, tuple]:
    logging.info("rpc_out_first: calling stored procedure via callproc")
    import pymssql

    out_param = pymssql.output(int, 5)
    params = (1, "two", decimal.Decimal("12.34"), out_param)
    callproc_result = cur.callproc("tds_rpc_out_first", params)
    logging.info("rpc_out_first: callproc returned %s", callproc_result)
    result_sets = collect_result_sets(cur)
    log_result_sets("rpc_out_first", result_sets)
    rpc_seen = wait_for_log(tail, 'proc_name="tds_rpc_out_first"', RPC_LOG_WAIT_SECS)
    if not rpc_seen:
        logging.warning("rpc_out_first: server log did not show RPC handler")
    return result_sets, rpc_seen, callproc_result


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    log_path = repo_root / "target" / "tds_dummy_pymssql_test.log"
    dump_path = repo_root / "target" / "tds_dummy_freetds.log"
    setup_logging(log_path)

    dump_path.parent.mkdir(parents=True, exist_ok=True)
    dump_path.write_text("", encoding="utf-8")
    os.environ.setdefault("TDSDUMP", str(dump_path))
    logging.info("FreeTDS dump path: %s", os.environ["TDSDUMP"])

    ensure_pymssql()
    import pymssql

    server_env = {**os.environ, "RUST_LOG": "info"}
    features = ["server-smol"]

    if TLS_ENABLED:
        cert_path, key_path = ensure_tls_materials(repo_root)
        server_env["TDS_DUMMY_TLS_CERT"] = str(cert_path)
        server_env["TDS_DUMMY_TLS_KEY"] = str(key_path)
        server_env["TDS_DUMMY_ENCRYPTION"] = TLS_ENCRYPTION
        features.append("server-rustls")
        logging.info(
            "TLS enabled: cert=%s key=%s encryption=%s",
            cert_path,
            key_path,
            TLS_ENCRYPTION,
        )
    else:
        logging.info("TLS disabled for this test run")

    cmd = [
        "cargo",
        "run",
        "--example",
        "tds_server_dummy",
        "--features",
        ",".join(features),
    ]

    logging.info("Starting dummy server: %s", " ".join(cmd))
    proc = subprocess.Popen(
        cmd,
        cwd=repo_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        env=server_env,
    )

    stop_evt = threading.Event()
    tail = deque(maxlen=200)

    stdout_thread = threading.Thread(
        target=reader_thread,
        args=(proc.stdout, "[server stdout]", stop_evt, tail),
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=reader_thread,
        args=(proc.stderr, "[server stderr]", stop_evt, tail),
        daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()

    try:
        logging.info("Waiting for server port %s:%s", HOST, PORT)
        deadline = time.time() + STARTUP_TIMEOUT_SECS
        ready = False
        while time.time() < deadline:
            if proc.poll() is not None:
                raise RuntimeError("server exited before opening port")
            try:
                with socket.create_connection((HOST, PORT), timeout=0.5):
                    ready = True
                    break
            except OSError:
                time.sleep(0.2)
        if not ready:
            raise RuntimeError("server did not open port in time")

        logging.info("Connecting with pymssql")
        conn_kwargs = {
            "server": HOST,
            "port": PORT,
            "user": "sa",
            "password": "x",
            "database": "master",
            "tds_version": "7.4",
            "login_timeout": CONNECT_TIMEOUT_SECS,
            "timeout": CONNECT_TIMEOUT_SECS,
        }
        if TLS_ENABLED:
            conn_kwargs["encryption"] = TLS_ENCRYPTION
        try:
            conn = pymssql.connect(**{**conn_kwargs, "use_uuid": True})
        except TypeError:
            logging.info("pymssql connect does not support use_uuid; retrying")
            conn = pymssql.connect(**conn_kwargs)

        try:
            try:
                conn.autocommit(True)
            except AttributeError:
                logging.info("pymssql connection does not support autocommit()")

            cur = conn.cursor()

            basic_sets = execute_and_collect(cur, QUERY, "basic")
            validate_single_value("basic", basic_sets)

            info_sets = execute_and_collect(cur, "SELECT 1 -- tds_info", "tds_info")
            validate_single_value("tds_info", info_sets)

            type_sets = execute_and_collect(cur, "SELECT 1 -- tds_types", "tds_types")
            validate_types("tds_types", type_sets)

            null_sets = execute_and_collect(cur, "SELECT 1 -- tds_nulls", "tds_nulls")
            validate_nulls("tds_nulls", null_sets)

            multi_sets = execute_and_collect(cur, "SELECT 1 -- tds_multi", "tds_multi")
            validate_multi("tds_multi", multi_sets)

            rpc_sets, rpc_seen, out_param, rpc_callproc = run_rpc(cur, tail)
            expect(rpc_seen, "rpc: RPC handler was not observed in server logs")

            validate_rpc_params("rpc_params", rpc_sets)

            rpc_value_set = find_result_set(rpc_sets, "rpc_value")
            if rpc_value_set:
                columns, rows = rpc_value_set
                idx = [col.lower() for col in columns].index("rpc_value")
                expect(rows[0][idx] == 7, f"rpc: unexpected row {rows}")
            else:
                logging.warning("rpc: rpc_value result set not found")

            if rpc_callproc and rpc_callproc[-1] != RPC_OUTPUT_EXPECTED:
                logging.warning("rpc: output param not updated (got %s)", rpc_callproc[-1])

            rpc_out_result, rpc_out_seen = run_rpc_output_only(cur, tail)
            expect(rpc_out_seen, "rpc_out: RPC handler was not observed in server logs")
            expect(
                rpc_out_result[-1] == RPC_OUTPUT_EXPECTED,
                f"rpc_out: output param value {rpc_out_result[-1]}",
            )

            rpc_out_first_sets, rpc_out_first_seen, rpc_out_first_result = run_rpc_output_first(
                cur, tail
            )
            expect(
                rpc_out_first_seen,
                "rpc_out_first: RPC handler was not observed in server logs",
            )
            if rpc_out_first_result[-1] == RPC_OUTPUT_EXPECTED:
                logging.info("rpc_out_first: output param updated with result sets present")
            else:
                logging.warning(
                    "rpc_out_first: output param not updated (got %s)",
                    rpc_out_first_result[-1],
                )
        finally:
            conn.close()

        logging.info("Test completed successfully")
        return 0
    except Exception as exc:  # pylint: disable=broad-except
        logging.error("Test failed: %s", exc)
        logging.error("Server output tail:")
        for line in list(tail):
            logging.error("%s", line)
        dump_lines = tail_file(dump_path, FREETDS_DUMP_LINES)
        if dump_lines:
            logging.error("FreeTDS dump tail:")
            for line in dump_lines:
                logging.error("%s", line)
        return 1
    finally:
        stop_evt.set()
        if proc.poll() is None:
            logging.info("Stopping dummy server (pid=%s)", proc.pid)
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                logging.warning("Server did not exit; killing")
                proc.kill()
        stdout_thread.join(timeout=1)
        stderr_thread.join(timeout=1)


if __name__ == "__main__":
    raise SystemExit(main())
