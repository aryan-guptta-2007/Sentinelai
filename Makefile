SHELL := /bin/bash
VENV := .venv
PY := $(VENV)/bin/python

.PHONY: install run demo dashboard report status test test-linux test-systemd clean

install:
	bash utils/setup.sh

run:
	$(PY) sentinel.py run

demo:
	$(PY) sentinel.py demo

dashboard:
	$(PY) sentinel.py dashboard

report:
	$(PY) sentinel.py report

status:
	$(PY) sentinel.py status

test:
	$(PY) -m pytest -q

test-linux:
	docker build -f docker/test.Dockerfile -t sentinelai-test .
	docker run --rm --cap-add NET_ADMIN --cap-add SYS_PTRACE sentinelai-test

test-systemd:
	bash tests/linux/run_systemd.sh

clean:
	rm -rf $(VENV) data/demo logs/demo reporter-output/reports/*.html
