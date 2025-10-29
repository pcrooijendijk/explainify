#!/bin/sh

python get_CWE.py
python relevant_patch.py
python CWE_runner.py
python read_semgrep.py