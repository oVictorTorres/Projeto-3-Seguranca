#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo "Uso: $0 <pdf-assinado> [pdf-estrutural-adulterado]" >&2
  exit 1
fi

input_path=$1
output_path=${2:-}

if [ ! -f "$input_path" ]; then
  echo "Arquivo nao encontrado: $input_path" >&2
  exit 1
fi

if [ -z "$output_path" ]; then
  directory=$(dirname -- "$input_path")
  filename=$(basename -- "$input_path")
  name=${filename%.*}
  output_path="$directory/$name-estrutural-adulterado.pdf"
fi

python3 - "$input_path" "$output_path" <<'PY'
import datetime
import re
import sys
from pathlib import Path

input_path = Path(sys.argv[1])
output_path = Path(sys.argv[2])
data = input_path.read_bytes()

if not data.startswith(b"%PDF-"):
    raise SystemExit(f"Arquivo nao parece ser um PDF valido: {input_path}")

start_matches = list(re.finditer(rb"startxref\s+(\d+)\s+%%EOF", data, re.DOTALL))
if not start_matches:
    raise SystemExit("Nao foi possivel localizar startxref/%%EOF no PDF.")

last_start = start_matches[-1]
previous_startxref = int(last_start.group(1))
prefix = data[:last_start.start()]

trailer_matches = list(re.finditer(rb"trailer\s*<<(.*?)>>", prefix, re.DOTALL))
if not trailer_matches:
    raise SystemExit("PDF com trailer classico nao encontrado. Este script didatico nao manipula xref stream.")

trailer = trailer_matches[-1].group(1)
size_match = re.search(rb"/Size\s+(\d+)", trailer)
root_match = re.search(rb"/Root\s+(\d+)\s+(\d+)\s+R", trailer)
if not size_match or not root_match:
    raise SystemExit("Trailer PDF sem /Size ou /Root reconhecivel.")

new_object_number = int(size_match.group(1))
root_object = root_match.group(1).decode("ascii")
root_generation = root_match.group(2).decode("ascii")
new_object_offset = len(data)
xref_offset = new_object_offset
timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%S")

id_line = ""
id_match = re.search(rb"/ID\s*(\[[^\]]+\])", trailer, re.DOTALL)
if id_match:
    id_line = f"/ID {id_match.group(1).decode('latin-1')}\n"

encrypt_line = ""
encrypt_match = re.search(rb"/Encrypt\s+(\d+)\s+(\d+)\s+R", trailer)
if encrypt_match:
    encrypt_line = (
        f"/Encrypt {encrypt_match.group(1).decode('ascii')} "
        f"{encrypt_match.group(2).decode('ascii')} R\n"
    )

incremental_update = f"""
% demo-adulteracao-estrutural: revisao incremental apos assinatura
{new_object_number} 0 obj
<<
/Producer (tamper-pdf-structure demo)
/ModDate (D:{timestamp}Z)
/TamperDemo (Structural incremental update after signature)
>>
endobj
xref
{new_object_number} 1
{new_object_offset:010d} 00000 n 
trailer
<<
/Size {new_object_number + 1}
/Root {root_object} {root_generation} R
/Info {new_object_number} 0 R
{id_line}{encrypt_line}/Prev {previous_startxref}
>>
startxref
{xref_offset}
%%EOF
""".encode("latin-1")

output_path.write_bytes(data + incremental_update)
print(f"PDF com adulteracao estrutural gerado em: {output_path}")
PY
