#!/bin/sh

cleanup() {
  ex=$?
  rm -rf test-tlswrapper-smtp-child.log
  exit "${ex}"
}
trap "cleanup" EXIT TERM INT

PATH="./:${PATH}"
export PATH

tests="short_session
data_resets_envelope
exact_rcpt_limit
line_exact_limit
line_too_long
mailfrom_exact_limit
mailfrom_too_long
mail_resets_previous_rcpts
rcpttodata_exact_limit
rcptto_too_long
rcptto_exact_limit
starttls_available_advertised
starttls_control_pipe_banner
starttls_fresh_transaction
starttls_short_session
starttls_resets_envelope
starttls_unavailable_rejected
too_many_rcpts
rcpttodata_too_large
"

for t in ${tests}; do
  echo "=== ${t} ==="
  python3 test-tlswrapper-smtp.py \
    --child-log test-tlswrapper-smtp-child.log \
    "${t}" 2>&1
  echo
done
