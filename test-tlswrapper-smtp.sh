#!/bin/sh

cleanup() {
  ex=$?
  rm -rf tlswrappernojail-smtp test-tlswrapper-smtp-child.log
  exit "${ex}"
}
trap "cleanup" EXIT TERM INT

PATH="./:${PATH}"
export PATH

rm -f tlswrappernojail-smtp
ln -s tlswrapper-test tlswrappernojail-smtp

tests="short_session
data_resets_envelope
line_too_long
mailfrom_too_long
mail_resets_previous_rcpts
rcptto_too_long
starttls_available_advertised
starttls_control_pipe_banner
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
