#!/bin/sh

tests="client_pings_first
server_pings_first
both_sides_ping_simultaneously
client_half_closes_after_pong
server_half_closes_after_pong
both_sides_half_close_after_pong
server_half_closes_without_sending_data_client_still_writes
client_half_closes_without_sending_data_server_still_writes
server_half_closes_before_any_client_data
client_half_closes_before_any_server_data
both_sides_half_close_without_data
server_half_closes_and_client_sends_large_payload
client_half_closes_and_server_sends_large_payload
both_sides_large_payload
reply_after_client_eof
reply_after_empty_client_eof
remote_silent_close
"

for t in ${tests}; do
  echo "=== ${t} ==="
  python3 test-tlswrapper-tcp.py "${t}" 2>&1
  echo
done
