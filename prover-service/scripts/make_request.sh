#!/bin/bash

if [ $# -ne 2 ]; then
  echo "Usage: ./make_request.sh <host_url> <path/to/input.json>"
  exit 1
fi

curl -i --header "Content-Type: application/json"   --request POST   --data "$(cat $2)" $1/v0/prove
echo ""
