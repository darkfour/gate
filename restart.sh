#!/bin/sh
echo "killing..."
pkill -f "gate_server.py"
while pgrep -f "gate_server.py" > /dev/null
do
    echo "waiting..."
    sleep 0.1
done

echo "restarting..."
pypy gate_server.py
