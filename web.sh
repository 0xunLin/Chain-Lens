#!/bin/bash
# web.sh - Starts the Chain Lens Web Visualizer

# Check if python is available
if ! command -v python3 &> /dev/null; then
    echo "Error: python3 could not be found."
    exit 1
fi

# Set default port if not set
PORT=${PORT:-3000}

echo "Starting Chain Lens Web Visualizer on port $PORT..."
echo "http://127.0.0.1:$PORT"

# Run server.py (Assumes server.py is in the root or same dir as web.sh)
python3 server.py --port $PORT