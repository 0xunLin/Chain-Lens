import http.server
import socketserver
import argparse
import json
import subprocess
from urllib.parse import urlparse, parse_qs

class WebVisualizerHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        # Serve static files from the 'web' directory
        super().__init__(*args, directory="web", **kwargs)
        
    def do_GET(self):
        parsed_url = urlparse(self.path)
        
        # 1. Health Check Endpoint (Required by spec)
        if parsed_url.path == '/api/health':
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"ok": True}).encode('utf-8'))
            
        elif parsed_url.path == '/api/demo':
            try:
                with open('fixtures/transactions/tx_legacy_p2pkh.json', 'r') as f:
                    data = f.read()
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(data.encode('utf-8'))
            except Exception as e:
                self.send_response(500)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"ok": False, "error": {"message": str(e)}}).encode('utf-8'))
                
        elif parsed_url.path == '/api/demo/block':
            try:
                result = subprocess.run(
                    ["python3", "main.py", "--block", "fixtures/blocks/blk04330.dat", "fixtures/blocks/rev04330.dat", "fixtures/blocks/xor.dat"], 
                    capture_output=True, text=True
                )
                output = result.stdout.strip()
                if result.returncode != 0 and not output:
                    output = json.dumps({
                        "ok": False,
                        "error": {
                            "code": "CLI_EXECUTION_ERROR",
                            "message": result.stderr.strip()
                        }
                    })
                    
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(output.encode('utf-8'))
            except Exception as e:
                self.send_response(500)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"ok": False, "error": {"message": str(e)}}).encode('utf-8'))
            
        # 2. Analyze Endpoint (Connecting Frontend to main.py)
        elif parsed_url.path == '/api/analyze':
            query_params = parse_qs(parsed_url.query)
            fixture_id = query_params.get('id', [''])[0]
            mode = query_params.get('mode', ['tx'])[0]
            
            if not fixture_id:
                self.send_error(400, "Missing 'id' parameter")
                return
            
            try:
                if mode == "tx":
                    # Execute the CLI tool safely as a subprocess
                    result = subprocess.run(
                        ["python3", "main.py", fixture_id], 
                        capture_output=True, 
                        text=True
                    )
                    
                    output = result.stdout.strip()
                    
                    # If main.py crashed before it could output JSON, wrap the error
                    if result.returncode != 0 and not output:
                        output = json.dumps({
                            "ok": False,
                            "error": {
                                "code": "CLI_EXECUTION_ERROR",
                                "message": result.stderr.strip()
                            }
                        })
                        
                    self.send_response(200)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(output.encode('utf-8'))
                    
                else:
                    # For a web demo, block mode requires handling multiple file uploads 
                    # (blk, rev, xor) which goes beyond a simple GET request. 
                    # We return a graceful fallback for the UI.
                    self.send_response(200)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({
                        "ok": False, 
                        "error": {
                            "code": "BLOCK_MODE_UNSUPPORTED_ON_WEB", 
                            "message": "Block analysis requires blk.dat, rev.dat, and xor.dat files. Please use the CLI tool for block mode."
                        }
                    }).encode('utf-8'))

            except Exception as e:
                self.send_response(500)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({
                    "ok": False,
                    "error": {"code": "INTERNAL_SERVER_ERROR", "message": str(e)}
                }).encode('utf-8'))
                
        # 3. Static File Fallback
        else:
            super().do_GET()

    def do_POST(self):
        parsed_url = urlparse(self.path)
        
        if parsed_url.path == '/api/analyze/tx':
            try:
                content_len = int(self.headers.get('Content-Length', 0))
                post_data = self.rfile.read(content_len).decode('utf-8')
                data = json.loads(post_data)
                
                with open('tmp_fixture.json', 'w') as f:
                    json.dump(data, f)
                
                result = subprocess.run(
                    ["python3", "main.py", "tmp_fixture.json"], 
                    capture_output=True, text=True
                )
                output = result.stdout.strip()
                if result.returncode != 0 and not output:
                    output = json.dumps({
                        "ok": False,
                        "error": {
                            "code": "CLI_EXECUTION_ERROR",
                            "message": result.stderr.strip()
                        }
                    })
                    
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(output.encode('utf-8'))
                
            except Exception as e:
                self.send_response(500)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({
                    "ok": False,
                    "error": {"code": "INTERNAL_SERVER_ERROR", "message": str(e)}
                }).encode('utf-8'))
                
        elif parsed_url.path == '/api/analyze/block':
            try:
                content_len = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_len)
                
                content_type = self.headers.get("Content-Type", "")
                if "boundary=" not in content_type:
                    raise ValueError("No multipart boundary found in request")
                boundary = content_type.split("boundary=")[1].strip().encode('utf-8')
                
                parts = body.split(b"--" + boundary)
                files = {}
                for part in parts:
                    if not part or part == b"--\r\n" or part == b"--": continue
                    if part.startswith(b"\r\n"): part = part[2:]
                    if b"\r\n\r\n" not in part: continue
                    
                    header_data, content = part.split(b"\r\n\r\n", 1)
                    if content.endswith(b"\r\n"): content = content[:-2]
                    
                    header_str = header_data.decode('utf-8', 'ignore')
                    name = None
                    for line in header_str.split("\r\n"):
                        if line.lower().startswith("content-disposition:"):
                            import re
                            m = re.search(r'name="([^"]+)"', line)
                            if m: name = m.group(1)
                    if name:
                        files[name] = content
                
                required = ['blk_file', 'rev_file', 'xor_file']
                if not all(k in files for k in required):
                    self.send_response(400)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({
                        "ok": False,
                        "error": {"code": "BAD_REQUEST", "message": "Missing block files"}
                    }).encode('utf-8'))
                    return
                    
                with open('tmp_blk.dat', 'wb') as f: f.write(files.get('blk_file', b''))
                with open('tmp_rev.dat', 'wb') as f: f.write(files.get('rev_file', b''))
                with open('tmp_xor.dat', 'wb') as f: f.write(files.get('xor_file', b''))
                
                result = subprocess.run(
                    ["python3", "main.py", "--block", "tmp_blk.dat", "tmp_rev.dat", "tmp_xor.dat"], 
                    capture_output=True, text=True
                )
                
                output = result.stdout.strip()
                if result.returncode != 0 and not output:
                    output = json.dumps({
                        "ok": False,
                        "error": {
                            "code": "CLI_EXECUTION_ERROR",
                            "message": result.stderr.strip()
                        }
                    })
                    
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(output.encode('utf-8'))
                
            except Exception as e:
                self.send_response(500)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({
                    "ok": False,
                    "error": {"code": "INTERNAL_SERVER_ERROR", "message": str(e)}
                }).encode('utf-8'))
                
        else:
            self.send_response(404)
            self.end_headers()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=3000)
    args = parser.parse_args()
    
    print(f"[*] Chain Lens Web Server starting on http://127.0.0.1:{args.port}")
    print("[*] Press CTRL+C to stop.")
    
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", args.port), WebVisualizerHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Shutting down server...")
            httpd.server_close()