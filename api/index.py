from http.server import BaseHTTPRequestHandler
import html


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        page = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Attack Graph Generator</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                body {
                    font-family: Arial, sans-serif;
                    max-width: 700px;
                    margin: 80px auto;
                    padding: 20px;
                }

                h1 {
                    text-align: center;
                }

                input {
                    width: 100%;
                    padding: 12px;
                    margin: 15px 0;
                    box-sizing: border-box;
                }

                button {
                    width: 100%;
                    padding: 12px;
                    cursor: pointer;
                }

                #result {
                    margin-top: 20px;
                }
            </style>
        </head>

        <body>

            <h1>🛡️ Attack Graph Generator</h1>

            <label>Enter Network</label>

            <input
                id="network"
                type="text"
                placeholder="Example: 192.168.1.0/24"
            >

            <button onclick="startScan()">Start Scan</button>

            <div id="result"></div>

            <script>
                function startScan() {
                    const network = document.getElementById("network").value;
                    const result = document.getElementById("result");

                    if (!network) {
                        result.innerHTML =
                            "<p style='color:red'>Please enter a network.</p>";
                        return;
                    }

                    result.innerHTML =
                        "<p style='color:green'>Network entered: "
                        + network +
                        "</p>";
                }
            </script>

        </body>
        </html>
        """

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(page.encode("utf-8"))
