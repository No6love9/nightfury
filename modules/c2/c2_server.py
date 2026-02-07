from core.base_module import BaseModule
from utils.polymorphic_wrapper import PolymorphicWrapper
from flask import Flask, request, jsonify
import threading

@PolymorphicWrapper.wrap_module
@PolymorphicWrapper.wrap_module
class C2Server(BaseModule):
    def __init__(self, framework):
        super().__init__(framework)
        self.name = "c2_server"
        self.description = "Start a simple C2 server for receiving beacons."
        self.app = Flask(__name__)
        self.beacons = []
        self._setup_routes()

    def _setup_routes(self):
        @self.app.route('/beacon', methods=['POST'])
        def beacon():
            data = request.json
            self.beacons.append(data)
            self.log(f"Received beacon from {request.remote_addr}")
            return jsonify({"status": "received"})

    def run(self, args):
        port = int(args[0]) if args else 8080
        self.log(f"Starting C2 server on port {port}...")
        
        # Run Flask in a separate thread
        thread = threading.Thread(target=lambda: self.app.run(host='0.0.0.0', port=port))
        thread.daemon = True
        thread.start()
        print(f"C2 Server running at http://0.0.0.0:{port}/")
        print("Use Ctrl+C to stop (this will exit the framework in this demo).")
