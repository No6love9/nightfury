from core.base_module import BaseModule
import pysher
import json
import time
import logging
import sys

# Disable pysher logging to keep output clean
logging.getLogger('pysher').setLevel(logging.ERROR)

class RunehallChat(BaseModule):
    def __init__(self, framework):
        super().__init__(framework)
        self.name = "runehall_chat"
        self.description = "Real-time chat scraper for Runehall.com using Pusher."
        self.pusher_key = "c5skPydW39Ukn2q1F5QUm4RD"
        self.pusher = None
        self.active = False

    def handle_message(self, *args, **kwargs):
        """Callback for chat messages."""
        try:
            data = json.loads(args[0])
            # The structure depends on the event, but usually has user and message
            user = data.get('user', {}).get('username', 'Unknown')
            message = data.get('message', '')
            timestamp = time.strftime('%H:%M:%S')
            
            print(f"[{timestamp}] \033[94m{user}\033[0m: {message}")
            
            # Optionally log to file
            with open("runehall_chat.log", "a") as f:
                f.write(f"[{timestamp}] {user}: {message}\n")
                
        except Exception as e:
            # self.log(f"Error parsing message: {str(e)}", "error")
            pass

    def run(self, args):
        self.log("Initializing Runehall Chat Scraper...")
        self.pusher = pysher.Pusher(self.pusher_key)

        def connect_handler(data):
            self.log("Connected to Runehall Pusher service.")
            channel = self.pusher.subscribe('general_chat')
            channel.bind('message', self.handle_message)
            self.log("Subscribed to 'general_chat' channel.")

        self.pusher.connection.bind('pusher:connection_established', connect_handler)
        self.pusher.connect()

        self.log("Scraper active. Press Ctrl+C to stop.")
        self.active = True
        
        try:
            while self.active:
                time.sleep(1)
        except KeyboardInterrupt:
            self.log("Stopping scraper...")
            self.pusher.disconnect()
            self.active = False
