#!/usr/bin/env python3

import socket
import argparse
import concurrent.futures

import sqlite3
import os
import hashlib

args = argparse.ArgumentParser(description="server")
args.add_argument("addr", action="store", help="ip address")
args.add_argument("port", type=int, action="store", help="port")
args_dict = vars(args.parse_args())


class Server:

    def __init__(self):
        self.conn = sqlite3.connect('users.db')
        self.cursor = self.conn.cursor()

        self.cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY,
                            username TEXT NOT NULL,
                            password TEXT NOT NULL,
                            salt BLOB NOT NULL)''')
        
        self.create_user("admin", "admin")
        
        self.conn.commit()
        self.conn.close()
        
        self.clients = []

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((args_dict["addr"], args_dict["port"]))
        self.sock.listen(100)
    
    @staticmethod
    def hash_password(password, salt):
        """Hash a password with a salt."""
        password = password.encode('utf-8')  # Convert the password to bytes
        salt = salt  # The salt is already a byte string
        return hashlib.pbkdf2_hmac('sha256', password, salt, 100000)  # Hash the password

    def create_user(self, username, password):        
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        salt = os.urandom(16)  # Generate a random salt
        hashed_password = self.hash_password(password, salt)  # Hash the password
        cursor.execute("INSERT INTO users (username, password, salt) VALUES (?, ?, ?)",
                            (username, hashed_password, salt))
        conn.commit()
        conn.close()
    
    def broadcast(self, conn, msg):
        for client in self.clients:
            if client != conn:
                try:
                    client.send(msg.encode())
                except:
                    client.close()
                    self.clients.remove(conn)
                    
    def authenticate_user(self, username, password):
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("SELECT password, salt FROM users WHERE username=?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user:
            hashed_password, salt = user
            if hashed_password == self.hash_password(password, salt):
                return True

        return False
        
    
    def client_handler(self, conn, addr):
        conn.send("Welcome to the chatroom!".encode())
        
        conn.send("Please enter your username and password separated by a space.".encode())
        
        while True:
            try:
                credentials = conn.recv(4096).decode().split()
                if len(credentials) == 2:
                    username, password = credentials
                    if self.authenticate_user(username, password):
                        conn.send("Login successful!".encode())
                        break
                    else:
                        conn.send("Invalid username or password. Please try again.".encode())
                else:
                    conn.send("Invalid input. Please provide username and password separated by a space.".encode())
            except Exception as e:
                print(e)
                continue
        
        conn.send("Connection established".encode())
        
        while True:
            try:
                msg = conn.recv(4096)
                if msg:
                    print(f"<{addr[0]}> {msg}")
                    self.broadcast(conn, f"<{addr[0]}> {msg}")
                else:
                    self.clients.remove(conn)
            except:
                continue

    def execute(self):
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = []
            while True:
                conn, addr = self.sock.accept()
                self.clients.append(conn)
                print(f"{addr[0]} connected")
                futures.append(
                    executor.submit(self.client_handler, conn=conn, addr=addr))


if __name__ == "__main__":
    ser = Server()
    ser.execute()
