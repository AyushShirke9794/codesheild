import subprocess
import sqlite3

def run_command(user_input):
    subprocess.call("echo " + user_input, shell=True)

def get_user(username):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchall()
