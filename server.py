from flask import Flask, jsonify, request
import sqlite3
import os
from datetime import datetime
import uuid
import secrets

app = Flask(__name__)
DATABASE = "task_manager.db"

def init_db():
	if not os.path.exists(DATABASE):
		conn = sqlite3.connect(DATABASE)
		c = conn.cursor()

		# create users table
		c.execute('''CREATE TABLE users (
			username TEXT PRIMARY KEY,
			password TEXT NOT NULL,
			role TEXT NOT NULL
			) 
			''')

		# Create Tasks table
		c.execute(''' CREATE TABLE tasks (
			id TEXT PRIMARY KEY,
			title TEXT NOT NULL,
			description TEXT,
			created_date TEXT,
			deadline TEXT,
			priority TEXT,
			assignee TEXT,
			status TEXT,
			FOREIGN KEY (assignee) REFERENCES users(username)
			)
			''')
		c.execute('''CREATE TABLE tokens (
			token TEXT PRIMARY KEY,
			username TEXT NOT NULL,
			created_date TEXT NOT NULL,
			FOREIGN KEY (username) REFERENCES users(username)
			)''')
		# Insert Default admin user
		c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ('admin', 'admin123', 'admin'))
		conn.commit()
		conn.close()

def get_db():
	conn = sqlite3.connect(DATABASE)
	conn.row_factory = sqlite3.Row
	return conn

def validate_token(token):
	conn = get_db()
	c = conn.cursor()
	c.execute("SELECT users.username, role, created_date FROM tokens JOIN users ON tokens.username = users.username WHERE token = ?", (token,))
	user = c.fetchone()
	if user:
		created_at = datetime.strptime(user[2], "%Y-%m-%d %H:%M:%S")
		if (datetime.now() - created_at).total_seconds() == 28800:
			c.execute("DELETE FROM tokens WHERE token= ?",(token,))
			conn.commit()
			user = None
	conn.close()
	return user if user else None


@app.route("/login", methods=["POST"])
def login():
	data = request.json
	username = data.get("username")
	password = data.get("password")
	if not username or not password:
		return jsonify({"error":"User name and password required"}), 400
	conn = get_db()
	c = conn.cursor()
	c.execute("SELECT * FROM users WHERE username = ? and password = ?", (username, password))
	user = c.fetchone()
	if not user:
		conn.close()
		return jsonify({"error":"Invalid credential"}), 401
	token = secrets.token_hex(16)
	c.execute("INSERT INTO tokens (token, username, created_date) VALUES (?, ?, ?)", (token, username, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
	conn.commit()
	conn.close()
	return jsonify({"token":token, "username":username, "role":user['role'] }), 200



@app.route("/register", methods=["POST"])
def register():
	token = request.headers.get("token")
	user = validate_token(token)
	if not user or user['role'] != "admin":
		return jsonify({"error":"admin access required"}), 403

	data = request.json
	username = data.get("username")
	password = data.get("password")
	role = data.get("role", "team").lower()
	if not user or not password:
		return jsonify({"error":"Username and password required"}), 400
	if role not in ["admin", "team"]:
		return jsonify({"error":"Invalid role, user admin or team"})
	conn = get_db()
	c = conn.cursor()
	try:
		c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, password, role))
		conn.commit()
	except sqlite3.IntegrityError:
		conn.close()
		return jsonify({"error":"Username already exists."}), 400
	conn.close()
	return jsonify({"Message":"User register successfuly"}), 201




@app.route("/tasks", methods=["POST"])
def create_task():
	token = request.headers.get("token")
	user = validate_token(token)
	if not user or user['role'] != "admin":
		return jsonify({"error":"Admin access required."}), 403
	data = request.json
	title = data.get("title")
	if not title:
		return jsonify({"error":"Title can not be empty."}), 400
	task = {
	"id": str(uuid.uuid4()),
	"title": title,
	"description": data.get("description", ""),
	"created_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
	"deadline": data.get("deadline", ""),
	"priority": data.get("priority", "medium").lower(),
	"assignee": data.get("assignee", ""),
	"status": data.get("status", "pending").lower()
	}
	if task['priority'] not in ['low','medium','high']:
		task['priority'] = 'medium'

	if task['deadline']:
		try:
			datetime.strptime(task['deadline'], "%Y-%m-%d")
		except ValueError:
			return jsonify({"error": "Invalid date format, use YYYY-MM-DD"}), 400
	conn = get_db()
	c = conn.cursor()
	c.execute("""INSERT INTO tasks (id, title, description, created_date, deadline, priority, assignee, status)
	 	VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
		(task["id"], task["title"], task["description"], task["created_date"],
        task["deadline"], task["priority"], task["assignee"], task["status"]))
	conn.commit()
	conn.close()
	return jsonify({"Message": "Task craeted", "task": task}), 201

@app.route("/tasks", methods=["GET"])
def get_task():
	token = request.headers.get("token")
	user = validate_token(token)
	if not user:
		return jsonify({"error":"Invalid token."}), 401
	conn = get_db()
	c = conn.cursor()
	if user['role'] == "admin":
		c.execute("SELECT * FROM tasks")
	else:
		c.execute("SELECT * FROM tasks WHERE assignee = ?", (user['username'],))
	task = [dict(row) for row in c.fetchall()]
	conn.close()
	return jsonify(task),  200

@app.route("/tasks/<id>", methods=["PUT"])
def update_task(id):
	token = request.headers.get("token")
	user = validate_token(token)
	if not user:
		return jsonify({"error": "Invalid token"}), 401
	conn = get_db()
	c = conn.cursor()
	c.execute("SELECT * FROM tasks WHERE id = ?", (id,))
	task = c.fetchone()
	if not task:
		conn.close()
		return jsonify({"error":"Task not found"}), 404
	task = dict(task)
	is_admin = user["role"] == "admin"
	if not is_admin and task["assignee"] != user["username"]:
		conn.close()
		return jsonify({"error": "access denied"}), 403
	data = request.json
	title = data.get("title", task["title"] if is_admin else task["title"])
	if not title:
		conn.close()
		return jsonify({"error":"Title required"}), 400
	deadline = data.get("deadline", task["deadline"]) if is_admin else task["deadline"]
	if deadline:
		try:
			datetime.strptime(deadline, "%Y-%m-%d")
		except ValueError:
			conn.close()
			return jsonify({"error": "Invalid date format, use YYYY-MM-DD"}), 400
	priority = data.get("priority", task["priority"]).lower() if is_admin else task["priority"]
	if priority not in ["low", "medium", "high"]:
		priority = "medium"
	c.execute("""UPDATE tasks SET title = ?, description = ?, deadline = ?, priority = ?, assignee = ?, status = ?
                 WHERE id = ?""",
                 (title, data.get("description", task["description"]),
                  deadline, priority, data.get("assignee", task["assignee"]) if is_admin else task["assignee"],
                  data.get("status", task["status"]).lower(), id))
	conn.commit()
	conn.close()
	return jsonify({"Message":"Task updated"}), 200

@app.route("/tasks/<id>", methods=["DELETE"])
def delete_task(id):
	token = request.headers.get("token")
	user = validate_token(token)
	if not user or user["role"] != "admin":
		return jsonify({"error": "admin access required."}), 403
	conn = get_db()
	c = conn.cursor()
	c.execute("SELECT * FROM tasks WHERE id = ?", (id,))
	if not c.fetchone():
		return jsonify({"error":"Task not found"}), 404
	c.execute("DELETE FROM tasks WHERE id = ?", (id,))
	conn.commit()
	conn.close()
	return jsonify({"Message":"Task deleted successfuly"}), 200



if __name__ == "__main__":
	init_db()
	app.run(debug=True, host="0.0.0.0", port=5000)