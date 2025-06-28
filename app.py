import tkinter as tk
from tkinter import ttk, messagebox
import requests
from datetime import datetime


API_BASE_URL = "http://localhost:5000"

class LginWindow:
	def __init__(self, root, on_success):
		self.root = root
		self.on_success = on_success
		self.root.title("Login")
		self.root.geometry("300x200")
		self.root.configure(bg="#f0f2f5")

		# UI
		frame = tk.Frame(self.root, bg="#f0f2f5")
		frame.pack(padx=20, pady=20, fill="both", expand=True)

		tk.Label(frame, text="Username", bg="#f0f2f5").grid(row=0, column=0, padx=5, pady=5, sticky='e')
		self.username_entry = ttk.Entry(frame)
		self.username_entry.grid(row=0, column=1, padx=5, pady=5, sticky='ew')

		tk.Label(frame, text="Password", bg="#f0f2f5").grid(row=1, column=0, padx=5, pady=5, sticky="e")
		self.password_entry = ttk.Entry(frame, show="*")
		self.password_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")

		ttk.Button(frame, text="Login", command=self.login).grid(row=2, column=0, columnspan=2, pady=10)
		frame.columnconfigure(1, weight=1)

		self.root.bind("<Return>", lambda event: self.login())


	def login(self):
		username = self.username_entry.get().strip()
		password = self.password_entry.get().strip()
		try:
			response = requests.post(f"{API_BASE_URL}/login", json= {"username": username, "password":password})
			data = response.json()
			if response.status_code == 200:
				self.on_success(data['username'], data['role'], data['token'])
				self.root.withdraw()
			else:
				messagebox.showerror("Error", data.get("error","login failed"))
		except requests.RequestException as e:
			messagebox.showerror("Error", f"Failed to connect to server {e}")


class TaskManagerApp:

	def __init__(self, root, username, role, token):
		self.root = root
		self.username = username
		self.role = role
		self.token = token
		self.root.title("Task Manager")
		self.root.geometry("800x600")
		self.root.configure(bg="#f0f2f5")


		# Style configuration
		style = ttk.Style()
		style.theme_use("clam")
		style.configure("Custon.TButton", padding=10, font=("Helvetica", 10), background="#4e73df", foreground="white")
		style.map("Custon.TButton",  background=[("active", "#3b5bdb")])
		style.configure("Treeview.Heading", font=("Helvetica", 10, "bold"), background="#dfe4ea")
		style.configure("Treeview", rowheight=25, font=("Helvetica", 9))
		style.configure("TLabel", font=("Helvetica", 10), background="#f0f2f5")
		style.configure("Custon.TEntry", padding=5)

		# Main containerr
		self.container = tk.Frame(self.root, bg="#f0f2f5")
		self.container.pack(padx=20, pady=20, fill="both", expand=True)

		header_frame = tk.Frame(self.container, bg="#f0f2f5")
		header_frame.pack(pady=10, fill="x")
		tk.Label(header_frame, text="Task Manager", font=("Helvetica", 18, "bold"), bg="#f0f2f5", fg="#2d3436").pack(side="left")
		tk.Label(header_frame, text=f"Logged in as: {self.username}", font=("Helvetica", 10), bg="#f0f2f5", fg="#2d3436").pack(side="right", padx=10)


		# Filte frame
		filter_frame = tk.Frame(self.container, bg="#f0f2f5")
		filter_frame.pack(fill="x", padx=10)


		# Filter Combobox
		self.filter_combo = ttk.Combobox(filter_frame, values=["all", "pending", "in-progress", "completed"], state="readonly")
		self.filter_combo.set("all")
		self.filter_combo.pack(side="right", padx=5)
		tk.Label(filter_frame, text="filter by status:", bg="#f0f2f5" ).pack(side="right")
		self.filter_combo.bind("<<ComboboxSelected>>", lambda event: self.refresh_tasks())


		# Task Treeview
		self.tree = ttk.Treeview(self.container, columns=("ID", "Title", "Status", "Priority", "Assignee", "Deadline"), show="headings")
		self.tree.heading("ID", text="ID")
		self.tree.heading("Title", text="Title")
		self.tree.heading("Status", text="Status")
		self.tree.heading("Priority", text="Priority")
		self.tree.heading("Assignee", text="Assignee")
		self.tree.heading("Deadline", text="Deadline")
		self.tree.column("ID", width=50, anchor="center")
		self.tree.column("Title", width=150)
		self.tree.column("Status", width=100)
		self.tree.column("Priority", width=100)
		self.tree.column("Assignee", width=100)
		self.tree.column("Deadline", width=100)
		self.tree.pack(pady=10, expand=True, fill="both")
		self.tree.bind("<Double-1>", self.edit_task_popup)
		self.refresh_tasks()

		header_frame1 = tk.Frame(self.container, bg="#f0f2f5")
		header_frame1.pack(pady=5, fill="x")

		tk.Label(header_frame1, text="Create Task", font=("Helvetica", 13, "bold"), bg="#f0f2f5", fg="#2d3436").pack(anchor="center", pady=5)
		
		# Input Frame
		input_frame = tk.Frame(self.container, bg="#f0f2f5")
		input_frame.pack(pady=10, fill="x")

		# Input Fields
		tk.Label(input_frame, text="Title:", bg="#f0f2f5").grid(row=0, column=0, padx=5, sticky="e")
		self.title_entry = ttk.Entry(input_frame, style="Custom.TEntry")
		self.title_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

		tk.Label(input_frame, text="Description:", bg="#f0f2f5").grid(row=1, column=0, padx=5, sticky="e")
		self.desc_entry = ttk.Entry(input_frame, style="Custom.TEntry")
		self.desc_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")

		tk.Label(input_frame, text="Deadline (YYYY-MM-DD):", bg="#f0f2f5").grid(row=0, column=2, padx=5, sticky="e")
		self.deadline_entry = ttk.Entry(input_frame, style="Custom.TEntry")
		self.deadline_entry.grid(row=0, column=3, padx=5, pady=5, sticky="ew")

		tk.Label(input_frame, text="Priority:", bg="#f0f2f5").grid(row=1, column=2, padx=5, sticky="e")
		self.priority_combo = ttk.Combobox(input_frame, values=["low", "medium", "high"], state="readonly")
		self.priority_combo.set("medium")
		self.priority_combo.grid(row=1, column=3, padx=5, pady=5, sticky="ew")

		tk.Label(input_frame, text="Assignee:", bg="#f0f2f5").grid(row=0, column=4, padx=5, sticky="e")
		self.assignee_entry= ttk.Entry(input_frame, style="Custom.TEntry")
		self.assignee_entry.grid(row=0, column=5, padx=5, pady=5, sticky="ew")
		if self.role != "admin":
			self.assignee_entry.configure(state="disabled")

		self.root.bind("<Return>", lambda event: self.create_task() if self.role == "admin" else None)

		input_frame.columnconfigure(1, weight=1)
		input_frame.columnconfigure(3, weight=1)
		input_frame.columnconfigure(5, weight=1)

		# Button Frame
		button_frame = tk.Frame(self.container, bg="#f0f2f5")
		button_frame.pack(pady=10)
		if self.role == "admin":
			ttk.Button(button_frame, text="Add Task", style="Custom.TButton", command=self.create_task).pack(side="left", padx=5)
			ttk.Button(button_frame, text="Delete Selected", style="Custom.TButton", command=self.delete_task).pack(side="left", padx=5)
			ttk.Button(button_frame, text="Register Users", style="Custom.TButton", command=self.register_user_popup).pack(side="left", padx=5)
		ttk.Button(button_frame, text="Clear Fields", style="Custom.TButton", command=self.clear_fields).pack(side="left", padx=5)
		ttk.Button(button_frame, text="Logout", style="Custom.TButton", command=self.logout).pack(side="left", padx=5)



	def logout(self):
		self.root.withdraw()
		login = LginWindow(self.root, self.start_app)
		self.root.deiconify()



	def refresh_tasks(self):
		for item in self.tree.get_children():
			self.tree.delete(item)
		try:
			response = requests.get(f"{API_BASE_URL}/tasks", headers = {"Token":self.token})
			if response.status_code == 200:
				tasks = response.json()
				filter_status = self.filter_combo.get()
				for task in tasks:
					if filter_status == "all" or task["status"] == filter_status:
						self.tree.insert("", tk.END, values=(
							task.get('id', 'N/A')[:8],
							task.get('title', ''),
							task.get('status', 'pending'),
							task.get('priority', ''),
							task.get('assignee', ''),
							task.get('deadline', '')
							))
			else:
				messagebox.showerror("error", response.json().get("error","Failed to load tasks"))
		except requests.RequestException as e:
			messagebox.showerror('error', f"Failed to connect to server: {e}")




	def create_task(self):
		if self.role != "admin":
			messagebox.showerror("error","Only admin can create tasks")
			return
		title = self.title_entry.get().strip()
		description = self.desc_entry.get().strip()
		deadline = self.deadline_entry.get().strip()
		priority = self.priority_combo.get().strip().lower()
		assignee = self.assignee_entry.get().strip()

		if not title:
			messagebox.showerror("Error", "Title can not be empty")
			return
		if deadline:
			try:
				datetime.strptime(deadline, "%Y-%m-%d")
			except ValueError:
				messagebox.showerror("Error", "Invalid date format. use YYYY-MM-DD")
				return
		if priority not in ['low', 'medium', 'high']:
			priority = 'medium'

		try:
			response = requests.post(f"{API_BASE_URL}/tasks", headers={"Token": self.token}, json={
				"title": title,
				"description": description,
				"deadline": deadline,
				"priority": priority,
				"assignee": assignee,
				"status": "pending"
			})
			if response.status_code == 201:
				self.refresh_tasks()
				self.clear_fields()
				messagebox.showinfo("Success", "Task added successfully")
			else:
				messagebox.showerror("error", response.json().get("error", "failed to create task"))
		except requests.RequestException as e:
			messagebox.showerror("Error", f"Failed to connect to sever {e}")



	def edit_task_popup(self, event):
		selected = self.tree.selection()
		if not selected:
			return

		item = self.tree.item(selected[0])
		task_id = item['values'][0]
		try:
			response = requests.get(f"{API_BASE_URL}/tasks", headers={"Token":self.token})
			if response.status_code != 200:
				messagebox.showerror("error", response.json().get("error","Failed to load tasks"))
				return
			tasks = response.json()
			task = next((t for t in tasks if t["id"][:8] == task_id), None)
			if not task:
				return
		except requests.RequestException as e:
			messagebox.showerror("error", f"Failed to connect to server {e}")
			return

		popup = tk.Toplevel(self.root)
		popup.title("Edit Task")
		popup.geometry("300x400")
		popup.configure(bg='#f0f2f5')
		popup.transient(self.root)
		popup.grab_set()

		tk.Label(popup, text='Edit Task', font=('Helvetica', 10, 'bold'), bg='#f0f2f5').pack(pady=10)

		frame = tk.Frame(popup, bg='#f0f2f5')
		frame.pack(padx=20, pady=10, fill='x')

		tk.Label(frame, text="Title:", bg="#f0f2f5").grid(row=0, column=0, padx=5, sticky="e")
		title_entry = ttk.Entry(frame)
		title_entry.insert(0, task.get('title', ''))
		title_entry.grid(row=0, column=1, padx=5, sticky="ew")
		if self.role != "admin":
			title_entry.configure(state="disabled")

		tk.Label(frame, text="Description:", bg="#f0f2f5").grid(row=1, column=0, padx=5, sticky="e")
		desc_entry = ttk.Entry(frame)
		desc_entry.insert(0, task.get('description', ''))
		desc_entry.grid(row=1, column=1, padx=5, sticky="ew")

		tk.Label(frame, text="Deadline:", bg="#f0f2f5").grid(row=2, column=0, padx=5, sticky="e")
		deadline_entry = ttk.Entry(frame)
		deadline_entry.insert(0, task.get('deadline', ''))
		deadline_entry.grid(row=2, column=1, padx=5, sticky="ew")
		if self.role != "admin":
			deadline_entry.configure(state="disabled")

		tk.Label(frame, text="Priority:", bg="#f0f2f5").grid(row=3, column=0, padx=5, sticky="e")
		priority_combo = ttk.Combobox(frame, values=["low", "medium", "high"], state="readonly")
		priority_combo.set(task.get('priority', 'medium'))
		priority_combo.grid(row=3, column=1, padx=5, sticky="ew")
		if self.role != "admin":
			priority_combo.configure(state="disabled")

		tk.Label(frame, text="Assignee:", bg="#f0f2f5").grid(row=4, column=0, padx=5, sticky="e")
		assignee_entry = ttk.Entry(frame)
		assignee_entry.insert(0, task.get('assignee', ''))
		assignee_entry.grid(row=4, column=1, padx=5, sticky="ew")
		if self.role != "admin":
			assignee_entry.configure(state="disabled")

		tk.Label(frame, text="Status:", bg="#f0f2f5").grid(row=5, column=0, padx=5, sticky="e")
		status_combo = ttk.Combobox(frame, values=["pending", "in-progress", "completed"], state="readonly")
		status_combo.set(task.get('status', 'pending'))
		status_combo.grid(row=5, column=1, padx=5, sticky="ew")

		popup.bind("<Return>", lambda event: save_edit())

		frame.columnconfigure(1, weight=1)

		def save_edit():
			if self.role != "admin" and task.get("assignee") != self.username:
				messagebox.showerror("error", "You can Only edit your own tasks")
				return
			title = title_entry.get().strip() if self.role == "admin" else task.get("title","")
			if not title:
				messagebox.showerror("Error", "Title cannot be empty.")
				return
            
			deadline = deadline_entry.get().strip()
			if deadline:
				try:
					datetime.strptime(deadline, "%Y-%m-%d")
				except ValueError:
					messagebox.showerror("Error", "Invalid deadline format (use YYYY-MM-DD).")
					return
            
			try:
				response = requests.put(f"{API_BASE_URL}/tasks/{task['id']}", headers={"Token": self.token}, 
					json={
						'title': title,
						'description': desc_entry.get().strip(),
						'deadline': deadline,
						'priority': priority_combo.get().lower(),
						'assignee': assignee_entry.get().strip(),
						'status': status_combo.get().lower()
					})
				if response.status_code == 200:
					self.refresh_tasks()
					popup.destroy()
					messagebox.showinfo("Success", "Task updated successfully.")
				else:
					messagebox.showerror("Error", response.json().get("error", "Failed to update task"))
			except requests.RequestException as e:
				messagebox.showerror("Error", f"Failed to connect to server: {e}")

		ttk.Button(popup, text="Save", command=save_edit).pack(pady=10)
		ttk.Button(popup, text="Cancel", command=popup.destroy).pack(pady=5)
		

	def delete_task(self):
		if self.role != "admin":
			messagebox.showerror("Error", "Only admins can delete tasks")
			return
		selected = self.tree.selection()
		if not selected:
			messagebox.showwarning("Warning", "Select a task to delete")
			return
		if not messagebox.askyesno("Confirm", "Delete selected task?"):
			return
		task_id = self.tree.item(selected[0])["values"][0]
		try:
			response = requests.get(f"{API_BASE_URL}/tasks", headers={"Token": self.token})
			if response.status_code != 200:
				messagebox.showerror("Error", response.json().get("error", "Failed to fetch tasks"))
				return
			tasks = response.json()
			task = next((t for t in tasks if t["id"][:8] == task_id), None)
			if not task:
				messagebox.showerror("Error", "Task not found")
				return
			response = requests.delete(f"{API_BASE_URL}/tasks/{task['id']}", headers={"Token": self.token})
			if response.status_code == 200:
				self.refresh_tasks()
				messagebox.showinfo("Success", "Task deleted successfully")
			else:
				messagebox.showerror("Error", response.json().get("error", "Failed to delete task"))
		except requests.RequestException as e:
			messagebox.showerror("Error", f"Failed to connect to server: {e}")


	def register_user_popup(self):
		popup = tk.Toplevel(self.root)
		popup.title("Register")
		popup.geometry("300x300")
		popup.configure(bg="#f0f2f5")
		popup.transient(self.root)
		popup.grab_set()

		tk.Label(popup, text="Register new user", font=("Helvetica", 12, "bold"), bg="#f0f2f5").pack(pady=10)
		frame = tk.Frame(popup, bg="#f0f2f5")
		frame.pack(padx=20, pady=20, fill="x")

		tk.Label(frame, text="Username:", bg="#f0f2f5").grid(column=0, row=0, padx=5, sticky="e")
		username_entry = ttk.Entry(frame, style="Custom.TEntry")
		username_entry.grid(row=0, column=1, padx=5, sticky="ew")

		tk.Label(frame, text="Password:", bg="#f0f2f5").grid(row=1, column=0, padx=5, sticky="e")
		password_entry = ttk.Entry(frame, show="*", style="Custom.TEntry")
		password_entry.grid(row=1, column=1, padx=5, sticky="ew")

		tk.Label(frame, text="Role:", bg="#f0f2f5").grid(row=2, column=0, padx=5, sticky="e")
		role_combo = ttk.Combobox(frame, values=["admin", "team"], state="readonly")
		role_combo.set("team")
		role_combo.grid(row=2, column=1, padx=5, sticky="ew")

		popup.bind("<Return>", lambda event: save_user())

		frame.columnconfigure(1, weight=1)

		def save_user():
			username = username_entry.get().strip()
			password = password_entry.get().strip()
			role = role_combo.get().lower()

			if not username or not password:
				messagebox.showerror("error","Username and password can not be empty")
				return
			if len(password) < 8 or not any(c.isupper() for c in password) or not any(c.isdigit() for c in password):
				messagebox.showerror("error","password must be atleast 8 characters with upper case and digits")
				return
			try:
				response = requests.post(
					f"{API_BASE_URL}/register",
					headers={"Token":self.token},
					json={"username": username, "password":password, "row":role}
					)
				if response.status_code == 201:
					popup.destroy()
					messagebox.showinfo("Message", "User registered successfully")
				else:
					messagebox.showerror("error", response.json().get("error", "failed to register user"))
			except requests.RequestException as e:
				messagebox.showerror("error", f"Failed to connect to server {e}")
		ttk.Button(frame, text="Register", style="Custom.TButton", command=save_user).grid(row=3, column=0, columnspan=2, pady=10)
		ttk.Button(frame, text="Cancel", style="Custom.TButton", command=popup.destroy).grid(row=4, column=0, columnspan=2, pady=5)


	def clear_fields(self):
		self.title_entry.delete(0, tk.END)
		self.desc_entry.delete(0, tk.END)
		self.priority_combo.set("medium")
		self.deadline_entry.delete(0, tk.END)
		if self.role == "admin":
			self.assignee_entry.delete(0, tk.END)

if __name__ == "__main__":
	root = tk.Tk()
	def start_app(username, role, token):
		root.withdraw()
		app = TaskManagerApp(tk.Tk(), username, role, token)
		root.deiconify()
	login = LginWindow(root, start_app)
	root.mainloop()