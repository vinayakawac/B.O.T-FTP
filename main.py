import tkinter as tk
import subprocess

class MainApp:
    def __init__(self, master):
        self.master = master
        master.title("File Transfer Application")
        master.geometry("300x200")

        self.label = tk.Label(master, text="Choose an option:")
        self.label.pack(pady=10)

        self.send_button = tk.Button(master, text="Start Client", command=self.start_client)
        self.send_button.pack(pady=5)

        self.receive_button = tk.Button(master, text="Start Server", command=self.start_server)
        self.receive_button.pack(pady=5)

    def start_client(self):
        # Start the client script
        subprocess.Popen(['python', 'client.py'])

    def start_server(self):
        # Start the server script
        subprocess.Popen(['python', 'server.py'])

if __name__ == "__main__":
    root = tk.Tk()
    app = MainApp(root)
    root.mainloop()