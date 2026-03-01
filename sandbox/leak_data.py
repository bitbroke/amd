import os

def leak_data():
    if os.path.exists("secrets.txt"):
        with open("secrets.txt", "rb") as f:
            data = f.read()
            print("Sending data to 1.2.3.4...")

if __name__ == "__main__":
    leak_data()