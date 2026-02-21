import os


# This app reads a file and sends it over a socket
def leak_data():
    if os.path.exists("secrets.txt"):
        with open("secrets.txt", "rb") as f:
            f.read()
            # Fake network connection
            print("Sending data to 1.2.3.4...")


if __name__ == "__main__":
    leak_data()
