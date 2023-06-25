import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.primitives.asymmetric import ec, dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import time


def perform_key_exchange(protocol, key_size):
    if not key_size:
        messagebox.showerror("Error", "Please select a key size.")
        return

    # Start measuring time
    start_time = time.time()

    if protocol == "ECDH":
        # Generate private key with the selected key size
        curve = ec.SECP256R1()  # Default key size
        if key_size == "384":
            curve = ec.SECP384R1()
        elif key_size == "521":
            curve = ec.SECP521R1()

        private_key = ec.generate_private_key(curve, default_backend())

        # Extract public key
        public_key = private_key.public_key()

        # Serialize public key
        serialized_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Assuming the serialized_public_key is transmitted to the other party

        # Deserialize public key received from the other party
        received_public_key = serialization.load_pem_public_key(
            serialized_public_key,
            backend=default_backend()
        )

        # Generate shared key using own private key and other party's public key
        start_shared_key_time = time.time()
        shared_key = private_key.exchange(ec.ECDH(), received_public_key)
        shared_key_time = time.time() - start_shared_key_time

    elif protocol == "DH":
        # Generate private key with the selected key size
        parameters = dh.generate_parameters(generator=2, key_size=int(key_size), backend=default_backend())
        private_key = parameters.generate_private_key()

        # Extract public key
        public_key = private_key.public_key()

        # Serialize public key
        serialized_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Assuming the serialized_public_key is transmitted to the other party

        # Deserialize public key received from the other party
        received_public_key = serialization.load_pem_public_key(
            serialized_public_key,
            backend=default_backend()
        )

        # Generate shared key using own private key and other party's public key
        start_shared_key_time = time.time()
        shared_key = private_key.exchange(received_public_key)
        shared_key_time = time.time() - start_shared_key_time

    # Convert shared key to integer
    shared_key_int = int.from_bytes(shared_key, "big")

    # Measure key generation speed
    key_generation_time = time.time() - start_time

    # Key size in bytes
    key_size_bytes = len(shared_key)

    # Show performance metrics in the GUI
    messagebox.showinfo(
        "Key Exchange Metrics",
        f"Key Exchange Protocol: {protocol}\n"
        f"Shared Key (bit length): {shared_key_int.bit_length()} bits\n"
        f"Shared Key Size: {key_size_bytes} bytes\n"
        f"Key Generation Speed: {key_generation_time:.6f} seconds\n"
        f"Shared Key Generation Time: {shared_key_time:.10f} seconds"
    )


def main():
    # Create the main window
    window = tk.Tk()
    window.title("Key Exchange GUI")

    # Key Exchange Protocol Dropdown Menu
    protocol_label = tk.Label(window, text="Key Exchange Protocol:")
    protocol_label.pack()

    protocol_var = tk.StringVar(window)
    protocol_var.set("ECDH")  # Default protocol

    protocol_menu = tk.OptionMenu(window, protocol_var, "ECDH", "DH")  # Add more protocols here
    protocol_menu.pack(pady=5)

    # Key Size Dropdown Menu
    key_size_label = tk.Label(window, text="Key Size:")
    key_size_label.pack()

    key_size_var = tk.StringVar(window)
    key_size_var.set("256")  # Default key size

    key_sizes_ecdh = ["256", "384", "521"]
    key_sizes_dh = ["1024", "2048", "3072"]
    key_size_menu = tk.OptionMenu(window, key_size_var, *key_sizes_ecdh)
    key_size_menu.pack(pady=5)

    def update_key_sizes(*args):
        key_size_var.set("256")
        if protocol_var.get() == "ECDH":
            key_size_menu['menu'].delete(0, 'end')
            for key_size in key_sizes_ecdh:
                key_size_menu['menu'].add_command(label=key_size, command=tk._setit(key_size_var, key_size))
        else:
            key_size_menu['menu'].delete(0, 'end')
            for key_size in key_sizes_dh:
                key_size_menu['menu'].add_command(label=key_size, command=tk._setit(key_size_var, key_size))

    protocol_var.trace('w', update_key_sizes)

    # Button to perform the key exchange
    button = tk.Button(window, text="Perform Key Exchange",
                       command=lambda: perform_key_exchange(protocol_var.get(), key_size_var.get()))
    button.pack(pady=10)

    # Run the GUI main loop
    window.mainloop()


if __name__ == "__main__":
    main()
