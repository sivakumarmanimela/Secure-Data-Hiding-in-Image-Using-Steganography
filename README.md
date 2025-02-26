# **Secure Data Hiding in Images Using Steganography**  

This project is a **GUI-based Image Steganography tool** developed using **Python** and **PyQt6**, enabling users to securely hide and retrieve secret messages within images using password protection.  

## **Features**  

✔ **Secure Message Embedding** – Hide text messages inside images without noticeable changes.  
✔ **Password-Protected Decryption** – Only authorized users with the correct password can extract the hidden message.  
✔ **User-Friendly GUI** – Intuitive graphical interface for encryption and decryption.  
✔ **Efficient Image Processing** – Uses OpenCV and NumPy for fast and accurate message embedding.  
✔ **Cross-Platform Compatibility** – Runs on Windows, Linux, and macOS with Python installed.  

## **How It Works**  

### **Encryption Process**  
1️⃣ Select an image for embedding.  
2️⃣ Enter the secret message and set a password.  
3️⃣ The system securely hides the message within the image and saves it.  

### **Decryption Process**  
1️⃣ Load the encrypted image.  
2️⃣ Enter the correct password.  
3️⃣ Retrieve and view the hidden message securely.  

## **Technologies Used**  

✔ **Programming Language:** Python – Implements encryption and decryption logic.  
✔ **Libraries & Frameworks:**  
- **OpenCV** – Handles image processing and message embedding.  
- **NumPy** – Supports array-based operations for efficient computations.
- **Tkinter** – Creates a user-friendly GUI for encryption and decryption.
- **Hashlib** – Provides SHA-256 hashing for password security.
- **Random & String Modules** – Used for generating salts to enhance security.


### **Prerequisites**  
Ensure **Python 3.8+** is installed on your system.  

### **Install Dependencies**  

```sh
pip install opencv-python numpy tkinter hashlib string random
```

### **Run the Application**  

```sh
python main.py
```

## **Screenshots**  


**Main Page**

![Main_Page](https://github.com/user-attachments/assets/96070f4a-33f6-4dec-8461-587e3bece3d0)


**Encryption Output**

![Encryption_Output](https://github.com/user-attachments/assets/a54a1303-014d-4aa6-9c09-be7d307c3916)


**Decryption Output**

![Decryption_Output](https://github.com/user-attachments/assets/79430b1f-0894-4806-9f17-e32c78932ce6)


## **Future Scope**  

✔ **Advanced Encryption** – Integrating AES or RSA encryption for enhanced security.  
✔ **Multi-File Support** – Extending to hide PDFs, audio, or video files within images.  
✔ **AI-Based Steganalysis Prevention** – Improving security against detection techniques.  
✔ **Cloud Storage Integration** – Secure cloud storage for encrypted images.  
✔ **Mobile Application Development** – Creating an Android/iOS version for better accessibility.  
