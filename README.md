# Secure AES Encryption & Decryption

This web application allows users to **securely encrypt and decrypt text** using **AES (Advanced Encryption Standard)** encryption. It provides a simple and secure interface for protecting sensitive information with a password-based system.

## How It Works

1. **Encryption**: 
   - The user enters the **plain text** and a **secret password**.
   - The application uses the **AES encryption algorithm** to securely encrypt the text.
   - The encrypted text is then displayed, which can only be decrypted using the same secret password.

2. **Decryption**: 
   - The user enters the **encrypted text** and the **secret password**.
   - The application uses the **AES decryption algorithm** to restore the original text, as long as the correct password is provided.

## Technologies Used

### **AES (Advanced Encryption Standard)**

- **AES** is a widely used symmetric encryption algorithm that operates on blocks of data (typically 128 bits) and can use key sizes of **128**, **192**, or **256 bits**. 
- It is used for both **encryption** and **decryption** with the same key, making it efficient for scenarios where both encryption and decryption are required.
- AES provides strong security and is commonly used in various fields such as banking, communications, and data storage.

### **CryptoJS Library**

- **CryptoJS** is a popular JavaScript library that provides several cryptographic algorithms, including AES, SHA-1, SHA-256, and more.
- In this project, we use the **AES encryption** and **AES decryption** functions provided by **CryptoJS** to secure and restore the data.
- The library is implemented on the client-side, meaning all encryption and decryption happen in the user's browser, ensuring that sensitive data does not leave the user's machine.

### **JavaScript**

- JavaScript is used to handle the logic for both **encryption** and **decryption** operations. 
- It manages the interaction with the user interface, accepts input (plain text, encrypted text, and password), and then calls the appropriate AES functions from **CryptoJS**.
- The JavaScript code ensures the proper handling of user data, the encryption process, and displaying the encrypted/decrypted results.

## How to Use

### Encrypt Text
1. Enter the text you want to encrypt.
2. Provide a secret password.
3. Click the **Encrypt** button to encrypt the text.

### Decrypt Text
1. Paste the encrypted text into the input field.
2. Provide the same secret password used for encryption.
3. Click the **Decrypt** button to reveal the original text.

## How to Set Up Locally

1. Clone the repository:
   ```bash
   git clone https://github.com/ArifuzzamanTusar/AES.git
   ```

2. Open the `index.html` file in a browser to run the app.


---

### **Additional Explanation on Technologies:**

- **AES Algorithm**: AES is a block cipher algorithm used to securely encrypt data. Its **symmetric** nature means that the same key is used for both encryption and decryption, making it efficient but also requiring careful management of keys.
  
- **CryptoJS Library**: CryptoJS offers an easy-to-use JavaScript implementation of the AES algorithm. By using this library, the encryption and decryption logic is handled securely within the browser, without the need for server-side processing, which ensures user data remains private.

