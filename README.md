# Secure Identity System (Assignment 1)

A full-stack Identity Management Microservice designed to demonstrate secure user authentication and data protection. This project implements a secure login system using **JWT (JSON Web Tokens)** and protects sensitive user data (Aadhaar/ID numbers) using **AES-256 Encryption** at rest.

## 🚀 Features

* **Secure Authentication:** User registration and login using hashed passwords (Bcrypt) and stateless session management (JWT).
* **Data Encryption:** Sensitive fields (Aadhaar/ID) are encrypted using AES-256-CBC before being stored in the database.
* **Decryption on Demand:** Data is only decrypted and sent to the frontend when a valid, authenticated user requests their own profile.
* **Modern UI:** Responsive Dashboard built with React and Tailwind CSS.

## 🛠️ Tech Stack

* **Frontend:** React.js, Tailwind CSS, Axios, Lucide React (Icons)
* **Backend:** Node.js, Express.js
* **Security:** Bcrypt (Hashing), Crypto (AES-256 Encryption), JSON Web Tokens (JWT)
* **Database:** SQLite (In-Memory for MVP demonstration)

---

## ⚙️ Installation & Setup

This project requires **Node.js** installed on your machine.

### 1. Clone the Repository
```bash
git clone [https://github.com/omkar614/Secure-Identity-System.git](https://github.com/omkar614/Secure-Identity-System.git)
cd secure-identity-system