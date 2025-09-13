# 🔐 Secure Wallet API (Rust)

## 📌 Overview
The **Secure Wallet API** is a backend service built with **Rust**, designed to provide secure and scalable wallet operations.  
It allows users to generate wallets, store balances, perform coin transfers, and protect transactions with **user-defined PIN authentication**.  

This project demonstrates how **Rust’s memory safety, concurrency model, and strong type system** can be leveraged to build secure financial applications.  

---

## 🚀 Features
- **Wallet Management**
  - Generate new wallets with unique addresses
  - Store and retrieve wallet balances
  - Manage multiple wallets per user  

- **PIN-based Security**
  - Users create their own secure PIN during wallet setup
  - PIN required for transfers and sensitive operations
  - Encrypted storage of PINs for maximum safety  

- **Coin Transfers**
  - Transfer coins between wallets
  - Strong validation on sender/receiver and balance checks
  - Secured with PIN verification  

- **Crypto Storage**
  - Safely stores digital assets
  - Ready for extension with blockchain integrations
  - Designed to handle multiple cryptocurrencies  

- **Security**
  - End-to-end encryption for sensitive data
  - Hashing for PINs and private keys
  - Rust’s safe concurrency and error handling to prevent exploits  

- **Documentation & Extensibility**
  - RESTful API endpoints documented with **Swagger/OpenAPI**
  - Designed for integration with **mobile and web clients**
  - Extensible architecture for adding payment processors or blockchain nodes  

---

## 🛠️ Tech Stack
- **Language:** Rust 🦀  
- **Framework:** Actix Web (or Rocket / Axum — specify what you used)  
- **Database:** PostgreSQL / SQLite (whichever you implemented)  
- **Authentication:** PIN-based with hashing (bcrypt/argon2)  
- **API Docs:** Swagger / OpenAPI  

---

## 📂 Project Structure
secure-wallet-api/
│── src/
│ ├── main.rs # Application entry point
│ ├── routes.rs # API routes
│ ├── handlers.rs # Request handlers
│ ├── models.rs # Wallet and transaction models
│ ├── services.rs # Business logic
│ ├── security.rs # PIN hashing & encryption
│── Cargo.toml # Rust dependencies
│── README.md # Documentation


---

## 📡 API Endpoints

### 🔑 Wallet Management
- `POST /wallets` → Create a new wallet  
- `GET /wallets/{id}` → Fetch wallet details  
- `GET /wallets/{id}/balance` → Check wallet balance  

### 🔐 PIN Security
- `POST /wallets/{id}/set-pin` → Set user-defined PIN  
- `POST /wallets/{id}/verify-pin` → Verify PIN  

### 💸 Transactions
- `POST /transactions/transfer` → Transfer coins between wallets (PIN required)  
- `GET /transactions/{id}` → Get transaction details  

---

## ⚙️ Setup & Installation

### 1️⃣ Clone the repo
```bash
git clone (https://github.com/Tkayce/secure-wallet-api-rust)
cd secure-wallet-api

2️⃣ Install dependencies

Make sure you have Rust installed (via rustup)
cargo build

3️⃣ Run the API
cargo run

4️⃣ Access API
The API runs by default at:

http://localhost:8000
