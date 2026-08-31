<div align="center">

# ⚡ TalentGrid API — Scalable Backend & Authentication Engine

**High-performance RESTful API powering the TalentGrid recruitment ecosystem with JWT HttpOnly security, MongoDB Atlas persistence, and Stripe Webhooks.**

[![Live API](https://img.shields.io/badge/Live_API-talentgrid--api.vercel.app-10b981?style=for-the-badge&logo=fastapi)](https://talentgrid-api.vercel.app)
[![Web Client](https://img.shields.io/badge/Web_Client-talentgrid--app.vercel.app-6254f5?style=for-the-badge&logo=vercel)](https://talentgrid-app.vercel.app)

[![Node.js](https://img.shields.io/badge/Node.js-18+-green?style=flat-square&logo=node.js)](https://nodejs.org/)
[![Express.js](https://img.shields.io/badge/Express.js-5.2-black?style=flat-square&logo=express)](https://expressjs.com/)
[![MongoDB](https://img.shields.io/badge/MongoDB-Atlas-47A248?style=flat-square&logo=mongodb)](https://mongodb.com/)
[![JWT](https://img.shields.io/badge/Auth-JWT_HttpOnly-FF5722?style=flat-square&logo=json-web-tokens)](https://jwt.io/)
[![Stripe](https://img.shields.io/badge/Payments-Stripe_API-635BFF?style=flat-square&logo=stripe)](https://stripe.com/)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

</div>

---

## 📌 Overview

**TalentGrid API** is a modular, event-driven backend service built with **Express 5** and **MongoDB Atlas Driver v7**. It orchestrates job marketplace lifecycle management, multi-role authentication pipelines (Seeker, Recruiter, Admin), verified application quotas, serverless connection pooling, and Stripe checkout verification.

---

## 🚀 Key Endpoints & Architecture

### 🔐 Authentication & Session
- `POST /api/auth/token` — Issues verified JWT payload encapsulated in `HttpOnly`, `Secure`, `SameSite` cookies (`hl_token`) and logs session tracking into MongoDB `tokens` collection.
- `POST /api/auth/logout` — Clears server authentication cookies.
- `GET /api/auth/me` — Validates current JWT authorization state.

### 💼 Jobs & Real-time Discovery
- `GET /api/jobs` — Full-text regex search, category filtering, `@remote` geolocation tagging, and dynamic aggregation for `typeCounts` (`full-time`, `part-time`, `contract`, `internship`, `remote`).
- `POST /api/jobs` — Creates verified job postings linked to recruiters.
- `PATCH /api/jobs/:id` & `DELETE /api/jobs/:id` — Controlled updates and deletion.

### 📝 Applications & Quota Enforcement
- `POST /api/applications` — Evaluates candidate application count and active subscription status. Restricts free applicants at **3 submissions** and requires upgrade beyond quota limit.
- `GET /api/applications` — Fetches candidate applicant pool per job ID.
- `PATCH /api/applications/:id/status` — Updates applicant hiring pipeline state (`Pending`, `Shortlisted`, `Interviewing`, `Rejected`, `Hired`).
- `GET /api/seeker/applications` — Aggregates candidate application history enriched with company branding, logo, and status markers.

### 🏢 Companies & Admin Moderation
- `POST /api/companies` — Onboards business profiles with `pending` initial review state.
- `GET /api/companies` — Lists companies with approval state filters.
- `PATCH /api/companies/:id/status` — **Admin-Only** action endpoint approving or rejecting business registrations.
- `GET /api/admin/users` — **Admin-Only** user directory audit.

### 💳 Stripe Payments
- `POST /api/create-checkout-session` — Generates Stripe-hosted checkout sessions with custom metadata.
- `GET /api/verify-checkout-session` — Confirms transaction success and synchronizes MongoDB `subscriptions` and `users` collections.

---

## ⚙️ Local Development Setup

### 1. Clone & Install Dependencies
```bash
git clone https://github.com/aminur167/talentgrid-api.git
cd talentgrid-api
npm install
```

### 2. Configure Environment Variables
Create a `.env` file in the root directory:
```env
PORT=5000
MONGODB_URI=your_mongodb_connection_string
JWT_SECRET=your_jwt_secret_key
JWT_EXPIRES_IN=7d
STRIPE_SECRET_KEY=sk_test_...
NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_test_...
```

### 3. Run Server
```bash
npm run dev
# or
node index.js
```

---

## 📄 License
Open-source under the [MIT License](LICENSE).
