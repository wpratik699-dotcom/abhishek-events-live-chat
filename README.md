# Abhishek Events — Live Customer Chat

This project turns the existing Abhishek Events website into a small customer-support system.

## What is included

- Existing Abhishek Events website + chatbot
- Customer "Chat with an Agent" handoff
- Real-time customer ↔ agent messaging
- Admin login
- Admin dashboard
- Create/disable agents
- Per-agent customer capacity
- Automatic assignment to an available agent
- Agent login
- Agent dashboard
- Conversation history stored in SQLite
- Agent online/offline status

## Beginner setup

1. Install Node.js 20+ from the official Node.js website.
2. Open this project folder in a terminal.
3. Run:
   `npm install`
4. Copy `.env.example` to `.env`.
5. Optionally change `ADMIN_PASSWORD` and `JWT_SECRET`.
6. Start:
   `npm start`
7. Open:
   - Website: http://localhost:3000/
   - Admin: http://localhost:3000/admin.html
   - Agent: http://localhost:3000/agent.html

## Default admin login

Username: `admin`
Password: `Admin@12345`

Change the password in `.env` before using this publicly.

## How to use it

1. Log in as admin.
2. Create an agent, for example:
   - Name: Rahul
   - Username: rahul
   - Password: Rahul@12345
   - Capacity: 5
3. Open the website in another browser/incognito window.
4. Open the chatbot and click "Chat with Agent".
5. Enter the customer's name and start the conversation.
6. Log in to the agent dashboard as Rahul.
7. Rahul can reply in real time.

## Important

This is a real working starter application, but before a public business launch you should add:
- HTTPS
- Strong production secrets
- Rate limiting / anti-spam
- Email or SMS verification if needed
- Backups
- Production database hosting
- Proper password reset flow
- Audit logs
- Privacy policy / consent wording

Do not put secrets such as JWT_SECRET or database credentials into frontend files.

## Project structure

public/
  index.html       Customer website
  contact.js       Contact settings
  admin.html       Admin dashboard
  agent.html       Agent dashboard
  dashboard.css    Dashboard styling
  chat-client.js   Shared real-time chat client

server/
  server.js        Express + WebSocket backend

data/
  app.db           Created automatically after first start
