SQL Injection Quest (SIQ)
A Cute Hacker-Themed SQL Injection Capture-the-Flag Challenge

Created for Database Security Demonstrations & Classroom Use

Introduction

SQL Injection Quest (SIQ) is a guided treasure-hunt Capture-the-Flag game where each level teaches a different SQL injection technique within a neon-green hacker-terminal themed environment.

This application is intentionally vulnerable and designed strictly for educational and classroom use.
Students progress through multiple SQLi levels, each unlocking the next clue.

Features

Hacker-terminal UI (neon green + ASCII styling)

Story-driven treasure hunt progression

Animated hacker avatar on login page

Real-time SQL injection logging

SQLite database auto-created on first run

Beginner-friendly introduction to SQL injection

Six SQL injection challenges from basic to advanced

Fully deployable on Render (free tier)

Learning Objectives

Students will learn and demonstrate:

How SQL injection works

Why unsanitized input is dangerous

Authentication bypass techniques

UNION-based data extraction

Blind SQL injection

Schema enumeration

Thinking like an attacker

How logs reveal malicious activity

Project Structure
ctf-sql-injection-game/
│
├.
├── app.py
├── database.db.  #auto-created at runtime
├── render.yaml
├── requirements.txt
├── static
│   ├── css
│   │   ├── README.md
│   │   └── theme.css
│   ├── images
│   │   ├── closed.jpeg
│   │   ├── front.jpeg
│   │   └── side.jpeg
│   └── js
│       └── typing.js
└── templates
    ├── admin_logs.html
    ├── admin_secret_win.html
    ├── admin_secret.html
    ├── base.html
    ├── blind.html
    ├── cart.html
    ├── clue1.html
    ├── clue2.html
    ├── debug.html
    ├── index.html
    ├── login.html
    ├── profile.html
    └── victory.html

Deploying on Render (Free Tier)
1. Push the project to GitHub

Make sure the repository includes:

app.py

requirements.txt

render.yaml

/templates

/static

2. Create a New Web Service

Environment: Python
Build Command:

pip install -r requirements.txt


Start Command:

gunicorn app:app


Enable Auto-Deploy if desired.

3. Deployment Complete

Render will provide a public URL. Students can begin the SQL Quest immediately.

CTF Levels
Level 1 — Login Bypass

Vulnerable login form where students practice basic SQL authentication bypass.

Level 2 — Search Injection

Search bar vulnerable to query manipulation and simple UNION statements.

Level 3 — UNION Table Dump

Students extract data using UNION, including schema details from sqlite_master.

Level 4 — Blind SQL Injection

A true/false response-based SQLi challenge using substring and boolean logic.

Level 5 — Schema / File Dump

UNION injection reveals:

sqlite_master

table definitions

hidden clues

Level 6 — Admin Access Without Password

A protected admin page requiring SQLi to bypass.
This is the final boss challenge.

Final Treasure

Completing all levels unlocks a special ASCII-styled treasure room with hacker-themed effects.

Instructor Notes

Safe & Sandboxed:
Uses a local SQLite database; no external services or personal data.

Easy Reset:
Delete database.db or redeploy.

Attack Logging:
All SQL injection attempts appear at:

/admin/logs


No Solutions Included:
This README does not reveal answers.
A private instructor-only solution sheet can be generated on request.

Requirements
Flask==2.3.2
gunicorn==21.2.0


SQLite is included with Python and requires no installation.