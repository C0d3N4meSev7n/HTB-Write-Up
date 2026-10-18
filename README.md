# HTB-Write-Up

## Table of Contents
- [About](#about)
- [Structure](#structure)
- [Write-ups](#write-ups)
- [Notes](#notes)

## About

I'm a self-taught web application security learner working toward a career as a web penetration tester. This repo collects my write-ups for Hack The Box Labs and CTFs.

Each write-up uses a report-style structure, but the content is narrated as a walkthrough: what I observed, why I tried the next step, and what it revealed. The goal is to show how I find vulnerabilities and understand why they exist, not just that I captured the flag.

## Structure

Every write-up follows the same skeleton:

| Part | What it contains |
|------|------------------|
| **Vulnerability** | The flaw stated up front: name, CWE, cause, consequence |
| **The Process** | Steps to reproduce, narrated with reasoning and evidence |
| **Impact** | What an attacker could achieve in a real scenario (only when applicable) |
| **Root Cause & Remediation** | Why the flaw exists, and how to fix each cause |


## Write-ups

### HTB Labs

| Published | Challenge | Category | Difficulty | Approach | Vulnerability |
|-----------|-----------|----------|------------|----------|---------------|
| 2026-10-18 | [Flag Command](HTB-Labs/flag-command/README.md) | Web | Very Easy | Black-box | Sensitive Data Exposure (CWE-200) |

## Notes

- Flags are redacted in all screenshots.
- Write-ups are for educational purposes and portfolio use. Techniques shown were performed only against Hack The Box's authorized lab environments.
- **Approach**: Black-box = no source code or credentials provided; Gray-box = partial information (e.g. a user account); White-box = full source access.
