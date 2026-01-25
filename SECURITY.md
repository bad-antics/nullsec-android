# Android Security Testing Guide

## Overview
Comprehensive Android application security testing techniques.

## Static Analysis

### APK Analysis
- Manifest review
- Permission analysis
- Component exports
- Intent filters

### Code Review
- Decompilation (jadx)
- Native libraries
- Hardcoded secrets
- Insecure storage

### Configuration
- Network security config
- Backup settings
- Debug flags
- Certificate pinning

## Dynamic Analysis

### Runtime Testing
- Frida hooking
- Method tracing
- SSL unpinning
- Root detection bypass

### Traffic Analysis
- Proxy setup
- Certificate installation
- API inspection
- WebSocket monitoring

## Common Vulnerabilities

### Data Storage
- SharedPreferences
- SQLite databases
- File permissions
- External storage

### Authentication
- Weak biometrics
- Session handling
- Token storage
- OAuth flows

### IPC Issues
- Broadcast receivers
- Content providers
- Deep links
- Pending intents

## Tools
- ADB commands
- drozer
- objection
- MobSF

## Legal Notice
For authorized security testing.
