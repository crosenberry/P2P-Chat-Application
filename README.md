# Secure Peer-to-Peer Chat Application

## Introduction
In the modern digital era, as communication largely moves online, the significance of secure communication has soared. This project intends to craft a Peer-to-Peer (P2P) Chat Application that champions not only direct communication but also underpins security and user experience.

### Run Configurations
 * To run multiple clients in parallel, run configurations must be set.
 * Navigate to 'Run' → 'Edit Configurations'
 * Click the '+' button.
 * In the Client.py configuration, click the "Allow Multiple Instances" button.

### Usage
 - First, install all requirements by running the command: pip install -r requirements.txt
 - Next, run [server.py](server.py) so that connections can be established.
 - Finally, run [client.py](client.py) for each device you wish to chat on.

## Objective
* Design and develop a P2P chat application focusing on:
  * End-to-end encryption for message confidentiality.
  * A user-friendly interface.

## Features & Enhancements

### End-to-End Encryption
* Use the cryptography library for symmetric encryption.
* Securely share session keys for individual chat sessions between peers.
* Ensure complete confidentiality of exchanged messages.

### Graphical User Interface (GUI)
* Craft a user-friendly GUI using the tkinter library.
* Integrate features like registration, login, chat, and file transfer.

## Implementation Plan & Timeline
**Week 1:**
* Research and initial planning.
* Establish a rudimentary P2P communication framework.

**Week 2:**
* Integrate end-to-end encryption.

**Week 3:**
* Conclude end-to-end encryption.
* Initiate GUI design.

**Week 4:**
* Perfect the GUI and merge with chat features.

**Week 5:**
* Dive into testing, debugging, and documentation.
* Ready a presentation and demo.

## Conclusion
Our Secure P2P Chat Application aims to blend potent security measures with a smooth user experience. With its focus on encryption and a user-friendly design, it promises users a secure and delightful platform for unhindered communication. This endeavor is not only in sync with current communication inclinations but also accentuates the criticality of privacy and security in digital discourse.
