# Authentication Vulnerabilities - Understanding and Exploitation

## Overview

This guide covers authentication vulnerabilities, specifically focusing on the dangers of default credentials and how attackers can exploit them to bypass login forms. We will use **BurpSuite**, a powerful web application security testing tool, to perform a **dictionary attack** and crack login credentials.

### Key Learning Objectives

- Understanding the basics of **Authentication** and why it's critical.
- Recognizing the dangers of **Default Credentials**.
- Learning how to **Bypass a Login Form** using **BurpSuite**.

## 1. Understanding Authentication

Authentication is the process of verifying a user's identity by validating their credentials (username, password, etc.). It ensures that users are who they claim to be. While often confused with authorization, authentication is strictly about identity verification. Authorization, on the other hand, deals with permissions and access control, determining what authenticated users can and cannot do.

### Common Authentication Vulnerabilities:

- **Weak Passwords**: Easily guessable passwords that can be cracked using brute force or dictionary attacks.
- **Default Credentials**: Devices or applications shipped with default, hard-coded usernames and passwords (e.g., `admin:admin`).
- **No Account Lockout**: Systems that allow unlimited login attempts without locking the account.
- **Insecure Password Storage**: Storing passwords in plaintext or using weak hashing algorithms.

## 2. Default Credentials: A Major Security Risk

Default credentials are pre-set username and password combinations that come with various devices or applications (e.g., `admin:admin`, `root:toor`). These credentials are intended to be changed after the initial setup, but they often remain unchanged, leaving systems vulnerable to attack.

### Why Are Default Credentials Dangerous?

- **Easily Guessable**: Attackers can easily find these credentials in manuals or on the internet.
- **Common Across Devices**: Multiple devices or applications may have the same default credentials.
- **Exposed to the Internet**: Devices and applications with unchanged default credentials may be exposed to the internet, making them easy targets for attackers.

#### Real-World Examples:

- The **Mirai botnet** leveraged default credentials to infect over **600,000 IoT devices** in 2018.
- Organizations like **Starbucks** and the **US Department of Defense** have been victims of vulnerabilities involving default credentials, leading to security breaches.

## 3. Exploiting Default Credentials with a Dictionary Attack Using BurpSuite

A **dictionary attack** is an attack method that uses a predefined list of possible usernames and passwords to gain unauthorized access to a system. This method is effective when default or common credentials are in use.

### Tools Required:

- **BurpSuite**: A popular tool for web application security testing.
- **FoxyProxy**: A browser extension to manage proxy settings, useful for routing traffic through BurpSuite.

### Step-by-Step Guide to Bypass Login Forms Using BurpSuite:

#### Step 1: Set Up BurpSuite

1. **Start BurpSuite**:
   - Launch BurpSuite from the **AttackBox** (if using a virtual environment) or install it from [PortSwigger's official site](https://portswigger.net/burp).

2. **Configure the Proxy**:
   - Go to **Proxy** > **Options** in BurpSuite and ensure **"Intercept is on."**
   - Open the **FoxyProxy** browser extension in **Firefox** (or your preferred browser).
   - Select the **Burp** proxy profile to route traffic through BurpSuite.

#### Step 2: Capture the Login Request

1. **Navigate to the Target Application**:
   - Enter the **IP address** or URL of the target application in the browser.

2. **Submit Login Form**:
   - Fill in a generic username and password (e.g., `admin:admin`).
   - Intercept the login request in BurpSuite; the request will appear under the **Proxy** tab.

#### Step 3: Set Up Burp Intruder for a Dictionary Attack

1. **Send Request to Intruder**:
   - Right-click the captured request in the **Proxy** tab and select **"Send to Intruder."**

2. **Configure Positions**:
   - Go to the **Intruder** tab, then click on **"Positions."**
   - Clear pre-selected positions and manually select the fields for the **username** and **password** by highlighting them and clicking **"Add."**

3. **Choose Attack Type**:
   - Select **"Cluster Bomb"** from the **Attack type** dropdown. This allows every combination of credentials to be tested.

#### Step 4: Configure Payloads

1. **Select Payload Sets**:
   - Navigate to the **Payloads** tab.
   - **Set 1 (Username)**: Add common default usernames like `admin`, `root`, `user`.
   - **Set 2 (Password)**: Add common default passwords like `password`, `admin`, `12345`.

2. **Add Payload Options**:
   - You can manually add entries or select lists from available payload options (e.g., **SecLists**).

#### Step 5: Launch the Attack

1. **Start the Attack**:
   - Click **"Start Attack"**. BurpSuite will automatically start testing all possible combinations of usernames and passwords.

2. **Analyze Results**:
   - Look for status codes or content length differences that may indicate a successful login. Typically, incorrect logins will have the same status or length; a correct combination will stand out with a different status or length.

#### Step 6: Gain Access

1. **Use the Correct Credentials**:
   - Once you identify the correct username and password combination, use it to log in to the target application.

2. **Disable Proxy**:
   - Turn off **FoxyProxy** after completing the attack to restore normal browser operation.

## 4. Important Notes

- **Legal and Ethical Use**: Ensure you have permission to perform security testing on any system. Unauthorized access is illegal and unethical.
- **Default Credential List Example**:

| **Username** | **Password** |
|--------------|--------------|
| `root`       | `root`       |
| `admin`      | `password`   |
| `user`       | `12345`      |

## 5. Conclusion

Understanding and exploiting authentication vulnerabilities, especially those involving default credentials, is a fundamental skill for any security professional. Tools like **BurpSuite** provide a powerful platform for learning about and testing these vulnerabilities in controlled environments.

> **Next Steps**: Practice using these techniques in a legal and ethical manner to strengthen your understanding of web application security.

