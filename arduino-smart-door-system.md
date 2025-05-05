# Arduino Smart Door System with Web Control

## Table of Contents
- [Overview](#overview)
- [System Architecture](#system-architecture)
- [Hardware Requirements](#hardware-requirements)
- [Software Components](#software-components)
- [Installation Guide](#installation-guide)
- [Database Schema](#database-schema)
- [Web Interface](#web-interface)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)
- [Future Enhancements](#future-enhancements)

## Overview

This document provides comprehensive documentation for building a smart door system using an Arduino Uno microcontroller with remote control capabilities via a web interface. The system allows authorized users to lock and unlock a door remotely from any web browser, with all access events logged in a database for security auditing.

![System Overview](https://placeholder-image.com/arduino-door-system.jpg)

## System Architecture

The smart door system consists of three main components:

1. **Arduino Controller** - Controls the physical door lock mechanism
2. **Web Server** - Hosts the interface and manages user authentication
3. **Database** - Stores user credentials and access logs

The system operates as follows:

```
┌───────────────┐     HTTP      ┌───────────────┐     HTTP      ┌───────────────┐
│  Web Browser  │ ────────────> │   Web Server  │ ────────────> │ Arduino + Lock│
│  (Any Device) │ <───────────  │   + Database  │ <───────────  │   Controller  │
└───────────────┘     HTTP      └───────────────┘     HTTP      └───────────────┘
```

## Hardware Requirements

### Core Components
- Arduino Uno board
- Ethernet shield (W5100 or compatible)
- Servo motor OR electronic door strike/magnetic lock
- 5V relay module (if using electronic lock)
- Power supply (5V for Arduino, 12V for electronic locks)
- Ethernet cable
- Jumper wires
- Breadboard (for prototyping)

### Optional Components
- Door sensor (reed switch)
- Status LEDs
- Backup battery
- 3D printed enclosure

## Software Components

### Arduino
- Arduino IDE (1.8.x or higher)
- Ethernet library
- Servo library

### Server
- Web server (Apache/Nginx)
- PHP 7.4 or higher
- MySQL/MariaDB database
- PHP PDO extension

## Installation Guide

### 1. Hardware Assembly

1. **Attach the Ethernet shield** to the Arduino Uno board
2. **Connect the servo motor** to the Arduino:
   - Signal wire to pin 9
   - Power wire to 5V
   - Ground wire to GND
3. **If using an electronic lock instead of servo:**
   - Connect relay module input to pin 9
   - Connect relay COM port to positive terminal of lock power supply
   - Connect relay NO port to positive terminal of lock
   - Connect negative terminal of lock to negative terminal of power supply
4. **Optional door sensor:**
   - Connect one wire to pin 2
   - Connect other wire to GND

### 2. Arduino Code Installation

1. Open the Arduino IDE
2. Install required libraries (if not already installed):
   ```
   Sketch > Include Library > Manage Libraries
   ```
   - Search and install "Ethernet"
   - Search and install "Servo"
3. Copy and paste the following code into a new sketch:

```cpp
// Arduino Smart Door System with Web Control
// Using Ethernet Shield

#include <SPI.h>
#include <Ethernet.h>
#include <Servo.h>

// Network configuration
byte mac[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED }; // MAC address for Ethernet shield
IPAddress ip(192, 168, 1, 177);                       // Arduino's IP address (change according to your network)
EthernetServer server(80);                            // Create server on port 80

// Door control
Servo doorLock;                 // Servo to control the lock
const int LOCK_PIN = 9;         // Servo connected to pin 9
const int DOOR_SENSOR_PIN = 2;  // Door sensor (optional) to detect if door is open/closed
bool doorLocked = true;         // Door state tracking

// Authentication
const char* validUsername = "admin";
const char* validPassword = "password123"; // Change this to a secure password!

void setup() {
  // Initialize serial communication
  Serial.begin(9600);
  
  // Initialize door lock control
  doorLock.attach(LOCK_PIN);
  lockDoor(); // Start with door locked
  
  // Optional door sensor setup
  pinMode(DOOR_SENSOR_PIN, INPUT_PULLUP);
  
  // Initialize Ethernet connection
  Ethernet.begin(mac, ip);
  
  // Check if Ethernet is connected
  if (Ethernet.hardwareStatus() == EthernetNoHardware) {
    Serial.println("Ethernet shield not found");
    while (true) {
      delay(1); // Do nothing, no point running without Ethernet hardware
    }
  }
  
  if (Ethernet.linkStatus() == LinkOFF) {
    Serial.println("Ethernet cable is not connected.");
  }
  
  // Start the server
  server.begin();
  Serial.print("Server started at ");
  Serial.println(Ethernet.localIP());
}

void loop() {
  // Listen for incoming clients
  EthernetClient client = server.available();
  
  if (client) {
    Serial.println("New client connected");
    
    // HTTP request storage
    String currentLine = "";
    String httpRequest = "";
    bool requestComplete = false;
    
    // Process client data
    while (client.connected()) {
      if (client.available()) {
        char c = client.read();
        httpRequest += c;
        
        // HTTP request ends with a blank line
        if (c == '\n') {
          if (currentLine.length() == 0) {
            requestComplete = true;
            break;
          } else {
            currentLine = "";
          }
        } else if (c != '\r') {
          currentLine += c;
        }
      }
    }
    
    // Process the completed request
    if (requestComplete) {
      // Check for authentication and commands
      bool authenticated = false;
      
      // Very basic auth checking - in a real system, use proper HTTP authentication
      if (httpRequest.indexOf("username=" + String(validUsername)) > 0 && 
          httpRequest.indexOf("password=" + String(validPassword)) > 0) {
        authenticated = true;
      }
      
      // Send HTTP response header
      client.println("HTTP/1.1 200 OK");
      client.println("Content-Type: text/html");
      client.println("Connection: close");
      client.println();
      
      // Send web page
      client.println("<!DOCTYPE HTML>");
      client.println("<html>");
      client.println("<head><title>Arduino Door Control</title>");
      client.println("<meta name='viewport' content='width=device-width, initial-scale=1'>");
      client.println("<style>");
      client.println("body { font-family: Arial; text-align: center; margin: 0px auto; background-color: #f0f0f0; }");
      client.println(".container { width: 90%; margin: 0px auto; padding: 20px; }");
      client.println(".button { display: block; width: 80%; margin: 10px auto; padding: 15px; font-size: 16px; color: white; text-decoration: none; border: none; border-radius: 5px; cursor: pointer; }");
      client.println(".unlock { background-color: #4CAF50; }");
      client.println(".lock { background-color: #f44336; }");
      client.println(".status { margin: 20px 0; padding: 10px; border-radius: 5px; }");
      client.println("form { margin: 20px 0; }");
      client.println("input { padding: 10px; margin: 5px; width: 80%; }");
      client.println("</style></head>");
      client.println("<body>");
      client.println("<div class='container'>");
      client.println("<h1>Smart Door Control System</h1>");
      
      // Check if the user is authenticated
      if (!authenticated) {
        // Login form
        client.println("<form method='post'>");
        client.println("<h2>Login</h2>");
        client.println("<input type='text' name='username' placeholder='Username'><br>");
        client.println("<input type='password' name='password' placeholder='Password'><br>");
        client.println("<input type='submit' class='button unlock' value='Login'>");
        client.println("</form>");
      } else {
        // Door status
        client.println("<div class='status' style='background-color: " + String(doorLocked ? "#ffcccc" : "#ccffcc") + ";'>");
        client.println("<h2>Door is currently " + String(doorLocked ? "LOCKED" : "UNLOCKED") + "</h2>");
        client.println("</div>");
        
        // Check for lock/unlock commands
        if (httpRequest.indexOf("GET /unlock") > 0) {
          unlockDoor();
          client.println("<div style='color: green;'>Door unlocked successfully!</div>");
        } else if (httpRequest.indexOf("GET /lock") > 0) {
          lockDoor();
          client.println("<div style='color: red;'>Door locked successfully!</div>");
        }
        
        // Control buttons
        client.println("<a href='/unlock' class='button unlock'>Unlock Door</a>");
        client.println("<a href='/lock' class='button lock'>Lock Door</a>");
        
        // Optional: show door sensor status if connected
        int doorStatus = digitalRead(DOOR_SENSOR_PIN);
        client.println("<p>Door is physically " + String(doorStatus == HIGH ? "CLOSED" : "OPEN") + "</p>");
        
        // Logout option
        client.println("<a href='/' style='margin-top: 20px; display: inline-block;'>Logout</a>");
      }
      
      client.println("</div>");
      client.println("</body></html>");
    }
    
    // Give the web browser time to receive the data
    delay(10);
    
    // Close the connection
    client.stop();
    Serial.println("Client disconnected");
  }
}

// Function to lock the door
void lockDoor() {
  doorLock.write(0);  // Adjust angle as needed for your servo
  doorLocked = true;
  Serial.println("Door locked");
  logAction("Door locked");
}

// Function to unlock the door
void unlockDoor() {
  doorLock.write(90); // Adjust angle as needed for your servo
  doorLocked = false;
  Serial.println("Door unlocked");
  logAction("Door unlocked");
}

// Function to log actions (in a real system, this would send data to a database)
void logAction(String action) {
  // This is where you would implement database logging
  // For now, we just print to Serial
  Serial.print("LOG: ");
  Serial.print(action);
  Serial.print(" at ");
  Serial.println(millis()); // Just using millis for timestamp in this example
}
```

4. **Adjust network settings:**
   - Update the `mac[]` array with a unique MAC address
   - Update the `IPAddress ip` with an available IP on your network
   - Update `validUsername` and `validPassword` with secure credentials

5. **Upload the code:**
   - Connect Arduino to your computer
   - Select correct board and port from Tools menu
   - Click Upload button (→)

6. **Verify operation:**
   - Open the Serial Monitor (Tools > Serial Monitor)
   - Set baud rate to 9600
   - Confirm that the Arduino reports its IP address

### 3. Database Setup

1. **Install MySQL/MariaDB** on your server
2. **Create database and user:**
   - Open MySQL console or phpMyAdmin
   - Execute the following SQL:

```sql
-- Database creation
CREATE DATABASE IF NOT EXISTS smart_door;
USE smart_door;

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role ENUM('user', 'admin') NOT NULL DEFAULT 'user',
    email VARCHAR(100),
    full_name VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    status ENUM('active', 'inactive', 'suspended') DEFAULT 'active'
);

-- Access logs table
CREATE TABLE IF NOT EXISTS access_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    action ENUM('login', 'logout', 'lock', 'unlock', 'failed_attempt') NOT NULL,
    status ENUM('success', 'failed') NOT NULL,
    ip_address VARCHAR(45),
    device_info VARCHAR(255),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Door status table
CREATE TABLE IF NOT EXISTS door_status (
    id INT AUTO_INCREMENT PRIMARY KEY,
    status ENUM('locked', 'unlocked') NOT NULL,
    changed_by INT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (changed_by) REFERENCES users(id) ON DELETE SET NULL
);

-- Access schedule (for time-based permissions)
CREATE TABLE IF NOT EXISTS access_schedule (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    day_of_week ENUM('monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday', 'all') NOT NULL,
    start_time TIME NOT NULL,
    end_time TIME NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- API tokens (for mobile app or other integrations)
CREATE TABLE IF NOT EXISTS api_tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token VARCHAR(255) NOT NULL,
    description VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NULL,
    last_used_at TIMESTAMP NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create default admin user
-- Default password is 'admin123' - CHANGE THIS IN PRODUCTION!
INSERT INTO users (username, password, role, email, full_name)
VALUES (
    'admin', 
    '$2y$10$8KOhNMX.FJfUVVfD6mFsEOxiL58A8g9vWqBT6J5r0un9XiYn0FvVm', 
    'admin',
    'admin@example.com',
    'System Administrator'
) ON DUPLICATE KEY UPDATE role = 'admin';

-- Create a regular user
-- Default password is 'user123' - CHANGE THIS IN PRODUCTION!
INSERT INTO users (username, password, role, email, full_name)
VALUES (
    'user', 
    '$2y$10$wz0QCNzAZS3jVQKvPH5zz.wQq.3dkBS4SmqgYz8l6Yd8NckH01n4W', 
    'user',
    'user@example.com',
    'Regular User'
) ON DUPLICATE KEY UPDATE role = 'user';

-- Create indexes for performance
CREATE INDEX idx_access_logs_timestamp ON access_logs(timestamp);
CREATE INDEX idx_access_logs_user_id ON access_logs(user_id);
CREATE INDEX idx_door_status_timestamp ON door_status(timestamp);
CREATE INDEX idx_users_username ON users(username);
```

### 4. Web Interface Setup

1. **Install a web server** (Apache/Nginx) with PHP support
2. **Create a directory** for the web application:
   ```
   mkdir -p /var/www/html/smart-door
   ```
3. **Create the PHP file** for the web interface:
   ```
   nano /var/www/html/smart-door/index.php
   ```
4. **Copy the following PHP code:**

```php
<?php
// Smart Door Web Interface
// Database connection parameters
$host = "localhost";
$dbname = "smart_door";
$username = "door_user";
$password = "secure_password"; // Change this in production!

// Establish database connection
try {
    $conn = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch(PDOException $e) {
    die("Connection failed: " . $e->getMessage());
}

// Initialize session
session_start();

// Function to log access attempts
function logAccess($user_id, $action, $status) {
    global $conn;
    $stmt = $conn->prepare("INSERT INTO access_logs (user_id, action, status, ip_address, timestamp) 
                            VALUES (:user_id, :action, :status, :ip, NOW())");
    $stmt->bindParam(':user_id', $user_id);
    $stmt->bindParam(':action', $action);
    $stmt->bindParam(':status', $status);
    $stmt->bindParam(':ip', $_SERVER['REMOTE_ADDR']);
    $stmt->execute();
}

// Function to send command to Arduino
function sendCommandToArduino($command) {
    $arduino_ip = "192.168.1.177"; // Arduino's IP address
    $url = "http://$arduino_ip/$command";
    
    // Use cURL to send the command
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10); // 10-second timeout
    $response = curl_exec($ch);
    $success = !curl_errno($ch);
    curl_close($ch);
    
    return $success;
}

// Handle login
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['login'])) {
    $input_username = $_POST['username'];
    $input_password = $_POST['password'];
    
    $stmt = $conn->prepare("SELECT id, username, password, role FROM users WHERE username = :username");
    $stmt->bindParam(':username', $input_username);
    $stmt->execute();
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if ($user && password_verify($input_password, $user['password'])) {
        // Login successful
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['role'] = $user['role'];
        
        logAccess($user['id'], "login", "success");
    } else {
        // Login failed
        $login_error = "Invalid username or password";
        logAccess(0, "login", "failed");
    }
}

// Handle logout
if (isset($_GET['logout'])) {
    if (isset($_SESSION['user_id'])) {
        logAccess($_SESSION['user_id'], "logout", "success");
    }
    session_destroy();
    header("Location: index.php");
    exit;
}

// Handle door control actions
if (isset($_SESSION['user_id'])) {
    if (isset($_GET['action'])) {
        $action = $_GET['action'];
        
        if ($action == "unlock") {
            $success = sendCommandToArduino("unlock");
            logAccess($_SESSION['user_id'], "unlock", $success ? "success" : "failed");
            $message = $success ? "Door unlocked successfully" : "Failed to unlock door";
        } else if ($action == "lock") {
            $success = sendCommandToArduino("lock");
            logAccess($_SESSION['user_id'], "lock", $success ? "success" : "failed");
            $message = $success ? "Door locked successfully" : "Failed to lock door";
        }
    }
}

// Admin: Add new user
if (isset($_SESSION['role']) && $_SESSION['role'] == 'admin' && isset($_POST['add_user'])) {
    $new_username = $_POST['new_username'];
    $new_password = password_hash($_POST['new_password'], PASSWORD_DEFAULT);
    $new_role = $_POST['new_role'];
    
    $stmt = $conn->prepare("INSERT INTO users (username, password, role) VALUES (:username, :password, :role)");
    $stmt->bindParam(':username', $new_username);
    $stmt->bindParam(':password', $new_password);
    $stmt->bindParam(':role', $new_role);
    
    try {
        $stmt->execute();
        $admin_message = "User added successfully";
    } catch(PDOException $e) {
        $admin_message = "Error adding user: " . $e->getMessage();
    }
}

// Get access logs (for admin)
$logs = [];
if (isset($_SESSION['role']) && $_SESSION['role'] == 'admin') {
    $stmt = $conn->query("SELECT a.id, u.username, a.action, a.status, a.ip_address, a.timestamp 
                          FROM access_logs a 
                          LEFT JOIN users u ON a.user_id = u.id 
                          ORDER BY a.timestamp DESC 
                          LIMIT 100");
    $logs = $stmt->fetchAll(PDO::FETCH_ASSOC);
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Smart Door Control System</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 0;
            background-color: #f4f4f4;
        }
        .container {
            width: 80%;
            margin: auto;
            overflow: hidden;
            padding: 20px;
        }
        header {
            background: #35424a;
            color: white;
            padding: 20px;
            border-bottom: #e8491d 3px solid;
        }
        header h1 {
            margin: 0;
        }
        .btn {
            display: inline-block;
            background: #333;
            color: #fff;
            padding: 10px 20px;
            margin: 5px;
            border: none;
            cursor: pointer;
            text-decoration: none;
            font-size: 15px;
            border-radius: 5px;
        }
        .btn-primary {
            background: #e8491d;
        }
        .btn-success {
            background: #4CAF50;
        }
        .btn-danger {
            background: #f44336;
        }
        .card {
            background: #fff;
            padding: 20px;
            margin: 20px 0;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .form-group {
            margin: 15px 0;
        }
        .form-group label {
            display: block;
            margin-bottom: 5px;
        }
        .form-group input {
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 5px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }
        table, th, td {
            border: 1px solid #ddd;
        }
        th, td {
            padding: 10px;
            text-align: left;
        }
        th {
            background-color: #f4f4f4;
        }
        .status-message {
            padding: 10px;
            background-color: #e7f3fe;
            border-left: 3px solid #2196F3;
            margin: 15px 0;
        }
        .error-message {
            padding: 10px;
            background-color: #ffdddd;
            border-left: 3px solid #f44336;
            margin: 15px 0;
        }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>Smart Door Control System</h1>
            <?php if (isset($_SESSION['username'])): ?>
                <p>Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?> 
                <small>[<?php echo htmlspecialchars($_SESSION['role']); ?>]</small> | 
                <a href="?logout=1" style="color: white;">Logout</a></p>
            <?php endif; ?>
        </div>
    </header>

    <div class="container">
        <?php if (isset($message)): ?>
            <div class="status-message"><?php echo $message; ?></div>
        <?php endif; ?>
        
        <?php if (isset($login_error)): ?>
            <div class="error-message"><?php echo $login_error; ?></div>
        <?php endif; ?>
        
        <?php if (isset($admin_message)): ?>
            <div class="status-message"><?php echo $admin_message; ?></div>
        <?php endif; ?>

        <?php if (!isset($_SESSION['user_id'])): ?>
            <!-- Login Form -->
            <div class="card">
                <h2>Login</h2>
                <form method="post" action="">
                    <div class="form-group">
                        <label for="username">Username:</label>
                        <input type="text" id="username" name="username" required>
                    </div>
                    <div class="form-group">
                        <label for="password">Password:</label>
                        <input type="password" id="password" name="password" required>
                    </div>
                    <button type="submit" name="login" class="btn btn-primary">Login</button>
                </form>
            </div>
        <?php else: ?>
            <!-- Door Control Buttons -->
            <div class="card">
                <h2>Door Control</h2>
                <p>Use the buttons below to control the door remotely.</p>
                <a href="?action=unlock" class="btn btn-success">Unlock Door</a>
                <a href="?action=lock" class="btn btn-danger">Lock Door</a>
            </div>
            
            <?php if (isset($_SESSION['role']) && $_SESSION['role'] == 'admin'): ?>
                <!-- Admin Section -->
                <div class="card">
                    <h2>Admin Controls</h2>
                    
                    <!-- Add User Form -->
                    <h3>Add New User</h3>
                    <form method="post" action="">
                        <div class="form-group">
                            <label for="new_username">Username:</label>
                            <input type="text" id="new_username" name="new_username" required>
                        </div>
                        <div class="form-group">
                            <label for="new_password">Password:</label>
                            <input type="password" id="new_password" name="new_password" required>
                        </div>
                        <div class="form-group">
                            <label for="new_role">Role:</label>
                            <select name="new_role" id="new_role">
                                <option value="user">Regular User</option>
                                <option value="admin">Administrator</option>
                            </select>
                        </div>
                        <button type="submit" name="add_user" class="btn btn-primary">Add User</button>
                    </form>
                    
                    <!-- Access Logs -->
                    <h3>Access Logs</h3>
                    <table>
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>User</th>
                                <th>Action</th>
                                <th>Status</th>
                                <th>IP Address</th>
                                <th>Timestamp</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($logs as $log): ?>
                                <tr>
                                    <td><?php echo htmlspecialchars($log['id']); ?></td>
                                    <td><?php echo htmlspecialchars($log['username'] ?? 'Unknown'); ?></td>
                                    <td><?php echo htmlspecialchars($log['action']); ?></td>
                                    <td><?php echo htmlspecialchars($log['status']); ?></td>
                                    <td><?php echo htmlspecialchars($log['ip_address']); ?></td>
                                    <td><?php echo htmlspecialchars($log['timestamp']); ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php endif; ?>
        <?php endif; ?>
    </div>
</body>
</html>
```

5. **Update the configuration:**
   - Change database connection parameters
   - Update Arduino IP address in the `sendCommandToArduino` function

6. **Set proper permissions:**
   ```
   chown -R www-data:www-data /var/www/html/smart-door
   chmod -R 750 /var/www/html/smart-door
   ```

## Security Considerations

### Physical Security
1. **Tamper protection** - Install the Arduino and related components in a secure, tamper-resistant enclosure
2. **Backup power** - Use a UPS or battery backup to ensure the system works during power outages
3. **Fail-secure mechanism** - Configure the lock to remain secure if power or connectivity is lost

### Network Security
1. **Isolated Network** - Consider placing the door controller on a separate VLAN
2. **Firewall Rules** - Restrict access to the Arduino's IP address to only authorized devices
3. **HTTPS** - Consider setting up a reverse proxy with HTTPS to encrypt communications
4. **VPN Access** - For remote access, use a VPN instead of exposing the system directly to the internet

### Software Security
1. **Strong Passwords** - Change default passwords immediately
2. **Input Validation** - Implement thorough validation for all user inputs
3. **Rate Limiting** - Add protection against brute force attacks
4. **Regular Updates** - Keep all software components updated
5. **Access Logging** - Monitor and review the access logs regularly
6. **Session Timeouts** - Implement automatic logout after periods of inactivity

## Troubleshooting

### Arduino Issues

| Problem | Possible Cause | Solution |
|---------|----------------|----------|
| Arduino not responding | Power issue | Check power supply and connections |
| | Network issue | Verify Ethernet cable connection |
| | Code error | Check Serial Monitor for error messages |
| Servo not moving | Incorrect pin | Verify pin connections |
| | Power issue | Ensure adequate power for servo |
| | Mechanical obstruction | Check for physical blockage |

### Web Interface Issues

| Problem | Possible Cause | Solution |
|---------|----------------|----------|
| Cannot access web page | Server not running | Check web server status |
| | Network issue | Verify network connectivity |
| | Permission issue | Check file permissions |
| Cannot login | Incorrect credentials | Verify username and password |
| | Database issue | Check database connection |
| Door won't unlock | Communication error | Verify Arduino is online |
| | Command format error | Check URL format in code |

### Database Issues

| Problem | Possible Cause | Solution |
|---------|----------------|----------|
| Cannot connect to database | Service not running | Start MySQL service |
| | Incorrect credentials | Verify database username and password |
| | Network issue | Check if database allows remote connections |
| Missing logs | Query error | Verify SQL queries |
| | Permission issue | Check user permissions |

## Future Enhancements

### Advanced Authentication
- Implement two-factor authentication
- Add fingerprint or RFID card reader
- Integrate with facial recognition

### Mobile Integration
- Develop a dedicated mobile app
- Add push notifications for door events
- Implement geofencing for automatic unlocking

### Home Automation Integration
- Connect with smart home platforms (Home Assistant, HomeKit, etc.)
- Voice control through smart assistants
- Integrate with security cameras

### Advanced Features
- Time-based access control
- User group management
- Emergency override mechanisms
- Automatic locking schedules

---

## License

This project is released under the MIT License.

## Disclaimer

This system is provided as-is without any guarantees or warranty. The authors are not responsible for any damage or security incidents resulting from the implementation of this system. Always assess security risks before deploying in a production environment.
