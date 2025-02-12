<?php
// Start the session
session_start();

// Check if the form was submitted
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Get the token value from the form
    $token = $_POST["token"];

    // Set the cookie
    setcookie("token", $token, time() + 86400 * 30, "/"); // Cookie expires in 30 days
} ?>

<!DOCTYPE html>
<html>
<head>
    <title>Login via a token - rtnyL</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f4;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        h1 {
            color: #333;
        }
        form {
            background: #ffffff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            max-width: 400px;
            width: 100%;
        }
        label, input {
            display: block;
            width: 100%;
            margin-top: 10px;
        }
        label {
            margin-bottom: 5px;
            font-weight: bold;
        }
        input[type="password"] {
            padding: 10px;
            border: 1px solid #ccc;
            border-radius: 4px;
            box-sizing: border-box;
        }
        input[type="submit"] {
            margin-top: 15px;
            padding: 10px 20px;
            color: #fff;
            background-color: #007bff;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            box-sizing: border-box;
        }
        input[type="submit"]:hover {
            background-color: #0056b3;
        }
    </style>
</head>
<body>

<form method="post">
    <h1>Login</h1>
    <label for="token">Token:</label>
    <input type="password" name="token" id="token">
    <input type="submit" value="Login">
</form>

</body>
</html>
