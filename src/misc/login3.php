<?php
// Start the session
session_start();

// Check if the form was submitted
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Get the token value from the form
    $token = $_POST["token"];

    // Set the cookie
    setcookie("token", $token, time() + 86400 * 30, "/"); // Cookie expires in 30 days
    header("Location: /");
} ?>

<!DOCTYPE html>
<html>
<head>
    <title>Login via a token - femboySocial</title>

    <!-- favicons -->
    <link rel="icon" type="image/png" href="/assets/favicons/favicon-96x96.png" sizes="96x96" />
    <link rel="icon" type="image/svg+xml" href="/assets/favicons/favicon.svg" />
    <link rel="shortcut icon" href="/assets/favicons/favicon.ico" />
    <link rel="apple-touch-icon" sizes="180x180" href="/assets/favicons/apple-touch-icon.png" />
    <meta name="apple-mobile-web-app-title" content="FS" />
    <link rel="manifest" href="/assets/favicons/site.webmanifest" />

    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #1e1e2e;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        h1 {
            color: #cdd6f4;
        }
        form {
            background: #313244;
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
            color: #cdd6f4;
        }
        input[type="password"] {
            padding: 10px;
            border: 1px solid #ccc;
            border-radius: 4px;
            box-sizing: border-box;
            background-color: #1e1e2e;
        }
        input[type="submit"] {
            margin-top: 15px;
            padding: 10px 20px;
            color: #fff;
            background-color: #89b4fa;
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
