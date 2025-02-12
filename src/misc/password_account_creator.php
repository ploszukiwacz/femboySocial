<?php
die("nuhuh");
// Pfad zur JSON-Datei mit den Account-Einstellungen
$accountSettingsFile = "../database/accounts.json";

// Funktion zum Laden der Account-Einstellungen
function loadAccountSettings($file)
{
    return file_exists($file)
        ? json_decode(file_get_contents($file), true)
        : [];
}

// Funktion zum Speichern der Account-Einstellungen
function saveAccountSettings($file, $data)
{
    file_put_contents($file, json_encode($data, JSON_PRETTY_PRINT));
}

// Konto erstellen
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    // Alle POST-Daten lesen
    $username = isset($_POST["username"]) ? trim($_POST["username"]) : "";
    $password = isset($_POST["password"]) ? trim($_POST["password"]) : "";
    $accountName = isset($_POST["account_name"])
        ? trim($_POST["account_name"])
        : "";

    // ÃœberprÃ¼fen, ob alle Felder ausgefÃ¼llt sind
    if (!empty($username) && !empty($password) && !empty($accountName)) {
        $settings = loadAccountSettings($accountSettingsFile);

        // Passwort hashen
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

        // Neues Konto hinzufÃ¼gen oder aktualisieren
        $settings[$accountName] = [
            "username" => $username,
            "password" => $hashedPassword,
            "tokens" => [],
        ];

        // Speichern
        saveAccountSettings($accountSettingsFile, $settings);
        echo "Special account for $username created successfully!";
    } else {
        echo "All fields are required!";
    }
}
?>

<!-- HTML-Formular zum Erstellen eines speziellen Kontos -->
<form method="POST" action="">
    Username: <input type="text" name="username" required><br>
    Password: <input type="password" name="password" required><br>
    Account Name: <input type="text" name="account_name" required><br>
    <input type="submit" value="Create Account">
</form>
