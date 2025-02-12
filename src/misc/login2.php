<?php
// Pfade zu den JSON-Dateien
$accountSettingsFile = "../data/database/accounts.json";
$specialAccountsFile = "../data/database/login2.json";

// Funktion zum Laden der Account-Einstellungen
function loadJson($file)
{
    if (file_exists($file)) {
        return json_decode(file_get_contents($file), true);
    }
    return [];
}

// Funktion zum Speichern der Account-Einstellungen
function saveJson($file, $data)
{
    file_put_contents($file, json_encode($data, JSON_PRETTY_PRINT));
}

// Token generieren
function generateToken()
{
    return bin2hex(random_bytes(16));
}

// Login-Prozess
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $username = $_POST["username"] ?? "";
    $password = $_POST["password"] ?? "";
    $accountName = $_POST["account_name"] ?? "";

    if ($username && $password && $accountName) {
        // Laden der Daten
        $accountSettings = loadJson($accountSettingsFile);
        $specialAccounts = loadJson($specialAccountsFile);

        // ÃœberprÃ¼fen, ob die Anmeldedaten im Konto vorhanden sind
        if (
            isset($accountSettings[$accountName]) &&
            $accountSettings[$accountName]["username"] === $username &&
            password_verify(
                $password,
                $accountSettings[$accountName]["password"]
            )
        ) {
            // Token generieren
            $token = generateToken();

            // Token zu den speziellen Konten hinzufÃ¼gen
            if (!isset($specialAccounts[$username])) {
                $specialAccounts[$username] = [
                    "tokens" => [],
                ];
            }

            // Token hinzufÃ¼gen
            $specialAccounts[$username]["tokens"][] = $token;
            saveJson($specialAccountsFile, $specialAccounts);

            // Token im Cookie setzen
            setcookie("id", $token, time() + 86400 * 30, "/"); // Cookie fÃ¼r 30 Tage setzen

            echo "Login successful!";
        } else {
            echo "Invalid username or password!";
        }
    } else {
        echo "All fields are required!";
    }
}
?>

<!-- HTML-Formular zum Einloggen -->
<form method="POST" action="">
    Username: <input type="text" name="username" required><br>
    Password: <input type="password" name="password" required><br>
    Account Name: <input type="text" name="account_name" required><br>
    <input type="submit" value="Login">
</form>
