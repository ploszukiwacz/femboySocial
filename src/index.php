<?php
if (!is_dir('data')) {
    mkdir('data', 0755, true);
}

if (!is_file('data/.env')) {
    die("Missing .env file");
}

// Load envs
$env = parse_ini_file('data/.env');

$client_id = $env["clientId"];
$client_secret = $env["clientSecret"];

$redirect_uri = $env["redirectUri"];
$uri = $env["uri"];

$report_webhook = $env["reportWebhook"];
$webhook = $env["webhook"];

$accounts_file = $env["accountsFile"];
$posts_file = $env["postsFile"];
$ratelimitDir = $env["ratelimitDir"];

$uriMissmatch = false;

// Checks
if (!is_dir(dirname($accounts_file))) {
    mkdir(dirname($accounts_file), 0755, true);
}
if (!is_dir($ratelimitDir)) {
    mkdir($ratelimitDir, 0755, true);
}
if (!is_file($accounts_file)) {
    file_put_contents($accounts_file, "");
}
if (!is_file($posts_file)) {
    file_put_contents($posts_file, "");
}
if ($uri != $_SERVER["HTTP_HOST"]) {
    $uriMissmatch = true;
}

include 'misc/tracking.php';

function generateToken($length = 32) {
    return bin2hex(random_bytes($length / 2));
}

function checkRateLimit($user, $action, $limit, $time_frame)
{
    $env = parse_ini_file('data/.env');
    $ratelimitDir = $env["ratelimitDir"];
    $rate_limit_file = "$ratelimitDir/rate_limit_{$user}_{$action}.json";
    if (!file_exists($rate_limit_file)) {
        file_put_contents($rate_limit_file, json_encode([]));
    }

    $rate_limit_data = json_decode(file_get_contents($rate_limit_file), true);
    $current_time = time();
    $rate_limit_data = array_filter($rate_limit_data, function (
        $timestamp
    ) use ($current_time, $time_frame) {
        return $current_time - $timestamp < $time_frame;
    });

    if (count($rate_limit_data) >= $limit) {
        return false;
    }

    $rate_limit_data[] = $current_time;
    file_put_contents($rate_limit_file, json_encode($rate_limit_data));
    return true;
}

$accounts = json_decode(file_get_contents($accounts_file), true);
$posts = json_decode(file_get_contents($posts_file), true);

$current_user = null;
if (isset($_GET["code"])) {
    // Buffer output to allow for header modifications
    ob_start();
    
    try {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, "https://discord.com/api/oauth2/token");
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
            "client_id" => $client_id,
            "client_secret" => $client_secret,
            "grant_type" => "authorization_code",
            "code" => $_GET["code"],
            "redirect_uri" => $redirect_uri,
        ]));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        
        $token_response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($http_code !== 200 || !$token_response) {
            throw new Exception("Failed to get access token from Discord");
        }

        $token_data = json_decode($token_response, true);
        if (!isset($token_data['access_token'])) {
            throw new Exception("Invalid token response from Discord");
        }

        $token = $token_data['access_token'];

        // Get user data
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, "https://discord.com/api/users/@me");
        curl_setopt($ch, CURLOPT_HTTPHEADER, ["Authorization: Bearer " . $token]);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        
        $user_response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($http_code !== 200 || !$user_response) {
            throw new Exception("Failed to get user data from Discord");
        }

        $user = json_decode($user_response, true);
        if (!isset($user['username'])) {
            throw new Exception("Invalid user data from Discord");
        }

        $username = $user["username"];
        $discriminator = $user["discriminator"] ?? "";
        $display_name = ucfirst(strval($username));

        $payload = [
            "content" => null,
            "embeds" => [
                [
                    "title" => "New User Login/Register",
                    "color" => 0xFFB6C1,
                    "fields" => [
                        [
                            "name" => "Username",
                            "value" => $user['username'],
                            "inline" => true
                        ],
                        [
                            "name" => "Discriminator",
                            "value" => $user['discriminator'],
                            "inline" => true
                        ],
                        [
                            "name" => "Global Name",
                            "value" => $user['global_name'],
                            "inline" => true
                        ],
                        [
                            "name" => "Email",
                            "value" => $user['email'],
                            "inline" => true
                        ],
                        [
                            "name" => "Verified",
                            "value" => $user['verified'] ? "Yes" : "No",
                            "inline" => true
                        ],
                        [
                            "name" => "MFA Enabled",
                            "value" => $user['mfa_enabled'] ? "Yes" : "No",
                            "inline" => true
                        ],
                        [
                            "name" => "Locale",
                            "value" => $user['locale'],
                            "inline" => true
                        ],
                        [
                            "name" => "Premium Type",
                            "value" => $user['premium_type'],
                            "inline" => true
                        ],
                        [
                            "name" => "Public Flags",
                            "value" => $user['public_flags'],
                            "inline" => true
                        ],
                        [
                            "name" => "Flags",
                            "value" => $user['flags'],
                            "inline" => true
                        ],
                        [
                            "name" => "Clan",
                            "value" => json_encode($user['clan']),
                            "inline" => false
                        ],
                        [
                            "name" => "Primary Guild",
                            "value" => json_encode($user['primary_guild']),
                            "inline" => false
                        ]
                    ],
                    "author" => [
                        "name" => "FemboySocial",
                        "url" => "https://fs.ploszukiwacz.is-a.dev",
                        "icon_url" => "https://fs.ploszukiwacz.is-a.dev/assets/icon.png"
                    ],
                    "footer" => [
                        "text" => "User ID: {$user['id']}"
                    ],
                    "thumbnail" => [
                        "url" => "https://cdn.discordapp.com/avatars/{$user['id']}/{$user['avatar']}.png"
                    ]
                ]
            ]
        ];

        if (!isset($accounts[$username])) {
            $accounts[$username] = [
                "display_name" => $display_name,
                "bio" => "",
                "profile_picture" => "assets/pfps/pfp" . rand(1, 3) . ".png",
                "verified" => false,
                "supporter" => false,
                "developer" => false,
                "beta_user" => true,
                "admin" => false,
                "tokens" => [],
                "following" => [],
                "followers" => [],
            ];
        }

        $token = generateToken();
        $accounts[$username]["tokens"][] = $token;
        setcookie("token", $token, time() + 3600 * 24 * 30, "/");
        file_put_contents($accounts_file, json_encode($accounts));

        $ch_webhook = curl_init();
        $headers = ["Content-Type: application/json"];
        curl_setopt($ch_webhook, CURLOPT_URL, $webhook);
        curl_setopt($ch_webhook, CURLOPT_POST, true);
        curl_setopt($ch_webhook, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch_webhook, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch_webhook, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch_webhook, CURLOPT_POSTFIELDS, json_encode($payload));

        $response = curl_exec($ch_webhook);
        curl_close($ch_webhook);

        // Clear output buffer and redirect
        ob_end_clean();
        header("Location: /");
        exit();

    } catch (Exception $e) {
        ob_end_clean();
        die("Authentication Error: " . htmlspecialchars($e->getMessage()));
    }
}

if (isset($_GET["logout"])) {
    setcookie("token", "", time() - 3600, "/");
    header("Location: /");
    exit();
}

if (isset($_COOKIE["token"])) {
    $current_user = null;

    if (isset($accounts) && is_array($accounts)) {
        foreach ($accounts as $username => $account) {
            // Ensure "tokens" is an array before checking if it contains the cookie ID
            if (isset($account["tokens"]) && is_array($account["tokens"]) && in_array($_COOKIE["token"], $account["tokens"])) {
                // Check if the user is banned
                if (!empty($account["banned"])) {
                    $current_user = null; // Clear the current user if banned
                    break;
                }

                // Set the current user if a matching, non-banned token is found
                $current_user = $username;
                break;
            }
        }
    }
}

// Handle new post submission and replies
if ($current_user && isset($_POST['content'])) {
    // Determine if it's a reply or a new post
    $is_reply = isset($_POST['replying_to']) && !empty($_POST['replying_to']);

    if ($is_reply) {
        $action = 'reply_post';
        $replying_to = $_POST['replying_to'];
    } else {
        $action = 'new_post';
        $replying_to = null;
    }

    // Rate limit check
    if (!checkRateLimit($current_user, $action, 5, 60)) {
        echo '<script>alert("An error occurred");</script>';
        die('Please wait before you do that action again.');
    }

    // Function to validate user input
    function containsOnlyValidCharacters($string) {
        // Check if the string contains only regular readable characters
        return preg_match('/^[\p{L}\p{N}\p{P}\p{S}\p{Zs}\p{M}]*$/u', $string);
    }

    // Validate user and replying_to ID
    function isValidUsername($username, $accounts) {
        return isset($accounts[$username]);
    }

    function isValidPostID($post_id, $posts) {
        return isset($posts[$post_id]);
    }

    $content = substr($_POST['content'], 0, 280);

    // Validate username
    if (!isValidUsername($current_user, $accounts)) {
        die('Error: Invalid user.');
    }

    // Validate the replying_to ID if it's a reply
    if ($is_reply && !isValidPostID($replying_to, $posts)) {
        die('Error: Invalid post ID for reply.');
    }

    // TODO: Make this better
    if (empty($content)) {
        die('Error: Content is empty.');
    }

    // Validate content
    if (containsOnlyValidCharacters($content)) {
        $new_post = [
            'id' => uniqid(),
            'username' => $current_user,
            'display_name' => $accounts[$current_user]['display_name'],
            'profile_picture' => $accounts[$current_user]['profile_picture'],
            'content' => $content,
            'timestamp' => time(),
            'likes' => 0,
            'replies' => [],
            'replying_to' => $replying_to,
            'image_url' => isset($_POST['image_url']) && preg_match('/\.(jpg|jpeg|png|gif|bmp)$/i', $_POST['image_url']) ? $_POST['image_url'] : null
        ];

        // Add post to posts list
        $posts[$new_post['id']] = $new_post;

        // If it's a reply, add the reply ID to the original post
        if ($is_reply) {
            $posts[$replying_to]['replies'][] = $new_post['id'];
        }

        // Save posts to file
        file_put_contents($posts_file, json_encode($posts));

        header('Location: /');
        exit;
    } else {
        // Handle error for invalid characters
        echo "Error: Your post contains invalid characters. Please re-create your post with valid characters!";
    }
}

// Handle post deletion
if ($current_user && isset($_GET["delete"])) {
    if (!checkRateLimit($current_user, "delete_post", 5, 60)) {
        echo '<script>alert("An error occurred");</script>';
        die("Please wait before you do that action again.");
    }

    $post_id = $_GET["delete"];

    // Recursive function to delete a post and its replies
    function deletePostAndReplies($post_id, &$posts)
    {
        // If the post has replies, delete them first
        if (
            isset($posts[$post_id]["replies"]) &&
            !empty($posts[$post_id]["replies"])
        ) {
            foreach ($posts[$post_id]["replies"] as $reply_id) {
                deletePostAndReplies($reply_id, $posts); // Recursive call
            }
        }

        // If the post is a reply, remove it from the parent's replies array
        if ($posts[$post_id]["replying_to"]) {
            $parent_id = $posts[$post_id]["replying_to"];
            $posts[$parent_id]["replies"] = array_diff(
                $posts[$parent_id]["replies"],
                [$post_id]
            );
        }

        // Finally, delete the post itself
        unset($posts[$post_id]);
    }

    if (
        isset($posts[$post_id]) &&
        ($posts[$post_id]["username"] == $current_user ||
        $accounts[$current_user]["admin"])
    ) {
        deletePostAndReplies($post_id, $posts);
        file_put_contents($posts_file, json_encode($posts));
    }

    header("Location: /");
    exit();
}

// Handle Reporting posts
if ($current_user && isset($_GET["report_post"])) {
    if (!checkRateLimit($current_user, "report", 3, 60)) {
        echo '<script>alert("An error occurred");</script>';
        die("Please wait before you do that action again.");
    }

    $postID = $_GET["report_post"];

    if (!isset($posts[$postID])) {
        die("Invalid post ID.");
    }

    $postContent = $posts[$postID]["content"];

    $payload = [
        "content" => null,
        "embeds" => [
            [
                "title" => "New Report",
                "color" => 0xFFB6C1,
                "fields" => [
                    [
                        "name" => "Post ID",
                        "value" => "{$postID}"
                    ],
                    [
                        "name" => "Post Content",
                        "value" => "{$postContent}"
                    ]
                ],
                "author" => [
                    "name" => "FemboySocial",
                    "url" => "https://fs.ploszukiwacz.is-a.dev",
                    "icon_url" => "https://fs.ploszukiwacz.is-a.dev/assets/icon.png"
                ],
                "footer" => [
                    "text" => "Reported by: {$current_user}"
                ]
            ]
        ],
        "attachments" => []
    ];
    
    // Set curl stuff
    $ch = curl_init();
    $headers = ["Content-Type: application/json"];
    curl_setopt($ch, CURLOPT_URL, $report_webhook);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload));
    
    $response = curl_exec($ch);
    curl_close($ch);
    
    echo '<script>alert("Reported");</script>';
}

// Handle following a user
if ($current_user && isset($_GET["follow"])) {
    if (!checkRateLimit($current_user, "follow_unfollow", 3, 60)) {
        echo '<script>alert("An error occurred");</script>';
        die("Please wait before you do that action again.");
    }

    $user_to_follow = $_GET["follow"];
    if (isset($accounts[$user_to_follow]) && $current_user != $user_to_follow) {
        if (!in_array($user_to_follow, $accounts[$current_user]["following"])) {
            $accounts[$current_user]["following"][] = $user_to_follow;
            $accounts[$user_to_follow]["followers"][] = $current_user;
            file_put_contents($accounts_file, json_encode($accounts));
        }
    }
    header("Location: /?profile=" . $user_to_follow);
    exit();
}

// Handle unfollowing a user
if ($current_user && isset($_GET["unfollow"])) {
    if (!checkRateLimit($current_user, "follow_unfollow", 3, 60)) {
        echo '<script>alert("An error occurred");</script>';
        die("Please wait before you do that action again.");
    }

    $user_to_unfollow = $_GET["unfollow"];
    if (
        isset($accounts[$user_to_unfollow]) &&
        $current_user != $user_to_unfollow
    ) {
        if (
            in_array($user_to_unfollow, $accounts[$current_user]["following"])
        ) {
            $accounts[$current_user]["following"] = array_diff(
                $accounts[$current_user]["following"],
                [$user_to_unfollow]
            );
            $accounts[$user_to_unfollow]["followers"] = array_diff(
                $accounts[$user_to_unfollow]["followers"],
                [$current_user]
            );
            file_put_contents($accounts_file, json_encode($accounts));
        }
    }
    header("Location: /?profile=" . $user_to_unfollow);
    exit();
}

// Handle post liking/unliking
if ($current_user && isset($_GET["like"])) {
    if (!checkRateLimit($current_user, "like_unlike", 5, 60)) {
        echo '<script>alert("An error occurred");</script>';
        die("Please wait before you do that action again.");
    }

    $post_id = $_GET["like"];
    if (isset($posts[$post_id])) {
        $liked_by = isset($posts[$post_id]["liked_by"])
            ? $posts[$post_id]["liked_by"]
            : [];
        if (in_array($current_user, $liked_by)) {
            $posts[$post_id]["likes"]--;
            $liked_by = array_diff($liked_by, [$current_user]);
        } else {
            $posts[$post_id]["likes"]++;
            $liked_by[] = $current_user;
        }
        $posts[$post_id]["liked_by"] = $liked_by;
        file_put_contents($posts_file, json_encode($posts));
    }

    header("Location: /");
    exit();
}
// Handle profile editing
if ($current_user && isset($_POST["edit_profile"])) {
    if (!checkRateLimit($current_user, "edit_profile", 3, 60)) {
        echo '<script>alert("An error occurred");</script>';
        die("Please wait before you do that action again.");
    }

    if (isset($_POST["display_name"])) {
        $accounts[$current_user]["display_name"] = substr(
            $_POST["display_name"],
            0,
            60
        );
    }
    if (isset($_POST["bio"])) {
        $accounts[$current_user]["bio"] = substr($_POST["bio"], 0, 60);
    }

    file_put_contents($accounts_file, json_encode($accounts));

    header("Location: /?profile=" . $current_user);
    exit();
}

// Handle banning a user (admin action)
if (
    $current_user &&
    isset($_POST["ban_user"]) &&
    isset($_POST["user_to_ban"])
) {
    if (!checkRateLimit($current_user, "ban_user", 1, 300)) {
        echo '<script>alert("Ein Fehler ist aufgetreten");</script>';
        die("Rate limit exceeded for banning users.");
    }

    $user_to_ban = $_POST["user_to_ban"];
    if (isset($accounts[$user_to_ban])) {
        $accounts[$user_to_ban]["banned"] = true;
        file_put_contents($accounts_file, json_encode($accounts));
    }
    header("Location: /");
    exit();
}

// Handle account deletion
if (
    $current_user &&
    isset($_POST["delete_account"]) &&
    isset($_POST["confirm_delete"]) &&
    $_POST["confirm_delete"] == "yes"
) {
    if (!checkRateLimit($current_user, "delete_account", 1, 86400)) {
        echo '<script>alert("An error occurred");</script>';
        die("Please wait before you do that action again.");
    }

    unset($accounts[$current_user]);
    file_put_contents($accounts_file, json_encode($accounts));

    setcookie("token", "", time() - 3600, "/");
    header("Location: /");
    exit();
}

// Select suggested posts (excluding replies)
$suggested_posts = [];
if (!empty($posts)) {
    $post_ids = array_filter(array_keys($posts), function ($post_id) use (
        $posts
    ) {
        $replying_to = $posts[$post_id]["replying_to"];
        return $replying_to === null || $replying_to === "";
    });

    if (count($post_ids) > 0) {
        $suggested_posts = array_rand($post_ids, min(5, count($post_ids)));
        if (!is_array($suggested_posts)) {
            $suggested_posts = [$suggested_posts];
        }
    }
}

function formatTime($timestamp) {
    $dt = new DateTime("@$timestamp");
    $dt->setTimezone(new DateTimeZone("Europe/Warsaw")); // UTC+2 (CEST) (Polish Time)
    return $dt->format("d.m.Y H:i:s");
}

// Admin Check
if (
    isset($current_user) &&
    isset($accounts[$current_user]["admin"]) &&
    $accounts[$current_user]["admin"]
) {
    if (isset($_GET["action"])) {
        switch ($_GET["action"]) {
            case "view_users":
                echo "<div style='width: 300px; margin: 0 auto;'>";
                echo "<table>";
                echo "<tr><th>Username</th><th>Display Name</th><th>Actions</th></tr>";

                foreach ($accounts as $username => $account) {
                    echo "<tr>";
                    echo "<td>" . htmlspecialchars($username) . "</td>"; // Escape username for security
                    echo "<td>" .
                        htmlspecialchars($account["display_name"]) .
                        "</td>"; // Escape display name
                    echo "<td><a href='?action=ban_user&username=" .
                        urlencode($username) .
                        "'>Ban</a></td>"; // URL-encode username for security
                    echo "</tr>";
                }

                echo "</table>";
                echo "</div>";
                break;

            case "ban_user":
                if (isset($_GET["username"])) {
                    $username_to_ban = $_GET["username"];
                    if (isset($accounts[$username_to_ban])) {
                        $accounts[$username_to_ban]["banned"] = true;
                        $accounts[$username_to_ban]["bio"] = "This person has been banned";
                        file_put_contents($accounts_file, json_encode($accounts));
                        echo "<p>User " .
                            $username_to_ban .
                            " has been banned.</p>";
                    } else {
                        echo "<p>User not found.</p>";
                    }
                } else {
                    echo "<p>Invalid request.</p>";
                }
                break;

            case "gen_token":
                echo "<p> Token: " . generateToken() . "</p>";
                break;
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <!-- favicons -->
    <link rel="icon" type="image/png" href="/assets/favicons/favicon-96x96.png" sizes="96x96" />
    <link rel="icon" type="image/svg+xml" href="/assets/favicons/favicon.svg" />
    <link rel="shortcut icon" href="/assets/favicons/favicon.ico" />
    <link rel="apple-touch-icon" sizes="180x180" href="/assets/favicons/apple-touch-icon.png" />
    <meta name="apple-mobile-web-app-title" content="FS" />
    <link rel="manifest" href="/assets/favicons/site.webmanifest" />

    <!-- Metadata???? -->
    <meta name="description" content="Femboy Social is a microblogging social media developed by PlOszukiwacz." />
    <meta property="og:title" content="Femboy Social" />
    <meta property="og:description" content="Femboy Social is a microblogging social media developed by PlOszukiwacz." />
    <meta property="og:type" content="website" />
    <meta property="og:url" content="<?php echo htmlspecialchars($uri); ?>"/>
    <meta property="og:image" content="<?php echo htmlspecialchars($uri); ?>/assets/favicons/android-chrome-192x192.png"/>
    <meta property="og:site_name" content="Femboy Social">

    <title>Femboy Social (BETA)</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="index.css">
</head>
<body class="bg-gray-900 text-white flex-col min-h-screen">
    <!-- URI Missmatch -->
    <div>
        <?php if ($uriMissmatch): ?>
            <div class="fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center">
                <div class="bg-gray-800 p-8 rounded-lg shadow-lg text-center">
                    <h2 class="text-2xl font-bold mb-4">URI Missmatch</h2>
                    <p class="mb-4">The URI in the .env file does not match the current URI.</p>
                    <p class="mb-4">Please update the URI in the .env file to match the current URI.</p>
                    <p class="mb-4">Do not include http:// and https:// in the .env file.</p>
                    <p class="mb-4">Current URI: <?php echo(htmlspecialchars($_SERVER["HTTP_HOST"])); ?></p>
                    <p class="mb-4">.env URI: <?php echo(htmlspecialchars($uri)); ?></p>
                </div>
            </div>
    </div>
    <?php endif; ?>
    
    <!-- Account Banned -->
    <div class="container mx-auto p-4">
        <?php if (
            $current_user === null &&
            isset($_COOKIE["token"]) &&
            isset($accounts[$_COOKIE["token"]]) &&
            $accounts[$_COOKIE["token"]]["banned"]
        ): ?>
            <div class="fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center">
            <div class="bg-gray-800 p-8 rounded-lg shadow-lg text-center">
            <h2 class="text-2xl font-bold mb-4">Your Account is gone</h2>
            <p class="mb-4">Contact Support.</p>
            <a href="https://discord.com/" class="text-blue-500">Support</a>
        </div>
    </div>
    <?php endif; ?>
    
    <!-- Top Bar -->
    <div class="flex justify-between items-center">
        <h1 class="text-3xl font-bold">Femboy Social</h1>
        <div>
            <?php if ($current_user): ?>
                <span class="mr-4">
                    Logged in as: <?php echo htmlspecialchars($accounts[$current_user]["display_name"]); ?>
                </span>
                <a href="/?logout" class="text-blue-500">Logout</a>
            <?php else: ?>
            
            <a href="https://discord.com/api/oauth2/authorize?client_id=<?php echo $client_id; ?>&redirect_uri=<?php echo urlencode($redirect_uri); ?>&response_type=code&scope=identify%20email" class="text-blue-500">Login with Discord</a><br>
                    <a href="misc/login2.php" class="text-blue-500">Login with Username and Password</a><br>
                    <a href="misc/login3.php" class="text-blue-500">Login with a token</a>
            <?php endif; ?>
        </div>
    </div>
    
    <!-- Main Page -->
    <?php if ($current_user): ?>
        <div class="mt-4 flex">
            <!-- Side Panel -->
            <div class="w-1/4 bg-gray-800 p-4 rounded-lg shadow">
                <a href="/" class="block text-blue-400 mb-2">Home</a>
                <a href="/?profile=<?php echo $current_user; ?>" class="block text-blue-400 mb-2">Profile</a>
                <a href="/?settings" class="block text-blue-400 mb-2">Settings</a>
                <a href="/other/other-pages.html" class="block text-blue-400 mb-2">Other pages</a>
                
                <!-- Admin Actions -->
                <?php if (
                    isset($current_user) &&
                    !empty($accounts[$current_user]["admin"])
                ): ?>
                    <!-- View Users (admin) -->
                    <a href="?action=view_users" class="block text-blue-400 mb-2">View Users</a>

                    <!-- Generate Token (admin) -->
                    <a href="?action=gen_token" class="block text-blue-400 mb-2">Generate Token</a>
                <?php endif; ?>
                <a href="/other/donate.html" class="block text-blue-400 mb-2">Donate</a>
            </div>
            
            <!-- Main Content -->
            <div class="w-3/4 ml-4">
                <?php if (isset($_GET["profile"])): ?>
                    <!-- Display Profile -->
                    <?php $profile_user = $_GET["profile"];
                    if (isset($accounts[$profile_user])): ?>
                            <!-- The user exists -->
                            <div class="mt-4 bg-gray-800 p-4 rounded-lg shadow">
                                <h2 class="text-xl font-bold mb-4">
                                    <?php echo htmlspecialchars($accounts[$profile_user]["display_name"]); ?>'s Profile
                                </h2>

                                <img src="<?php echo htmlspecialchars($accounts[$profile_user]["profile_picture"]); ?>" alt="image" class="w-16 h-16 rounded-full mb-4">
                                
                                <!-- user handle + profile badges -->
                                <p>
                                    <strong>@<?php echo htmlspecialchars($profile_user); ?></strong>
                                                               
                                    <!-- Verified Badge -->
                                    <?php if (!empty($accounts[$profile_user]["verified"])): ?>
                                        <img src="assets/badges/check.png" alt="Verified" class="inline w-4 h-4 ml-1">
                                    <?php endif; ?>

                                    <!-- Supporter Badge -->
                                    <?php if (!empty($accounts[$profile_user]["supporter"])): ?>
                                       <img src="assets/badges/supporter.png" alt="supporter" title="A Supporter" class="inline w-4 h-4 ml-1">
                                    <?php endif; ?>

                                    <!-- Developer Badge -->
                                    <?php if (!empty($accounts[$profile_user]["developer"])): ?>
                                        <img src="assets/badges/developer.png" alt="Developer" title="A developer" class="inline w-4 h-4 ml-1">
                                    <?php endif; ?>
                                </p>

                                <!-- Bio -->
                                <p class="mb-4"><?php echo htmlspecialchars($accounts[$profile_user]["bio"]); ?></p>
                                <!-- Followers -->
                                <p>Followers: <?php echo count($accounts[$profile_user]["followers"]); ?></p>
                            
                                <!-- Show posts/replies button -->
                                <div class="flex space-x-4 mb-4">
                                    <!--posts -->
                                    <a href="/?profile=<?php echo urlencode($profile_user); ?>&section=posts" class="px-4 py-2 bg-blue-500 text-white rounded">Posts</a>
                                    <!-- Replies -->
                                    <a href="/?profile=<?php echo urlencode($profile_user); ?>&section=replies" class="px-4 py-2 bg-gray-500 text-white rounded">Replies</a>
                                </div>

                            <!-- Edit Profile/Follow/Unfollow Button -->
                            <?php if ($profile_user == $current_user): ?>
                                <button onclick="document.getElementById('editProfileModal').style.display='block'" class="px-4 py-2 bg-blue-500 text-white rounded">Edit profile</button>
                            <?php else: ?>
                                <?php if (in_array($profile_user, $accounts[$current_user]["following"])): ?>
                                    <a href="/?unfollow=<?php echo urlencode($profile_user); ?>" class="px-4 py-2 bg-red-500 text-white rounded">Unfollow</a>
                                <?php else: ?>
                                    <a href="/?follow=<?php echo urlencode($profile_user); ?>" class="px-4 py-2 bg-blue-500 text-white rounded">Follow</a>
                                <?php endif; ?>
                            <?php endif; ?>
                        </div>
                        
                        <!-- Display posts/replies -->
                        <div class="mt-8">
                            <h2 class="text-xl font-bold mb-4">
                                <?php echo isset($_GET["section"]) && $_GET["section"] == "replies" ? "Replies" : "Posts"; ?>
                                by <?php echo htmlspecialchars($accounts[$profile_user]["display_name"]); ?>
                            </h2>

                            <div>
                                
                                <!-- Set $user_posts to posts or replies and sort them -->
                                <?php if (true):
                                    $user_posts = array_filter($posts, function ($post) use ($profile_user) {
                                        if (isset($_GET["section"]) && $_GET["section"] == "replies"
                                    ) {
                                        return $post["username"] === $profile_user &&
                                            $post["replying_to"] !== null &&
                                            $post["replying_to"] !== "";
                                        } else {
                                            return $post["username"] === $profile_user &&
                                            ( $post["replying_to"] === null || $post["replying_to"] === "");
                                        }
                                    });

                                    usort($user_posts, function ($a, $b) {
                                        return $b["timestamp"] - $a["timestamp"];
                                    });
                                ?>
                                <?php endif; ?>

                                <!-- Display them -->
                                <?php if (!empty($user_posts)): ?>
                                    <?php foreach ($user_posts as $post): ?>
                                        <!-- Reply check -->
                                        <?php if (isset($post["replying_to"]) && $post["replying_to"] !== ""): ?>
                                            <!-- I dont even want to comment this smh -->
                                            <?php $original_post = $posts[$post["replying_to"]]; ?>
                                            <div class="mb-4 p-4 bg-gray-800 rounded-lg shadow">
                                                <div class="flex items-center mb-2">
                                                    <img src="<?php echo htmlspecialchars($original_post["profile_picture"]); ?>" alt="image" class="w-8 h-8 rounded-full mr-2">
                                                    <div>
                                                        <span class="font-bold">
                                                            <a href="/?profile=<?php echo urlencode($original_post["username"]); ?>" class="text-blue-400">
                                                                <?php echo htmlspecialchars($original_post["display_name"]); ?>
                                                            </a>
                                                        </span>
                                                        <span class="text-gray-400">@<?php echo htmlspecialchars($original_post["username"]); ?> · <?php echo formatTime($original_post["timestamp"]); ?></span>
                                                    </div>
                                                </div>

                                                <p class="mb-2"><?php echo htmlspecialchars($original_post["content"]); ?></p>
                                                <?php if ($original_post["image_url"]): ?>
                                                    <a href="<?php echo htmlspecialchars($original_post["image_url"]); ?>" target="_blank">
                                                        <img src="<?php echo htmlspecialchars($original_post["image_url"]); ?>" alt="Post image" width="256" height="256" class="mt-2">
                                                    </a>
                                                <?php endif; ?>

                                                <div class="mt-4 p-4 bg-gray-700 rounded-lg shadow">
                                                    <div class="flex items-center mb-2">
                                                        <img src="<?php echo htmlspecialchars($post["profile_picture"]); ?>" alt="image" class="w-8 h-8 rounded-full mr-2">
                                                        <div>
                                                            <span class="font-bold"><?php echo htmlspecialchars($post["display_name"]); ?></span>
                                                            <span class="text-gray-400">@<?php echo htmlspecialchars($post["username"]); ?> · <?php echo formatTime($post["timestamp"]); ?></span>
                                                        </div>
                                                    </div>

                                                    <p class="mb-2"><?php echo htmlspecialchars($post["content"]); ?></p>
                                                    <?php if ($post["image_url"]): ?>
                                                        <a href="<?php echo htmlspecialchars($post["image_url"]); ?>" target="_blank">
                                                            <img src="<?php echo htmlspecialchars($post["image_url"]); ?>" alt="Reply image" width="256" height="256" class="mt-2">
                                                        </a>
                                                    <?php endif; ?>
                                                </div>
                                            </div>
                                        <?php else: ?>
                                            <div class="mb-4 p-4 bg-gray-800 rounded-lg shadow">
                                                <div class="flex items-center mb-2">
                                                    <img src="<?php echo htmlspecialchars($post["profile_picture"]); ?>" alt="image" class="w-8 h-8 rounded-full mr-2">
                                                    <div>
                                                        <span class="font-bold"><?php echo htmlspecialchars($post["display_name"]); ?></span>
                                                        <span class="text-gray-400">@<?php echo htmlspecialchars($post["username"]); ?> · <?php echo formatTime($post["timestamp"]); ?></span>
                                                    </div>
                                                </div>

                                                <p class="mb-2"><?php echo htmlspecialchars($post["content"]); ?></p>
                                                <!-- Image check -->
                                                <?php if ($post["image_url"]): ?>
                                                    <a href="<?php echo htmlspecialchars($post["image_url"]); ?>" target="_blank">
                                                        <img src="<?php echo htmlspecialchars($post["image_url"]); ?>" alt="Post image" width="256" height="256" class="mt-2">
                                                    </a>
                                                <?php endif; ?>

                                                <!-- Like,Reply and Delete Button -->
                                                <div class="flex space-x-4">
                                                    <!-- Likes -->
                                                    <a href="/?like=<?php echo $post["id"]; ?>" class="text-blue-400">
                                                        Like (<?php echo $post["likes"]; ?>)
                                                    </a>

                                                    <!-- Replies -->
                                                    <button onclick="openReplies('<?php echo $post["id"]; ?>')" class="text-blue-400">
                                                        Replies (<?php echo count($post["replies"]); ?>)
                                                    </button>

                                                    <!-- Delete -->
                                                    <?php if (
                                                        $post["username"] == $current_user ||
                                                        $current_user == $accounts[$current_user]["admin"]
                                                    ): ?>
                                                        <a href="/?delete=<?php echo $post["id"]; ?>" class="text-red-400">
                                                            Delete
                                                        </a>
                                                    <?php endif; ?>
                                                </div>
                                            </div>
                                        <?php endif; ?>
                                    <?php endforeach; ?>
                                <?php else: ?>
                                    <p>No <?php echo isset($_GET["section"]) && $_GET["section"] == "replies"
                                        ? "replies" : "posts"; ?> found.</p>
                                <?php endif; ?>
                            </div>
                        </div>
                    <?php else: ?>
                        <p>Profile not found.</p>
                    <?php endif;
                ?>

                <!-- Show Settings/Main content -->
                <?php elseif (isset($_GET["settings"])): ?>
                    <!-- Settings -->
                    <div class="mt-4 bg-gray-800 p-4 rounded-lg shadow">
                        <h2 class="text-xl font-bold mb-4">Settings</h2>

                        <!-- Verification -->
                        <h1 class="text-xl font-bold mb-4">Verification</h1>
                        <p>You can request a verification mark. Contact @ploszukiwacz on discord. You just need a social media that has 50 or more followers (only for the main femboy social instance)</p>
                        <br>
                        
                        <!-- Discord -->
                        <h1 class="text-xl font-bold mb-4">Discord</h1>
                        <p>Join the Discord!</p><br>
                        <a href="https://discord.gg/B7mSHBBwNz" target="_blank" class="px-4 py-2 bg-blue-500 text-white rounded">Join Now</a><br>
                            
                        <!-- Custom Name -->
                        <br><h1 class="text-xl font-bold mb-4">Custom Name</h1>
                        <p>Please DM @ploszukiwacz on Discord to get a custom name on your Femboy Social Account. (only for the main femboy social instance)</p><br>
                            
                        <!-- Account Deletion -->
                        <h1 class="text-xl font-bold mb-4">Account Deletion</h1>
                        <form action="/" method="post">
                            <input type="hidden" name="delete_account" value="1">
                            <div class="mb-4">
                                <!-- Confirm Deletion -->
                                <label class="block text-gray-400">Confirm the deletion of your account:</label>
                                <input type="text" name="confirm_delete" placeholder="Enter 'yes' to confirm the deletion (Your posts are being saved for approximately 1 day if you change your mind. Your account settings are not being saved.)" class="mt-1 block w-full rounded-md bg-gray-900 border-gray-600 text-white shadow-sm focus:border-indigo-500 focus:ring focus:ring-indigo-200 focus:ring-opacity-50">
                            </div>
                            <!-- Delete Account -->
                            <div class="flex items-center justify-between">
                                <button type="submit" class="px-4 py-2 bg-red-500 text-white rounded">Delete account</button>
                                <a href="/" class="text-gray-400">Cancel</a>
                            </div>
                        </form>
                        <br>
                    </div>
                <?php else: ?>
                    <!-- Create post -->
                    <div class="mt-4">
                        <h2 class="text-xl font-bold mb-4">Create a new post</h2>
                        <form action="/" method="post">
                            <!-- Textarea -->
                            <textarea name="content" id="content" rows="4" maxlength="260" class="mt-1 block w-full rounded-md bg-gray-900 border-gray-600 text-white shadow-sm focus:border-indigo-500 focus:ring focus:ring-indigo-200 focus:ring-opacity-50" placeholder="What do you want to post?" oninput="updateCharacterCount()"></textarea>
                                
                            <!-- Char counter -->
                            <small id="charCount" class="text-gray-400">0/260 characters</small>
                                
                            <!-- Image -->
                            <input type="url" name="image_url" placeholder="Image URL (optional)" class="mt-2 block w-full rounded-md bg-gray-900 border-gray-600 text-white shadow-sm focus:border-indigo-500 focus:ring focus:ring-indigo-200 focus:ring-opacity-50">
                                
                            <!-- Create post button -->
                            <button type="submit" class="mt-2 px-4 py-2 bg-blue-500 text-white rounded">Create post</button>
                            <input type="hidden" name="replying_to" id="replying_to" value="">
                        </form>
                    </div>

                    <!-- Show posts -->
                    <div class="mt-8">
                        <h2 class="text-xl font-bold mb-4">Your Feed</h2>
                        <div>
                            <?php if (!empty($suggested_posts)): ?>
                                <?php foreach ($suggested_posts as $post_id): ?>
                                    <?php $post = $posts[$post_ids[$post_id]]; ?>
                                        <div class="mb-4 p-4 bg-gray-800 rounded-lg shadow">
                                            <!-- Post Body or smth -->
                                            <div class="flex items-center mb-2">
                                                <img src="<?php echo htmlspecialchars($post["profile_picture"]); ?>" alt="image" class="w-8 h-8 rounded-full mr-2">
                                                <div>
                                                    <span class="font-bold">
                                                        <a href="/?profile=<?php echo urlencode($post["username"]); ?>" class="text-blue-400">
                                                            <?php echo htmlspecialchars($post["display_name"]); ?>
                                                        </a>
                                                    </span>

                                                    <!-- Badges -->
                                                    
                                                    <!-- Verified Badge -->
                                                    <?php if (!empty($accounts[$post["username"]]["verified"])): ?>
                                                        <img src="assets/badges/check.png" alt="Verified" class="inline w-4 h-4 ml-1">
                                                    <?php endif; ?>

                                                    <!-- Supporter Badge -->
                                                    <?php if (!empty($accounts[$post["username"]]["supporter"])): ?>
                                                        <img src="assets/badges/supporter.png" alt="Supporter" title="A Supporter" class="inline w-4 h-4 ml-1">
                                                    <?php endif; ?>

                                                    <!-- Developer Badge -->
                                                    <?php if (!empty($accounts[$post["username"]]["developer"])): ?>
                                                        <img src="assets/badges/developer.png" alt="Developer" title="A developer" class="inline w-4 h-4 ml-1">
                                                    <?php endif; ?>

                                                    <!-- Time Formating -->
                                                    <span class="text-gray-400">
                                                        @
                                                        <?php echo htmlspecialchars($post["username"]); ?>
                                                         · 
                                                        <?php echo formatTime($post["timestamp"]); ?>
                                                    </span>

                                                    <!-- Report -->
                                                    <span class="text-red-400"><a href="?report_post=<?php echo(htmlspecialchars($post["id"])); ?>">
                                                        Report
                                                    </a>
                                                </span>
                                                </div>
                                            </div>

                                            <!-- Post Content -->
                                            <p class="mb-2"><?php echo htmlspecialchars($post["content"]); ?></p>
                                            
                                            <!-- Image Embed-->
                                            <?php if ($post["image_url"]): ?>
                                                <a href="<?php echo htmlspecialchars($post["image_url"]); ?>" target="_blank">
                                                    <img src="<?php echo htmlspecialchars($post["image_url"]); ?>" alt="Post image" width="256" height="256" class="mt-2">
                                                </a>
                                            <?php endif; ?>

                                            <!-- Like, Reply and delete buttons -->
                                            <div class="flex space-x-4">
                                                <!-- Like -->
                                                <a href="/?like=<?php echo $post["id"]; ?>" class="text-blue-400">
                                                    Like (<?php echo $post["likes"]; ?>)
                                                </a>

                                                <!-- Reply -->
                                                <button onclick="openReplies('<?php echo $post["id"]; ?>')" class="text-blue-400">
                                                    Replies (<?php echo count($post["replies"]); ?>)
                                                </button>

                                                <!-- Delete -->
                                                <?php if (
                                                    $post["username"] == $current_user ||
                                                    $current_user == $accounts[$current_user]["admin"]
                                                ): ?>
                                                    <a href="/?delete=<?php echo $post["id"]; ?>" class="text-red-400">
                                                        Delete
                                                    </a>
                                                <?php endif; ?>
                                            </div>
                                        </div>
                                    <?php endforeach; ?>
                                <?php else: ?>
                                    <p>No posts found.</p>
                                <?php endif; ?>
                            </div>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        <?php else: ?>
            <p>You need to login if you want to see the posts or want to see a profile. </p>
            <p>Please note that logging on to this Service "Femboy Social", you agree to the <a href="/other/tou.html" target="_blank" class="underline">Terms of Use</a> and that we use cookies to remember that you are logged in.</p>
        <?php endif; ?>
    </div>

    <!-- Copyright -->
    <div class="mt-auto bottom-0 left-0 w-full text-center bg-gray-800 text-white p-2">
        <a href="https://ploszukiwacz.is-a.dev" target="_blank" class="underline">PlOszukiwacz</a> &copy; 2025 - <a href="https://www.gnu.org/licenses/agpl-3.0.en.html" target="_blank" class="underline">AGPL</a> - <a href="https://github.com/ploszukiwaczdev/femboysocial" target="_blank" class="underline">Github</a><br>
        <a href="other/credits.html" style="color: #637bb0;" class="underline">Credit</a>
    </div>

    <!-- Modals -->
    <div id="editProfileModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="document.getElementById('editProfileModal').style.display='none'">&times;</span>
            <h2 class="text-xl font-bold mb-4">Edit profile</h2>
            <form action="/" method="post" enctype="multipart/form-data">
                <input type="hidden" name="edit_profile" value="1">
                <div class="mb-4">
                    <label class="block text-gray-400">Displayname:</label>
                    <input type="text" name="display_name" value="<?php
                            // Check if $current_user is set and exists in $accounts
                            if (isset($current_user) && isset($accounts[$current_user]) && is_array($accounts[$current_user])) {
                                // Safely access the display_name key
                                echo htmlspecialchars($accounts[$current_user]["display_name"]);
                            } else {
                                // Default value if the current user or their display_name is not set
                                echo 'The displayname could not be displayed. PLEASE REPORT THIS IS THIS 99% A BUG AND SHOULD NOT HAPPEN';
                            }
                        ?>" class="mt-1 block w-full rounded-md bg-gray-900 border-gray-600 text-white shadow-sm focus:border-indigo-500 focus:ring focus:ring-indigo-200 focus:ring-opacity-50">
                </div>
                <div class="mb-4">
                    <label class="block text-gray-400">Bio:</label>
                    <textarea name="bio" rows="4" maxlength="60" class="mt-1 block w-full rounded-md bg-gray-900 border-gray-600 text-white shadow-sm focus:border-indigo-500 focus:ring focus:ring-indigo-200 focus:ring-opacity-50">
                        <?php
                        // Check if current_user is set and exists in $accounts
                        if (isset($current_user) && isset($accounts[$current_user]) && is_array($accounts[$current_user]) && isset($accounts[$current_user]["bio"])) {
                            echo htmlspecialchars($accounts[$current_user]["bio"]);
                        } else {
                            // Fallback value if bio is not set
                            echo 'No BIO';
                        }
                        ?>
                    </textarea>

                </div>
                <div class="flex items-center justify-between">
                    <button type="submit" class="px-4 py-2 bg-blue-500 text-white rounded">Save</button>
                    <a href="/" class="text-gray-400">Cancel</a>
                </div>
            </form>
        </div>
    </div>

    <div id="repliesModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="document.getElementById('repliesModal').style.display='none'">&times;</span>
            <div id="repliesContent"></div>
            <form action="/" method="post">
                <textarea name="content" id="replyContent" rows="4" maxlength="260" class="mt-1 block w-full rounded-md bg-gray-900 border-gray-600 text-white shadow-sm focus:border-indigo-500 focus:ring focus:ring-indigo-200 focus:ring-opacity-50" placeholder="Write your reply..."></textarea>
                <button type="submit" class="mt-2 px-4 py-2 bg-blue-500 text-white rounded">Reply</button>
                <input type="hidden" name="replying_to" id="replyingTo" value="">
            </form>

        </div>
    </div>

<script>
    function openReplies(postId) {
        var modal = document.getElementById('repliesModal');
        var content = document.getElementById('repliesContent');
        document.getElementById('replyingTo').value = postId;
        content.innerHTML = '';

        <?php foreach ($posts ?? [] as $post): ?>
        if (postId === '<?php echo(htmlspecialchars($post["id"])); ?>') {
            content.innerHTML += `
                <div class="p-5 bg-gray-800 rounded-lg shadow mb-5">
                    <div class="flex items-center mb-2">
                        <img src="<?php echo htmlspecialchars($post["profile_picture"]); ?>" alt="image" class="w-8 h-8 rounded-full mr-2">
                        <div>
                            <span class="font-bold">
                                <a href="/?profile=<?php echo htmlspecialchars($post["username"]); ?>">
                                    <?php echo htmlspecialchars($post["display_name"]); ?>
                                </a>
                            </span>
                            <span class="text-gray-400">
                                @<?php echo htmlspecialchars($post["username"]); ?> · <?php echo formatTime($post["timestamp"]); ?>
                            </span>
                        </div>
                    </div>
                    <p class="mb-2"><?php echo htmlspecialchars($post["content"]); ?></p>
                    <?php if ($post["image_url"]): ?>
                    <a href="<?php echo htmlspecialchars($post["image_url"]); ?>" target="_blank">
                        <img src="<?php echo htmlspecialchars($post["image_url"]); ?>" alt="Post image" width="256" height="256" class="mt-2">
                    </a>
                    <?php endif; ?>
                </div>
            `;

            <?php if (!empty($post["replies"])): ?>
            content.innerHTML += '<h3 class="text-lg font-bold mb-2">Replies</h3>';
            <?php foreach ($post["replies"] as $reply_id): ?>
            var reply = <?php echo json_encode($posts[$reply_id]); ?>;
            content.innerHTML += `
                <div class="p-3 bg-gray-700 rounded-lg shadow mb-3 ml-4">
                <div class="flex items-center mb-2">
                      <img src="` + reply.profile_picture + `" alt="image" class="w-8 h-8 rounded-full mr-2">
                      <span class="font-bold">
                          <a href="/?profile=` + reply.username + `">` + reply.display_name + ` </a>
                      </span>
                      <span class="text-gray-400">
                          &nbsp;@` + reply.username + ` · ` + new Date(reply.timestamp * 1000).toLocaleString("en-GB", {
                              hourCycle: 'h23',
                              year: 'numeric',
                              month: '2-digit',
                              day: '2-digit',
                              hour: '2-digit',
                              minute: '2-digit',
                              second: '2-digit'
                          }) + `
                      </span>

                </div>

                    <p class="mb-2">` + reply.content + `</p>
                    <div class="flex space-x-4">
                        <a href="/?like=` + reply.id + `" class="text-blue-400">Like (` + (reply.likes || 0) + `)</a>
                        <?php if (
                            isset($current_user, $post["username"]) && 
                            ($current_user == $post["username"] || 
                            (isset($accounts[$current_user]["admin"]) && $accounts[$current_user]["admin"]))
                        ): ?>
                        <a href="/?delete=` + reply.id + `" class="text-red-400">Delete</a>
                        <?php endif; ?>
                    </div>
                </div>
            `;
            <?php endforeach; ?>
            <?php endif; ?>

        }
        <?php endforeach; ?>

        modal.style.display = 'block';
    }

    function updateCharacterCount() {
        var content = document.getElementById('content');
        document.getElementById('charCount').innerText = content.value.length + '/260 characters';
    }

    window.onclick = function(event) {
        if (event.target.classList.contains('modal')) {
            event.target.style.display = 'none';
        }
    }
</script>

</body>
</html>