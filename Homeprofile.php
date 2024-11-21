<?php
session_start(); // Start session

// Check likes session variable is set; if not, initialize it
if (!isset($_SESSION['likes'])) {
    $_SESSION['likes'] = [];
}

// likes cookies if they exist
if (isset($_COOKIE['likes'])) {
    $_SESSION['likes'] = json_decode($_COOKIE['likes'], true);
}

// Function to handle likes
function handleLike($name) {
    if (!in_array($name, $_SESSION['likes'])) {
        $_SESSION['likes'][] = $name; // Add name to likes if not already liked
    } else {
        $_SESSION['likes'] = array_diff($_SESSION['likes'], [$name]); // Remove name from likes if already liked
    }

    // Set/update the likes
    setcookie('likes', json_encode($_SESSION['likes']), time() + (86400 * 30), "/"); // 30 days expiration
}

// Check like action was requested
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['like_name'])) {
    handleLike($_POST['like_name']);
}

$profiles = [
    ["name" => "Rennalien Oliva", "position" => "Team Leader", "email" => "olivarennalien_bsit@plmun.edu.ph", "image" => "rennalien.jfif", "facebook_url" => "https://www.facebook.com/rennalien.oliva.3"],
    ["name" => "Ellyza Galindo", "position" => "Developer", "email" => "galindoellyza_bsit@plmun.edu.ph", "image" => "Ellyza.jfif", "facebook_url" => "https://www.facebook.com/ellyzaa.galindo"],
    ["name" => "Jeric Mendoza", "position" => "Developer", "email" => "mendozajeric_bsit@plmun.edu.ph", "image" => "Jeric.jfif", "facebook_url" => "https://www.facebook.com/profile.php?id=100068864546897"],
    ["name" => "Sarahmel Ocado", "position" => "Designer", "email" => "ocadosarahmel_bsit@plmun.edu.ph", "image" => "sarahmel.jpg", "facebook_url" => "https://www.facebook.com/sarahmel.ocado.3"],
    ["name" => "McEphraem San Jose", "position" => "Designer", "email" => "sanjosemcephraem_bsit@plmun.edu.ph", "image" => "McEphraem.jfif", "facebook_url" => "https://www.facebook.com/mcephraemsanjose"],
    ["name" => "Norielyn Talavera", "position" => "Developer", "email" => "talaveranorielyn_bsit@plmun.edu.ph", "image" => "Norielyn.jpg.jfif", "facebook_url" => "https://www.facebook.com/norie.talavera?mibextid=ZbWKwL"]
];
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Team Profiles</title>
    <link rel="stylesheet" type="text/css" href="stylesheet.css"> <!-- Link to the CSS -->
</head>
<body>
    <header>
        <div class="container">
            <h1>Meet Our Team</h1>
        </div>
    </header>

    <div class="search-container">
        <input type="text" id="search-input" placeholder="Search for a team member...">
    </div>

    <div class="container">
        <?php foreach ($profiles as $profile): ?>
            <div class="profile" data-name="<?= strtolower($profile['name']) ?>">
                <img src="image/<?= $profile['image'] ?>" alt="<?= $profile['name'] ?>">
                <h2><?= $profile['name'] ?></h2>
                <p>Position: <?= $profile['position'] ?></p>
                <p><i>IE account: <?= $profile['email'] ?></i></p>
                <p><a href="<?= $profile['facebook_url'] ?>" target="_blank">View Facebook Profile</a></p>
                
                <!-- Reaction button -->
                <form method="POST" style="display:inline;">
                    <input type="hidden" name="like_name" value="<?= $profile['name'] ?>">
                    <button type="submit" style="background-color: <?= in_array($profile['name'], $_SESSION['likes']) ? '#ff9999' : '#cce5ff' ?>; border: none; border-radius: 5px; padding: 5px;">
                        <?= in_array($profile['name'], $_SESSION['likes']) ? 'Unlike' : 'Like' ?>
                    </button>
                </form>
            </div>
        <?php endforeach; ?>
    </div>

    <button onclick="goBack()" class="back-button">Go Back</button>

    <script>
        function goBack() {
            window.history.back();
        }

        // Search functionality
        document.getElementById('search-input').addEventListener('input', function() {
            const searchTerm = this.value.toLowerCase();
            const profiles = document.querySelectorAll('.profile');

            profiles.forEach(profile => {
                const name = profile.getAttribute('data-name');
                if (name.includes(searchTerm)) {
                    profile.style.display = '';
                } else {
                    profile.style.display = 'none'; 
                }
            });
        });
    </script>
</body>
</html>
