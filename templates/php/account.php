<?php
    $paths = [
        'AccountPassword' => $_SERVER['AUTH_PATH_ACCOUNT_PASSWORD'] ?? '/account/password',
        'Logout' => $_SERVER['AUTH_PATH_LOGOUT'] ?? '/logout',
        'Assets' => $_SERVER['AUTH_ASSETS_PATH'] ?? '/assets',
    ];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>My Account</title>
    <link rel="stylesheet" href="<?php echo htmlspecialchars($paths['Assets']); ?>/css/style.css">
    <link rel="stylesheet" href="<?php echo htmlspecialchars($paths['Assets']); ?>/css/account.css">
</head>
<body>
    <div class="container content-container">
        <h2>My Account</h2>
        <p>Welcome, <?php echo htmlspecialchars($_SERVER['HTTP_X_USERNAME']); ?>!</p>
        <ul>
            <li><a href="<?php echo htmlspecialchars($paths['AccountPassword']); ?>">Change Password</a></li>
        </ul>
        <div class="logout-link">
            <form action="<?php echo htmlspecialchars($paths['Logout']); ?>" method="post">
                <input type="hidden" name="xsrf_token" value="<?php echo htmlspecialchars($_SERVER['AUTH_LOGOUT_XSRF_TOKEN'] ?? '', ENT_QUOTES); ?>">
                <button type="submit">Logout</button>
            </form>
        </div>
    </div>
</body>
</html>