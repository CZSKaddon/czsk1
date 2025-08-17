<?php
session_start();

// Definice hesel
define('ADMIN_PASSWORD', '51784Ohnisov');
define('VIEWER_PASSWORD', 'ohajo');

// Zpracování přihlašovacího formuláře
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $enteredPassword = $_POST['password'] ?? '';
    if ($enteredPassword === ADMIN_PASSWORD) {
        $_SESSION['authenticated'] = true;
        $_SESSION['role'] = 'admin';
        header('Location: app.html');
        exit;
    } elseif ($enteredPassword === VIEWER_PASSWORD) {
        $_SESSION['authenticated'] = true;
        $_SESSION['role'] = 'viewer';
        header('Location: app.html');
        exit;
    } else {
        $error = 'Nesprávné heslo!';
    }
}

// Kontrola, zda je uživatel již přihlášen
if (isset($_SESSION['authenticated']) && $_SESSION['authenticated'] === true) {
    header('Location: app.html');
    exit;
}
?>

<!DOCTYPE html>
<html lang="cs">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Přihlášení - Sledování FVE</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 font-sans">
    <div class="container mx-auto p-4 max-w-md flex items-center justify-center h-screen">
        <div class="bg-white p-6 rounded-lg shadow-md w-full">
            <h2 class="text-lg font-semibold mb-4 text-center">Přihlášení</h2>
            <form method="POST">
                <label class="block text-sm font-medium text-gray-700">Heslo</label>
                <input type="password" name="password" class="mt-1 block w-full border border-gray-300 rounded-md p-2" placeholder="Zadejte heslo" required>
                <button type="submit" class="mt-4 w-full bg-blue-500 text-white p-2 rounded-md hover:bg-blue-600">Přihlásit se</button>
            </form>
            <?php if (isset($error)): ?>
                <p class="mt-2 text-red-500 text-center"><?php echo htmlspecialchars($error); ?></p>
            <?php endif; ?>
        </div>
    </div>
</body>
</html>