<?php
session_start();
if(isset($_SESSION["users"])){
    header("Location: index.html");
    exit();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GeeDev Registration</title>
    <link rel="stylesheet" href="sun.css"> 
    <link rel="stylesheet" href="//unpkg.com/bootstrap@3.3.7/dist/css/bootstrap.min.css" type="text/css" />
  <link rel="stylesheet" href="//unpkg.com/bootstrap-select@1.12.4/dist/css/bootstrap-select.min.css" type="text/css" />
  <link rel="stylesheet" href="//unpkg.com/bootstrap-select-country@4.0.0/dist/css/bootstrap-select-country.min.css" type="text/css" />

  <script src="//unpkg.com/jquery@3.4.1/dist/jquery.min.js"></script>
  <script src="//unpkg.com/bootstrap@3.3.7/dist/js/bootstrap.min.js"></script>
  <script src="//unpkg.com/bootstrap-select@1.12.4/dist/js/bootstrap-select.min.js"></script>
  <script src="//unpkg.com/bootstrap-select-country@4.0.0/dist/js/bootstrap-select-country.min.js"></script>
</head>
<body>
    <div class="wrapper">
        <?php
        require_once "database.php";

        if(isset($_SESSION["login"])){
            header("Location: index.html");
            exit(); 
        }

        $errors = [];

        if(isset($_POST["submit"])) {
            $LNAME = $_POST["LastName"];
            $FNAME = $_POST["FirstName"];
            $address = $_POST["address"];
            $Barangay = $_POST["barangay"];
            // Check if the keys are set before accessing them
            $city = isset($_POST["City"]) ? $_POST["City"] : "";
            $country = isset($_POST["Country"]) ? $_POST["Country"] : "";
            $email = $_POST["Email"];
            $password = $_POST["password"];
            $passwordHash = password_hash($password, PASSWORD_DEFAULT);
            $username = $_POST[ "username" ];
        
            // Validation code and other checks continue...
        
            // Validation
            if (empty($LNAME) || empty($FNAME) || empty($address) || empty($Barangay) || empty($city) || empty($email) || empty($country) || empty($password)) {
                $errors[] = "All fields are required";
            }

            if (!filter_var($email, FILTER_VALIDATE_EMAIL)){
                $errors[] = "Email is not valid";
            }

            if (!isValidUsername($username)) {
                $errors[] = "Username is not valid. It should contain only letters, numbers, underscores, and hyphens.";
            }

            if(strlen($password) < 8) {
                $errors[] = "Password must be at least 8 characters long";
            }

           
            // Check if email already exists
            $sql = "SELECT * FROM users WHERE email = ?";
            $stmt = mysqli_prepare($conn, $sql);
            mysqli_stmt_bind_param($stmt, "s", $email);
            mysqli_stmt_execute($stmt);
            $result = mysqli_stmt_get_result($stmt);
            $rowCount = mysqli_num_rows($result);
            if ($rowCount > 0) {
                $errors[] = "Email already exists";
            }

            // If no errors, insert user into database
            if (empty($errors)) {
                $sql = "INSERT INTO users (LNAME, FNAME, address, Barangay, city, country, email, password, username) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
                $stmt = mysqli_prepare($conn, $sql);
                if ($stmt) {
                    mysqli_stmt_bind_param($stmt, "sssssssss", $LNAME, $FNAME, $address, $Barangay, $city, $country, $email, $passwordHash, $username);
                    mysqli_stmt_execute($stmt);
                    echo "<div class='alert alert-success'>You are Registered Successfully!</div>";
                    
                    // Redirect to login.php after successful registration
                    header("Location: login.php");
                    exit();
                } else {
                    die("Something went wrong.");
                }
            }
            } else {
                // Display errors
                foreach($errors as $error) {
                    echo "<div class='alert alert-danger'>$error</div>";
                }
            }

        function isValidUsername($username) {
            // Username should contain only letters, numbers, underscores, and hyphens.
            return preg_match('/^[a-zA-Z0-9_-]+$/', $username);
        }
        ?>
        <form action="registration.php" method="post">
            <h1>Register</h1>
            <div class="input-box">
                <input type="text" name="LastName" placeholder="Last Name:" required>
            </div>
            <div class="input-box">
                <input type="text" name="FirstName" placeholder="First Name:" required>
            </div>
            <div class="input-box">
                <input type="text" name="address" placeholder="Address:" required>
            </div>
            <div class="input-box">
                <input type="text" name="barangay" placeholder="Barangay:" required>
            </div>
            <div class="input-box">
                <input type="text" name="city" placeholder="City:" required>
            </div>
            <div class="form-group">
                 <select class="selectpicker countrypicker" name="country" id="country" data-flag="true" ></select>        
            </div>
            <div class="input-box">
                <input type="email" name="Email" placeholder="Email:" required>
            </div>
            <div class="input-box">
                <input type="text" name="username" placeholder="Username:" required>
            </div>
            <div class="input-box">
                <input type="password" name="password" placeholder="Password:" required>
            </div>
            <div class="input-box">
                <input type="password" name="repeat_password" placeholder="Confirm Password:" required>
            </div>

            <button type="submit" name="submit" class="btn">Register</button>

            <div class="register-link">
                <p>Already have an account? <a href="login.php">Login</a></p>
            </div>
            <script>
                $('.countrypicker').countrypicker();
            </script>
        </form>
    </div>
</body>
</html>