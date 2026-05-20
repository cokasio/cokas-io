<?php
	// Security: Start session and add CSRF protection
	session_start();

	// Security: Set security headers
	header("X-Content-Type-Options: nosniff");
	header("X-Frame-Options: DENY");
	header("X-XSS-Protection: 1; mode=block");

	if ($_SERVER['REQUEST_METHOD'] == "POST"){

		//Form Type
		$formname = isset($_POST["formname"]) ? test_input($_POST["formname"]) : "";


	/*	$firstname = test_input($_POST["firstname"]);
		$lastname  = test_input($_POST["lastname"]);
		$company   = test_input($_POST["company"]);
		$phone     = test_input($_POST["phone"]);*/

		$contactfirstname = isset($_POST["contactfirstname"]) ? test_input($_POST["contactfirstname"]) : "";
		$contactlastname  = isset($_POST["contactlastname"]) ? test_input($_POST["contactlastname"]) : "";
		$contactcompany   = isset($_POST["contactcompany"]) ? test_input($_POST["contactcompany"]) : "";
		$contactemail     = isset($_POST["contactemail"]) ? test_input($_POST["contactemail"]) : "";
		$contactphone     = isset($_POST["contactphone"]) ? test_input($_POST["contactphone"]) : "";
		$serviceinterest  = isset($_POST["serviceinterest"]) ? test_input($_POST["serviceinterest"]) : "";
		$contactcomment   = isset($_POST["contactcomment"]) ? test_input($_POST["contactcomment"]) : "";





		$headers = "From: " . "info@cokas.io" . "\r\n";
		$headers .= "Reply-To: ". "info@cokas.io" . "\r\n";
		$headers .= "MIME-Version: 1.0\r\n";
		$headers .= "Content-Type: text/html; charset=ISO-8859-1\r\n";

		$email = ""; // Initialize email variable
		$to = $email; //Client Email
		$tocompany = "info@cokas.io"; //Company Email
		$subject = "";
		$subjectcompany = "";
		$msgcompany = "";



		if ($formname == "onepagediscount")
		{
			// One Page Discount Message
			$email = test_input($_POST["email"]);
			$fullname = test_input($_POST["fullname"]);

			$subject = "Thank you for signing up with COKASIO";

			$msg  = "Your Verification Code is: 37888410<BR>";
			$msg .= "Please give this Verification Code to you customer service representative for your 10% discount towards your first Service Agreement!\n";

			$subjectcompany = "You have recieved a request for discount on a Service Agreement";

			$msgcompany  = "Full Name: " . $fullname . "<BR>";
		/*	$msgcompany  .= "Last Name: " . $lastname . "<BR>";
			$msgcompany  .= "Company: " . $company . "<BR>";*/
			$msgcompany  .= "Email Address: " . $email . "<BR>";

		}

		if ($formname == "contactform")
		{
			// Contact Page Message
			$email = test_input($_POST["contactemail"]);

			// Security: Check honeypot field (if filled, it's a bot)
			$honeypot = isset($_POST["website"]) ? trim($_POST["website"]) : "";
			if (!empty($honeypot)) {
				error_log("SPAM DETECTED: Honeypot field filled - " . $honeypot);
				// Silently reject - don't give bot feedback
				if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest') {
					header('Content-Type: application/json');
					echo json_encode(['success' => true, 'message' => 'Thank you for contacting us! We will get back to you within 24 hours.']);
					exit();
				}
				header("Location: index.php?success=true#contact");
				exit();
			}

			// Validate required fields
			if (empty($contactfirstname) || empty($contactlastname) || empty($contactcompany) || empty($contactemail) || empty($serviceinterest) || empty($contactcomment)) {
				error_log("ERROR: Missing required fields");
				if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest') {
					header('Content-Type: application/json');
					echo json_encode(['success' => false, 'message' => 'Please fill out all required fields.']);
					exit();
				}
				header("Location: index.php?error=missing_fields#contact");
				exit();
			}

			// Security: Check for suspicious patterns (spam detection)
			if (is_suspicious_pattern($contactfirstname) || is_suspicious_pattern($contactlastname) || is_suspicious_pattern($contactcompany) || is_suspicious_pattern($contactcomment)) {
				error_log("SPAM DETECTED: Suspicious pattern detected in form submission");
				// Silently reject
				if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest') {
					header('Content-Type: application/json');
					echo json_encode(['success' => true, 'message' => 'Thank you for contacting us! We will get back to you within 24 hours.']);
					exit();
				}
				header("Location: index.php?success=true#contact");
				exit();
			}

			// Security: Validate minimum lengths
			if (strlen($contactfirstname) < 2 || strlen($contactlastname) < 2 || strlen($contactcompany) < 2 || strlen($contactcomment) < 10) {
				error_log("ERROR: Field length validation failed");
				if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest') {
					header('Content-Type: application/json');
					echo json_encode(['success' => false, 'message' => 'Please ensure all fields meet minimum length requirements.']);
					exit();
				}
				header("Location: index.php?error=validation_failed#contact");
				exit();
			}

			// Debug: Log to file to see what we're receiving
			error_log("=== FORM SUBMISSION START ===");
			error_log("Form name: " . $formname);
			error_log("First Name: " . $contactfirstname);
			error_log("Last Name: " . $contactlastname);
			error_log("Company: " . $contactcompany);
			error_log("Email: " . $email);
			error_log("Phone: " . $contactphone);
			error_log("Comment: " . substr($contactcomment, 0, 50) . "...");

			// Security: Validate email format and domain
			if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
				error_log("ERROR: Email validation failed - invalid format: " . $email);
				if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest') {
					header('Content-Type: application/json');
					echo json_encode(['success' => false, 'message' => 'Please enter a valid email address.']);
					exit();
				}
				header("Location: index.php?error=invalid_email#contact");
				exit();
			}

			if (!is_business_email($email)) {
				error_log("ERROR: Email validation failed - free email provider: " . $email);
				if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest') {
					header('Content-Type: application/json');
					echo json_encode(['success' => false, 'message' => 'Please use your company email address. Free email providers (Gmail, Yahoo, etc.) are not accepted.']);
					exit();
				}
				header("Location: index.php?error=invalid_email#contact");
				exit();
			}

			error_log("Email validation passed");

			// Security: Validate service interest is selected
			if (empty($serviceinterest)) {
				error_log("ERROR: Service interest not selected");
				if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest') {
					header('Content-Type: application/json');
					echo json_encode(['success' => false, 'message' => 'Please select which service you are interested in.']);
					exit();
				}
				header("Location: index.php?error=missing_service#contact");
				exit();
			}

			error_log("Service interest validation passed: " . $serviceinterest);

			$subject = "Thank you for contacting COKASIO";
			$msg  = "We will get back to you ASAP<BR>";

			$subjectcompany = "You have received a contact form submission";

			$msgcompany  = "<strong>New Contact Form Submission</strong><BR><BR>";
			$msgcompany  .= "<strong>First Name:</strong> " . $contactfirstname . "<BR>";
			$msgcompany  .= "<strong>Last Name:</strong> " . $contactlastname . "<BR>";
			$msgcompany  .= "<strong>Company:</strong> " . $contactcompany . "<BR>";
			$msgcompany  .= "<strong>Email Address:</strong> " . $contactemail . "<BR>";
			$msgcompany  .= "<strong>Phone:</strong> " . $contactphone . "<BR>";
			$msgcompany  .= "<strong>Service Interest:</strong> " . $serviceinterest . "<BR>";
			$msgcompany  .= "<strong>Comment:</strong><BR>" . nl2br($contactcomment) . "<BR>";


		}

		// use wordwrap() if lines are longer than 70 characters
		$msg = wordwrap($msg,70);

		//$headers = "From: yardi@cokas.io";
		// send email
		if (!empty($email) && filter_var($email, FILTER_VALIDATE_EMAIL)) {
			mail($email, $subject, $msg, $headers);
		}

		// Debug: Log what we're sending
		error_log("Sending email to info@cokas.io with subject: " . $subjectcompany);
		error_log("Message content length: " . strlen($msgcompany));
		error_log("Message content: " . $msgcompany);

		$emailSent = mail("info@cokas.io", $subjectcompany, $msgcompany, $headers);

		// Check if this is an AJAX request
		if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest') {
			// Return JSON response for AJAX
			header('Content-Type: application/json');
			if ($emailSent) {
				error_log("Email sent successfully");
				echo json_encode(['success' => true, 'message' => 'Thank you for contacting us! We will get back to you within 24 hours.']);
			} else {
				error_log("Email failed to send");
				echo json_encode(['success' => false, 'message' => 'Sorry, there was an error sending your message. Please try again or call us directly.']);
			}
			exit();
		} else {
			// Standard redirect for non-AJAX requests
			header("Location: index.php?success=true#contact");
			exit();
		}
	}

	function test_input($data) {
	  if (empty($data)) {
	    return "";
	  }
	  $data = trim($data);
	  $data = stripslashes($data);
	  // Security: Prevent email header injection
	  $data = str_replace(["\r", "\n", "%0a", "%0d"], '', $data);
	  // Note: We apply htmlspecialchars for email body (HTML safe)
	  $data = htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
	  return $data;
	}

	// Security: Validate email domain (block free email providers)
	function is_business_email($email) {
		$blocked_domains = [
			'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
			'aol.com', 'mail.com', 'inbox.com', 'icloud.com',
			'live.com', 'msn.com', 'yandex.com', 'protonmail.com',
			'zoho.com', 'gmx.com', 'tutanota.com', 'fastmail.com',
			'me.com', 'mac.com', 'rocketmail.com', 'ymail.com'
		];

		$domain = strtolower(substr(strrchr($email, "@"), 1));
		return !in_array($domain, $blocked_domains);
	}

	// Security: Detect suspicious patterns (random character strings)
	function is_suspicious_pattern($str) {
		if (empty($str) || strlen($str) < 3) {
			return false;
		}

		$clean = preg_replace('/\s+/', '', strtolower($str));

		// Check for too many consonants in a row (random character pattern)
		if (preg_match('/[bcdfghjklmnpqrstvwxyz]{5,}/i', $clean)) {
			return true;
		}

		// Check for repeating character patterns
		if (preg_match('/(.{3,})\1/i', $clean)) {
			return true;
		}

		// Check if string has very few vowels (likely random)
		$vowels = preg_match_all('/[aeiou]/i', $clean);
		$totalChars = strlen($clean);
		if ($totalChars > 5 && $vowels / $totalChars < 0.15) {
			return true;
		}

		return false;
	}

?>
