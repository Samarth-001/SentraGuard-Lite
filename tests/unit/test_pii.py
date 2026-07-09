# from app.detectors.pii import PIIDetector


# def test_finds_email():
#     detector = PIIDetector()
#     result = detector.scan("Reach me at john.doe@example.com for details.")

#     assert result.matched is True
#     assert result.tag == "pii"
#     assert "email pattern matched" in result.evidence


# def test_redaction_masks_email_correctly():
#     detector = PIIDetector()
#     result = detector.scan("Email me at john.doe@example.com please.")

#     assert "john.doe@example.com" not in result.sanitized_text
#     assert "[REDACTED_EMAIL]" in result.sanitized_text
#     assert result.sanitized_text == "Email me at [REDACTED_EMAIL] please."


# def test_finds_phone_number():
#     detector = PIIDetector()
#     result = detector.scan("Call me at 555-123-4567 tomorrow.")

#     assert result.matched is True
#     assert "phone number pattern matched" in result.evidence


# def test_redaction_masks_phone_correctly():
#     detector = PIIDetector()
#     result = detector.scan("Call 555-123-4567 anytime.")

#     assert "555-123-4567" not in result.sanitized_text
#     assert "[REDACTED_PHONE]" in result.sanitized_text


# def test_no_pii_does_not_match():
#     detector = PIIDetector()
#     result = detector.scan("Just a normal sentence with no personal data.")

#     assert result.matched is False
#     assert result.score == 0
#     assert result.sanitized_text == "Just a normal sentence with no personal data."


# def test_email_and_phone_both_redacted_in_same_text():
#     detector = PIIDetector()
#     result = detector.scan("Email abc@gmail.com or call 555-123-4567.")

#     assert result.matched is True
#     assert "abc@gmail.com" not in result.sanitized_text
#     assert "555-123-4567" not in result.sanitized_text
#     assert set(result.evidence) == {"email pattern matched", "phone number pattern matched"}


# def test_evidence_never_contains_raw_matched_value():
#     detector = PIIDetector()
#     result = detector.scan("My email is secret.person@example.com")

#     joined_evidence = " ".join(result.evidence)
#     assert "secret.person@example.com" not in joined_evidence